use super::{Error, KeyManifest, invalid};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct VerifiedKeys {
    pub(super) document: KeyManifest,
    pub(super) digest: String,
    /// When Rekor logged the manifest, in Unix milliseconds.
    pub(super) published_unix_ms: i64,
}

#[derive(Debug)]
struct Learned {
    keys: VerifiedKeys,
    conflicting: bool,
}

/// Root decisions remain authoritative even when unrelated delivery is incomplete.
#[derive(Debug, Default)]
pub struct KeyState(Mutex<Option<Learned>>);

impl KeyState {
    pub(super) fn learn(&self, keys: VerifiedKeys) -> Result<(), Error> {
        let mut state = self.0.lock().map_err(invalid)?;
        if let Some(previous) = state.as_mut() {
            if keys.document.generation == previous.keys.document.generation
                && keys.digest != previous.keys.digest
            {
                previous.conflicting = true;
                return Err(Error::Equivocation);
            }
            check(previous, &keys.document, &keys.digest)?;
        }
        *state = Some(Learned {
            keys,
            conflicting: false,
        });
        drop(state);
        Ok(())
    }

    pub(super) fn check(&self, keys: &KeyManifest, digest: &str) -> Result<(), Error> {
        if let Some(previous) = self.0.lock().map_err(invalid)?.as_ref() {
            check(previous, keys, digest)?;
        }
        Ok(())
    }

    pub(crate) fn require_current(&self, keys: &KeyManifest) -> Result<(), Error> {
        let state = self.0.lock().map_err(invalid)?;
        let learned = state.as_ref().ok_or(Error::InactiveKey)?;
        if learned.conflicting {
            return Err(Error::Equivocation);
        }
        if keys.generation != learned.keys.document.generation {
            let current = &learned.keys.document;
            // A root renewal with unchanged keys may arrive before complete evidence
            // that carries it. Keep existing work eligible until its original
            // deadline; never accept the older document as a new candidate.
            if keys.generation > current.generation
                || !keys.active_key.same_signer(&current.active_key)
                || keys.expires_at > current.expires_at
            {
                return Err(Error::Rollback);
            }
        }
        drop(state);
        Ok(())
    }
}

fn check(previous: &Learned, keys: &KeyManifest, digest: &str) -> Result<(), Error> {
    let old = &previous.keys.document;
    if keys.generation < old.generation {
        return Err(Error::Rollback);
    }
    if keys.generation == old.generation && (previous.conflicting || digest != previous.keys.digest)
    {
        return Err(Error::Equivocation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_keys() -> VerifiedKeys {
        let session: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        // Key state compares generations, digests and deadlines, so a production build can use
        // the staging sample under the production environment name.
        let mut document = session["evidence"]["document"]["keys"]["document"].clone();
        document["environment"] = "prod".into();
        VerifiedKeys {
            digest: crate::authority::payload_sha256(&document).unwrap(),
            document: serde_json::from_value(document).unwrap(),
            published_unix_ms: 0,
        }
    }

    #[test]
    fn renewal_keeps_old_snapshots_usable_but_cannot_restore_them_as_current() {
        let original = sample_keys();
        let state = KeyState::default();
        state.learn(original.clone()).unwrap();
        let mut renewal = original.clone();
        renewal.document.generation += 1;
        renewal.document.expires_at = "2100-02-01T00:00:00Z".into();
        renewal.document.active_key.rekor_public_key = "different publisher metadata".into();
        renewal.digest = "authenticated renewal".into();
        state.learn(renewal.clone()).unwrap();
        state.require_current(&original.document).unwrap();
        assert_eq!(state.learn(original.clone()).unwrap_err(), Error::Rollback);

        let mut shortened = renewal;
        shortened.document.generation += 1;
        shortened.document.expires_at = "2099-12-31T00:00:00Z".into();
        shortened.digest = "authenticated earlier deadline".into();
        state.learn(shortened).unwrap();
        assert_eq!(
            state.require_current(&original.document).unwrap_err(),
            Error::Rollback
        );
    }

    #[test]
    fn authenticated_conflict_blocks_old_snapshots_until_a_later_root_decision() {
        let original = sample_keys();
        let state = KeyState::default();
        state.learn(original.clone()).unwrap();
        let mut conflicting = original.clone();
        conflicting.digest = "different authenticated decision".into();
        assert_eq!(state.learn(conflicting).unwrap_err(), Error::Equivocation);
        assert_eq!(
            state.require_current(&original.document).unwrap_err(),
            Error::Equivocation
        );
        assert_eq!(
            state.learn(original.clone()).unwrap_err(),
            Error::Equivocation
        );
        let mut recovery = original.clone();
        recovery.document.generation += 1;
        recovery.digest = "later authenticated root decision".into();
        state.learn(recovery.clone()).unwrap();
        state.require_current(&recovery.document).unwrap();
        state.require_current(&original.document).unwrap();
        assert_eq!(state.learn(original).unwrap_err(), Error::Rollback);
    }
}
