//! Historical boot appraisal never installs current authorization or creates a live session.

use std::sync::Arc;

use serde_json::Value;

use super::{Error, Verifier, boot::VerifiedBoot};

/// Maximum encoded boot archive size, including its inclusion proof.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024;

type Archive = crate::LoggedDocument<super::boot::BootPublication>;

#[cfg(all(test, feature = "staging"))]
mod tests {
    use super::*;
    use crate::{attestation::certificate::ParsedNativeCertificate, authority::Environment};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    fn fixture() -> (Verifier, Value, Value, i64) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-v1.json"
        ))
        .unwrap();
        let verifier = Verifier::new(
            Environment::Staging,
            serde_json::from_value(fixture["root"].clone()).unwrap(),
        )
        .unwrap();
        let certificate = URL_SAFE_NO_PAD
            .decode(fixture["certificate"].as_str().unwrap())
            .unwrap();
        let parsed = ParsedNativeCertificate::parse(&certificate).unwrap();
        let proof: Value = serde_json::from_slice(parsed.evidence.boot_inclusion).unwrap();
        let archive = json!({
            "document": {
                "schema": "stogas.node-registration.v1",
                "boot": serde_json::from_slice::<Value>(parsed.evidence.boot_document).unwrap(),
                "evidence_sha256": proof["evidence_sha256"]
            },
            "signature": proof["signature"],
            "inclusion": proof["inclusion"]
        });
        (
            verifier,
            archive,
            fixture["evidence"].clone(),
            fixture["verified_at_ms"].as_i64().unwrap(),
        )
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn history_survives_expiry_and_cannot_restore_current_key_authorization() {
        let (mut verifier, archive, evidence, now) = fixture();
        let current = verifier.refresh(&bytes(&evidence), now).unwrap();
        let rotated: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/hardware-session-rotated-v1.json"
        ))
        .unwrap();
        let later = now + 366 * 24 * 60 * 60 * 1000;
        verifier
            .verify_key_manifest(&bytes(&rotated["document"]["keys"]), later)
            .unwrap();
        assert!(current.require_current_keys().is_err());
        let summary = verifier
            .verify_evidence_archive(&bytes(&evidence), later)
            .unwrap();
        assert_eq!(summary["evidence_sha256"], current.evidence_sha256());
        assert_eq!(summary["document"], evidence["document"]);
        let boot = verifier
            .verify_boot_archive(&bytes(&archive), &bytes(&evidence), later)
            .unwrap();
        assert!(boot.hardware().validity().not_after_unix_ms < later);
        assert!(Arc::ptr_eq(verifier.current().unwrap(), &current));
        assert!(current.require_current_keys().is_err());
        assert!(verifier.refresh(&bytes(&evidence), later).is_err());
        assert!(
            verifier
                .verify_boot_archive(
                    &bytes(&archive),
                    &bytes(&evidence),
                    boot.integrated_time_unix_ms() - 1
                )
                .is_err()
        );
    }

    #[test]
    fn history_rejects_substituted_dependencies_signatures_times_and_hardware() {
        let (verifier, archive, evidence, now) = fixture();
        verifier
            .verify_boot_archive(&bytes(&archive), &bytes(&evidence), now)
            .unwrap();
        for (pointer, replacement) in [
            ("/document/evidence_sha256", json!("0".repeat(64))),
            (
                "/document/boot/report_data/tls_spki_sha256",
                json!("0".repeat(64)),
            ),
            (
                "/inclusion/verificationMaterial/tlogEntries/0/integratedTime",
                json!("1"),
            ),
            (
                "/inclusion/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
                json!("AAAA"),
            ),
            ("/signature/signature", json!("AAAA")),
        ] {
            let mut changed = archive.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                verifier
                    .verify_boot_archive(&bytes(&changed), &bytes(&evidence), now)
                    .is_err(),
                "{pointer}"
            );
            assert!(verifier.current().is_none());
        }
        let mut changed = evidence.clone();
        changed["document"]["gateways"] = json!([]);
        assert!(
            verifier
                .verify_boot_archive(&bytes(&archive), &bytes(&changed), now)
                .is_err()
        );
        let mut extra = archive;
        extra["current"] = json!(true);
        assert!(
            verifier
                .verify_boot_archive(&bytes(&extra), &bytes(&evidence), now)
                .is_err()
        );
        for malformed in [
            b"{}".as_slice(),
            br#"{"boot":{},"boot":{}}"#,
            &vec![b' '; MAX_ARCHIVE_BYTES + 1],
        ] {
            assert!(
                verifier
                    .verify_boot_archive(malformed, &bytes(&evidence), now)
                    .is_err()
            );
        }
        assert!(verifier.current().is_none());
    }
}

impl Verifier {
    /// Verify archived evidence without installing it as current trust. Collateral is
    /// authenticated here; boot-specific historical validity is checked by
    /// `verify_boot_archive`. The returned summary cannot establish a live connection.
    ///
    /// # Errors
    /// Rejects malformed, incomplete or unauthenticated evidence.
    pub fn verify_evidence_archive(
        &self,
        evidence: &[u8],
        now_unix_ms: i64,
    ) -> Result<Value, Error> {
        Ok(self
            .historical_verifier()?
            .refresh(evidence, now_unix_ms)?
            .summary())
    }

    fn historical_verifier(&self) -> Result<Self, Error> {
        Ok(Self {
            authority: self.authority.historical_authority()?,
            current: None,
            revocations: Arc::default(),
        })
    }

    /// Appraise an archived boot at its authenticated log-inclusion time using the exact
    /// evidence it names. This proves historical evidence, not current permission
    /// or that any particular HTTPS connection reached the node.
    ///
    /// # Errors
    /// Rejects malformed archives, substituted evidence, future/forged log times, failed
    /// hardware/signature checks or collateral invalid at the logged time.
    pub fn verify_boot_archive(
        &self,
        archive: &[u8],
        evidence: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerifiedBoot, Error> {
        if archive.len() > MAX_ARCHIVE_BYTES || evidence.len() > crate::MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let archive: Archive = serde_json::from_value(
            crate::strict_json::from_slice(archive).map_err(super::invalid)?,
        )
        .map_err(super::invalid)?;
        let entries = archive.inclusion["verificationMaterial"]["tlogEntries"]
            .as_array()
            .filter(|entries| entries.len() == 1)
            .ok_or_else(|| super::invalid("boot archive requires one log entry"))?;
        // This is only a candidate clock. verify_logged_boot authenticates this exact
        // integratedTime before returning anything to the caller.
        let at = entries[0]["integratedTime"]
            .as_str()
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| value.checked_mul(1000))
            .filter(|value| *value > 0 && *value <= now_unix_ms)
            .ok_or_else(|| super::invalid("invalid boot archive log time"))?;
        let snapshot = self.historical_verifier()?.refresh(evidence, at)?;
        if archive.document.schema != super::boot::BOOT_PUBLICATION_SCHEMA
            || snapshot.evidence_sha256() != archive.document.evidence_sha256
        {
            return Err(super::invalid("boot archive evidence identity differs"));
        }
        let document = crate::canonical_json(
            &serde_json::to_value(&archive.document.boot).map_err(super::invalid)?,
        )
        .map_err(super::invalid)?;
        let inclusion = serde_json::to_vec(&serde_json::json!({
            "evidence_sha256": archive.document.evidence_sha256,
            "signature": archive.signature,
            "inclusion": archive.inclusion,
        }))
        .map_err(super::invalid)?;
        let boot = snapshot.verify_logged_boot(document.as_bytes(), &inclusion, at)?;
        if boot.integrated_time_unix_ms() != at {
            return Err(super::invalid("boot archive log time differs"));
        }
        Ok(boot)
    }
}
