//! Offline authorization of current evidence. Delivery and evidence appraisal remain separate.

use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use stogas_offline_sigstore::TrustedRoot;
use thiserror::Error;

use crate::{
    AllowedCatalog, AllowedIgvm, HardwarePolicy, MAX_INPUT_BYTES, STOGAS_SIGNATURE_DOMAIN,
    StogasSignature, VerifiedCatalogRelease, VerifiedHardwarePolicy, VerifiedRelease,
    canonical_json, strict_json,
};

pub const KEY_MANIFEST_SCHEMA: &str = "stogas.keys.v1";
pub const APPROVAL_MANIFEST_SCHEMA: &str = "stogas.approvals.v1";
const MAX_REVISION: u64 = (1 << 53) - 1;

mod keys;
pub(crate) use keys::KeyState;
use keys::VerifiedKeys;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Environment {
    #[serde(rename = "prod")]
    Production,
    #[cfg(feature = "staging")]
    #[serde(rename = "staging")]
    Staging,
}

impl Environment {
    /// Fixed evidence origins in delivery preference order.
    #[must_use]
    pub const fn evidence_origins(self) -> [&'static str; 2] {
        match self {
            Self::Production => [
                "https://evidence.stogas.ai/evidence/latest.json",
                "https://evidence2.stogas.ai/evidence/latest.json",
            ],
            #[cfg(feature = "staging")]
            Self::Staging => [
                "https://evidence-staging.stogas.ai/evidence/latest.json",
                "https://evidence2-staging.stogas.ai/evidence/latest.json",
            ],
        }
    }

    #[must_use]
    pub const fn api_origin(self) -> &'static str {
        match self {
            Self::Production => "https://api.stogas.ai",
            #[cfg(feature = "staging")]
            Self::Staging => "https://api-staging.stogas.ai",
        }
    }

    #[must_use]
    pub const fn e2ee_origin(self) -> &'static str {
        match self {
            Self::Production => "https://e2ee.stogas.ai",
            #[cfg(feature = "staging")]
            Self::Staging => "https://e2ee-staging.stogas.ai",
        }
    }

    /// Compiled Stogas trust seed; evidence cannot select or replace this authority.
    ///
    /// # Errors
    /// Returns an error if the compiled root is malformed.
    pub fn stogas_root(self) -> Result<RootKey, Error> {
        match self {
            Self::Production => {
                serde_json::from_str(include_str!("prod-root.json")).map_err(invalid)
            }
            #[cfg(feature = "staging")]
            Self::Staging => {
                serde_json::from_str(include_str!("staging-root.json")).map_err(invalid)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RootKey {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OnlineKey {
    pub key_id: String,
    /// Canonical standard-base64 composite ML-DSA-65 and Ed25519 `SubjectPublicKeyInfo` DER.
    pub public_key: String,
    /// Root-authenticated Ed25519 publisher association for Rekor searches, not approval authority.
    pub rekor_public_key: String,
}

impl OnlineKey {
    pub(crate) fn same_signer(&self, other: &Self) -> bool {
        self.key_id == other.key_id && self.public_key == other.public_key
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyManifest {
    pub schema: String,
    pub environment: Environment,
    pub generation: u64,
    /// Root-authorized deadline for live use; historical appraisal uses the logged time.
    pub expires_at: String,
    pub active_key: OnlineKey,
    pub retired_keys: Vec<OnlineKey>,
}

impl KeyManifest {
    fn expiry_unix_ms(&self) -> Result<i64, Error> {
        if self.expires_at.len() != 20 {
            return Err(invalid("key manifest expiry must use whole UTC seconds"));
        }
        let expiry = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| invalid("key manifest expiry is not a UTC timestamp"))?;
        if expiry.timestamp_subsec_nanos() != 0
            || expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string() != self.expires_at
        {
            return Err(invalid("key manifest expiry must use whole UTC seconds"));
        }
        Ok(expiry.timestamp_millis())
    }
}

pub type SignedKeyManifest = crate::LoggedDocument<KeyManifest>;

/// Everything Stogas currently approves, under one online-key signature. The exact key
/// manifest digest makes that manifest's root-signed expiry the expiry of the whole decision.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalManifest {
    pub schema: String,
    pub environment: Environment,
    pub revision: u64,
    pub key_manifest_sha256: String,
    /// Digest of the evidence's Sigstore files, so this decision selects the Sigstore keys.
    pub sigstore_sha256: String,
    /// Ordered by strictly increasing release sequence.
    pub gateways: Vec<AllowedIgvm>,
    /// Ordered by strictly increasing catalog sequence.
    pub catalogs: Vec<AllowedCatalog>,
    pub hardware_policy: HardwarePolicy,
}

pub type SignedApprovalManifest = crate::LoggedDocument<ApprovalManifest>;

/// Sigstore's exact TUF files as standard base64: every root after the verifier's compiled
/// root in version order, the current targets metadata, and the trusted root it lists.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreFiles {
    pub roots: Vec<String>,
    pub targets: String,
    pub trusted_root: String,
}

/// Sigstore keys that Sigstore's own signatures authorize. They verify an approval's
/// transparency proofs only when that approval names their digest.
#[derive(Debug)]
pub struct VerifiedSigstore {
    digest: String,
    trusted_root: TrustedRoot,
    root_version: u64,
    targets_version: u64,
}

impl VerifiedSigstore {
    /// # Errors
    /// Rejects malformed files, broken root chains and trusted roots that differ from the
    /// signed targets listing.
    pub fn verify(files: &SigstoreFiles) -> Result<Self, Error> {
        Self::check(files, stogas_offline_sigstore::verify_trust_update)
    }

    /// Publishers also require Sigstore's current timestamp and snapshot to name these files
    /// before new evidence carries them.
    ///
    /// # Errors
    /// Rejects everything [`Self::verify`] rejects, plus stale or inconsistent metadata.
    pub fn verify_current(
        files: &SigstoreFiles,
        snapshot: &[u8],
        timestamp: &[u8],
        now_unix_ms: i64,
    ) -> Result<Self, Error> {
        Self::check(files, |roots, targets, trusted_root| {
            stogas_offline_sigstore::verify_current_trust_update(
                roots,
                targets,
                trusted_root,
                snapshot,
                timestamp,
                now_unix_ms,
            )
        })
    }

    fn check(
        files: &SigstoreFiles,
        verify: impl FnOnce(
            &[&[u8]],
            &[u8],
            &[u8],
        ) -> Result<
            stogas_offline_sigstore::TrustUpdate,
            stogas_offline_sigstore::Error,
        >,
    ) -> Result<Self, Error> {
        let decode = |text: &String| STANDARD.decode(text).map_err(|_| sigstore("base64"));
        let roots = files
            .roots
            .iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        let roots: Vec<_> = roots.iter().map(Vec::as_slice).collect();
        let update = verify(
            &roots,
            &decode(&files.targets)?,
            &decode(&files.trusted_root)?,
        )
        .map_err(sigstore)?;
        Ok(Self {
            digest: payload_sha256(files)?,
            trusted_root: update.trusted_root,
            root_version: update.root_version,
            targets_version: update.targets_version,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) const fn trusted_root(&self) -> &TrustedRoot {
        &self.trusted_root
    }

    /// Public summary for bindings.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "sigstore_sha256": self.digest,
            "root_version": self.root_version,
            "targets_version": self.targets_version
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("approval evidence exceeds the input limit")]
    TooLarge,
    #[error("invalid approval evidence: {0}")]
    Invalid(String),
    #[error("approval evidence belongs to another authority or environment")]
    Authority,
    #[error("transparency log verification failed: {0}")]
    Transparency(String),
    #[error("Sigstore keys failed verification: {0}")]
    Sigstore(String),
    #[error("approval signing key is not active")]
    InactiveKey,
    #[error("root key authorization has expired")]
    Expired,
    #[error("approval signature is invalid")]
    Signature,
    #[error("approval evidence rolls back an accepted decision")]
    Rollback,
    #[error("different signed decisions use the same revision")]
    Equivocation,
    #[error("{0} is not in the signed approval manifest")]
    NotApproved(&'static str),
    #[error("approved evidence failed verification: {0}")]
    Evidence(String),
}

/// Holds only authenticated decisions, never CRLs, checkpoints, compression or HTTP `ETags`.
#[derive(Clone, Debug)]
pub struct VerifiedApprovals {
    authority: [u8; 32],
    keys: KeyManifest,
    approvals: SignedApprovalManifest,
    sigstore: Arc<VerifiedSigstore>,
    keys_digest: String,
    approvals_digest: String,
    expires_unix_ms: i64,
}

impl VerifiedApprovals {
    /// Check the root deadline without redoing immutable signature verification.
    ///
    /// # Errors
    /// Rejects use at or after expiry. Refreshing delivery bytes cannot extend it.
    pub const fn valid_until(&self, now_unix_ms: i64) -> Result<i64, Error> {
        if now_unix_ms >= self.expires_unix_ms {
            Err(Error::Expired)
        } else {
            Ok(self.expires_unix_ms)
        }
    }

    #[must_use]
    pub const fn keys(&self) -> &KeyManifest {
        &self.keys
    }

    #[must_use]
    pub const fn manifest(&self) -> &ApprovalManifest {
        &self.approvals.document
    }

    /// The approval manifest with its signature and Rekor inclusion proof.
    #[must_use]
    pub const fn evidence(&self) -> &SignedApprovalManifest {
        &self.approvals
    }

    /// The Sigstore keys this decision selected.
    #[must_use]
    pub const fn sigstore(&self) -> &Arc<VerifiedSigstore> {
        &self.sigstore
    }

    /// Verify one listed release's launch manifest and its independent build proof.
    ///
    /// # Errors
    /// Rejects an invalid launch manifest, build proof or placeholder proof in production.
    pub(crate) fn verify_gateway(
        &self,
        release: &AllowedIgvm,
        now_unix_ms: i64,
    ) -> Result<VerifiedRelease, Error> {
        let verified =
            crate::verify_gateway_release(release, self.sigstore.trusted_root(), now_unix_ms)
                .map_err(|error| Error::Evidence(error.to_string()))?;
        if !self.accepts_provenance(&verified.provenance) {
            return Err(Error::Authority);
        }
        Ok(verified)
    }

    /// Verify one listed catalog's release manifest and its independent build proof.
    ///
    /// # Errors
    /// Rejects an invalid release manifest, build proof or placeholder proof in production.
    pub(crate) fn verify_catalog(
        &self,
        catalog: &AllowedCatalog,
        now_unix_ms: i64,
    ) -> Result<VerifiedCatalogRelease, Error> {
        let verified =
            crate::verify_catalog_release(catalog, self.sigstore.trusted_root(), now_unix_ms)
                .map_err(|error| Error::Evidence(error.to_string()))?;
        if !self.accepts_provenance(&verified.provenance) {
            return Err(Error::Authority);
        }
        Ok(verified)
    }

    /// # Errors
    /// Rejects invalid hardware rules.
    pub(crate) fn verify_hardware_policy(&self) -> Result<VerifiedHardwarePolicy, Error> {
        crate::verify_hardware_policy(&self.approvals.document.hardware_policy)
            .map_err(|error| Error::Evidence(error.to_string()))
    }

    // A staging-capable binary must still reject placeholders when its selected context is production.
    const fn accepts_provenance(&self, provenance: &crate::ReleaseProvenance) -> bool {
        match (self.keys.environment, provenance) {
            (Environment::Production, crate::ReleaseProvenance::Github) => true,
            #[cfg(feature = "staging")]
            (Environment::Staging, _) => true,
            #[cfg(feature = "staging")]
            (Environment::Production, crate::ReleaseProvenance::Staging) => false,
        }
    }
}

/// The caller selects this root from its trusted environment configuration, never the bundle.
/// A candidate does not replace learned decisions until every referenced evidence object passes.
#[derive(Debug)]
pub struct ApprovalVerifier {
    environment: Environment,
    root: RootKey,
    authority: [u8; 32],
    accepted: Option<VerifiedApprovals>,
    key_state: Arc<KeyState>,
}

impl ApprovalVerifier {
    /// Separate historical appraisal from all learned current decisions.
    #[cfg(feature = "snp")]
    pub(crate) fn historical_authority(&self) -> Result<Self, Error> {
        Self::new(self.environment, self.root.clone())
    }

    /// Verify and retain a root decision independently of approval/artifact delivery.
    ///
    /// # Errors
    /// Rejects invalid inclusion, signatures, environments, conflicts or rollback.
    pub fn verify_key_manifest(
        &self,
        bytes: &[u8],
        trust: &TrustedRoot,
        now_unix_ms: i64,
    ) -> Result<KeyManifest, Error> {
        let keys = self.observe_keys(bytes, trust, now_unix_ms)?.document;
        if now_unix_ms >= keys.expiry_unix_ms()? {
            return Err(Error::Expired);
        }
        Ok(keys)
    }

    /// # Errors
    /// Rejects malformed or weak root keys and ambiguous key identifiers.
    pub fn new(environment: Environment, root: RootKey) -> Result<Self, Error> {
        let root_der = decode_key(&root.key_id, &root.public_key)?;
        let authority = Sha256::digest(&root_der).into();
        Ok(Self {
            environment,
            root,
            authority,
            accepted: None,
            key_state: Arc::default(),
        })
    }

    fn verify_keys(
        &self,
        bytes: &[u8],
        trust: &TrustedRoot,
        now_unix_ms: i64,
    ) -> Result<VerifiedKeys, Error> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let keys: SignedKeyManifest = parse(bytes)?;
        validate_keys(&keys.document, self.environment, &self.root)?;
        let document = serde_json::to_value(&keys.document).map_err(invalid)?;
        verify_signature(
            &document,
            &keys.signature,
            &self.root.key_id,
            &self.root.public_key,
        )?;
        // Logging proves publication; only the root signature authorizes this manifest.
        let published = verify_document_inclusion(
            &document,
            &keys.signature,
            &keys.inclusion,
            trust,
            now_unix_ms,
        )?;
        let published = published
            .checked_mul(1000)
            .ok_or_else(|| invalid("log time overflow"))?;
        if keys.document.expiry_unix_ms()? <= published {
            return Err(invalid("key authorization expired before publication"));
        }
        Ok(VerifiedKeys {
            digest: payload_sha256(&keys.document)?,
            document: keys.document,
        })
    }

    pub(crate) fn observe_keys(
        &self,
        bytes: &[u8],
        trust: &TrustedRoot,
        now_unix_ms: i64,
    ) -> Result<VerifiedKeys, Error> {
        let keys = self.verify_keys(bytes, trust, now_unix_ms)?;
        self.key_state.learn(keys.clone())?;
        Ok(keys)
    }

    pub(crate) fn key_state(&self) -> Arc<KeyState> {
        Arc::clone(&self.key_state)
    }

    pub(crate) fn verify_with_keys(
        &self,
        keys: VerifiedKeys,
        approvals: SignedApprovalManifest,
        sigstore: Arc<VerifiedSigstore>,
        now_unix_ms: i64,
    ) -> Result<VerifiedApprovals, Error> {
        verify_document_inclusion(
            &serde_json::to_value(&approvals.document).map_err(invalid)?,
            &approvals.signature,
            &approvals.inclusion,
            sigstore.trusted_root(),
            now_unix_ms,
        )?;
        let candidate = verify_online_approval(self.authority, keys.document, approvals, sigstore)?;
        candidate.valid_until(now_unix_ms)?;
        self.check_update(&candidate)?;
        Ok(candidate)
    }

    /// Call only after the complete candidate bundle passes artifact and collateral checks.
    /// Rechecks ordering so overlapping acquisitions cannot undo a newer accepted decision.
    ///
    /// # Errors
    /// Rejects a candidate from another authority, rollback or equivocation.
    pub fn accept(&mut self, candidate: VerifiedApprovals) -> Result<(), Error> {
        self.check_update(&candidate)?;
        self.key_state.learn(VerifiedKeys {
            document: candidate.keys.clone(),
            digest: candidate.keys_digest.clone(),
        })?;
        self.accepted = Some(candidate);
        Ok(())
    }

    #[must_use]
    pub const fn accepted(&self) -> Option<&VerifiedApprovals> {
        self.accepted.as_ref()
    }

    fn check_update(&self, candidate: &VerifiedApprovals) -> Result<(), Error> {
        if candidate.authority != self.authority || candidate.keys.environment != self.environment {
            return Err(Error::Authority);
        }
        self.key_state
            .check(&candidate.keys, &candidate.keys_digest)?;
        let Some(previous) = &self.accepted else {
            return Ok(());
        };
        if candidate.keys.generation < previous.keys.generation {
            return Err(Error::Rollback);
        }
        if candidate.keys.generation == previous.keys.generation {
            if candidate.keys_digest != previous.keys_digest {
                return Err(Error::Equivocation);
            }
            if candidate.manifest().revision < previous.manifest().revision {
                return Err(Error::Rollback);
            }
            if candidate.manifest().revision == previous.manifest().revision
                && candidate.approvals_digest != previous.approvals_digest
            {
                return Err(Error::Equivocation);
            }
        }
        Ok(())
    }
}

/// Stable payload identity. Approval signatures and supporting evidence are not part of it.
///
/// # Errors
/// Returns an error if the payload cannot be serialized as canonical JSON.
pub fn payload_sha256(payload: &impl Serialize) -> Result<String, Error> {
    let value = serde_json::to_value(payload).map_err(invalid)?;
    Ok(hex::encode(Sha256::digest(canonical_payload(&value)?)))
}

fn verify_online_approval(
    authority: [u8; 32],
    keys: KeyManifest,
    signed: SignedApprovalManifest,
    sigstore: Arc<VerifiedSigstore>,
) -> Result<VerifiedApprovals, Error> {
    let approvals = &signed.document;
    if approvals.schema != APPROVAL_MANIFEST_SCHEMA || !valid_revision(approvals.revision) {
        return Err(Error::Invalid("approval schema or revision".into()));
    }
    if approvals.environment != keys.environment {
        return Err(Error::Authority);
    }
    let keys_digest = payload_sha256(&keys)?;
    if approvals.key_manifest_sha256 != keys_digest {
        return Err(Error::Invalid("key manifest digest mismatch".into()));
    }
    if approvals.sigstore_sha256 != sigstore.digest {
        return Err(Error::Invalid("Sigstore files digest mismatch".into()));
    }
    // One release per sequence keeps release selection and history unambiguous.
    if !increasing(
        approvals
            .gateways
            .iter()
            .map(|release| release.document.sequence),
    ) || !increasing(
        approvals
            .catalogs
            .iter()
            .map(|release| release.document.sequence),
    ) {
        return Err(Error::Invalid(
            "approved releases must be ordered by unique sequence".into(),
        ));
    }
    let document = serde_json::to_value(approvals).map_err(invalid)?;
    verify_signature(
        &document,
        &signed.signature,
        &keys.active_key.key_id,
        &keys.active_key.public_key,
    )?;
    let approvals_digest = hex::encode(Sha256::digest(canonical_payload(&document)?));
    let expires_unix_ms = keys.expiry_unix_ms()?;
    Ok(VerifiedApprovals {
        authority,
        keys,
        approvals: signed,
        sigstore,
        keys_digest,
        approvals_digest,
        expires_unix_ms,
    })
}

fn increasing(mut sequences: impl Iterator<Item = u64>) -> bool {
    let mut previous = 0;
    sequences.all(|sequence| std::mem::replace(&mut previous, sequence) < sequence)
}

fn validate_keys(
    keys: &KeyManifest,
    environment: Environment,
    root: &RootKey,
) -> Result<(), Error> {
    if keys.schema != KEY_MANIFEST_SCHEMA || !valid_revision(keys.generation) {
        return Err(Error::Invalid("key manifest schema or generation".into()));
    }
    if keys.environment != environment {
        return Err(Error::Authority);
    }
    keys.expiry_unix_ms()?;
    if keys
        .retired_keys
        .windows(2)
        .any(|pair| pair[0].key_id >= pair[1].key_id)
    {
        return Err(Error::Invalid(
            "retired keys must be sorted and unique".into(),
        ));
    }
    let mut ids = BTreeSet::from([root.key_id.as_str()]);
    let mut public_keys = BTreeSet::from([root.public_key.as_str()]);
    for key in std::iter::once(&keys.active_key).chain(&keys.retired_keys) {
        decode_key(&key.key_id, &key.public_key)?;
        decode_rekor_key(key)?;
        if !ids.insert(&key.key_id) || !public_keys.insert(&key.public_key) {
            return Err(Error::Invalid("duplicate or root operational key".into()));
        }
    }
    Ok(())
}

pub(crate) fn verify_signature(
    document: &Value,
    signature: &StogasSignature,
    key_id: &str,
    public_key: &str,
) -> Result<(), Error> {
    if signature.key_id != key_id {
        return Err(Error::InactiveKey);
    }
    decode_key(key_id, public_key)?;
    let mut payload = STOGAS_SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(&canonical_payload(document)?);
    crate::verify_stogas_signature(public_key, &payload, &signature.signature)
        .map_err(|_| Error::Signature)
}

pub(crate) fn verify_document_inclusion(
    document: &Value,
    signature: &StogasSignature,
    inclusion: &Value,
    trust: &TrustedRoot,
    now_unix_ms: i64,
) -> Result<i64, Error> {
    let artifact = canonical_json(&serde_json::json!({"document":document, "signature":signature}))
        .map_err(invalid)?;
    stogas_offline_sigstore::verify_rekor_document_inclusion(
        trust,
        &serde_json::to_vec(inclusion).map_err(invalid)?,
        artifact.as_bytes(),
        now_unix_ms,
    )
    .map_err(|error| Error::Transparency(error.to_string()))
}

pub(crate) fn valid_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= 128
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn decode_key(key_id: &str, public_key: &str) -> Result<Vec<u8>, Error> {
    if !valid_key_id(key_id) {
        return Err(Error::Invalid("key identifier".into()));
    }
    let bytes = STANDARD.decode(public_key).map_err(invalid)?;
    if STANDARD.encode(&bytes) != public_key {
        return Err(Error::Invalid("public key encoding".into()));
    }
    crate::signing::public_key_from_spki(&bytes).map_err(invalid)?;
    Ok(bytes)
}

fn decode_rekor_key(key: &OnlineKey) -> Result<Vec<u8>, Error> {
    let bytes = STANDARD.decode(&key.rekor_public_key).map_err(invalid)?;
    if bytes.len() != 44 || STANDARD.encode(&bytes) != key.rekor_public_key {
        return Err(Error::Invalid("Rekor public key encoding".into()));
    }
    let public = VerifyingKey::from_public_key_der(&bytes).map_err(invalid)?;
    if public.is_weak() {
        return Err(Error::Invalid("weak Rekor public key".into()));
    }
    Ok(bytes)
}

fn canonical_payload(value: &Value) -> Result<Vec<u8>, Error> {
    let mut canonical = canonical_json(value).map_err(invalid)?;
    canonical.pop(); // The document-file newline is not signed or hashed as a payload.
    Ok(canonical.into_bytes())
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    serde_json::from_value(strict_json::from_slice(bytes).map_err(invalid)?).map_err(invalid)
}

fn sigstore(error: impl std::fmt::Display) -> Error {
    Error::Sigstore(error.to_string())
}

const fn valid_revision(revision: u64) -> bool {
    revision > 0 && revision <= MAX_REVISION
}
fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
