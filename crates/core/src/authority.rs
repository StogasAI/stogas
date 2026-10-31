//! Offline authorization of current evidence.
//!
//! The root-signed key manifest authorizes an online key, and that key signs each evidence
//! revision. Release, hardware and vendor appraisal remain in `evidence`.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use stogas_sigstore::TrustedRoot;
use thiserror::Error;

use crate::{
    AllowedCatalog, AllowedIgvm, AmdCollateral, AmdSevSnpPolicy, MAX_INPUT_BYTES,
    STOGAS_SIGNATURE_DOMAIN, StogasSignature, VerifiedCatalogRelease, VerifiedRelease,
    canonical_json, strict_json,
};

pub const KEY_MANIFEST_SCHEMA: &str = "stogas.keys.v1";
pub const EVIDENCE_SCHEMA: &str = "stogas.evidence.v1";
const MAX_REVISION: u64 = (1 << 53) - 1;

mod keys;
pub(crate) use keys::{KeyState, VerifiedKeys};

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
    /// Canonical standard-base64 Ed25519 `SubjectPublicKeyInfo` DER of the only key that may
    /// log this root's key manifests in Rekor, so a search by it finds every one.
    pub rekor_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OnlineKey {
    pub key_id: String,
    /// Canonical standard-base64 composite ML-DSA-65 and Ed25519 `SubjectPublicKeyInfo` DER.
    pub public_key: String,
    /// Canonical standard-base64 Ed25519 `SubjectPublicKeyInfo` DER of the only key that may log
    /// this key's signatures in Rekor, so a search by it finds every one. It approves nothing.
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

/// Everything Stogas currently approves, with the keys and vendor material that verify it, under
/// one online-key signature. The embedded root-signed key manifest's expiry bounds the document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDocument {
    pub schema: String,
    pub environment: Environment,
    pub revision: u64,
    pub keys: SignedKeyManifest,
    pub sigstore: SigstoreFiles,
    /// Ordered by strictly increasing release sequence.
    pub gateways: Vec<AllowedIgvm>,
    /// Ordered by strictly increasing catalog sequence.
    pub catalogs: Vec<AllowedCatalog>,
    pub hardware_policies: Vec<AmdSevSnpPolicy>,
    pub vendor_collateral: Vec<AmdCollateral>,
    /// Absent until Stogas signs the environment's onion addresses, and in revisions before then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onion_services: Option<OnionServices>,
}

/// The onion addresses of an environment's public hosts.
///
/// The API's address also serves the E2EE and evidence hosts. Its relay reads only the server
/// name in each TLS handshake and passes the connection on unread, so clients check the same
/// certificates and attestation as without Tor.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OnionServices {
    pub api: String,
    pub app: String,
    pub website: String,
}

impl OnionServices {
    fn validate(&self) -> Result<(), Error> {
        if [&self.api, &self.app, &self.website]
            .into_iter()
            .all(|address| valid_onion_address(address))
        {
            Ok(())
        } else {
            Err(Error::Invalid("onion address".into()))
        }
    }
}

/// Whether `address` is a canonical version 3 onion address: the lowercase base32 of an Ed25519
/// key, its two-byte checksum and the version byte 3, then `.onion` (Tor's rend-spec-v3).
fn valid_onion_address(address: &str) -> bool {
    const CHECKSUM: &[u8] = b".onion checksum";
    let Some(label) = address.strip_suffix(".onion") else {
        return false;
    };
    // 56 characters of 5 bits each carry exactly the 35 bytes, with no padding.
    if label.len() != 56 {
        return false;
    }
    let mut decoded = [0_u8; 35];
    let (mut buffer, mut bits, mut next) = (0_u16, 0, 0);
    for character in label.bytes() {
        let value = match character {
            b'a'..=b'z' => character - b'a',
            b'2'..=b'7' => character - b'2' + 26,
            _ => return false,
        };
        buffer = (buffer << 5 | u16::from(value)) & 0x1fff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded[next] = (buffer >> bits).to_le_bytes()[0];
            next += 1;
        }
    }
    let (key, rest) = decoded.split_at(32);
    if rest[2] != 3 {
        return false;
    }
    let mut input = Vec::with_capacity(CHECKSUM.len() + 33);
    input.extend_from_slice(CHECKSUM);
    input.extend_from_slice(key);
    input.push(3);
    libcrux_sha3::sha256(&input)[..2] == rest[..2]
}

/// The published `evidence/latest.json`.
pub type SignedEvidence = crate::LoggedDocument<EvidenceDocument>;

/// Sigstore's exact TUF files as standard base64: every root after the verifier's compiled
/// root in version order, the current targets metadata, and the trusted root it lists.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreFiles {
    pub roots: Vec<String>,
    pub targets: String,
    pub trusted_root: String,
}

/// Sigstore keys that Sigstore's own signatures authorize. They verify transparency proofs only
/// for the evidence that carries them.
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
        Self::check(files, stogas_sigstore::verify_trust_update)
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
            stogas_sigstore::verify_current_trust_update(
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
        ) -> Result<stogas_sigstore::TrustUpdate, stogas_sigstore::Error>,
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
    #[error("signed evidence exceeds the input limit")]
    TooLarge,
    #[error("invalid signed evidence: {0}")]
    Invalid(String),
    #[error("signed evidence belongs to another authority or environment")]
    Authority,
    #[error("transparency log verification failed: {0}")]
    Transparency(String),
    #[error("Sigstore keys failed verification: {0}")]
    Sigstore(String),
    #[error("signing key is not active")]
    InactiveKey,
    #[error("root key authorization has expired")]
    Expired,
    #[error("signature is invalid")]
    Signature,
    #[error("signed evidence rolls back an accepted revision")]
    Rollback,
    #[error("different signed documents use the same revision or generation")]
    Equivocation,
    #[error("{0} is not in the signed evidence")]
    NotApproved(&'static str),
    #[error("listed evidence failed verification: {0}")]
    Evidence(String),
}

/// The online signature and Rekor entry that publish one evidence document.
#[derive(Clone, Debug, Serialize)]
pub struct Proof {
    pub signature: StogasSignature,
    pub inclusion: Value,
}

/// Authenticated evidence contents. Never holds CRL state, checkpoints or HTTP `ETags`.
#[derive(Clone, Debug)]
pub struct VerifiedEvidence {
    document: EvidenceDocument,
    /// Absent only for an operator's unsigned candidate, which is never accepted.
    proof: Option<Proof>,
    sigstore: Arc<VerifiedSigstore>,
    keys_digest: String,
    digest: String,
    expires_unix_ms: i64,
}

impl VerifiedEvidence {
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
        &self.document.keys.document
    }

    #[must_use]
    pub const fn document(&self) -> &EvidenceDocument {
        &self.document
    }

    #[must_use]
    pub const fn proof(&self) -> Option<&Proof> {
        self.proof.as_ref()
    }

    /// SHA-256 of the canonical document: the identity of this evidence revision.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub const fn sigstore(&self) -> &Arc<VerifiedSigstore> {
        &self.sigstore
    }

    /// Verify one listed release's launch manifest and its independent build proof.
    ///
    /// # Errors
    /// Rejects an invalid launch manifest, build proof or placeholder proof in production.
    pub(crate) fn verify_gateway(&self, release: &AllowedIgvm) -> Result<VerifiedRelease, Error> {
        let verified = crate::verify_gateway_release(release, self.sigstore.trusted_root())
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
    ) -> Result<VerifiedCatalogRelease, Error> {
        let verified = crate::verify_catalog_release(catalog, self.sigstore.trusted_root())
            .map_err(|error| Error::Evidence(error.to_string()))?;
        if !self.accepts_provenance(&verified.provenance) {
            return Err(Error::Authority);
        }
        Ok(verified)
    }

    /// # Errors
    /// Rejects invalid hardware rules.
    pub(crate) fn verify_hardware_policies(&self) -> Result<(), Error> {
        crate::validate_hardware_policies(&self.document.hardware_policies)
            .map_err(|error| Error::Evidence(error.to_string()))
    }

    // A staging-capable binary must still reject placeholders when its selected context is production.
    const fn accepts_provenance(&self, provenance: &crate::ReleaseProvenance) -> bool {
        match (self.document.environment, provenance) {
            (Environment::Production, crate::ReleaseProvenance::Github) => true,
            #[cfg(feature = "staging")]
            (Environment::Staging, _) => true,
            #[cfg(feature = "staging")]
            (Environment::Production, crate::ReleaseProvenance::Staging) => false,
        }
    }
}

/// The caller selects this root from its trusted environment configuration, never the evidence.
/// A candidate does not replace accepted evidence until every listed object passes.
#[derive(Debug)]
pub struct Authority {
    environment: Environment,
    root: RootKey,
    accepted: Option<VerifiedEvidence>,
    key_state: Arc<KeyState>,
}

impl Authority {
    /// Separate historical appraisal from all learned current decisions.
    #[cfg(feature = "snp")]
    pub(crate) fn historical_authority(&self) -> Result<Self, Error> {
        Self::new(self.environment, self.root.clone())
    }

    /// Verify and retain a root decision independently of the evidence that carries it.
    ///
    /// # Errors
    /// Rejects invalid inclusion, signatures, environments, conflicts or rollback.
    pub fn verify_key_manifest(
        &self,
        bytes: &[u8],
        trust: &TrustedRoot,
        now_unix_ms: i64,
    ) -> Result<KeyManifest, Error> {
        let keys = self.observe_keys(bytes, trust)?.document;
        if now_unix_ms >= keys.expiry_unix_ms()? {
            return Err(Error::Expired);
        }
        Ok(keys)
    }

    /// Verify the manifest that authorized a signature Rekor logged at `signed_unix_ms`. Rekor
    /// must have logged the manifest first, so a key cannot sign before its authorization, and
    /// the manifest must not have expired by then. A later expiry does not invalidate it.
    ///
    /// # Errors
    /// Rejects everything [`Self::verify_key_manifest`] rejects, and a later manifest.
    pub(crate) fn verify_key_manifest_at(
        &self,
        bytes: &[u8],
        trust: &TrustedRoot,
        signed_unix_ms: i64,
    ) -> Result<KeyManifest, Error> {
        let keys = self.verify_keys(bytes, trust)?;
        if keys.published_unix_ms > signed_unix_ms {
            return Err(invalid("key manifest was logged after the signature"));
        }
        if signed_unix_ms >= keys.document.expiry_unix_ms()? {
            return Err(Error::Expired);
        }
        Ok(keys.document)
    }

    /// # Errors
    /// Rejects malformed or weak root keys and ambiguous key identifiers.
    pub fn new(environment: Environment, root: RootKey) -> Result<Self, Error> {
        decode_key(&root.key_id, &root.public_key)?;
        decode_rekor_key(&root.rekor_public_key)?;
        Ok(Self {
            environment,
            root,
            accepted: None,
            key_state: Arc::default(),
        })
    }

    fn verify_keys(&self, bytes: &[u8], trust: &TrustedRoot) -> Result<VerifiedKeys, Error> {
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
        // Only the root signature authorizes this manifest. The root's own Rekor key must log
        // it, so a stolen root cannot authorize keys where a search by that key misses them.
        let published = verify_document_inclusion(
            &document,
            &keys.signature,
            &keys.inclusion,
            trust,
            &self.root.rekor_public_key,
        )?;
        if keys.document.expiry_unix_ms()? <= published {
            return Err(invalid("key authorization expired before publication"));
        }
        Ok(VerifiedKeys {
            digest: payload_sha256(&keys.document)?,
            document: keys.document,
            published_unix_ms: published,
        })
    }

    pub(crate) fn observe_keys(
        &self,
        bytes: &[u8],
        trust: &TrustedRoot,
    ) -> Result<VerifiedKeys, Error> {
        let keys = self.verify_keys(bytes, trust)?;
        self.key_state.learn(keys.clone())?;
        Ok(keys)
    }

    pub(crate) fn key_state(&self) -> Arc<KeyState> {
        Arc::clone(&self.key_state)
    }

    /// Check a document whose embedded key manifest and Sigstore files the caller verified,
    /// without its signature. Rejects anything that could not follow the accepted evidence.
    pub(crate) fn check(
        &self,
        keys: VerifiedKeys,
        document: EvidenceDocument,
        sigstore: Arc<VerifiedSigstore>,
        now_unix_ms: i64,
    ) -> Result<VerifiedEvidence, Error> {
        let candidate = check_document(keys, document, sigstore)?;
        candidate.valid_until(now_unix_ms)?;
        self.check_update(&candidate)?;
        Ok(candidate)
    }

    /// Installs a candidate that [`Self::check`] returned in the same refresh, once its signature
    /// and its release, hardware and collateral checks pass. A refresh holds the authority
    /// exclusively from that check to here, so the candidate still follows the accepted evidence,
    /// and its key manifest was learned before the check.
    ///
    /// # Errors
    /// Rejects a candidate without a verified signature.
    pub(crate) fn accept(&mut self, candidate: VerifiedEvidence) -> Result<(), Error> {
        if candidate.proof.is_none() {
            return Err(Error::Signature);
        }
        self.accepted = Some(candidate);
        Ok(())
    }

    #[must_use]
    pub const fn accepted(&self) -> Option<&VerifiedEvidence> {
        self.accepted.as_ref()
    }

    /// Checks that `candidate` may follow the accepted evidence under the root decisions
    /// learned so far. Its key manifest passed this authority's root and environment.
    pub(crate) fn check_update(&self, candidate: &VerifiedEvidence) -> Result<(), Error> {
        // Rejects an older generation and a different manifest with the same generation.
        self.key_state
            .check(candidate.keys(), &candidate.keys_digest)?;
        let Some(previous) = &self.accepted else {
            return Ok(());
        };
        // A newer root-signed generation supersedes every revision the earlier one allowed, so
        // a compromised online key that signed the maximum revision cannot block recovery.
        if candidate.keys().generation > previous.keys().generation {
            return Ok(());
        }
        match candidate.document.revision.cmp(&previous.document.revision) {
            Ordering::Less => Err(Error::Rollback),
            Ordering::Equal if candidate.digest != previous.digest => Err(Error::Equivocation),
            _ => Ok(()),
        }
    }
}

/// Verify the online signature and Rekor entry that publish a checked document.
pub(crate) fn verify_proof(
    candidate: &mut VerifiedEvidence,
    signature: StogasSignature,
    inclusion: Value,
) -> Result<(), Error> {
    let document = serde_json::to_value(&candidate.document).map_err(invalid)?;
    let key = &candidate.document.keys.document.active_key;
    verify_signature(&document, &signature, &key.key_id, &key.public_key)?;
    verify_document_inclusion(
        &document,
        &signature,
        &inclusion,
        candidate.sigstore.trusted_root(),
        &key.rekor_public_key,
    )?;
    candidate.proof = Some(Proof {
        signature,
        inclusion,
    });
    Ok(())
}

/// Stable payload identity. Signatures and log proofs are not part of it.
///
/// # Errors
/// Returns an error if the payload cannot be serialized as canonical JSON.
pub fn payload_sha256(payload: &impl Serialize) -> Result<String, Error> {
    let value = serde_json::to_value(payload).map_err(invalid)?;
    Ok(hex::encode(Sha256::digest(canonical_payload(&value)?)))
}

fn check_document(
    keys: VerifiedKeys,
    document: EvidenceDocument,
    sigstore: Arc<VerifiedSigstore>,
) -> Result<VerifiedEvidence, Error> {
    if document.schema != EVIDENCE_SCHEMA || !valid_revision(document.revision) {
        return Err(Error::Invalid("evidence schema or revision".into()));
    }
    // The caller verified these parts of the same delivery; the document must carry them.
    if payload_sha256(&document.keys.document)? != keys.digest
        || payload_sha256(&document.sigstore)? != sigstore.digest()
    {
        return Err(Error::Invalid(
            "verified keys or Sigstore files differ".into(),
        ));
    }
    if document.environment != keys.document.environment {
        return Err(Error::Authority);
    }
    // One release per sequence keeps release selection and history unambiguous.
    if !increasing(
        document
            .gateways
            .iter()
            .map(|release| release.document.sequence),
    ) || !increasing(
        document
            .catalogs
            .iter()
            .map(|release| release.document.sequence),
    ) {
        return Err(Error::Invalid(
            "approved releases must be ordered by unique sequence".into(),
        ));
    }
    if let Some(onion) = &document.onion_services {
        onion.validate()?;
    }
    Ok(VerifiedEvidence {
        digest: payload_sha256(&document)?,
        expires_unix_ms: keys.document.expiry_unix_ms()?,
        document,
        proof: None,
        sigstore,
        keys_digest: keys.digest,
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
    // One Rekor key per signer attributes each logged entry to exactly one key.
    let mut rekor_keys = BTreeSet::from([root.rekor_public_key.as_str()]);
    for key in std::iter::once(&keys.active_key).chain(&keys.retired_keys) {
        decode_key(&key.key_id, &key.public_key)?;
        decode_rekor_key(&key.rekor_public_key)?;
        if !ids.insert(&key.key_id)
            || !public_keys.insert(&key.public_key)
            || !rekor_keys.insert(&key.rekor_public_key)
        {
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

/// Verify that `submitter`, a Rekor key from validated authorization, logged this signed
/// document, and return the log time in Unix milliseconds.
pub(crate) fn verify_document_inclusion(
    document: &Value,
    signature: &StogasSignature,
    inclusion: &Value,
    trust: &TrustedRoot,
    submitter: &str,
) -> Result<i64, Error> {
    let artifact = canonical_json(&serde_json::json!({"document":document, "signature":signature}))
        .map_err(invalid)?;
    stogas_sigstore::verify_rekor_document_inclusion(
        trust,
        &serde_json::to_vec(inclusion).map_err(invalid)?,
        artifact.as_bytes(),
        &STANDARD.decode(submitter).map_err(invalid)?,
    )
    .map_err(|error| Error::Transparency(error.to_string()))?
    .checked_mul(1000)
    .ok_or_else(|| invalid("log time overflow"))
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

fn decode_rekor_key(key: &str) -> Result<Vec<u8>, Error> {
    let bytes = STANDARD.decode(key).map_err(invalid)?;
    if bytes.len() != 44 || STANDARD.encode(&bytes) != key {
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

pub(crate) const fn valid_revision(revision: u64) -> bool {
    revision > 0 && revision <= MAX_REVISION
}
fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
