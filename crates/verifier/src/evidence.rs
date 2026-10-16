//! Complete current evidence, independent of fleet membership and connection lifetime.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    VerifiedCatalogRelease, VerifiedHardwarePolicy, VerifiedRelease,
    approvals::{
        self, ApprovalVerifier, Environment, RootKey, SignedApprovalManifest, SignedKeyManifest,
        SigstoreFiles, VerifiedApprovals, VerifiedSigstore, payload_sha256,
    },
};

#[cfg(feature = "snp")]
pub mod boot;
mod collateral;
#[cfg(feature = "snp")]
mod history;
#[cfg(feature = "snp")]
mod session;
#[cfg(feature = "snp")]
mod snp;

pub use collateral::Validity;
#[cfg(feature = "snp")]
pub use history::MAX_ARCHIVE_BYTES;
#[cfg(feature = "snp")]
pub use session::VerifiedSession;
#[cfg(feature = "snp")]
pub use snp::{SnpHardwareFacts, VerifiedSnpReport};

/// Completed local work. Individual checks never imply that the candidate was accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStep {
    Decode,
    Sigstore,
    KeyManifest,
    VendorRevocations,
    Envelope,
    ApprovalManifest,
    GatewayRelease,
    CatalogRelease,
    HardwarePolicy,
    VendorCollateral,
    Accepted,
}

/// An observation of a successful check, independent of the caller's clock and UI.
#[derive(Debug, Serialize)]
pub struct VerificationCheck<'a> {
    pub step: VerificationStep,
    pub reference: Option<&'a str>,
    pub cached: bool,
}

/// The replacement body of `evidence/latest.json`. Boot records travel with session evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: String,
    pub sigstore: SigstoreFiles,
    pub keys: SignedKeyManifest,
    pub approvals: SignedApprovalManifest,
    pub vendor_collateral: Vec<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: String,
    pub body_sha256: String,
    pub body: Bundle,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("current evidence exceeds the input limit")]
    TooLarge,
    #[error("invalid current evidence: {0}")]
    Invalid(String),
    #[error(transparent)]
    Approval(#[from] approvals::Error),
    #[error("invalid vendor collateral: {0}")]
    Collateral(String),
    #[error("the required vendor collateral is absent")]
    MissingCollateral,
    #[error("the required vendor collateral is outside its validity interval")]
    CollateralExpired,
    #[error("the required vendor certificate is revoked")]
    Revoked,
    #[error("vendor revocation evidence rolls back or conflicts with an authenticated CRL")]
    CrlOrder,
    #[error("invalid hardware attestation: {0}")]
    Attestation(String),
}

impl Error {
    /// Stable reason for bindings; callers never classify failures by parsing display text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge | Self::Approval(approvals::Error::TooLarge) => "evidence_too_large",
            Self::MissingCollateral => "missing_collateral",
            Self::CollateralExpired => "expired_collateral",
            Self::Revoked => "revoked",
            Self::CrlOrder => "crl_order",
            Self::Approval(approvals::Error::Rollback) => "rollback",
            Self::Approval(approvals::Error::Equivocation) => "conflicting_approval",
            Self::Approval(approvals::Error::NotApproved(_)) => "not_approved",
            Self::Approval(approvals::Error::InactiveKey) => "key_rejected",
            Self::Approval(approvals::Error::Authority) => "wrong_authority",
            Self::Approval(approvals::Error::Expired) => "expired_key_authorization",
            Self::Attestation(_) => "invalid_attestation",
            Self::Invalid(_)
            | Self::Collateral(_)
            | Self::Approval(
                approvals::Error::Invalid(_)
                | approvals::Error::Transparency(_)
                | approvals::Error::Sigstore(_)
                | approvals::Error::Signature
                | approvals::Error::Evidence(_),
            ) => "invalid_evidence",
        }
    }
}

#[derive(Debug)]
struct Cached<T> {
    digest: String,
    verified_at: i64,
    value: Arc<T>,
}

/// Only a complete, authenticated candidate can become a snapshot. Immutable results are shared
/// with active users; each new connection still checks current authorization and vendor validity.
#[derive(Debug)]
pub struct Snapshot {
    body_sha256: String,
    #[cfg(feature = "snp")]
    identity: Arc<()>,
    approvals: VerifiedApprovals,
    keys_evidence: SignedKeyManifest,
    key_state: Arc<approvals::KeyState>,
    gateways: BTreeMap<String, Cached<VerifiedRelease>>,
    catalogs: BTreeMap<String, Cached<VerifiedCatalogRelease>>,
    hardware: VerifiedHardwarePolicy,
    collateral_evidence: Vec<BTreeMap<String, Value>>,
    collateral: collateral::Store,
}

impl Snapshot {
    /// Current vendor validity for monitoring. This does not appraise a node or authorize a session.
    #[must_use]
    pub fn collateral_summary(&self, now_unix_ms: i64) -> Vec<Value> {
        self.collateral.summary(now_unix_ms)
    }

    /// Identity of the complete verified evidence contents, including collateral.
    #[must_use]
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    /// Verified public configuration for bindings. This does not appraise a live node.
    /// Releases follow the approval manifest's sequence order.
    #[must_use]
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "sigstore": self.approvals.sigstore().summary(),
            "keys": self.keys_evidence, "approvals": self.approvals.evidence(),
            "gateways": by_sequence(&self.gateways, |release| release.sequence),
            "catalogs": by_sequence(&self.catalogs, |release| release.sequence),
            "hardware_policy": self.hardware, "vendor_collateral": self.collateral_evidence
        })
    }

    /// Check learned root retirement before starting new work. Retained request snapshots
    /// remain available for content/receipt verification after an update.
    ///
    /// # Errors
    /// Rejects an older root generation or an authenticated conflicting root decision.
    pub fn require_current_keys(&self) -> Result<(), Error> {
        self.key_state
            .require_current(self.approvals.keys())
            .map_err(Error::from)
    }
    #[must_use]
    pub const fn approvals(&self) -> &VerifiedApprovals {
        &self.approvals
    }

    #[must_use]
    pub fn gateway(&self, release_id: &str) -> Option<&VerifiedRelease> {
        self.gateways
            .get(release_id)
            .map(|entry| entry.value.as_ref())
    }

    #[must_use]
    pub fn catalog(&self, release_id: &str) -> Option<&VerifiedCatalogRelease> {
        self.catalogs
            .get(release_id)
            .map(|entry| entry.value.as_ref())
    }

    /// Select the highest approved catalog compatible with this approved gateway release. The
    /// catalog names the oldest gateway that reads it, and the gateway the oldest catalog it reads.
    #[must_use]
    pub fn compatible_catalog(&self, gateway_id: &str) -> Option<(&str, &VerifiedCatalogRelease)> {
        self.require_current_keys().ok()?;
        let gateway = self.gateway(gateway_id)?;
        self.catalogs
            .iter()
            .filter(|(_, entry)| {
                entry.value.minimum_gateway_sequence <= gateway.sequence
                    && entry.value.sequence >= gateway.minimum_catalog_sequence
            })
            .max_by_key(|(_, entry)| entry.value.sequence)
            .map(|(id, entry)| (id.as_str(), entry.value.as_ref()))
    }

    #[must_use]
    pub const fn hardware_policy(&self) -> &VerifiedHardwarePolicy {
        &self.hardware
    }

    /// The vendor-signed interval for one chip/TCB, capped by the root authorization deadline.
    /// Fetch timestamps never extend either limit.
    ///
    /// # Errors
    /// Missing or expired material blocks only operations requiring that platform.
    #[cfg_attr(
        not(feature = "snp"),
        expect(
            clippy::missing_const_for_fn,
            reason = "The SNP implementation reads shared revocation state."
        )
    )]
    pub fn collateral_validity(
        &self,
        chip_id: &str,
        reported_tcb: &str,
        now_unix_ms: i64,
    ) -> Result<Validity, Error> {
        #[cfg(feature = "snp")]
        {
            let expires = self.approvals.valid_until(now_unix_ms)?;
            let mut validity = self
                .collateral
                .validity(chip_id, reported_tcb, now_unix_ms)?;
            validity.not_after_unix_ms = validity.not_after_unix_ms.min(expires);
            Ok(validity)
        }
        #[cfg(not(feature = "snp"))]
        {
            let _ = (chip_id, reported_tcb, now_unix_ms);
            Err(Error::MissingCollateral)
        }
    }
}

/// Networkless verifier. The connector owns fetching, origin-specific `ETags` and acquisition bounds.
pub struct Verifier {
    approvals: ApprovalVerifier,
    current: Option<Arc<Snapshot>>,
    revocations: Arc<collateral::Revocations>,
}

impl Verifier {
    /// # Errors
    /// Rejects an environment whose Stogas trust seed has not been provisioned.
    pub fn stogas(environment: Environment) -> Result<Self, Error> {
        Self::new(environment, environment.stogas_root()?)
    }

    /// Learn a root-signed key manifest without requiring the rest of the bundle. Its log
    /// proof uses the current snapshot's Sigstore keys, or the compiled ones before any.
    ///
    /// # Errors
    /// Rejects unauthenticated or conflicting root decisions.
    pub fn verify_key_manifest(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<crate::approvals::KeyManifest, Error> {
        let trust = match &self.current {
            Some(snapshot) => snapshot.approvals.sigstore().trusted_root(),
            None => stogas_offline_sigstore::TrustedRoot::embedded()
                .map_err(|error| approvals::Error::Sigstore(error.to_string()))?,
        };
        Ok(self
            .approvals
            .verify_key_manifest(bytes, trust, now_unix_ms)?)
    }

    /// # Errors
    /// Rejects an invalid locally configured trust root.
    pub fn new(environment: Environment, root: RootKey) -> Result<Self, Error> {
        Ok(Self {
            approvals: ApprovalVerifier::new(environment, root)?,
            current: None,
            revocations: Arc::default(),
        })
    }

    #[must_use]
    pub const fn current(&self) -> Option<&Arc<Snapshot>> {
        self.current.as_ref()
    }

    /// Verify the complete candidate before installing a snapshot. Authenticated vendor
    /// revocation is retained independently, including when another candidate object fails.
    ///
    /// # Errors
    /// Rejects invalid, incomplete, conflicting or superseded evidence without losing current
    /// artifacts. Previously learned vendor revocation still constrains their use.
    pub fn refresh(&mut self, bytes: &[u8], now_unix_ms: i64) -> Result<Arc<Snapshot>, Error> {
        self.refresh_observed(bytes, now_unix_ms, |_| {})
    }

    /// Refresh with observations after actual checks, including reuse of authenticated bytes.
    /// Observers must not panic. Only `Accepted` establishes a complete current snapshot.
    ///
    /// # Errors
    /// Has the same validation and retained-revocation behavior as [`Self::refresh`].
    pub fn refresh_observed(
        &mut self,
        bytes: &[u8],
        now_unix_ms: i64,
        mut observer: impl FnMut(VerificationCheck<'_>),
    ) -> Result<Arc<Snapshot>, Error> {
        let mut checked = |step, reference: Option<&str>, cached| {
            observer(VerificationCheck {
                step,
                reference,
                cached,
            });
        };
        let value = parse_json(bytes)?;
        checked(VerificationStep::Decode, None, false);
        // Sigstore's own signatures authenticate its keys, so they can check the root's log
        // proof before the approval that names them is verified.
        let keys = self
            .sigstore(&value["body"]["sigstore"])
            .and_then(|(sigstore, reused)| {
                checked(VerificationStep::Sigstore, None, reused);
                let keys = self.approvals.observe_keys(
                    &serde_json::to_vec(&value["body"]["keys"]).map_err(invalid)?,
                    sigstore.trusted_root(),
                    now_unix_ms,
                )?;
                Ok((sigstore, keys))
            });
        if keys.is_ok() {
            checked(VerificationStep::KeyManifest, None, false);
        }
        // Vendor revocation is an independent signed decision. Retain it even if a missing
        // release, altered approval or other malformed object prevents snapshot installation.
        #[cfg(feature = "snp")]
        let vendor = self.revocations.observe(&value["body"], now_unix_ms);
        #[cfg(feature = "snp")]
        if keys.is_ok() && vendor.is_ok() {
            checked(VerificationStep::VendorRevocations, None, false);
        }
        // Process both independent authorities before returning either delivery failure.
        let (sigstore, keys) = keys?;
        #[cfg(feature = "snp")]
        vendor?;
        let Envelope {
            body_sha256, body, ..
        } = parse_envelope(value)?;
        checked(VerificationStep::Envelope, None, false);
        let approvals =
            self.approvals
                .verify_with_keys(keys, body.approvals, sigstore, now_unix_ms)?;
        checked(VerificationStep::ApprovalManifest, None, false);
        let snapshot = Arc::new(self.verify_snapshot(
            Candidate {
                body_sha256,
                keys: body.keys,
                approvals,
                vendor_collateral: body.vendor_collateral,
            },
            now_unix_ms,
            &mut checked,
        )?);
        self.approvals.accept(snapshot.approvals.clone())?;
        self.current = Some(Arc::clone(&snapshot));
        checked(VerificationStep::Accepted, None, false);
        Ok(snapshot)
    }

    fn verify_snapshot(
        &self,
        candidate: Candidate,
        now_unix_ms: i64,
        checked: &mut impl FnMut(VerificationStep, Option<&str>, bool),
    ) -> Result<Snapshot, Error> {
        let approvals = candidate.approvals;
        let prior = self.current.as_deref();
        // A release check depends only on its bytes, the fixed environment and the Sigstore
        // keys, so unchanged entries reuse earlier results. The approval manifest still
        // decides what is listed.
        let releases = prior
            .filter(|snapshot| Arc::ptr_eq(snapshot.approvals.sigstore(), approvals.sigstore()));
        let mut gateways = BTreeMap::new();
        for gateway in &approvals.manifest().gateways {
            let id = payload_sha256(&gateway.document)?;
            let (entry, reused) = cached(
                releases.and_then(|snapshot| snapshot.gateways.get(&id)),
                payload_sha256(gateway)?,
                now_unix_ms,
                || approvals.verify_gateway(gateway, now_unix_ms),
            )?;
            checked(VerificationStep::GatewayRelease, Some(id.as_str()), reused);
            gateways.insert(id, entry);
        }
        let mut catalogs = BTreeMap::new();
        for catalog in &approvals.manifest().catalogs {
            let id = payload_sha256(&catalog.document)?;
            let (entry, reused) = cached(
                releases.and_then(|snapshot| snapshot.catalogs.get(&id)),
                payload_sha256(catalog)?,
                now_unix_ms,
                || approvals.verify_catalog(catalog, now_unix_ms),
            )?;
            checked(VerificationStep::CatalogRelease, Some(id.as_str()), reused);
            catalogs.insert(id, entry);
        }
        let hardware = approvals.verify_hardware_policy()?;
        checked(VerificationStep::HardwarePolicy, None, false);
        let collateral = collateral::Store::verify(
            &candidate.vendor_collateral,
            prior.map(|snapshot| &snapshot.collateral),
            Arc::clone(&self.revocations),
        )?;
        checked(VerificationStep::VendorCollateral, None, false);
        Ok(Snapshot {
            body_sha256: candidate.body_sha256,
            #[cfg(feature = "snp")]
            identity: Arc::new(()),
            approvals,
            keys_evidence: candidate.keys,
            key_state: self.approvals.key_state(),
            gateways,
            catalogs,
            hardware,
            collateral_evidence: candidate.vendor_collateral,
            collateral,
        })
    }
}

impl Verifier {
    /// Verify the evidence's Sigstore files, reusing the current snapshot's result for the
    /// same files.
    fn sigstore(&self, files: &Value) -> Result<(Arc<VerifiedSigstore>, bool), Error> {
        let files: SigstoreFiles = serde_json::from_value(files.clone()).map_err(invalid)?;
        let digest = payload_sha256(&files)?;
        if let Some(snapshot) = &self.current
            && snapshot.approvals.sigstore().digest() == digest
        {
            return Ok((Arc::clone(snapshot.approvals.sigstore()), true));
        }
        Ok((Arc::new(VerifiedSigstore::verify(&files)?), false))
    }
}

/// An envelope whose approval decision passed; its listed objects are not yet verified.
struct Candidate {
    body_sha256: String,
    keys: SignedKeyManifest,
    approvals: VerifiedApprovals,
    vendor_collateral: Vec<BTreeMap<String, Value>>,
}

fn by_sequence<T: Serialize>(
    entries: &BTreeMap<String, Cached<T>>,
    sequence: impl Fn(&T) -> u64,
) -> Vec<Value> {
    let mut entries: Vec<_> = entries.iter().collect();
    entries.sort_unstable_by_key(|(_, entry)| sequence(&entry.value));
    entries
        .into_iter()
        .map(|(id, entry)| serde_json::json!({"release_id": id, "release": entry.value.as_ref()}))
        .collect()
}

fn cached<T>(
    prior: Option<&Cached<T>>,
    digest: String,
    now_unix_ms: i64,
    verify: impl FnOnce() -> Result<T, approvals::Error>,
) -> Result<(Cached<T>, bool), Error> {
    let (value, verified_at, reused) =
        match prior.filter(|entry| entry.digest == digest && now_unix_ms >= entry.verified_at) {
            Some(entry) => (Arc::clone(&entry.value), entry.verified_at, true),
            None => (Arc::new(verify()?), now_unix_ms, false),
        };
    Ok((
        Cached {
            digest,
            verified_at,
            value,
        },
        reused,
    ))
}

fn parse_json(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    crate::strict_json::from_slice(bytes).map_err(invalid)
}

fn parse_envelope(value: Value) -> Result<Envelope, Error> {
    let digest = payload_sha256(&value["body"])?;
    let envelope: Envelope = serde_json::from_value(value).map_err(invalid)?;
    if envelope.schema != crate::BUNDLE_ENVELOPE_SCHEMA
        || envelope.body.schema != "stogas.confidential-bundle.v1"
    {
        return Err(Error::Invalid("unsupported bundle schema".into()));
    }
    if digest != envelope.body_sha256 {
        return Err(Error::Invalid("bundle body checksum differs".into()));
    }
    Ok(envelope)
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
