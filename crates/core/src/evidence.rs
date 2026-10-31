//! Complete current evidence, independent of fleet membership and connection lifetime.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize as _, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    VerifiedCatalogRelease, VerifiedRelease,
    authority::{
        self, Authority, Environment, EvidenceDocument, KeyManifest, RootKey, SignedEvidence,
        SigstoreFiles, VerifiedEvidence, VerifiedKeys, VerifiedSigstore, payload_sha256,
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
    Signature,
    GatewayRelease,
    CatalogRelease,
    HardwarePolicy,
    VendorCollateral,
    /// The evidence signs onion addresses, each a valid version 3 address.
    OnionServices,
    Accepted,
}

/// An observation of a successful check, independent of the caller's clock and UI.
#[derive(Debug, Serialize)]
pub struct VerificationCheck<'a> {
    pub step: VerificationStep,
    pub reference: Option<&'a str>,
    pub cached: bool,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("current evidence exceeds the input limit")]
    TooLarge,
    #[error("invalid current evidence: {0}")]
    Invalid(String),
    #[error(transparent)]
    Authority(#[from] authority::Error),
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
            Self::TooLarge | Self::Authority(authority::Error::TooLarge) => "evidence_too_large",
            Self::MissingCollateral => "missing_collateral",
            Self::CollateralExpired => "expired_collateral",
            Self::Revoked => "revoked",
            Self::CrlOrder => "crl_order",
            Self::Authority(authority::Error::Rollback) => "rollback",
            Self::Authority(authority::Error::Equivocation) => "conflicting_evidence",
            Self::Authority(authority::Error::NotApproved(_)) => "not_approved",
            Self::Authority(authority::Error::InactiveKey) => "key_rejected",
            Self::Authority(authority::Error::Authority) => "wrong_authority",
            Self::Authority(authority::Error::Expired) => "expired_key_authorization",
            Self::Attestation(_) => "invalid_attestation",
            Self::Invalid(_)
            | Self::Collateral(_)
            | Self::Authority(
                authority::Error::Invalid(_)
                | authority::Error::Transparency(_)
                | authority::Error::Sigstore(_)
                | authority::Error::Signature
                | authority::Error::Evidence(_),
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
    #[cfg(feature = "snp")]
    identity: Arc<()>,
    evidence: VerifiedEvidence,
    key_state: Arc<authority::KeyState>,
    gateways: BTreeMap<String, Cached<VerifiedRelease>>,
    catalogs: BTreeMap<String, Cached<VerifiedCatalogRelease>>,
    collateral: collateral::Store,
}

impl Snapshot {
    /// Current vendor validity for monitoring. This does not appraise a node or authorize a session.
    #[must_use]
    pub fn collateral_summary(&self, now_unix_ms: i64) -> Vec<Value> {
        self.collateral.summary(now_unix_ms)
    }

    /// SHA-256 of the canonical evidence document, which includes the keys and vendor collateral.
    #[must_use]
    pub fn evidence_sha256(&self) -> &str {
        self.evidence.digest()
    }

    /// Verified public configuration for bindings. This does not appraise a live node.
    /// Releases follow their sequence order. An operator's unsigned candidate has no signature.
    #[must_use]
    pub fn summary(&self) -> Value {
        let proof = self.evidence.proof();
        serde_json::json!({
            "evidence_sha256": self.evidence.digest(),
            "document": self.evidence.document(),
            "signature": proof.map(|proof| &proof.signature),
            "inclusion": proof.map(|proof| &proof.inclusion),
            "sigstore": self.evidence.sigstore().summary(),
            "gateways": by_sequence(&self.gateways, |release| release.sequence),
            "catalogs": by_sequence(&self.catalogs, |release| release.sequence)
        })
    }

    /// Check learned root retirement before starting new work. Retained request snapshots
    /// remain available for content/receipt verification after an update.
    ///
    /// # Errors
    /// Rejects an older root generation or an authenticated conflicting root decision.
    pub fn require_current_keys(&self) -> Result<(), Error> {
        self.key_state
            .require_current(self.evidence.keys())
            .map_err(Error::from)
    }

    #[must_use]
    pub const fn evidence(&self) -> &VerifiedEvidence {
        &self.evidence
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

    /// The vendor-signed interval for one chip/TCB, capped by the root authorization deadline.
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
            let expires = self.evidence.valid_until(now_unix_ms)?;
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

    /// The chip certificate's own interval, which only a newly fetched VCEK extends. CRL
    /// freshness and the root authorization deadline renew separately.
    ///
    /// # Errors
    /// Rejects a platform without verified collateral.
    #[cfg(feature = "snp")]
    pub fn vcek_validity(&self, chip_id: &str, reported_tcb: &str) -> Result<Validity, Error> {
        self.collateral.vcek_validity(chip_id, reported_tcb)
    }
}

/// Networkless verifier. The connector owns fetching, origin-specific `ETags` and acquisition bounds.
pub struct Verifier {
    authority: Authority,
    current: Option<Arc<Snapshot>>,
    revocations: Arc<collateral::Revocations>,
    delivery: Option<Delivery>,
}

/// The delivery that produced the current snapshot. Its signatures, proofs and release checks
/// give the same result for the same bytes, and its time checks reject only instants before it
/// was verified or at its root deadline. A repeat delivery therefore rechecks only the deadline
/// and the root decisions learned since.
#[derive(Debug)]
struct Delivery {
    bytes: Box<[u8]>,
    verified_at: i64,
    revocations: u64,
    checks: Vec<(VerificationStep, Option<String>)>,
}

impl Verifier {
    /// # Errors
    /// Rejects an environment whose Stogas trust seed has not been provisioned.
    pub fn stogas(environment: Environment) -> Result<Self, Error> {
        Self::new(environment, environment.stogas_root()?)
    }

    /// Learn a root-signed key manifest without requiring complete evidence. Its log proof
    /// uses the current snapshot's Sigstore keys, or the compiled ones before any.
    ///
    /// # Errors
    /// Rejects unauthenticated or conflicting root decisions.
    pub fn verify_key_manifest(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<KeyManifest, Error> {
        let trust = match &self.current {
            Some(snapshot) => snapshot.evidence.sigstore().trusted_root(),
            None => stogas_sigstore::TrustedRoot::embedded()
                .map_err(|error| authority::Error::Sigstore(error.to_string()))?,
        };
        Ok(self
            .authority
            .verify_key_manifest(bytes, trust, now_unix_ms)?)
    }

    /// # Errors
    /// Rejects an invalid locally configured trust root.
    pub fn new(environment: Environment, root: RootKey) -> Result<Self, Error> {
        Ok(Self {
            authority: Authority::new(environment, root)?,
            current: None,
            revocations: Arc::default(),
            delivery: None,
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
    /// Bytes that repeat the current snapshot's delivery return that same snapshot, with each of
    /// its checks observed as reused, so sessions bound to it need no new appraisal.
    ///
    /// # Errors
    /// Has the same validation and retained-revocation behavior as [`Self::refresh`].
    pub fn refresh_observed(
        &mut self,
        bytes: &[u8],
        now_unix_ms: i64,
        mut observer: impl FnMut(VerificationCheck<'_>),
    ) -> Result<Arc<Snapshot>, Error> {
        if let Some((snapshot, delivery)) = self.repeated(bytes, now_unix_ms)? {
            for (step, reference) in &delivery.checks {
                observer(VerificationCheck {
                    step: *step,
                    reference: reference.as_deref(),
                    cached: true,
                });
            }
            return Ok(snapshot);
        }
        let mut checks = Vec::new();
        let mut checked = |step, reference: Option<&str>, cached| {
            checks.push((step, reference.map(str::to_owned)));
            observer(VerificationCheck {
                step,
                reference,
                cached,
            });
        };
        let value = parse_json(bytes)?;
        checked(VerificationStep::Decode, None, false);
        let (keys, sigstore) = self.observe(&value["document"], now_unix_ms, &mut checked)?;
        let signed: SignedEvidence = serde_json::from_value(value).map_err(invalid)?;
        let mut candidate = self
            .authority
            .check(keys, signed.document, sigstore, now_unix_ms)?;
        authority::verify_proof(&mut candidate, signed.signature, signed.inclusion)?;
        checked(VerificationStep::Signature, None, false);
        let snapshot = Arc::new(self.verify_snapshot(candidate, now_unix_ms, &mut checked)?);
        self.authority.accept(snapshot.evidence.clone())?;
        self.current = Some(Arc::clone(&snapshot));
        checked(VerificationStep::Accepted, None, false);
        self.delivery = Some(Delivery {
            bytes: bytes.into(),
            verified_at: now_unix_ms,
            revocations: self.revocations.changes(),
            checks,
        });
        Ok(snapshot)
    }

    /// The current snapshot again when `bytes` repeat its delivery. A clock behind that
    /// verification, or vendor revocation learned since, repeats the complete verification.
    fn repeated(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<Option<(Arc<Snapshot>, &Delivery)>, Error> {
        let (Some(snapshot), Some(delivery)) = (&self.current, &self.delivery) else {
            return Ok(None);
        };
        if *delivery.bytes != *bytes
            || now_unix_ms < delivery.verified_at
            || delivery.revocations != self.revocations.changes()
        {
            return Ok(None);
        }
        // In the order a complete verification reaches them: root decisions learned since,
        // then the root deadline.
        self.authority.check_update(&snapshot.evidence)?;
        snapshot.evidence.valid_until(now_unix_ms)?;
        Ok(Some((Arc::clone(snapshot), delivery)))
    }

    /// Check an unsigned evidence document as [`Self::refresh`] would, so an operator never
    /// signs and logs a revision that clients reject. The result has no signature and is never
    /// accepted; root decisions and vendor revocation it carries are still learned.
    ///
    /// # Errors
    /// Rejects everything [`Self::refresh`] rejects, except the missing signature.
    pub fn check_unsigned(&self, bytes: &[u8], now_unix_ms: i64) -> Result<Arc<Snapshot>, Error> {
        let value = parse_json(bytes)?;
        let (keys, sigstore) = self.observe(&value, now_unix_ms, &mut |_, _, _| {})?;
        let document: EvidenceDocument = serde_json::from_value(value).map_err(invalid)?;
        let candidate = self
            .authority
            .check(keys, document, sigstore, now_unix_ms)?;
        Ok(Arc::new(self.verify_snapshot(
            candidate,
            now_unix_ms,
            &mut |_, _, _| {},
        )?))
    }

    /// Verify the document's Sigstore files and root-signed key manifest, and learn its
    /// authenticated vendor revocation even when another part of the document is invalid.
    fn observe(
        &self,
        document: &Value,
        now_unix_ms: i64,
        checked: &mut impl FnMut(VerificationStep, Option<&str>, bool),
    ) -> Result<(VerifiedKeys, Arc<VerifiedSigstore>), Error> {
        // Sigstore's own signatures authenticate its keys, so they can check the root's log
        // proof before the online signature over the whole document is verified.
        let keys = self
            .sigstore(&document["sigstore"])
            .and_then(|(sigstore, reused)| {
                checked(VerificationStep::Sigstore, None, reused);
                let keys = self.authority.observe_keys(
                    &serde_json::to_vec(&document["keys"]).map_err(invalid)?,
                    sigstore.trusted_root(),
                )?;
                Ok((keys, sigstore))
            });
        if keys.is_ok() {
            checked(VerificationStep::KeyManifest, None, false);
        }
        // Vendor revocation is an independent signed decision. Retain it even if a missing
        // release, altered signature or other malformed object prevents acceptance.
        #[cfg(feature = "snp")]
        let vendor = self.revocations.observe(document, now_unix_ms);
        #[cfg(not(feature = "snp"))]
        let _ = now_unix_ms;
        #[cfg(feature = "snp")]
        if keys.is_ok() && vendor.is_ok() {
            checked(VerificationStep::VendorRevocations, None, false);
        }
        // Process both independent authorities before returning either failure.
        let keys = keys?;
        #[cfg(feature = "snp")]
        vendor?;
        Ok(keys)
    }

    fn verify_snapshot(
        &self,
        evidence: VerifiedEvidence,
        now_unix_ms: i64,
        checked: &mut impl FnMut(VerificationStep, Option<&str>, bool),
    ) -> Result<Snapshot, Error> {
        let prior = self.current.as_deref();
        // A release check depends only on its bytes, the fixed environment and the Sigstore
        // keys, so unchanged entries reuse earlier results. The signed document still decides
        // what is listed.
        let releases =
            prior.filter(|snapshot| Arc::ptr_eq(snapshot.evidence.sigstore(), evidence.sigstore()));
        let mut gateways = BTreeMap::new();
        for gateway in &evidence.document().gateways {
            let id = payload_sha256(&gateway.document)?;
            let (entry, reused) = cached(
                releases.and_then(|snapshot| snapshot.gateways.get(&id)),
                payload_sha256(gateway)?,
                now_unix_ms,
                || evidence.verify_gateway(gateway),
            )?;
            checked(VerificationStep::GatewayRelease, Some(id.as_str()), reused);
            gateways.insert(id, entry);
        }
        let mut catalogs = BTreeMap::new();
        for catalog in &evidence.document().catalogs {
            let id = payload_sha256(&catalog.document)?;
            let (entry, reused) = cached(
                releases.and_then(|snapshot| snapshot.catalogs.get(&id)),
                payload_sha256(catalog)?,
                now_unix_ms,
                || evidence.verify_catalog(catalog),
            )?;
            checked(VerificationStep::CatalogRelease, Some(id.as_str()), reused);
            catalogs.insert(id, entry);
        }
        evidence.verify_hardware_policies()?;
        checked(VerificationStep::HardwarePolicy, None, false);
        let collateral = collateral::Store::verify(
            &evidence.document().vendor_collateral,
            prior.map(|snapshot| &snapshot.collateral),
            Arc::clone(&self.revocations),
        )?;
        checked(VerificationStep::VendorCollateral, None, false);
        // The document check validated the addresses with the rest of its shape.
        if evidence.document().onion_services.is_some() {
            checked(VerificationStep::OnionServices, None, false);
        }
        Ok(Snapshot {
            #[cfg(feature = "snp")]
            identity: Arc::new(()),
            evidence,
            key_state: self.authority.key_state(),
            gateways,
            catalogs,
            collateral,
        })
    }

    /// Verify the evidence's Sigstore files, reusing the current snapshot's result for the
    /// same files.
    fn sigstore(&self, files: &Value) -> Result<(Arc<VerifiedSigstore>, bool), Error> {
        let files = SigstoreFiles::deserialize(files).map_err(invalid)?;
        let digest = payload_sha256(&files)?;
        if let Some(snapshot) = &self.current
            && snapshot.evidence.sigstore().digest() == digest
        {
            return Ok((Arc::clone(snapshot.evidence.sigstore()), true));
        }
        Ok((Arc::new(VerifiedSigstore::verify(&files)?), false))
    }
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
    verify: impl FnOnce() -> Result<T, authority::Error>,
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

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
