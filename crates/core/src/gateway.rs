//! Gateway-side producers for the formats this crate verifies: boot keys and
//! documents, quote batches, session evidence, receipts and boot requests.
//! Only the gateway's native build enables this module.

use crate::{
    attestation::{
        BatchProof, Binding, MAX_BATCH_LEAVES,
        evidence::{REPORT_BYTES, SessionEvidence},
    },
    authority::Environment,
    evidence::boot::{self, BootRecord, BootReportData, BootRequestPurpose},
    kem::{PrivateKey, XWing},
    receipt::{self, Receipt},
    secret_release,
    signing::{self, SIGNATURE_BYTES, SigningKey, mldsa},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{Kem as _, Serializable as _};
use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid gateway input: {0}")]
    Input(&'static str),
    #[error("boot provisioning authentication failed")]
    Authentication,
    #[error(transparent)]
    Signing(#[from] signing::Error),
}

impl From<secret_release::Error> for Error {
    fn from(error: secret_release::Error) -> Self {
        match error {
            secret_release::Error::InvalidInput(reason) => Self::Input(reason),
            secret_release::Error::Crypto | secret_release::Error::Authentication => {
                Self::Authentication
            }
        }
    }
}

/// One boot's signing key and one-time provisioning key.
///
/// Private keys never leave this value. The provisioning key is erased after its
/// one successful open; the signing key when this value drops.
pub struct NodeKeys {
    signing: SigningKey,
    recipient: Mutex<Option<PrivateKey>>,
    recipient_public: String,
}

impl NodeKeys {
    /// Derive both keys from independent random seeds: composite ML-DSA-65 and
    /// Ed25519 for signing and X-Wing for provisioning. The caller erases its seed copies.
    #[must_use]
    pub fn from_seeds(signing: &[[u8; signing::SEED_BYTES]; 2], provisioning: &[u8; 32]) -> Self {
        let recipient = PrivateKey::from_seed(Zeroizing::new(*provisioning));
        Self {
            signing: SigningKey::from_seeds(signing),
            recipient_public: URL_SAFE_NO_PAD.encode(XWing::sk_to_pk(&recipient).to_bytes()),
            recipient: Mutex::new(Some(recipient)),
        }
    }

    /// SNP report data committing this boot's public keys, TLS key and registration challenge.
    ///
    /// # Errors
    /// Rejects an environment absent from this build.
    pub fn report_data(
        &self,
        environment: Environment,
        tls_spki_sha256: &[u8; 32],
        challenge: &[u8; 32],
    ) -> Result<[u8; 64], Error> {
        self.boot_report_data(environment, tls_spki_sha256, challenge)
            .commitment()
            .map_err(|_| Error::Input("boot report data"))
    }

    /// The exact logged boot document for a quote over `report_data` with the same inputs.
    ///
    /// # Errors
    /// Rejects reports of another size or whose report data commits other inputs.
    pub fn boot_document(
        &self,
        environment: Environment,
        tls_spki_sha256: &[u8; 32],
        challenge: &[u8; 32],
        report: &[u8],
        gateway_release_id: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        let data = self.boot_report_data(environment, tls_spki_sha256, challenge);
        let commitment = data
            .commitment()
            .map_err(|_| Error::Input("boot report data"))?;
        if report.len() != REPORT_BYTES || report[0x50..0x90] != commitment {
            return Err(Error::Input("boot quote commits other report data"));
        }
        let record = BootRecord {
            schema: boot::BOOT_SCHEMA.into(),
            gateway_release_id: hex::encode(gateway_release_id),
            report: URL_SAFE_NO_PAD.encode(report),
            report_data: data,
        };
        let value = serde_json::to_value(record).map_err(|_| Error::Input("boot document"))?;
        crate::canonical_json(&value)
            .map(String::into_bytes)
            .map_err(|_| Error::Input("boot document"))
    }

    /// Sign one registration acknowledgement or certificate renewal for this boot.
    ///
    /// # Errors
    /// Fails only when signing fails.
    pub fn sign_boot_request(
        &self,
        purpose: BootRequestPurpose,
        node_id: &str,
        issued_at_ms: i64,
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        Ok(self
            .signing
            .sign(&boot::request_message(purpose, node_id, issued_at_ms))?)
    }

    /// Sign exact content hashes and the metadata bag, excluding any `receipt` member.
    ///
    /// # Errors
    /// Rejects malformed or oversized metadata and signing failures.
    pub fn sign_receipt(
        &self,
        boot_sha256: &[u8; 32],
        request: &[u8; 32],
        response: &[u8; 32],
        metadata: &[u8],
    ) -> Result<Receipt, Error> {
        if metadata.len() > receipt::MAX_METADATA_BYTES {
            return Err(Error::Input("receipt metadata size"));
        }
        let metadata = crate::strict_json::from_slice(metadata)
            .map_err(|_| Error::Input("receipt metadata"))?;
        let digest =
            receipt::metadata_digest(&metadata).map_err(|_| Error::Input("receipt metadata"))?;
        let signature = self
            .signing
            .sign(&receipt::message(request, response, &digest))?;
        Ok(Receipt {
            schema: receipt::SCHEMA.into(),
            boot_sha256: hex::encode(boot_sha256),
            request_sha256: hex::encode(request),
            response_sha256: hex::encode(response),
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }

    /// Open Control's provisioning envelope for this exact boot, then erase the
    /// provisioning key. A rejected envelope leaves the key in place.
    ///
    /// # Errors
    /// Rejects another boot, a malformed envelope, failed authentication or a
    /// provisioning key that has already opened its envelope.
    pub fn open_provisioning(
        &self,
        boot_sha256: &[u8; 32],
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut recipient = self
            .recipient
            .lock()
            .map_err(|_| Error::Input("provisioning key state"))?;
        let opened = secret_release::open_provisioning(
            recipient
                .as_ref()
                .ok_or(Error::Input("provisioning key already used"))?,
            boot_sha256,
            envelope,
        )?;
        *recipient = None;
        drop(recipient);
        Ok(opened)
    }

    fn boot_report_data(
        &self,
        environment: Environment,
        tls_spki_sha256: &[u8; 32],
        challenge: &[u8; 32],
    ) -> BootReportData {
        BootReportData {
            schema: boot::REPORT_DATA_SCHEMA.into(),
            environment,
            signing_public_key: URL_SAFE_NO_PAD.encode(self.signing.public_key()),
            hpke_public_key: self.recipient_public.clone(),
            tls_spki_sha256: hex::encode(tls_spki_sha256),
            registration_challenge: hex::encode(challenge),
        }
    }
}

/// Fresh per-connection native TLS signer using pure ML-DSA-65. Its SPKI digest
/// enters the quote batch.
pub struct TlsKey(mldsa::SigningKey);

impl TlsKey {
    /// # Errors
    /// Fails only when randomness is unavailable.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(mldsa::SigningKey::generate()?))
    }

    #[must_use]
    pub const fn public_key(&self) -> &[u8; mldsa::PUBLIC_KEY_BYTES] {
        self.0.public_key()
    }

    /// Sign a TLS 1.3 handshake transcript or this connection's certificate, with no context.
    ///
    /// # Errors
    /// Fails only when signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; mldsa::SIGNATURE_BYTES], Error> {
        Ok(self.0.sign(message, &[])?)
    }
}

/// Leaf for one native TLS handshake.
#[must_use]
pub fn tls_leaf(
    environment: Environment,
    boot_sha256: &[u8; 32],
    challenge: &[u8; 32],
    signer_spki_sha256: &[u8; 32],
) -> [u8; 64] {
    Binding::NativeTls {
        environment,
        boot_evidence_sha256: *boot_sha256,
        challenge: *challenge,
        signer_spki_sha256: *signer_spki_sha256,
    }
    .leaf_hash()
}

/// Leaf for one encrypted session setup transcript.
#[must_use]
pub fn e2ee_leaf(
    environment: Environment,
    boot_sha256: &[u8; 32],
    transcript_sha256: &[u8; 32],
) -> [u8; 64] {
    Binding::E2eeSession {
        environment,
        boot_evidence_sha256: *boot_sha256,
        transcript_sha256: *transcript_sha256,
    }
    .leaf_hash()
}

/// Commit up to 1,024 channel leaves in one SNP report, returning its report data and
/// each leaf's proof in input order.
///
/// # Errors
/// Rejects empty or oversized batches.
pub fn quote_batch(leaves: &[[u8; 64]]) -> Result<([u8; 64], Vec<BatchProof>), Error> {
    let count = u16::try_from(leaves.len())
        .ok()
        .filter(|count| (1..=MAX_BATCH_LEAVES).contains(count))
        .ok_or(Error::Input("quote batch size"))?;
    let mut siblings = vec![Vec::new(); leaves.len()];
    let root = crate::attestation::subtree(leaves, &mut siblings);
    let proofs = siblings
        .into_iter()
        .zip(0..)
        .map(|(siblings, index)| BatchProof::new(count, index, siblings))
        .collect();
    Ok((crate::attestation::batch_report_data(count, &root), proofs))
}

/// Encode the session evidence shared by native certificates and encrypted setup.
/// `certificate` selects the CMW extension value instead of the bare payload.
///
/// # Errors
/// Rejects invalid fields and evidence beyond the transport limit.
pub fn session_evidence(
    report: &[u8],
    proof: &[u8],
    boot_document: &[u8],
    boot_inclusion: &[u8],
    certificate: bool,
) -> Result<Vec<u8>, Error> {
    let proof = BatchProof::from_bytes(proof).map_err(|_| Error::Input("quote proof"))?;
    let payload = SessionEvidence::encode(report, &proof, boot_document, boot_inclusion)
        .map_err(|_| Error::Input("session evidence"))?;
    if certificate {
        SessionEvidence::extension(&payload).map_err(|_| Error::Input("session evidence"))
    } else {
        Ok(payload)
    }
}
