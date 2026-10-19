//! The same bounded binary evidence is used by TLS certificates and E2EE setup.
//! Parsing supplies untrusted bytes; hardware, boot and approval appraisal follow.

use super::BatchProof;
use thiserror::Error;

pub const MAX_EVIDENCE_BYTES: usize = 58 * 1024;
pub(crate) const REPORT_BYTES: usize = 1184;

#[derive(Debug, Error)]
pub enum Error {
    #[error("session evidence exceeds the transport size limit")]
    TooLarge,
    #[error("invalid session evidence framing")]
    Framing,
    #[error("invalid session evidence proof: {0}")]
    Proof(#[from] super::Error),
}

#[derive(Debug)]
pub struct SessionEvidence<'a> {
    pub report: &'a [u8],
    pub proof: BatchProof,
    pub boot_document: &'a [u8],
    pub boot_inclusion: &'a [u8],
}

impl<'a> SessionEvidence<'a> {
    /// Borrow payload bytes and allocate only the bounded proof path.
    ///
    /// # Errors
    /// Rejects excessive, truncated, empty or trailing fields and invalid proofs.
    pub fn from_bytes(mut payload: &'a [u8]) -> Result<Self, Error> {
        if payload.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::TooLarge);
        }
        let report = take(&mut payload, REPORT_BYTES)?;
        let proof_len = take(&mut payload, 2)?;
        let proof_len = usize::from(u16::from_be_bytes([proof_len[0], proof_len[1]]));
        let proof = BatchProof::from_bytes(take(&mut payload, proof_len)?)?;
        let boot_document = take_field(&mut payload)?;
        let boot_inclusion = take_field(&mut payload)?;
        if !payload.is_empty() {
            return Err(Error::Framing);
        }
        Ok(Self {
            report,
            proof,
            boot_document,
            boot_inclusion,
        })
    }
}

impl SessionEvidence<'_> {
    /// The framing read by `from_bytes`.
    ///
    /// # Errors
    /// Rejects reports of another size, empty boot fields and oversized evidence.
    #[cfg(feature = "gateway")]
    pub fn encode(
        report: &[u8],
        proof: &BatchProof,
        boot_document: &[u8],
        boot_inclusion: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let proof = proof.to_bytes();
        if report.len() != REPORT_BYTES || boot_document.is_empty() || boot_inclusion.is_empty() {
            return Err(Error::Framing);
        }
        let size =
            REPORT_BYTES + 2 + proof.len() + 4 + boot_document.len() + 4 + boot_inclusion.len();
        if size > MAX_EVIDENCE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut payload = Vec::with_capacity(size);
        payload.extend_from_slice(report);
        payload.extend_from_slice(
            &u16::try_from(proof.len())
                .map_err(|_| Error::Framing)?
                .to_be_bytes(),
        );
        payload.extend_from_slice(&proof);
        for field in [boot_document, boot_inclusion] {
            payload.extend_from_slice(
                &u32::try_from(field.len())
                    .map_err(|_| Error::Framing)?
                    .to_be_bytes(),
            );
            payload.extend_from_slice(field);
        }
        Ok(payload)
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    let (value, rest) = input.split_at_checked(length).ok_or(Error::Framing)?;
    *input = rest;
    Ok(value)
}

fn take_field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let prefix = take(input, 4)?;
    let length = usize::try_from(u32::from_be_bytes(
        prefix.try_into().map_err(|_| Error::Framing)?,
    ))
    .map_err(|_| Error::Framing)?;
    if length == 0 {
        return Err(Error::Framing);
    }
    take(input, length)
}
