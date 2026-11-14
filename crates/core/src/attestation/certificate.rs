//! Decode the bounded native-TLS certificate evidence. Parsing does not establish trust.

use der::{
    Decode as _, Encode as _, Sequence,
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use x509_cert::time::Validity;

pub use super::evidence::MAX_EVIDENCE_BYTES;
use super::{Binding, evidence::SessionEvidence};
use crate::authority::Environment;

pub const MEDIA_TYPE: &[u8] = b"application/vnd.stogas.native-tls.v1";
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024 - 13;
const CMW_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.35");

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid session evidence: {0}")]
    Evidence(#[from] super::evidence::Error),
    #[error("invalid native certificate or public key")]
    Certificate,
    #[error("missing, duplicate or malformed native attestation extension")]
    Extension,
    #[error("native attestation exceeds the transport size limit")]
    TooLarge,
    #[error("invalid native evidence framing")]
    Framing,
    #[error("native channel proof failed: {0}")]
    Proof(#[from] super::Error),
}

impl<'a> SessionEvidence<'a> {
    /// Parse this profile's canonical RFC 9999 CBOR Record CMW, inside the DER
    /// OCTET STRING choice. Borrow payloads; allocate only the bounded proof path.
    ///
    /// # Errors
    /// Rejects wrong types, unknown encodings, oversized/truncated or trailing data.
    pub fn from_extension(encoded: &'a [u8]) -> Result<Self, Error> {
        // This profile always exceeds 255 bytes and stays below 65536, so its
        // canonical DER length is exactly two bytes. No general ASN.1 parser is needed.
        if encoded.len() > MAX_EVIDENCE_BYTES + MEDIA_TYPE.len() + 10 {
            return Err(Error::TooLarge);
        }
        if encoded.len() < 4 || encoded[..2] != [0x04, 0x82] {
            return Err(Error::Extension);
        }
        let der_length = usize::from(u16::from_be_bytes([encoded[2], encoded[3]]));
        if der_length != encoded.len() - 4 {
            return Err(Error::Extension);
        }
        let cmw = &encoded[4..];
        let prefix_len = 3 + MEDIA_TYPE.len() + 3;
        if cmw.len() < prefix_len
            || cmw[..3]
                != [
                    0x82,
                    0x78,
                    u8::try_from(MEDIA_TYPE.len()).map_err(|_| Error::Framing)?,
                ]
            || &cmw[3..3 + MEDIA_TYPE.len()] != MEDIA_TYPE
            || cmw[3 + MEDIA_TYPE.len()] != 0x59
        {
            return Err(Error::Extension);
        }
        let size = usize::from(u16::from_be_bytes([
            cmw[prefix_len - 2],
            cmw[prefix_len - 1],
        ]));
        if size > MAX_EVIDENCE_BYTES {
            return Err(Error::TooLarge);
        }
        if size != cmw.len() - prefix_len {
            return Err(Error::Framing);
        }
        Ok(Self::from_bytes(&cmw[prefix_len..])?)
    }

    /// Wrap an encoded payload in the extension value read by `from_extension`.
    ///
    /// # Errors
    /// Rejects payloads beyond `MAX_EVIDENCE_BYTES`.
    #[cfg(feature = "gateway")]
    pub fn extension(payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::TooLarge);
        }
        let size = |length: usize| u16::try_from(length).map_err(|_| Error::TooLarge);
        let mut cmw = vec![
            0x82,
            0x78,
            u8::try_from(MEDIA_TYPE.len()).map_err(|_| Error::Framing)?,
        ];
        cmw.extend_from_slice(MEDIA_TYPE);
        cmw.push(0x59);
        cmw.extend_from_slice(&size(payload.len())?.to_be_bytes());
        cmw.extend_from_slice(payload);
        let mut extension = vec![0x04, 0x82];
        extension.extend_from_slice(&size(cmw.len())?.to_be_bytes());
        extension.extend_from_slice(&cmw);
        Ok(extension)
    }

    /// Check the local challenge, certificate key and exact immutable boot object
    /// against report data. Hardware signatures and boot/current policy verification
    /// are separate required checks; success here alone must never authorize TLS.
    ///
    /// # Errors
    /// Rejects a substituted channel, boot object or Merkle path.
    pub fn verify_channel_binding(
        &self,
        environment: Environment,
        challenge: [u8; 32],
        signer_spki_sha256: [u8; 32],
    ) -> Result<(), Error> {
        let report_data = self.report.get(0x50..0x90).ok_or(Error::Framing)?;
        self.proof.verify(
            &Binding::NativeTls {
                environment,
                challenge,
                signer_spki_sha256,
                boot_evidence_sha256: Sha256::digest(self.boot_document).into(),
            },
            report_data.try_into().map_err(|_| Error::Framing)?,
        )?;
        Ok(())
    }
}

/// The fields of an RFC 5280 certificate that native evidence reads, borrowed from its DER. The
/// TLS stack checks the certificate's signature.
#[derive(Sequence)]
struct Certificate<'a> {
    tbs: TbsCertificate<'a>,
    signature_algorithm: AnyRef<'a>,
    signature: BitStringRef<'a>,
}

#[derive(Sequence)]
struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", optional = "true")]
    version: Option<AnyRef<'a>>,
    serial_number: AnyRef<'a>,
    signature: AnyRef<'a>,
    issuer: AnyRef<'a>,
    validity: Validity,
    subject: AnyRef<'a>,
    subject_public_key_info: AnyRef<'a>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<BitStringRef<'a>>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<BitStringRef<'a>>,
    #[asn1(context_specific = "3", optional = "true")]
    extensions: Option<Vec<Extension<'a>>>,
}

#[derive(Sequence)]
struct Extension<'a> {
    id: ObjectIdentifier,
    #[asn1(default = "Default::default")]
    critical: bool,
    value: &'a OctetStringRef,
}

#[derive(Debug)]
pub struct ParsedNativeCertificate<'a> {
    pub evidence: SessionEvidence<'a>,
    pub signer_spki_sha256: [u8; 32],
    not_before_unix_ms: i64,
    not_after_unix_ms: i64,
}

impl<'a> ParsedNativeCertificate<'a> {
    /// # Errors
    /// Rejects malformed/oversized certificates, non-ML-DSA-65 keys and missing or
    /// duplicate evidence. The TLS stack must still verify `CertificateVerify`.
    pub fn parse(der: &'a [u8]) -> Result<Self, Error> {
        if der.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::TooLarge);
        }
        // DER decoding also rejects trailing data.
        let certificate = Certificate::from_der(der)
            .map_err(|_| Error::Certificate)?
            .tbs;
        // Strict decoding makes this encoding the exact bytes that the certificate holds.
        let key = certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| Error::Certificate)?;
        crate::signing::mldsa::public_key_from_spki(&key).map_err(|_| Error::Certificate)?;
        let mut extensions = certificate
            .extensions
            .iter()
            .flatten()
            .filter(|extension| extension.id == CMW_OID);
        let extension = extensions.next().ok_or(Error::Extension)?;
        if extensions.next().is_some() {
            return Err(Error::Extension);
        }
        let unix_ms = |time: x509_cert::time::Time| {
            i64::try_from(time.to_unix_duration().as_millis()).map_err(|_| Error::Certificate)
        };
        Ok(Self {
            evidence: SessionEvidence::from_extension(extension.value.as_bytes())?,
            signer_spki_sha256: Sha256::digest(&key).into(),
            not_before_unix_ms: unix_ms(certificate.validity.not_before)?,
            not_after_unix_ms: unix_ms(certificate.validity.not_after)?,
        })
    }

    /// # Errors
    /// Rejects certificates before their validity interval or at/after expiry.
    pub const fn valid_at(&self, now_unix_ms: i64) -> Result<(), Error> {
        if now_unix_ms < self.not_before_unix_ms || now_unix_ms >= self.not_after_unix_ms {
            return Err(Error::Certificate);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
