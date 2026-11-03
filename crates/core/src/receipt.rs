//! One signature over salted content commitments and the canonical Stogas metadata bag.
//!
//! The gateway signs `stogas.receipt.v2`, a zero byte, the request commitment, the response
//! commitment and the SHA-256 of the RFC 8785 metadata bag without `receipt` and `salts`. Each
//! commitment hides its side's content digest under a salt that only the client receives (see
//! [`canonical`]), so a receipt proves either side without revealing the other.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::evidence::boot::VerifiedBoot;

pub mod canonical;
mod chat;
mod events;
pub(crate) mod http;

pub use canonical::{
    CanonicalError, Commitment, ContentDigest, Salt, Side, request_digest, response_digest,
};
pub use events::StreamContent;

pub const SCHEMA: &str = "stogas.receipt.v2";
pub const MAX_BYTES: usize = 5 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024 + MAX_METADATA_BYTES + 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid content receipt")]
    Invalid,
    #[error("the {0} does not match the receipt")]
    Content(Side),
    #[error("the metadata has no {0} salt, so the {0} cannot be checked")]
    Salt(Side),
    #[error("receipt does not identify the verified boot")]
    Identity,
    #[error("receipt signature failed")]
    Signature,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub boot_sha256: String,
    pub request_commitment: String,
    pub response_commitment: String,
    pub signature: String,
}

/// The salts that the receipt commits each side under, as lowercase hex.
///
/// The gateway returns both and keeps neither. To prove one side, share the bag with only that
/// side's salt: the other side's commitment then reveals nothing, not even whether a guess is
/// right.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Salts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

/// A receipt and the salts it was signed with, as the gateway returns them.
#[derive(Debug, Serialize)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub salts: Salts,
}

/// This confirms metadata, and each side whose content was checked, under an appraised boot
/// key. It does not renew the boot's authorization or establish when inference ran.
#[derive(Debug, Serialize)]
pub struct VerifiedReceipt {
    pub node_id: String,
    pub boot_sha256: String,
    pub request_commitment: String,
    pub response_commitment: String,
    /// Whether the request was checked against its commitment, rather than left hidden.
    pub request_verified: bool,
    pub response_verified: bool,
}

impl Receipt {
    /// # Errors
    /// Rejects malformed/ambiguous JSON, unknown fields and oversized receipts.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        serde_json::from_value(crate::strict_json::from_slice(bytes).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)
    }

    /// Verify using the retained request appraisal or an independently verified historical
    /// boot. Each side given checks the caller's own digest of that side's content; a side left
    /// out stays hidden and is signed only as its commitment.
    ///
    /// # Errors
    /// Rejects altered content, boot references, schema, keys or signatures, and a checked
    /// side whose salt is missing.
    pub fn verify(
        &self,
        boot: &VerifiedBoot,
        request: Option<&ContentDigest>,
        response: Option<&ContentDigest>,
        salts: &Salts,
        metadata: &serde_json::Value,
    ) -> Result<VerifiedReceipt, Error> {
        self.verify_key(
            &boot.record().report_data.signing_public_key,
            boot.document_sha256(),
            [(request, &salts.request), (response, &salts.response)],
            &metadata_digest(metadata)?,
        )?;
        Ok(VerifiedReceipt {
            node_id: boot.hardware().node_id().to_owned(),
            boot_sha256: self.boot_sha256.clone(),
            request_commitment: self.request_commitment.clone(),
            response_commitment: self.response_commitment.clone(),
            request_verified: request.is_some(),
            response_verified: response.is_some(),
        })
    }

    fn verify_key(
        &self,
        public_key: &str,
        boot: &[u8; 32],
        sides: [(Option<&ContentDigest>, &Option<String>); 2],
        metadata: &[u8; 32],
    ) -> Result<(), Error> {
        if self.schema != SCHEMA {
            return Err(Error::Invalid);
        }
        if self.boot_sha256 != hex::encode(boot) {
            return Err(Error::Identity);
        }
        let commitments = [
            decode_hex::<32>(&self.request_commitment)?,
            decode_hex::<32>(&self.response_commitment)?,
        ];
        for ((side, (digest, salt)), signed) in [Side::Request, Side::Response]
            .into_iter()
            .zip(sides)
            .zip(&commitments)
        {
            if let Some(digest) = digest {
                let salt = decode_hex::<32>(salt.as_deref().ok_or(Error::Salt(side))?)?;
                if canonical::commitment(side, &salt, digest) != *signed {
                    return Err(Error::Content(side));
                }
            }
        }
        let key = decode(public_key)?;
        if key.len() != crate::signing::PUBLIC_KEY_BYTES {
            return Err(Error::Identity);
        }
        let signature = decode(&self.signature)?;
        crate::signing::verify(
            &key,
            &message(&commitments[0], &commitments[1], metadata),
            &signature,
        )
        .map_err(|_| Error::Signature)
    }
}

pub(crate) fn message(request: &Commitment, response: &Commitment, metadata: &[u8; 32]) -> Vec<u8> {
    [SCHEMA.as_bytes(), b"\0", request, response, metadata].concat()
}

/// The complete metadata bag is authenticated, excluding the receipt and its salts.
#[derive(Debug, Serialize)]
pub struct VerifiedMetadata {
    /// The bag as received, including the receipt but not the salts.
    pub metadata: serde_json::Value,
    pub receipt: VerifiedReceipt,
}

/// Content digests and the final metadata bag, read before the signing boot is appraised.
/// Nothing here is authenticated until `verify` succeeds.
pub struct Signed {
    metadata: serde_json::Value,
    request: Option<ContentDigest>,
    response: Option<ContentDigest>,
}

impl Signed {
    /// Read a buffered response whose body carries its `stogas` bag.
    ///
    /// # Errors
    /// Rejects malformed or oversized responses and metadata.
    pub fn buffered(request: Option<ContentDigest>, body: &[u8]) -> Result<Self, Error> {
        if body.len() > MAX_BUFFERED_BYTES {
            return Err(Error::Invalid);
        }
        let mut value = canonical::parse_object(body)?;
        let metadata = value
            .as_object_mut()
            .and_then(|object| object.remove("stogas"))
            .filter(serde_json::Value::is_object)
            .ok_or(Error::Invalid)?;
        let response = canonical::digest(&value)?;
        Self::new(request, metadata, Some(response))
    }

    /// Pair a detached final `stogas` bag with content digests computed locally. A side
    /// without a digest stays hidden.
    ///
    /// # Errors
    /// Rejects malformed or oversized metadata.
    pub fn detached(
        request: Option<ContentDigest>,
        metadata: &[u8],
        response: Option<ContentDigest>,
    ) -> Result<Self, Error> {
        if metadata.len() > MAX_METADATA_BYTES {
            return Err(Error::Invalid);
        }
        let metadata = crate::strict_json::from_slice(metadata).map_err(|_| Error::Invalid)?;
        Self::new(request, metadata, response)
    }

    fn new(
        request: Option<ContentDigest>,
        metadata: serde_json::Value,
        response: Option<ContentDigest>,
    ) -> Result<Self, Error> {
        if !metadata.is_object() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            metadata,
            request,
            response,
        })
    }

    /// The boot the receipt names, for locating its archived evidence. `verify`
    /// rejects the receipt unless the appraised boot is this exact document.
    #[must_use]
    pub fn boot_sha256(&self) -> Option<&str> {
        self.metadata.pointer("/receipt/boot_sha256")?.as_str()
    }

    /// The bag as received, salts included, for writing a proof that reveals chosen sides.
    #[must_use]
    pub const fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }

    /// # Errors
    /// Rejects malformed receipts, changed content and incorrect signatures.
    pub fn verify(self, boot: &VerifiedBoot) -> Result<VerifiedMetadata, Error> {
        let mut metadata = self.metadata;
        let object = metadata.as_object_mut().ok_or(Error::Invalid)?;
        let salts: Salts = match object.remove("salts") {
            Some(salts) => serde_json::from_value(salts).map_err(|_| Error::Invalid)?,
            None => Salts::default(),
        };
        let receipt = object.get("receipt").ok_or(Error::Invalid)?;
        let receipt = Receipt::parse(&serde_json::to_vec(receipt).map_err(|_| Error::Invalid)?)?;
        let receipt = receipt.verify(
            boot,
            self.request.as_ref(),
            self.response.as_ref(),
            &salts,
            &metadata,
        )?;
        Ok(VerifiedMetadata { metadata, receipt })
    }
}

/// Verify a buffered response and its appended bag against the request's digest.
///
/// # Errors
/// Rejects malformed/oversized responses and incorrect signatures or content.
pub fn verify_buffered(
    boot: &VerifiedBoot,
    request: &ContentDigest,
    body: &[u8],
) -> Result<VerifiedMetadata, Error> {
    Signed::buffered(Some(*request), body)?.verify(boot)
}

/// Streaming verification. The terminal delimiter is withheld until `finish`.
pub struct Stream {
    request: ContentDigest,
    body: http::SseBody,
}

/// SSE framing guard for encrypted responses even when receipts were not requested.
/// Release the terminal delimiter only after authenticated record completion and outer EOF.
pub struct StreamCompletion(http::SseBody);
impl Default for StreamCompletion {
    fn default() -> Self {
        Self(http::SseBody::transport())
    }
}
impl StreamCompletion {
    /// # Errors
    /// Rejects malformed or post-terminal SSE framing.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.0.push(bytes).map_err(|_| Error::Invalid)
    }
    /// # Errors
    /// Rejects truncated streams. The caller must first authenticate record completion and EOF.
    pub fn finish(self) -> Result<(), Error> {
        self.0.require_complete().map_err(|_| Error::Invalid)
    }
}
impl Stream {
    #[must_use]
    pub fn new(request: ContentDigest) -> Self {
        Self {
            request,
            body: http::SseBody::new(),
        }
    }
    /// # Errors
    /// Rejects malformed, repeated, misplaced or oversized stream metadata, and events that
    /// do not assemble to a response.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.body.push(bytes).map_err(|_| Error::Invalid)
    }
    /// The caller must observe transport EOF, then append `\n\n` only after this succeeds.
    ///
    /// # Errors
    /// Rejects incomplete streams, changed content and invalid receipt signatures.
    pub fn finish(self, boot: &VerifiedBoot) -> Result<VerifiedMetadata, Error> {
        self.signed()?.verify(boot)
    }
    /// Read a complete saved stream before its signing boot is appraised.
    ///
    /// # Errors
    /// Rejects incomplete streams and malformed metadata.
    pub fn signed(self) -> Result<Signed, Error> {
        let (metadata, response) = self.body.finish().map_err(|_| Error::Invalid)?;
        Signed::detached(
            Some(self.request),
            &metadata,
            Some(canonical::digest(&response)?),
        )
    }
}

/// The response that a complete saved stream carries, as its receipt signs it, and the stream's
/// `stogas` bag. Write the response out to share it as a proof.
///
/// # Errors
/// Rejects incomplete or malformed streams.
pub fn stream_response(sse: &[u8]) -> Result<(serde_json::Value, Vec<u8>), Error> {
    let mut body = http::SseBody::new();
    body.push(sse).map_err(|_| Error::Invalid)?;
    let (metadata, response) = body.finish().map_err(|_| Error::Invalid)?;
    Ok((response, metadata))
}

/// Verify a detached final `stogas` bag against content digests computed locally. A side
/// without a digest stays hidden.
///
/// # Errors
/// Rejects malformed metadata, changed content and invalid signatures.
pub fn verify_metadata(
    bytes: &[u8],
    boot: &VerifiedBoot,
    request: Option<&ContentDigest>,
    response: Option<&ContentDigest>,
) -> Result<VerifiedMetadata, Error> {
    Signed::detached(request.copied(), bytes, response.copied())?.verify(boot)
}

pub(crate) fn metadata_digest(metadata: &serde_json::Value) -> Result<[u8; 32], Error> {
    use sha2::{Digest as _, Sha256};
    let mut object = metadata.as_object().ok_or(Error::Invalid)?.clone();
    object.remove("receipt");
    object.remove("salts");
    let canonical = serde_json_canonicalizer::to_vec(&object).map_err(|_| Error::Invalid)?;
    if canonical.len() > MAX_METADATA_BYTES {
        return Err(Error::Invalid);
    }
    Ok(Sha256::digest(canonical).into())
}

fn decode(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

/// Lowercase hex of exactly `N` bytes.
pub(crate) fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != 2 * N || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Error::Invalid);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::Invalid)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
