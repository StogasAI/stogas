//! Content digests and salted commitments.
//!
//! A receipt binds the request and the response by meaning rather than by bytes: each side is
//! hashed in its RFC 8785 form, so whitespace, key order and how a stream was cut into events
//! do not change it. Each digest is then committed under its own random salt, which only the
//! client receives. Without that salt, nobody holding a receipt or a log can confirm a guessed
//! prompt by hashing it, and a client can reveal one side's salt without the other's.

use serde_json::Value;
use sha2::{Digest as _, Sha256, Sha512};

/// SHA-512, because the client chooses what is hashed: a collision would let it claim either
/// of two contents, and SHA-512 keeps collisions out of reach where SHA-256 offers half as much.
pub const DIGEST_BYTES: usize = 64;
pub const SALT_BYTES: usize = 32;
pub const COMMITMENT_BYTES: usize = 32;
const COMMITMENT_DOMAIN: &[u8] = b"stogas.receipt.v2.commitment";
/// The largest integer that every JSON reader holds exactly (RFC 7493, section 2.2).
const MAX_EXACT_INTEGER: &[u8] = b"9007199254740991";

pub type ContentDigest = [u8; DIGEST_BYTES];
pub type Salt = [u8; SALT_BYTES];
pub type Commitment = [u8; COMMITMENT_BYTES];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Request,
    Response,
}

impl Side {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }

    const fn label(self) -> &'static [u8] {
        self.name().as_bytes()
    }
}

impl core::fmt::Display for Side {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanonicalError {
    #[error("content is not one JSON object without duplicate keys")]
    Json,
    /// RFC 8785 writes every number as a double, so two such integers could share one form.
    #[error("content has an integer beyond -9007199254740991 to 9007199254740991")]
    Integer,
}

/// The request as the client sent it, without the top-level `encryption_keys`, whose secrets
/// never reach the provider and must not be revealed to prove the request.
///
/// # Errors
/// Rejects anything but one JSON object without duplicate keys and with exact integers.
pub fn request_digest(body: &[u8]) -> Result<ContentDigest, CanonicalError> {
    let mut value = parse_object(body)?;
    if let Value::Object(object) = &mut value {
        object.remove("encryption_keys");
    }
    digest(&value)
}

/// A buffered response, without the top-level `stogas` object that carries its receipt. A saved
/// canonical response, such as the one a stream assembles to, has no `stogas` object and hashes
/// the same.
///
/// # Errors
/// Rejects anything but one JSON object without duplicate keys and with exact integers.
pub fn response_digest(body: &[u8]) -> Result<ContentDigest, CanonicalError> {
    let mut value = parse_object(body)?;
    if let Value::Object(object) = &mut value {
        object.remove("stogas");
    }
    digest(&value)
}

/// # Errors
/// Rejects numbers that RFC 8785 cannot write, which a parsed value can still hold.
pub fn digest(value: &Value) -> Result<ContentDigest, CanonicalError> {
    let canonical = serde_json_canonicalizer::to_vec(value).map_err(|_| CanonicalError::Json)?;
    Ok(Sha512::digest(canonical).into())
}

/// The value that a receipt signs for one side. Its salt makes it reveal nothing about the
/// content, and the side keeps a request's commitment from passing as a response's.
#[must_use]
pub fn commitment(side: Side, salt: &Salt, digest: &ContentDigest) -> Commitment {
    Sha256::new()
        .chain_update(COMMITMENT_DOMAIN)
        .chain_update([0])
        .chain_update(side.label())
        .chain_update([0])
        .chain_update(salt)
        .chain_update(digest)
        .finalize()
        .into()
}

/// Read one JSON object as a receipt reads content: without duplicate keys or invalid Unicode,
/// and with exact integers.
///
/// # Errors
/// Rejects anything else.
pub fn parse_object(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let value = parse(bytes)?;
    if !value.is_object() {
        return Err(CanonicalError::Json);
    }
    Ok(value)
}

/// The deepest nesting that the gateway admits in a request, so that every request it admits
/// can carry a receipt.
const MAX_DEPTH: usize = 128;

/// One JSON value, read strictly, whose integers RFC 8785 writes exactly.
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let value = crate::strict_json::from_slice_nested(bytes, MAX_DEPTH)
        .map_err(|_| CanonicalError::Json)?;
    // The parsed value cannot tell an integer beyond 2^64 from a float, so read the tokens.
    check_integers(bytes)?;
    Ok(value)
}

/// Rejects an integer token beyond the exact range. A token with a fraction or an exponent is
/// a double to every provider, so RFC 8785's double form already means the same number.
/// The input is valid JSON, so strings end and escapes are complete.
fn check_integers(bytes: &[u8]) -> Result<(), CanonicalError> {
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => {
                index += 1;
                while let Some(&byte) = bytes.get(index) {
                    index += if byte == b'\\' { 2 } else { 1 };
                    if byte == b'"' {
                        break;
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                while bytes.get(index).is_some_and(|byte| {
                    matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                }) {
                    index += 1;
                }
                let token = &bytes[start..index];
                if !token.iter().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                    let digits = token.strip_prefix(b"-").unwrap_or(token);
                    if digits.len() > MAX_EXACT_INTEGER.len()
                        || digits.len() == MAX_EXACT_INTEGER.len() && digits > MAX_EXACT_INTEGER
                    {
                        return Err(CanonicalError::Integer);
                    }
                }
            }
            _ => index += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
