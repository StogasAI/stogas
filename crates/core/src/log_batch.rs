//! Signed batches of request log rows.
//!
//! A gateway boot seals every row that it sends to analytics into numbered batches. A batch is
//! an RFC 9162 Merkle tree over SHA-512, with one leaf per row, and the boot's key signs its
//! root together with the batch's number, the time it was open and its size. Each row names its
//! batch and leaf in `log_batch`, so the row hashes with its own place in the tree. A proof
//! carries the row as analytics returns it, the signed batch, and the hashes on the row's path to
//! the root; it shows that the attested gateway wrote exactly this row, unchanged since.
//!
//! A row's leaf is SHA-512 of a zero byte, `stogas.log-row.v1`, a zero byte and the row's RFC
//! 8785 form, so whitespace and key order never matter. An inner node is SHA-512 of a one byte
//! and its two children. The signed message is `stogas.log-batch.v1`, a zero byte, the boot
//! document's SHA-256, the big-endian 32-bit batch number, the big-endian 64-bit Unix
//! milliseconds when the batch opened and when it was sealed, the big-endian 32-bit leaf count
//! and the 64-byte root.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha512};

use crate::evidence::boot::VerifiedBoot;
use crate::receipt::canonical;

pub const SCHEMA: &str = "stogas.log-batch.v1";
pub const PROOF_SCHEMA: &str = "stogas.log-proof.v1";
/// The most rows that one batch holds. A gateway seals a fuller minute early, so a path holds at
/// most 13 hashes and a batch's leaves stay well under a megabyte.
pub const MAX_LEAVES: u32 = 8_192;
/// A row is at most the 128 KiB that settlement stores, as JSON from any reader.
pub const MAX_ROW_BYTES: usize = 6 * 128 * 1024;
/// A proof holds one row, its batch and its path.
pub const MAX_PROOF_BYTES: usize = MAX_ROW_BYTES + 16 * 1024;
const MAX_PATH: usize = 13;
const LEAF_DOMAIN: &[u8] = b"stogas.log-row.v1\0";
const BATCH_DOMAIN: &[u8] = b"stogas.log-batch.v1\0";

pub type Hash = [u8; 64];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid request log proof")]
    Invalid,
    #[error("the request log row is not JSON that a batch can sign")]
    Row,
    #[error("the request log row does not name this batch and leaf")]
    Place,
    #[error("the request log row does not match its signed batch")]
    Inclusion,
    #[error("the batch does not name the verified boot")]
    Identity,
    #[error("the batch signature failed")]
    Signature,
    #[error(transparent)]
    Format(#[from] crate::format::FormatError),
}

/// One sealed batch, as the gateway stores it without its leaves and as a proof carries it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub schema: String,
    pub node_id: String,
    pub boot_sha256: String,
    pub sequence: u32,
    pub opened_at: String,
    pub sealed_at: String,
    pub leaf_count: u32,
    /// Lowercase hex of the 64-byte root.
    pub root: String,
    /// Base64url without padding of the composite ML-DSA-65 and Ed25519 signature.
    pub signature: String,
}

/// A row, the batch that holds it, and the hashes from its leaf to the root, deepest first.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema: String,
    pub row: Value,
    pub batch: Batch,
    /// Lowercase hex of each 64-byte sibling.
    pub path: Vec<String>,
}

/// A row whose batch signature verified under an appraised boot key. It does not establish that
/// analytics holds every row the batch counts.
#[derive(Debug, Serialize)]
pub struct VerifiedRow {
    pub request_id: Option<String>,
    pub node_id: String,
    pub boot_sha256: String,
    pub sequence: u32,
    pub index: u32,
    pub leaf_count: u32,
    pub opened_at: String,
    pub sealed_at: String,
    /// The commitments of the receipt that answered this request, which match the
    /// `request_commitment` and `response_commitment` in the response's Stogas metadata.
    pub receipt_commitments: Option<ReceiptCommitments>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ReceiptCommitments {
    pub request: String,
    pub response: String,
}

/// A row's leaf. The row must be one JSON object that RFC 8785 writes exactly: no duplicate keys,
/// invalid Unicode or integers beyond ±(2^53−1).
///
/// # Errors
/// Rejects anything else, and rows over the size limit.
pub fn row_leaf(row: &[u8]) -> Result<Hash, Error> {
    if row.len() > MAX_ROW_BYTES {
        return Err(Error::Row);
    }
    leaf(&canonical::parse_object(row).map_err(|_| Error::Row)?)
}

/// A parsed row's leaf.
///
/// # Errors
/// Rejects numbers that RFC 8785 cannot write.
pub fn leaf(row: &Value) -> Result<Hash, Error> {
    if !row.is_object() {
        return Err(Error::Row);
    }
    let canonical = serde_json_canonicalizer::to_vec(row).map_err(|_| Error::Row)?;
    Ok(Sha512::new()
        .chain_update([0])
        .chain_update(LEAF_DOMAIN)
        .chain_update(canonical)
        .finalize()
        .into())
}

/// The RFC 9162 tree hash of one or more leaves.
///
/// # Panics
/// Panics on an empty slice; a batch always holds a row.
#[must_use]
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => panic!("a batch holds at least one leaf"),
        [leaf] => *leaf,
        _ => {
            let split = split(leaves.len());
            parent(&root(&leaves[..split]), &root(&leaves[split..]))
        }
    }
}

/// The RFC 9162 inclusion path of one leaf, deepest sibling first.
///
/// # Panics
/// Panics when the index is outside the leaves.
#[must_use]
pub fn path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    assert!(index < leaves.len(), "the leaf is in the batch");
    let mut siblings = Vec::new();
    let (mut start, mut end) = (0, leaves.len());
    // Walk down from the root, then reverse, since a proof lists the deepest sibling first.
    while end - start > 1 {
        let split = start + split(end - start);
        if index < split {
            siblings.push(root(&leaves[split..end]));
            end = split;
        } else {
            siblings.push(root(&leaves[start..split]));
            start = split;
        }
    }
    siblings.reverse();
    siblings
}

/// Fold a leaf and its path into the root that they imply, following RFC 9162 section 2.1.3.2.
/// Returns `None` for an index outside the tree or a path of the wrong length.
#[must_use]
pub fn path_root(leaf: &Hash, index: u32, leaf_count: u32, path: &[Hash]) -> Option<Hash> {
    if index >= leaf_count || path.len() > MAX_PATH {
        return None;
    }
    let (mut index, mut last) = (index, leaf_count - 1);
    let mut root = *leaf;
    for sibling in path {
        if last == 0 {
            return None;
        }
        if index & 1 == 1 || index == last {
            root = parent(sibling, &root);
            while index & 1 == 0 && index != 0 {
                index >>= 1;
                last >>= 1;
            }
        } else {
            root = parent(&root, sibling);
        }
        index >>= 1;
        last >>= 1;
    }
    (last == 0).then_some(root)
}

/// The bytes that a boot's key signs for one batch.
#[must_use]
pub fn message(
    boot_sha256: &[u8; 32],
    sequence: u32,
    opened_at_ms: i64,
    sealed_at_ms: i64,
    leaf_count: u32,
    root: &Hash,
) -> Vec<u8> {
    [
        BATCH_DOMAIN,
        boot_sha256,
        &sequence.to_be_bytes(),
        &opened_at_ms.to_be_bytes(),
        &sealed_at_ms.to_be_bytes(),
        &leaf_count.to_be_bytes(),
        root,
    ]
    .concat()
}

/// A batch time as logs write theirs: UTC with milliseconds.
#[must_use]
pub fn timestamp(unix_ms: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp_millis(unix_ms)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Read a batch time, accepting only the exact form that `timestamp` writes.
fn unix_ms(value: &str) -> Result<i64, Error> {
    let ms = DateTime::parse_from_rfc3339(value)
        .map_err(|_| Error::Invalid)?
        .timestamp_millis();
    (timestamp(ms).as_deref() == Some(value))
        .then_some(ms)
        .ok_or(Error::Invalid)
}

impl Batch {
    /// The signed message, after checking the batch's fields.
    ///
    /// # Errors
    /// Rejects another schema, malformed fields, a batch that closed before it opened and a
    /// size beyond the limit.
    pub fn message(&self) -> Result<Vec<u8>, Error> {
        let opened = unix_ms(&self.opened_at)?;
        let sealed = unix_ms(&self.sealed_at)?;
        if self.schema != SCHEMA
            || self.sequence == 0
            || self.leaf_count == 0
            || self.leaf_count > MAX_LEAVES
            || sealed < opened
        {
            return Err(Error::Invalid);
        }
        Ok(message(
            &decode_hex(&self.boot_sha256)?,
            self.sequence,
            opened,
            sealed,
            self.leaf_count,
            &decode_hex(&self.root)?,
        ))
    }

    /// Check the signature under a raw composite public key.
    ///
    /// # Errors
    /// Rejects malformed batches and signatures that do not verify.
    pub fn verify_key(&self, public_key: &[u8]) -> Result<(), Error> {
        let message = self.message()?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| Error::Invalid)?;
        if URL_SAFE_NO_PAD.encode(&signature) != self.signature {
            return Err(Error::Invalid);
        }
        crate::signing::verify(public_key, &message, &signature).map_err(|_| Error::Signature)
    }
}

impl Proof {
    /// # Errors
    /// Rejects oversized, malformed or ambiguous JSON, unknown fields and rows that RFC 8785
    /// cannot write exactly.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(Error::Invalid);
        }
        let value = canonical::parse_object(bytes).map_err(|_| Error::Invalid)?;
        crate::format::check(&value, PROOF_SCHEMA)?;
        crate::format::check(&value["batch"], SCHEMA)?;
        serde_json::from_value(value).map_err(|_| Error::Invalid)
    }

    /// Whether a JSON document is a request log proof, in any version of its format, rather than
    /// a receipt's metadata.
    #[must_use]
    pub fn is_proof(value: &Value) -> bool {
        value
            .get("schema")
            .and_then(Value::as_str)
            .is_some_and(|schema| crate::format::same_format(schema, PROOF_SCHEMA))
    }

    /// Check the row's place and path against the batch, without its signature.
    ///
    /// # Errors
    /// Rejects a row that names another node, batch or leaf, and a row or path that does not
    /// reach the signed root.
    pub fn verify_inclusion(&self) -> Result<u32, Error> {
        if self.schema != PROOF_SCHEMA {
            return Err(Error::Invalid);
        }
        self.batch.message()?;
        let row = self.row.as_object().ok_or(Error::Row)?;
        let place = row.get("log_batch").ok_or(Error::Place)?;
        let (Some(sequence), Some(index)) = (
            place.get("sequence").and_then(Value::as_u64),
            place.get("index").and_then(Value::as_u64),
        ) else {
            return Err(Error::Place);
        };
        if row.get("node_id").and_then(Value::as_str) != Some(self.batch.node_id.as_str())
            || sequence != u64::from(self.batch.sequence)
            || place.as_object().map(serde_json::Map::len) != Some(2)
        {
            return Err(Error::Place);
        }
        let index = u32::try_from(index).map_err(|_| Error::Place)?;
        if index >= self.batch.leaf_count {
            return Err(Error::Place);
        }
        let path = self
            .path
            .iter()
            .map(|hash| decode_hex::<64>(hash))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = leaf(&self.row)?;
        if path_root(&leaf, index, self.batch.leaf_count, &path)
            != Some(decode_hex(&self.batch.root)?)
        {
            return Err(Error::Inclusion);
        }
        Ok(index)
    }

    /// Verify the row against an independently verified historical boot.
    ///
    /// # Errors
    /// Rejects altered rows, places, paths, batches, boot references and signatures.
    pub fn verify(&self, boot: &VerifiedBoot) -> Result<VerifiedRow, Error> {
        let index = self.verify_inclusion()?;
        if self.batch.boot_sha256 != hex::encode(boot.document_sha256())
            || self.batch.node_id != boot.hardware().node_id()
        {
            return Err(Error::Identity);
        }
        let key = URL_SAFE_NO_PAD
            .decode(&boot.record().report_data.signing_public_key)
            .map_err(|_| Error::Identity)?;
        self.batch.verify_key(&key)?;
        Ok(VerifiedRow {
            request_id: self
                .row
                .get("request_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            node_id: self.batch.node_id.clone(),
            boot_sha256: self.batch.boot_sha256.clone(),
            sequence: self.batch.sequence,
            index,
            leaf_count: self.batch.leaf_count,
            opened_at: self.batch.opened_at.clone(),
            sealed_at: self.batch.sealed_at.clone(),
            receipt_commitments: self.receipt_commitments(),
        })
    }

    fn receipt_commitments(&self) -> Option<ReceiptCommitments> {
        let commitments = self.row.get("receipt_commitments")?;
        let side = |name| {
            commitments
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        Some(ReceiptCommitments {
            request: side("request")?,
            response: side("response")?,
        })
    }
}

/// The largest power of two below `count`, where RFC 9162 splits a tree of `count` leaves.
const fn split(count: usize) -> usize {
    1 << (count - 1).ilog2()
}

fn parent(left: &Hash, right: &Hash) -> Hash {
    Sha512::new()
        .chain_update([1])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Lowercase hex of exactly `N` bytes.
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != 2 * N || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Error::Invalid);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::Invalid)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
