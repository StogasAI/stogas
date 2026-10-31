//! C2SP signed notes and the transparency-log checkpoints they carry.
//!
//! This reads notes as Go's `golang.org/x/mod/sumdb/note` and `transparency-dev/formats` do,
//! which sigstore-go uses for both Rekor versions: a signature line from any other key, such as
//! a witness cosignature, is ignored, and the log's own signature must verify.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
use spki::SubjectPublicKeyInfoRef;

use crate::crypto::{ED25519_OID, verify_spki_auto};

const MAX_NOTE_BYTES: usize = 16 * 1024;
// Go's reader stops at the same count.
const MAX_SIGNATURES: usize = 100;
const SIGNATURE_PREFIX: &str = "\u{2014} ";

/// A checkpoint that its log signed.
#[derive(Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
}

/// Opens a checkpoint that the log key `spki` signed under `name` with key hash `hash`, without
/// checking its origin.
pub fn open_checkpoint(
    note: &str,
    name: &str,
    hash: [u8; 4],
    spki: &[u8],
) -> Result<Checkpoint, String> {
    let text = open(note, name, hash, spki)?;
    // Like `log.Checkpoint.Unmarshal`: origin, size and root hash, then optional extension lines.
    let mut lines = text.splitn(4, '\n');
    let (Some(origin), Some(size), Some(root), Some(_)) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return Err("checkpoint has too few lines".into());
    };
    if origin.is_empty() {
        return Err("checkpoint origin is empty".into());
    }
    let size = size
        .parse::<u64>()
        .ok()
        .filter(|_| size.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| "checkpoint tree size is invalid".to_owned())?;
    let root = STANDARD
        .decode(root)
        .ok()
        .and_then(|root| <[u8; 32]>::try_from(root).ok())
        .ok_or_else(|| "checkpoint root hash is invalid".to_owned())?;
    Ok(Checkpoint {
        origin: origin.to_owned(),
        size,
        root,
    })
}

/// Returns the note's text once a signature line from `name` with key hash `hash` verifies.
fn open<'a>(note: &'a str, name: &str, hash: [u8; 4], spki: &[u8]) -> Result<&'a str, String> {
    if note.len() > MAX_NOTE_BYTES {
        return Err("checkpoint exceeds resource limits".into());
    }
    if note
        .chars()
        .any(|character| character < ' ' && character != '\n')
    {
        return Err("checkpoint contains a control character".into());
    }
    let split = note
        .rfind("\n\n")
        .ok_or_else(|| "checkpoint has no signature block".to_owned())?;
    let (text, signatures) = (&note[..=split], &note[split + 2..]);
    let Some(signatures) = signatures.strip_suffix('\n') else {
        return Err("checkpoint signature block is empty or unterminated".into());
    };
    let mut verified = false;
    for (index, line) in signatures.split('\n').enumerate() {
        if index == MAX_SIGNATURES {
            return Err("checkpoint has too many signatures".into());
        }
        let (signer, encoded) = line
            .strip_prefix(SIGNATURE_PREFIX)
            .and_then(|line| line.split_once(' '))
            .ok_or_else(|| "checkpoint signature line is malformed".to_owned())?;
        let signature = STANDARD
            .decode(encoded)
            .ok()
            .filter(|signature| valid_name(signer) && signature.len() >= 5)
            .ok_or_else(|| "checkpoint signature line is malformed".to_owned())?;
        // Lines from other keys, such as witness cosignatures, are not this log's to check. Go
        // checks only the first line from each known key.
        if verified || signer != name || signature[..4] != hash[..] {
            continue;
        }
        verify_spki_auto(spki, text.as_bytes(), &signature[4..])
            .map_err(|error| format!("checkpoint log signature is invalid: {error}"))?;
        verified = true;
    }
    if !verified {
        return Err("checkpoint has no signature from its log".into());
    }
    Ok(text)
}

/// The C2SP key hash that Rekor v2 uses: SHA-256 of the name and key for Ed25519, of the key
/// alone for ECDSA. Rekor v1 hashes the key alone for every key type.
pub fn key_hash(name: &str, spki: &[u8]) -> Result<[u8; 4], String> {
    let key = SubjectPublicKeyInfoRef::try_from(spki)
        .map_err(|error| format!("invalid log public key: {error}"))?;
    let digest = if key.algorithm.oid == ED25519_OID {
        Sha256::new()
            .chain_update(name)
            .chain_update([b'\n', 1])
            .chain_update(key.subject_public_key.raw_bytes())
            .finalize()
    } else {
        Sha256::digest(spki)
    };
    Ok([digest[0], digest[1], digest[2], digest[3]])
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(char::is_whitespace) && !name.contains('+')
}

#[cfg(test)]
mod tests;
