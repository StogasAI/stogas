//! Bounded inclusion proofs for fresh channel attestations. Hardware evidence is verified separately.

use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::approvals::Environment;

mod identity;
pub use identity::snp_node_id;

pub const MAX_BATCH_LEAVES: u16 = 1_024;
pub const MAX_PROOF_HASHES: usize = 10;
const BATCH_DOMAIN: &[u8] = b"stogas.quote-batch.v1\0";
const TLS_DOMAIN: &[u8] = b"stogas.native-tls.v1\0";
const E2EE_DOMAIN: &[u8] = b"stogas.e2ee-session.v1\0";

#[derive(Clone, Copy, Debug)]
pub enum Binding {
    NativeTls {
        environment: Environment,
        boot_evidence_sha256: [u8; 32],
        challenge: [u8; 32],
        signer_spki_sha256: [u8; 32],
    },
    E2eeSession {
        environment: Environment,
        boot_evidence_sha256: [u8; 32],
        /// Complete setup transcript: challenge, recipient, session/node, suite and expiry hints.
        transcript_sha256: [u8; 32],
    },
}

impl Binding {
    pub(crate) fn leaf_hash(&self) -> [u8; 64] {
        let mut hash = Sha512::new();
        hash.update([0]);
        match self {
            Self::NativeTls {
                environment,
                boot_evidence_sha256,
                challenge,
                signer_spki_sha256,
            } => {
                hash.update(TLS_DOMAIN);
                hash.update([environment_byte(*environment)]);
                hash.update(boot_evidence_sha256);
                hash.update(challenge);
                hash.update(signer_spki_sha256);
            }
            Self::E2eeSession {
                environment,
                boot_evidence_sha256,
                transcript_sha256,
            } => {
                hash.update(E2EE_DOMAIN);
                hash.update([environment_byte(*environment)]);
                hash.update(boot_evidence_sha256);
                hash.update(transcript_sha256);
            }
        }
        hash.finalize().into()
    }
}

pub(crate) const fn environment_byte(environment: Environment) -> u8 {
    match environment {
        Environment::Production => 1,
        #[cfg(feature = "staging")]
        Environment::Staging => 2,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid attestation proof length")]
    Length,
    #[error("invalid attestation proof count, index or path")]
    Shape,
    #[error("attestation proof does not bind this channel")]
    Binding,
}

#[derive(Clone, Debug)]
pub struct BatchProof {
    leaf_count: u16,
    leaf_index: u16,
    siblings: Vec<[u8; 64]>,
}

impl BatchProof {
    /// Decode uint16 big-endian count/index followed by complete 64-byte sibling hashes.
    ///
    /// # Errors
    /// Rejects excessive bytes before allocation, invalid counts/indices and nonminimal paths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4
            || bytes.len() > 4 + 64 * MAX_PROOF_HASHES
            || !(bytes.len() - 4).is_multiple_of(64)
        {
            return Err(Error::Length);
        }
        let leaf_count = u16::from_be_bytes([bytes[0], bytes[1]]);
        let leaf_index = u16::from_be_bytes([bytes[2], bytes[3]]);
        if leaf_count == 0 || leaf_count > MAX_BATCH_LEAVES || leaf_index >= leaf_count {
            return Err(Error::Shape);
        }
        let (mut count, mut index, mut depth) = (leaf_count, leaf_index, 0);
        while count > 1 {
            let k = 1 << (count - 1).ilog2();
            if index < k {
                count = k;
            } else {
                index -= k;
                count -= k;
            }
            depth += 1;
        }
        if depth != (bytes.len() - 4) / 64 {
            return Err(Error::Shape);
        }
        let siblings = bytes[4..]
            .chunks_exact(64)
            .map(|chunk| {
                let mut hash = [0; 64];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect();
        Ok(Self {
            leaf_count,
            leaf_index,
            siblings,
        })
    }

    /// Verify RFC 9162 inclusion using SHA-512 and the versioned report-data commitment.
    /// This is not hardware verification; the caller must authenticate the report, boot and policy.
    ///
    /// # Errors
    /// Rejects substituted bindings, paths, counts or report data.
    pub fn verify(&self, binding: &Binding, report_data: &[u8; 64]) -> Result<(), Error> {
        self.verify_leaf(&binding.leaf_hash(), report_data)
    }

    pub(crate) fn verify_leaf(&self, leaf: &[u8; 64], report_data: &[u8; 64]) -> Result<(), Error> {
        let mut root = *leaf;
        let (mut index, mut last) = (self.leaf_index, self.leaf_count - 1);
        for sibling in &self.siblings {
            if index & 1 != 0 || index == last {
                root = parent_hash(sibling, &root);
                while index != 0 && index & 1 == 0 {
                    index >>= 1;
                    last >>= 1;
                }
            } else {
                root = parent_hash(&root, sibling);
            }
            index >>= 1;
            last >>= 1;
        }
        if last != 0 || batch_report_data(self.leaf_count, &root) != *report_data {
            return Err(Error::Binding);
        }
        Ok(())
    }

    #[cfg(feature = "gateway")]
    pub(crate) const fn new(leaf_count: u16, leaf_index: u16, siblings: Vec<[u8; 64]>) -> Self {
        Self {
            leaf_count,
            leaf_index,
            siblings,
        }
    }

    /// The encoding read by `from_bytes`.
    #[cfg(feature = "gateway")]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 64 * self.siblings.len());
        bytes.extend_from_slice(&self.leaf_count.to_be_bytes());
        bytes.extend_from_slice(&self.leaf_index.to_be_bytes());
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling);
        }
        bytes
    }
}

/// RFC 9162 tree hash over `leaves`. Each leaf's path receives its siblings,
/// deepest first, which is the order `verify` consumes.
#[cfg(feature = "gateway")]
pub(crate) fn subtree(leaves: &[[u8; 64]], paths: &mut [Vec<[u8; 64]>]) -> [u8; 64] {
    if let [leaf] = leaves {
        return *leaf;
    }
    let split = 1 << (leaves.len() - 1).ilog2();
    let left = subtree(&leaves[..split], &mut paths[..split]);
    let right = subtree(&leaves[split..], &mut paths[split..]);
    paths[..split].iter_mut().for_each(|path| path.push(right));
    paths[split..].iter_mut().for_each(|path| path.push(left));
    parent_hash(&left, &right)
}

pub(crate) fn batch_report_data(leaf_count: u16, root: &[u8; 64]) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(BATCH_DOMAIN);
    hash.update(leaf_count.to_be_bytes());
    hash.update(root);
    hash.finalize().into()
}

fn parent_hash(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

#[cfg(test)]
mod tests;

pub mod certificate;
pub mod evidence;
