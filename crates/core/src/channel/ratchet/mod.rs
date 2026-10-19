//! Double Ratchet with encrypted headers and full X25519 + ML-KEM-768 turns.
//!
//! State transitions follow PQ2HE; the wire encoding and domain-separated KDFs
//! are Stogas-specific. No sparse KEM fragments or protocol negotiation.

use super::Error;
use hkdf::Hkdf;
use sha2_v11::Sha512;
use zeroize::Zeroizing;

mod header;
mod keys;
mod peer;

pub use header::HEADER_BYTES;
pub use keys::PUBLIC_KEY_BYTES;
pub use peer::{InitialKey, Peer};

// These are one bound: outstanding starts, replay distance, and retained keys.
pub const MAX_SKIPPED_KEYS: usize = 256;
pub const SKIPPED_KEY_LIFETIME_MS: u64 = 60_000;
// Caps encryption usage per header key; ServerSession also caps cumulative
// authentication work. Both enter the tested GCM usage bound.
pub(super) const MAX_CHAIN_MESSAGES: u64 = 1 << 24;
pub(super) const PROTOCOL: &[u8] = b"stogas.e2ee.pqdr.v1_X25519_MLKEM768_HKDFSHA512_AES256GCM";
type Secret = Zeroizing<[u8; 32]>;

fn expand<const N: usize>(salt: Option<&[u8]>, input: &[u8], label: &[u8]) -> Zeroizing<[u8; N]> {
    let mut output = Zeroizing::new([0; N]);
    Hkdf::<Sha512>::new(salt, input)
        .expand_multi_info(&[PROTOCOL, label], output.as_mut())
        .expect("fixed HKDF outputs are within SHA-512 bounds");
    output
}

fn secret(bytes: &[u8]) -> Secret {
    let mut result = Zeroizing::new([0; 32]);
    result.copy_from_slice(bytes);
    result
}

// Growing vectors and tree nodes move their values without erasing old slots.
// Container-held secrets need fixed allocations; only their pointers may move.
type HeapSecret = Box<Zeroizing<[u8; 32]>>;

#[expect(
    clippy::unnecessary_box_returns,
    reason = "The fixed heap allocation prevents container moves from copying secret bytes."
)]
fn heap_secret(secret: &[u8; 32]) -> HeapSecret {
    let mut owned = Box::new(Zeroizing::new([0; 32]));
    owned.copy_from_slice(secret);
    owned
}

// Admission deadlines apply to delayed request starts. Response keys belong
// to outstanding request owners, which can legitimately wait much longer.
#[derive(Clone, Copy)]
pub(super) enum Retention {
    Timed,
    Owned,
}

impl Retention {
    const fn deadline(self, now: u64) -> Option<u64> {
        match self {
            Self::Timed => Some(now.saturating_add(SKIPPED_KEY_LIFETIME_MS)),
            Self::Owned => None,
        }
    }
}
