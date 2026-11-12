//! Plaintext storage that zeroes its bytes at memory-fill speed.

use core::ops::{Deref, DerefMut};
use std::collections::TryReserveError;

/// Plaintext bytes, zeroed before their memory is reused or freed.
///
/// Growing moves the bytes to a new allocation and zeroes the old one, and clearing or
/// dropping zeroes the contents. The spare capacity is never written, so zeroing the contents
/// covers everything the buffer held; a vector taken with `From` must hold nothing secret
/// beyond its length.
///
/// `zeroize` stores one volatile byte at a time, which took 0.45 ms per MiB in Node's
/// WebAssembly against 0.02 ms for one fill that its optimization barrier keeps.
#[derive(Default)]
pub struct PlaintextBuffer(Vec<u8>);

impl PlaintextBuffer {
    /// Append bytes, moving the contents to a larger allocation when they do not fit.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        if self.0.capacity() - self.0.len() < bytes.len() {
            self.move_to(Vec::with_capacity(
                (self.0.len() + bytes.len()).max(self.0.capacity().saturating_mul(2)),
            ));
        }
        self.0.extend_from_slice(bytes);
    }

    /// Make room for exactly `additional` more bytes.
    ///
    /// # Errors
    /// Returns the allocator's error and leaves the contents as they were.
    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), TryReserveError> {
        if self.0.capacity() - self.0.len() < additional {
            let mut grown = Vec::new();
            grown.try_reserve_exact(self.0.len().saturating_add(additional))?;
            self.move_to(grown);
        }
        Ok(())
    }

    /// Zero the contents and keep the allocation.
    pub fn clear(&mut self) {
        zero(&mut self.0);
        self.0.clear();
    }

    fn move_to(&mut self, mut grown: Vec<u8>) {
        grown.extend_from_slice(&self.0);
        self.clear();
        self.0 = grown;
    }
}

impl From<Vec<u8>> for PlaintextBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for PlaintextBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for PlaintextBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for PlaintextBuffer {
    fn drop(&mut self) {
        zero(&mut self.0);
    }
}

// A plain fill before a free is a dead store that the optimizer may remove; the barrier
// keeps it. Unlike a fill of `MaybeUninit` bytes, a byte-slice fill compiles to one memory
// fill even at `opt-level = "z"`.
fn zero(bytes: &mut [u8]) {
    bytes.fill(0);
    zeroize::optimization_barrier(&*bytes);
}

#[cfg(test)]
mod tests {
    use super::PlaintextBuffer;

    #[test]
    fn growing_and_clearing_keep_the_contents_and_reuse_the_allocation() {
        let mut buffer = PlaintextBuffer::default();
        for byte in 0..100_u8 {
            buffer.extend_from_slice(&[byte; 3]);
        }
        assert_eq!(buffer.len(), 300);
        assert!(
            buffer
                .chunks(3)
                .zip(0_u8..)
                .all(|(chunk, byte)| chunk == [byte; 3])
        );
        buffer.try_reserve_exact(1_000).unwrap();
        let capacity = buffer.0.capacity();
        assert!(capacity >= 1_300);
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.0.capacity(), capacity);
        buffer.extend_from_slice(&[9; 1_300]);
        assert_eq!(buffer.0.capacity(), capacity);
        assert!(buffer.try_reserve_exact(usize::MAX).is_err());
        assert_eq!(&*buffer, [9; 1_300]);
    }
}
