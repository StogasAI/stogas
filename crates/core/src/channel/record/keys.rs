//! One-way directional chain. Each step replaces the chain and releases one
//! record key; neither the message secret nor earlier record keys are retained.

use super::{Direction, Error};
use hkdf::Hkdf;
use sha2_v11::Sha256;
use zeroize::Zeroizing;

const KEY_DOMAIN: &[u8] = b"stogas.e2ee.record.v1\0";
const STEP_DOMAIN: &[u8] = b"stogas.e2ee.record-key.v1\0";

pub(super) struct Keys(Zeroizing<[u8; 32]>);

impl Keys {
    pub(super) fn new(
        secret: &[u8; 32],
        session_id: &[u8; 32],
        number: u64,
        direction: Direction,
    ) -> Result<Self, Error> {
        let mut chain = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::from_prk(secret)
            .map_err(|_| Error::Crypto)?
            .expand_multi_info(
                &[
                    KEY_DOMAIN,
                    session_id,
                    &number.to_be_bytes(),
                    &[direction as u8],
                ],
                chain.as_mut(),
            )
            .map_err(|_| Error::Crypto)?;
        Ok(Self(chain))
    }

    pub(super) fn next(&mut self, sequence: u64) -> Result<(Zeroizing<[u8; 32]>, [u8; 12]), Error> {
        let mut material = Zeroizing::new([0_u8; 64]);
        Hkdf::<Sha256>::from_prk(self.0.as_ref())
            .map_err(|_| Error::Crypto)?
            .expand_multi_info(&[STEP_DOMAIN, &sequence.to_be_bytes()], material.as_mut())
            .map_err(|_| Error::Crypto)?;
        self.0.copy_from_slice(&material[..32]);
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(&material[32..]);
        // A key is used once. The monotonic record number also supplies a
        // unique standard 96-bit GCM nonce without another KDF output block.
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        Ok((key, nonce))
    }
}
