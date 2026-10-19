//! Full ML-KEM-768 and X25519 key agreement. Private keys have one shared owner
//! while a transaction is staged, and are erased when the last owner retires.

use super::{Error, Secret, expand};
use libcrux_ml_kem::mlkem768 as kem;
use zeroize::{Zeroize as _, Zeroizing};

pub const PUBLIC_KEY_BYTES: usize = 32 + 1184;
pub(super) const CIPHERTEXT_BYTES: usize = 1088;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PublicKeys(pub [u8; PUBLIC_KEY_BYTES]);

impl PublicKeys {
    // Every X25519 encoding is a valid input; agreement rejects low-order results.
    pub fn validate(&self) -> Result<(), Error> {
        let key = kem::MlKem768PublicKey::try_from(&self.0[32..]).map_err(|_| Error::Record)?;
        if !kem::validate_public_key(&key) {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub fn encapsulate(&self, random: [u8; 32]) -> Result<([u8; CIPHERTEXT_BYTES], Secret), Error> {
        let key = kem::MlKem768PublicKey::try_from(&self.0[32..]).map_err(|_| Error::Record)?;
        // Remote keys are validated when accepting setup or a new turn.
        let (ciphertext, secret) = kem::encapsulate(&key, random);
        Ok((*ciphertext.as_slice(), Zeroizing::new(secret)))
    }
}

struct PrivateKem(kem::MlKem768PrivateKey);

impl Drop for PrivateKem {
    fn drop(&mut self) {
        self.0[0..kem::MlKem768PrivateKey::len()].zeroize();
    }
}

pub(super) struct KeyPair {
    dh: Secret,
    kem: PrivateKem,
    pub public: PublicKeys,
}

impl KeyPair {
    pub fn from_seed(seed: &Secret) -> Self {
        let bytes = expand::<96>(None, seed.as_ref(), b":KeyGeneration");
        let mut dh = Zeroizing::new([0; 32]);
        dh.copy_from_slice(&bytes[..32]);
        libcrux_curve25519::clamp(&mut dh);
        let mut kem_seed = Zeroizing::new([0; 64]);
        kem_seed.copy_from_slice(&bytes[32..]);
        let (private, public) = kem::generate_key_pair(*kem_seed).into_parts();
        let mut encoded = [0; PUBLIC_KEY_BYTES];
        libcrux_curve25519::secret_to_public(
            (&mut encoded[..32]).try_into().expect("fixed width"),
            &dh,
        );
        encoded[32..].copy_from_slice(public.as_slice());
        Self {
            dh,
            kem: PrivateKem(private),
            public: PublicKeys(encoded),
        }
    }

    pub fn agree(&self, remote: &PublicKeys) -> Result<Secret, Error> {
        let mut shared = Zeroizing::new([0; 32]);
        // HACL rejects an all-zero result in constant time: low-order and
        // non-contributory peer keys cannot complete a turn.
        libcrux_curve25519::ecdh(
            &mut shared,
            remote.0[..32].try_into().map_err(|_| Error::Record)?,
            &self.dh,
        )
        .map_err(|_| Error::Authentication)?;
        Ok(shared)
    }

    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> Secret {
        // The private key is generated locally; no imported expanded key is accepted.
        Zeroizing::new(kem::decapsulate(&self.kem.0, &(*ciphertext).into()))
    }
}

#[cfg(test)]
mod tests;
