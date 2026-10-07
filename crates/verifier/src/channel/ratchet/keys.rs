//! Full ML-KEM-768 and X448 key agreement. Private keys have one shared owner
//! while a transaction is staged, and are erased when the last owner retires.

use super::{Error, Secret, expand};
use libcrux_ml_kem::mlkem768 as kem;
use subtle::ConstantTimeEq as _;
use x448::{PublicKey, StaticSecret};
use zeroize::{Zeroize as _, Zeroizing};

pub const PUBLIC_KEY_BYTES: usize = 56 + 1184;
pub(super) const CIPHERTEXT_BYTES: usize = 1088;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PublicKeys(pub [u8; PUBLIC_KEY_BYTES]);

impl PublicKeys {
    pub fn validate(&self) -> Result<(), Error> {
        PublicKey::from_bytes(&self.0[..56]).ok_or(Error::Authentication)?;
        let key = kem::MlKem768PublicKey::try_from(&self.0[56..]).map_err(|_| Error::Record)?;
        if !kem::validate_public_key(&key) {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub fn encapsulate(&self, random: [u8; 32]) -> Result<([u8; CIPHERTEXT_BYTES], Secret), Error> {
        let key = kem::MlKem768PublicKey::try_from(&self.0[56..]).map_err(|_| Error::Record)?;
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
    dh: StaticSecret,
    kem: PrivateKem,
    pub public: PublicKeys,
}

impl KeyPair {
    pub fn from_seed(seed: &Secret) -> Self {
        let bytes = expand::<120>(None, seed.as_ref(), b":KeyGeneration");
        let mut dh_bytes = Zeroizing::new([0; 56]);
        dh_bytes.copy_from_slice(&bytes[..56]);
        let dh = StaticSecret::from(*dh_bytes);
        let mut kem_seed = Zeroizing::new([0; 64]);
        kem_seed.copy_from_slice(&bytes[56..]);
        let (private, public) = kem::generate_key_pair(*kem_seed).into_parts();
        let mut encoded = [0; PUBLIC_KEY_BYTES];
        encoded[..56].copy_from_slice(PublicKey::from(&dh).as_bytes());
        encoded[56..].copy_from_slice(public.as_slice());
        Self {
            dh,
            kem: PrivateKem(private),
            public: PublicKeys(encoded),
        }
    }

    pub fn agree(&self, remote: &PublicKeys) -> Result<Zeroizing<[u8; 56]>, Error> {
        let public = PublicKey::from_bytes(&remote.0[..56]).ok_or(Error::Authentication)?;
        let shared = self.dh.diffie_hellman(&public);
        if bool::from(shared.as_bytes().ct_eq(&[0; 56])) {
            return Err(Error::Authentication);
        }
        Ok(Zeroizing::new(*shared.as_bytes()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> Secret {
        // The private key is generated locally; no imported expanded key is accepted.
        Zeroizing::new(kem::decapsulate(&self.kem.0, &(*ciphertext).into()))
    }
}

#[cfg(test)]
mod tests;
