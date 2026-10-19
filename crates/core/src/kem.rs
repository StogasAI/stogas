// HPKE's KEM interface over libcrux's maintained X-Wing implementation.
// Keep primitive arithmetic and the hybrid combiner in the backend. This adapter
// owns checked serialization, secret lifetimes and HPKE's labeled key derivation.
use hpke::{Deserializable, HpkeError, Kem, Serializable, kem::SharedSecret, rand_core::CryptoRng};
use hybrid_array::typenum::{Prod, Sum, U3, U32, U64, U1024};
use libcrux_kem::XWing as Backend;
use libcrux_traits::kem::arrayref::Kem as _;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

type U1216 = Sum<U1024, Prod<U64, U3>>;
type U1120 = Sum<Sum<U1024, U64>, U32>;

#[derive(Clone)]
pub struct PrivateKey {
    seed: Zeroizing<[u8; 32]>,
    expanded: Zeroizing<[u8; 2432]>,
    public: PublicKey,
}

impl PrivateKey {
    pub(crate) fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let mut expanded = Zeroizing::new([0; 2432]);
        let mut public = PublicKey([0; 1216]);
        // Every 32-byte seed is valid; fixed array sizes rule out input errors.
        Backend::keygen(&mut public.0, &mut expanded, &seed)
            .expect("X-Wing key generation from a fixed-size seed");
        Self {
            seed,
            expanded,
            public,
        }
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;
    fn write_exact(&self, output: &mut [u8]) {
        output.copy_from_slice(self.seed.as_ref());
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(input: &[u8]) -> Result<Self, HpkeError> {
        Ok(Self::from_seed(Zeroizing::new(
            input.try_into().map_err(|_| HpkeError::ValidationError)?,
        )))
    }
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.as_ref().ct_eq(other.seed.as_ref())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 1216]);

impl Serializable for PublicKey {
    type OutputSize = U1216;
    fn write_exact(&self, output: &mut [u8]) {
        output.copy_from_slice(&self.0);
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(input: &[u8]) -> Result<Self, HpkeError> {
        let key = Self(input.try_into().map_err(|_| HpkeError::ValidationError)?);
        let mlkem = libcrux_ml_kem::mlkem768::MlKem768PublicKey::try_from(&key.0[..1184])
            .map_err(|_| HpkeError::ValidationError)?;
        if !libcrux_ml_kem::mlkem768::validate_public_key(&mlkem) {
            return Err(HpkeError::ValidationError);
        }
        Ok(key)
    }
}

#[derive(Clone)]
pub struct EncappedKey([u8; 1120]);

impl Serializable for EncappedKey {
    type OutputSize = U1120;
    fn write_exact(&self, output: &mut [u8]) {
        output.copy_from_slice(&self.0);
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(input: &[u8]) -> Result<Self, HpkeError> {
        input
            .try_into()
            .map(Self)
            .map_err(|_| HpkeError::ValidationError)
    }
}

pub struct XWing;

impl Kem for XWing {
    const KEM_ID: u16 = 0x647a;
    type NSecret = U32;
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type EncappedKey = EncappedKey;

    fn sk_to_pk(private: &PrivateKey) -> PublicKey {
        private.public.clone()
    }

    fn derive_keypair(ikm: &[u8]) -> (PrivateKey, PublicKey) {
        // HPKE PQ LabeledDerive(ikm, "DeriveKeyPair", "", 32).
        const SUFFIX: &[u8] = b"HPKE-v1KEM\x64\x7a\x00\x0dDeriveKeyPair\x00\x20";
        let mut labeled = Zeroizing::new(Vec::with_capacity(ikm.len() + SUFFIX.len()));
        labeled.extend_from_slice(ikm);
        labeled.extend_from_slice(SUFFIX);
        let private = PrivateKey::from_seed(Zeroizing::new(libcrux_sha3::shake256(&labeled)));
        let public = Self::sk_to_pk(&private);
        (private, public)
    }

    fn decap(
        private: &PrivateKey,
        sender: Option<&PublicKey>,
        ciphertext: &EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        if sender.is_some() {
            return Err(HpkeError::DecapError);
        }
        let mut shared = SharedSecret::<Self>::default();
        Backend::decaps(shared.0.as_mut(), &ciphertext.0, &private.expanded)
            .map_err(|_| HpkeError::DecapError)?;
        Ok(shared)
    }

    fn encap_with_rng(
        public: &PublicKey,
        sender: Option<(&PrivateKey, &PublicKey)>,
        rng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, EncappedKey), HpkeError> {
        if sender.is_some() {
            return Err(HpkeError::EncapError);
        }
        let mut coins = Zeroizing::new([0; 64]);
        rng.fill_bytes(coins.as_mut());
        let mut ciphertext = EncappedKey([0; 1120]);
        let mut shared = SharedSecret::<Self>::default();
        Backend::encaps(&mut ciphertext.0, shared.0.as_mut(), &public.0, &coins)
            .map_err(|_| HpkeError::EncapError)?;
        Ok((shared, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::rand_core::{TryCryptoRng, TryRng, utils};
    use serde_json::Value;
    use std::convert::Infallible;

    struct Coins<'a>(&'a [u8]);
    impl TryRng for Coins<'_> {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            utils::next_word_via_fill(self)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            utils::next_word_via_fill(self)
        }
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            let (used, remaining) = self.0.split_at(output.len());
            output.copy_from_slice(used);
            self.0 = remaining;
            Ok(())
        }
    }
    impl TryCryptoRng for Coins<'_> {}

    fn bytes(vector: &Value, name: &str) -> Vec<u8> {
        hex::decode(vector[name].as_str().unwrap()).unwrap()
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn xwing_and_hpke_specification_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/xwing.json")).unwrap();
        for vector in vectors["xwing"].as_array().unwrap() {
            let private = PrivateKey::from_bytes(&bytes(vector, "sk")).unwrap();
            let public = XWing::sk_to_pk(&private);
            assert_eq!(public.to_bytes().as_slice(), bytes(vector, "pk"));
            let coins = bytes(vector, "eseed");
            let (shared, ciphertext) =
                XWing::encap_with_rng(&public, None, &mut Coins(&coins)).unwrap();
            assert_eq!(ciphertext.to_bytes().as_slice(), bytes(vector, "ct"));
            assert_eq!(shared.0.as_slice(), bytes(vector, "ss"));
            assert_eq!(
                XWing::decap(&private, None, &ciphertext).unwrap().0,
                shared.0
            );
        }
        for vector in vectors["hpke"].as_array().unwrap() {
            let (private, public) = XWing::derive_keypair(&bytes(vector, "ikmR"));
            assert_eq!(private.to_bytes().as_slice(), bytes(vector, "skRm"));
            assert_eq!(public.to_bytes().as_slice(), bytes(vector, "pkRm"));
            let coins = bytes(vector, "ikmE");
            let (shared, ciphertext) =
                XWing::encap_with_rng(&public, None, &mut Coins(&coins)).unwrap();
            assert_eq!(ciphertext.to_bytes().as_slice(), bytes(vector, "enc"));
            assert_eq!(shared.0.as_slice(), bytes(vector, "shared_secret"));
            assert_eq!(
                XWing::decap(&private, None, &ciphertext).unwrap().0,
                shared.0
            );
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn xwing_agrees_with_independent_backend_and_rejects_low_order_ciphertexts() {
        use x_wing::{Decapsulate as _, Decapsulator as _};
        for byte in 0..32_u8 {
            let seed = [byte; 32];
            let private = PrivateKey::from_bytes(&seed).unwrap();
            let reference = x_wing::DecapsulationKey::from(seed);
            let coins = [byte.wrapping_add(127); 64];
            let (shared, ciphertext) =
                XWing::encap_with_rng(&private.public, None, &mut Coins(&coins)).unwrap();
            let (expected_ciphertext, expected_shared) = reference
                .encapsulation_key()
                .encapsulate_deterministic(&coins.into());
            assert_eq!(ciphertext.0.as_slice(), expected_ciphertext.as_slice());
            assert_eq!(shared.0, expected_shared);
            for index in [0, 767, 1087, 1088, 1100, 1119] {
                let mut changed = ciphertext.clone();
                changed.0[index] ^= 1;
                let actual = XWing::decap(&private, None, &changed).unwrap();
                let expected = reference.decapsulate(&changed.0.into());
                assert_eq!(actual.0, expected);
            }
            for low_order in [0, 1] {
                let mut changed = ciphertext.clone();
                changed.0[1088..].fill(0);
                changed.0[1088] = low_order;
                assert!(matches!(
                    XWing::decap(&private, None, &changed),
                    Err(HpkeError::DecapError)
                ));
            }
        }
    }
}
