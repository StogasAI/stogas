// Compile the actual private HPKE adapter into this analysis binary. Instrument
// its owned secrets here without exporting test hooks from the production crate.
include!("../../../../crates/core/src/kem.rs");

use super::{public, secret};
use hpke::rand_core::{TryCryptoRng, TryRng, utils};
use std::convert::Infallible;

struct Coins(u8);
impl TryRng for Coins {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill(self)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_word_via_fill(self)
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(output.len(), 64);
        output.fill(self.0);
        // The separate X25519 scalar-multiply probe covers its secret input.
        // The composite API branches on contributory agreement, a predicate
        // of the public point rather than the clamped private scalar.
        secret(&mut output[..32]);
        Ok(())
    }
}
impl TryCryptoRng for Coins {}

pub fn audit() {
    let mut private = PrivateKey::from_bytes(&[3; 32]).unwrap();
    let recipient = XWing::sk_to_pk(&private);
    for byte in [0, 1, 42, 127, 255] {
        let (mut shared, mut ciphertext) =
            XWing::encap_with_rng(&recipient, None, &mut Coins(byte)).unwrap();
        public(&mut shared.0);
        public(&mut ciphertext.0);
        // Only private polynomials and the implicit-rejection secret are tainted;
        // the embedded public matrix seed/hash are deliberately left public.
        secret(&mut private.expanded[..1152]);
        secret(&mut private.expanded[2368..2400]);
        let mut actual = XWing::decap(&private, None, &ciphertext).unwrap();
        public(&mut actual.0);
        assert_eq!(actual.0, shared.0);
        for index in [0, 31, 767, 1087] {
            let mut changed = ciphertext.clone();
            changed.0[index] ^= 1;
            let mut output = XWing::decap(&private, None, &changed).unwrap();
            public(&mut output.0);
            assert_ne!(output.0, shared.0);
        }
        public(private.expanded.as_mut());
    }
}
