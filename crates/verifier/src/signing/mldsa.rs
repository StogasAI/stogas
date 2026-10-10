//! Pure ML-DSA-65 (FIPS 204): per-connection TLS keys, whose TLS stacks support
//! no composite scheme, and the post-quantum component of the composite profile.

use super::{Error, SEED_BYTES, spki_key};
// libcrux builds add AVX2 on x86-64 and NEON on ARM64, and pick a backend at run time.
use libcrux_ml_dsa::ml_dsa_65::{
    self as ml_dsa, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};
use spki::ObjectIdentifier;
use zeroize::{Zeroize as _, Zeroizing};

/// FIPS 204 ML-DSA-65 public key length.
pub const PUBLIC_KEY_BYTES: usize = 1952;
/// FIPS 204 ML-DSA-65 signature length.
pub const SIGNATURE_BYTES: usize = 3309;
const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// An expanded signing key, erased on drop and never implicitly cloned or formatted.
pub struct SigningKey {
    secret: MLDSA65SigningKey,
    public: [u8; PUBLIC_KEY_BYTES],
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.secret.as_ref_mut().zeroize();
    }
}

impl SigningKey {
    /// Derive a key from a cryptographically random seed; the caller owns seed erasure.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        let pair = ml_dsa::generate_key_pair(*seed);
        Self {
            public: *pair.verification_key.as_ref(),
            secret: pair.signing_key,
        }
    }

    /// Generate a key from fresh operating-system randomness.
    ///
    /// # Errors
    /// Fails only when randomness is unavailable.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; SEED_BYTES]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Randomness)?;
        Ok(Self::from_seed(&seed))
    }

    /// The FIPS 204 public key encoding, without an ASN.1 wrapper.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public
    }

    /// Sign using fresh per-signature randomness and the supplied protocol context.
    ///
    /// # Errors
    /// Rejects overlong contexts, unavailable randomness and signing failures.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<[u8; SIGNATURE_BYTES], Error> {
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *randomness).map_err(|_| Error::Randomness)?;
        self.sign_with_randomness(message, context, &randomness)
    }

    pub(super) fn sign_with_randomness(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        check_context(context)?;
        ml_dsa::sign(&self.secret, message, context, *randomness)
            .map(|signature| *signature.as_ref())
            .map_err(|_| Error::Signing)
    }
}

/// Verify pure ML-DSA-65 using a raw public key and the exact signed message/context.
///
/// # Errors
/// Rejects wrong lengths, overlong contexts and invalid signatures.
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    check_context(context)?;
    let public_key = MLDSA65VerificationKey::new(public_key.try_into().map_err(|_| Error::Length)?);
    let signature = MLDSA65Signature::new(signature.try_into().map_err(|_| Error::Length)?);
    ml_dsa::verify(&public_key, message, context, &signature).map_err(|_| Error::Verification)
}

/// FIPS 204's external message representative for a remote pure ML-DSA signer.
/// This is not HashML-DSA: it preserves the exact message and protocol context.
pub(super) fn message_representative(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; 64], Error> {
    use libcrux_sha3::portable::incremental::{Shake256Xof, Xof as _};
    check_context(context)?;
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(Error::Length);
    }
    let tr = libcrux_sha3::shake256::<64>(public_key);
    let mut hash = Shake256Xof::new();
    hash.absorb(&tr);
    hash.absorb(&[0, u8::try_from(context.len()).map_err(|_| Error::Context)?]);
    hash.absorb(context);
    hash.absorb_final(message);
    let mut mu = [0; 64];
    hash.squeeze(&mut mu);
    Ok(mu)
}

/// Extract an ML-DSA-65 public key from its strict RFC 9881 `SubjectPublicKeyInfo`.
///
/// # Errors
/// Rejects trailing bytes, algorithm parameters, other algorithms and wrong key lengths.
pub fn public_key_from_spki(der: &[u8]) -> Result<&[u8; PUBLIC_KEY_BYTES], Error> {
    spki_key(der, OID)
}

const fn check_context(context: &[u8]) -> Result<(), Error> {
    if context.len() > 255 {
        return Err(Error::Context);
    }
    Ok(())
}
