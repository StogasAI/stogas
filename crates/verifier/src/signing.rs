//! Composite MLDSA65-Ed25519-SHA512 for every Stogas-controlled signature.
//!
//! Per draft-ietf-lamps-pq-composite-sigs, ML-DSA-65 and Ed25519 both sign one
//! message representative and both must verify, so forging a signature requires
//! breaking both algorithms. Formats own their purpose separation and encodings,
//! so the composite application context is always empty.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer as _, VerifyingKey, pkcs8::EncodePublicKey as _};
use sha2::{Digest as _, Sha512};
use spki::{
    AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef,
    der::{Decode as _, Encode as _, asn1::BitStringRef},
};

pub mod mldsa;

/// The ML-DSA-65 public key, then the Ed25519 public key.
pub const PUBLIC_KEY_BYTES: usize = mldsa::PUBLIC_KEY_BYTES + 32;
/// The ML-DSA-65 signature, then the Ed25519 signature.
pub const SIGNATURE_BYTES: usize = mldsa::SIGNATURE_BYTES + 64;
/// Each component's private key: an ML-DSA-65 key-generation seed or an Ed25519 secret.
pub const SEED_BYTES: usize = 32;
/// The message representative each component signs.
pub const REPRESENTATIVE_BYTES: usize = PREFIX.len() + LABEL.len() + 1 + 64;
const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.48");
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// Signature errors contain no key or document material.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    /// The document exceeds the shared bounded-input profile.
    #[error("signed document exceeds the input limit")]
    TooLarge,
    /// The fixed profile's public key or signature length differs.
    #[error("invalid signature key or signature length")]
    Length,
    /// The SPKI is malformed, uses another algorithm, or has parameters.
    #[error("invalid signature public key encoding")]
    PublicKey,
    /// Rekor compatibility keys use a separate 32-byte Ed25519 seed.
    #[error("invalid Rekor submission key seed")]
    SubmissionKey,
    /// FIPS 204 limits the signing context to 255 bytes.
    #[error("ML-DSA signing context exceeds 255 bytes")]
    Context,
    /// The signature is malformed or does not authenticate this message.
    #[error("signature verification failed")]
    Verification,
    /// Signature generation failed.
    #[error("signing failed")]
    Signing,
    /// The platform could not supply cryptographic randomness.
    #[error("cryptographic randomness is unavailable")]
    Randomness,
}

/// A composite signing key whose components are erased on drop and never
/// implicitly cloned or formatted.
pub struct SigningKey {
    mldsa: mldsa::SigningKey,
    ed25519: ed25519_dalek::SigningKey,
    public: [u8; PUBLIC_KEY_BYTES],
}

impl SigningKey {
    /// Derive a key from two independent random component seeds, ML-DSA-65 first;
    /// the caller owns seed erasure.
    #[must_use]
    pub fn from_seeds([mldsa_seed, ed25519_secret]: &[[u8; SEED_BYTES]; 2]) -> Self {
        let mldsa = mldsa::SigningKey::from_seed(mldsa_seed);
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(ed25519_secret);
        let mut public = [0; PUBLIC_KEY_BYTES];
        let (mldsa_public, ed25519_public) = public.split_at_mut(mldsa::PUBLIC_KEY_BYTES);
        mldsa_public.copy_from_slice(mldsa.public_key());
        ed25519_public.copy_from_slice(ed25519.verifying_key().as_bytes());
        Self {
            mldsa,
            ed25519,
            public,
        }
    }

    /// The raw composite public key, without an ASN.1 wrapper.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public
    }

    /// Encode the public key as DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    /// Returns an error if DER encoding fails.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, Error> {
        SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: OID,
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(&self.public)
                .map_err(|_| Error::PublicKey)?,
        }
        .to_der()
        .map_err(|_| Error::PublicKey)
    }

    /// Sign with hedged ML-DSA-65 and deterministic Ed25519.
    ///
    /// # Errors
    /// Fails when randomness is unavailable or either component fails.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], Error> {
        let representative = representative(message);
        let mut signature = [0; SIGNATURE_BYTES];
        let (mldsa_signature, ed25519_signature) = signature.split_at_mut(mldsa::SIGNATURE_BYTES);
        mldsa_signature.copy_from_slice(&self.mldsa.sign(&representative, LABEL)?);
        ed25519_signature.copy_from_slice(&self.ed25519.sign(&representative).to_bytes());
        Ok(signature)
    }
}

/// Verify a composite signature using a raw composite public key and the exact message.
/// Ed25519 verification is strict: it rejects weak keys and non-canonical encodings.
///
/// # Errors
/// Rejects wrong lengths and any component that does not verify.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        return Err(Error::Length);
    }
    let (mldsa_key, ed25519_key) = public_key.split_at(mldsa::PUBLIC_KEY_BYTES);
    let (mldsa_signature, ed25519_signature) = signature.split_at(mldsa::SIGNATURE_BYTES);
    let representative = representative(message);
    mldsa::verify(mldsa_key, &representative, LABEL, mldsa_signature)?;
    VerifyingKey::try_from(ed25519_key)
        .and_then(|key| {
            key.verify_strict(&representative, &Signature::from_slice(ed25519_signature)?)
        })
        .map_err(|_| Error::Verification)
}

/// What each component key signs when the two keys are remote, such as two Transit keys.
///
/// ML-DSA-65 signs `mldsa_mu` as FIPS 204's external message representative;
/// Ed25519 signs `ed25519_message`. Join the signatures in that order and verify
/// the result before use.
pub struct RemoteSigningInput {
    pub mldsa_mu: [u8; 64],
    pub ed25519_message: [u8; REPRESENTATIVE_BYTES],
}

/// Prepare remote component signing for a raw composite public key.
///
/// # Errors
/// Rejects invalid public-key lengths and oversized messages.
pub fn remote_signing_input(
    public_key: &[u8],
    message: &[u8],
) -> Result<RemoteSigningInput, Error> {
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(Error::Length);
    }
    if message.len() > crate::MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let ed25519_message = representative(message);
    Ok(RemoteSigningInput {
        mldsa_mu: mldsa::message_representative(
            &public_key[..mldsa::PUBLIC_KEY_BYTES],
            &ed25519_message,
            LABEL,
        )?,
        ed25519_message,
    })
}

/// Extract a composite public key from its strict DER `SubjectPublicKeyInfo` encoding.
///
/// # Errors
/// Rejects trailing bytes, algorithm parameters, other algorithms and wrong key lengths.
pub fn public_key_from_spki(der: &[u8]) -> Result<&[u8; PUBLIC_KEY_BYTES], Error> {
    spki_key(der, OID)
}

/// A Rekor compatibility key for a publisher whose signing key cannot be exported.
///
/// It grants no Stogas approval authority. Bind its public key to the composite key
/// in authenticated metadata; document verification must require both proofs.
pub struct RekorSubmissionKey(ed25519_dalek::SigningKey);

impl RekorSubmissionKey {
    /// Import a separate random seed. The caller owns erasure of its input copy.
    ///
    /// # Errors
    /// Rejects seeds that are not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(
            seed.try_into().map_err(|_| Error::SubmissionKey)?,
        )))
    }

    /// Encode the submission public key for authenticated publication and log searches.
    ///
    /// # Errors
    /// Returns an error if DER encoding fails.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, Error> {
        self.0
            .verifying_key()
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Error::PublicKey)
    }

    /// Sign SHA-512 of the complete signed document for Rekor v1. Persist the
    /// exact signed document and this deterministic submission before delivery.
    ///
    /// # Errors
    /// Rejects oversized documents and encoding or signing failures.
    pub fn prepare_submission(&self, signed_document: &[u8]) -> Result<String, Error> {
        if signed_document.len() > crate::MAX_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let digest = Sha512::new_with_prefix(signed_document);
        let signature = self
            .0
            .sign_prehashed(digest.clone(), None)
            .map_err(|_| Error::Signing)?;
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(self.public_key_spki()?)
        );
        crate::canonical_json(&serde_json::json!({
            "apiVersion":"0.0.1", "kind":"hashedrekord", "spec":{
                "data":{"hash":{"algorithm":"sha512","value":hex::encode(digest.finalize())}},
                "signature":{"content":STANDARD.encode(signature.to_bytes()),
                    "publicKey":{"content":STANDARD.encode(pem)}}
            }
        }))
        .map_err(|_| Error::Signing)
    }
}

/// `M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)` with an empty context.
fn representative(message: &[u8]) -> [u8; REPRESENTATIVE_BYTES] {
    let digest = Sha512::digest(message);
    let mut output = [0; REPRESENTATIVE_BYTES];
    for (byte, value) in output
        .iter_mut()
        .zip(PREFIX.iter().chain(LABEL).chain(&[0]).chain(&digest))
    {
        *byte = *value;
    }
    output
}

fn spki_key<const N: usize>(der: &[u8], oid: ObjectIdentifier) -> Result<&[u8; N], Error> {
    let spki = SubjectPublicKeyInfoRef::from_der(der).map_err(|_| Error::PublicKey)?;
    if spki.algorithm.oid != oid || spki.algorithm.parameters.is_some() {
        return Err(Error::PublicKey);
    }
    spki.subject_public_key
        .as_bytes()
        .ok_or(Error::PublicKey)?
        .try_into()
        .map_err(|_| Error::Length)
}

#[cfg(test)]
mod tests;
