//! Post-quantum boot provisioning: Control seals one envelope to a quote-bound
//! node key, and only the gateway holding that key opens it.

use crate::kem::XWing;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::AesGcm256, kdf::HkdfSha256, setup_sender,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROVISIONING_SCHEMA: &str = "stogas.boot-provisioning.v1";
const HPKE_INFO: &[u8] = b"stogas.secret-release.v1";
const XWING_PUBLIC_KEY_BYTES: usize = 1_216;
#[cfg(feature = "gateway")]
const ENCAPSULATED_KEY_BYTES: usize = 1_120;
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// One X-Wing HPKE delivery bound to an exact boot document digest.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provisioning {
    pub schema: String,
    pub boot_sha256: String,
    /// Unpadded base64url X-Wing encapsulated key.
    pub encapsulated_key: String,
    /// Unpadded base64url AES-256-GCM ciphertext and tag.
    pub ciphertext: String,
}

/// Provisioning failure. Messages contain no key or plaintext material.
#[derive(Debug, Error)]
pub enum Error {
    /// The recipient key, envelope or secret is invalid.
    #[error("invalid boot provisioning: {0}")]
    InvalidInput(&'static str),
    /// HPKE encryption failed.
    #[error("boot provisioning encryption failed")]
    Crypto,
    /// The envelope does not authenticate for this recipient and boot.
    #[error("boot provisioning authentication failed")]
    Authentication,
}

/// Seal one boot's provisioning with X-Wing, HKDF-SHA-256 and AES-256-GCM.
///
/// # Errors
/// Rejects an invalid X-Wing key or an empty or oversized secret, and reports
/// cryptographic failure.
pub fn seal_provisioning(
    public_key: &[u8],
    boot_sha256: &[u8; 32],
    plaintext: &[u8],
) -> Result<Provisioning, Error> {
    if public_key.len() != XWING_PUBLIC_KEY_BYTES {
        return Err(Error::InvalidInput(
            "X-Wing public key must contain 1216 bytes",
        ));
    }
    if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
        return Err(Error::InvalidInput("secret has an invalid size"));
    }
    let public_key = <XWing as hpke::Kem>::PublicKey::from_bytes(public_key)
        .map_err(|_| Error::InvalidInput("invalid X-Wing public key"))?;
    let (encapsulated_key, mut sender) =
        setup_sender::<AesGcm256, HkdfSha256, XWing>(&OpModeS::Base, &public_key, HPKE_INFO)
            .map_err(|_| Error::Crypto)?;
    let ciphertext = sender
        .seal(plaintext, &associated_data(boot_sha256))
        .map_err(|_| Error::Crypto)?;
    Ok(Provisioning {
        schema: PROVISIONING_SCHEMA.into(),
        boot_sha256: hex::encode(boot_sha256),
        encapsulated_key: URL_SAFE_NO_PAD.encode(encapsulated_key.to_bytes()),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

/// Open the envelope for this boot. The caller validates the plaintext's contents.
#[cfg(feature = "gateway")]
pub(crate) fn open_provisioning(
    private_key: &crate::kem::PrivateKey,
    boot_sha256: &[u8; 32],
    envelope: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    use hpke::{OpModeR, setup_receiver};
    let envelope: Provisioning = serde_json::from_value(
        crate::strict_json::from_slice(envelope)
            .map_err(|_| Error::InvalidInput("envelope encoding"))?,
    )
    .map_err(|_| Error::InvalidInput("envelope fields"))?;
    if envelope.schema != PROVISIONING_SCHEMA || envelope.boot_sha256 != hex::encode(boot_sha256) {
        return Err(Error::InvalidInput("envelope belongs to another boot"));
    }
    let encapsulated_key = decode(&envelope.encapsulated_key, ENCAPSULATED_KEY_BYTES)?;
    let ciphertext = decode(&envelope.ciphertext, MAX_SECRET_BYTES + 16)?;
    if encapsulated_key.len() != ENCAPSULATED_KEY_BYTES || ciphertext.len() <= 16 {
        return Err(Error::InvalidInput("envelope field size"));
    }
    let encapsulated_key = <XWing as hpke::Kem>::EncappedKey::from_bytes(&encapsulated_key)
        .map_err(|_| Error::InvalidInput("encapsulated key"))?;
    let mut recipient = setup_receiver::<AesGcm256, HkdfSha256, XWing>(
        &OpModeR::Base,
        private_key,
        &encapsulated_key,
        HPKE_INFO,
    )
    .map_err(|_| Error::Authentication)?;
    recipient
        .open(&ciphertext, &associated_data(boot_sha256))
        .map(zeroize::Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

// Canonical JSON of the envelope's public binding, with a final newline.
fn associated_data(boot_sha256: &[u8; 32]) -> Vec<u8> {
    format!(
        "{{\"boot_sha256\":\"{}\",\"schema\":\"{PROVISIONING_SCHEMA}\"}}\n",
        hex::encode(boot_sha256)
    )
    .into_bytes()
}

#[cfg(feature = "gateway")]
fn decode(value: &str, limit: usize) -> Result<Vec<u8>, Error> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(Error::InvalidInput("envelope field size"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidInput("envelope field encoding"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::InvalidInput("envelope field encoding"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Kem as _, OpModeR, setup_receiver};

    #[test]
    fn seals_for_the_exact_recipient_and_boot() {
        let (private_key, public_key) = XWing::gen_keypair();
        let sealed =
            seal_provisioning(&public_key.to_bytes(), &[7; 32], b"provider-secret").unwrap();
        assert_eq!(sealed.boot_sha256, hex::encode([7; 32]));
        let encapsulated = <XWing as hpke::Kem>::EncappedKey::from_bytes(
            &URL_SAFE_NO_PAD.decode(&sealed.encapsulated_key).unwrap(),
        )
        .unwrap();
        let ciphertext = URL_SAFE_NO_PAD.decode(&sealed.ciphertext).unwrap();
        let receiver = || {
            setup_receiver::<AesGcm256, HkdfSha256, XWing>(
                &OpModeR::Base,
                &private_key,
                &encapsulated,
                HPKE_INFO,
            )
            .unwrap()
        };
        assert!(
            receiver()
                .open(&ciphertext, &associated_data(&[8; 32]))
                .is_err()
        );
        assert_eq!(
            receiver()
                .open(&ciphertext, &associated_data(&[7; 32]))
                .unwrap(),
            b"provider-secret"
        );
        // The binding is the canonical JSON Control publishes beside the ciphertext.
        let binding =
            serde_json::json!({"schema": PROVISIONING_SCHEMA, "boot_sha256": hex::encode([7; 32])});
        assert_eq!(
            crate::canonical_json(&binding).unwrap().into_bytes(),
            associated_data(&[7; 32])
        );
        assert!(seal_provisioning(&public_key.to_bytes()[1..], &[7; 32], b"x").is_err());
        assert!(seal_provisioning(&public_key.to_bytes(), &[7; 32], b"").is_err());
    }
}
