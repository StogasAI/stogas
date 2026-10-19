//! Fixed-width encrypted headers. Every message carries both complete public
//! keys and the complete KEM ciphertext, so no padding is needed. The visible
//! request number is the standard 96-bit GCM nonce: each header key belongs to
//! one direction, which uses each request number at most once.

use super::{
    Error, Secret,
    keys::{CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, PublicKeys},
};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut as _, KeyInit as _},
};
use sha2_v11::{Digest as _, Sha256};
use zeroize::Zeroizing;

const FIELDS_BYTES: usize = PUBLIC_KEY_BYTES + CIPHERTEXT_BYTES + 16;
pub const HEADER_BYTES: usize = FIELDS_BYTES + 16;

fn nonce(request: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&request.to_be_bytes());
    nonce
}

pub(super) struct HeaderCipher(Aes256Gcm);

impl HeaderCipher {
    pub fn new(key: &Secret) -> Self {
        Self(Aes256Gcm::new_from_slice(key.as_ref()).expect("fixed AES-256 key size"))
    }

    pub fn seal(&self, header: &Header, request: u64) -> Result<Vec<u8>, Error> {
        let mut plaintext = header.encode();
        let tag = self
            .0
            .encrypt_inout_detached(
                &nonce(request).into(),
                super::PROTOCOL,
                plaintext.as_mut_slice().into(),
            )
            .map_err(|_| Error::Crypto)?;
        let mut output = Vec::with_capacity(HEADER_BYTES);
        output.extend_from_slice(plaintext.as_ref());
        output.extend_from_slice(&tag);
        Ok(output)
    }

    pub fn open(&self, encoded: &[u8], request: u64) -> Result<Header, Error> {
        if encoded.len() != HEADER_BYTES {
            return Err(Error::Record);
        }
        let mut plaintext = Zeroizing::new([0; FIELDS_BYTES]);
        plaintext.copy_from_slice(&encoded[..FIELDS_BYTES]);
        self.0
            .decrypt_inout_detached(
                &nonce(request).into(),
                super::PROTOCOL,
                plaintext.as_mut_slice().into(),
                encoded[FIELDS_BYTES..]
                    .try_into()
                    .map_err(|_| Error::Record)?,
            )
            .map_err(|_| Error::Authentication)?;
        Header::decode(&plaintext)
    }
}

#[derive(Clone)]
pub(super) struct Header {
    pub public: PublicKeys,
    pub ciphertext: [u8; CIPHERTEXT_BYTES],
    pub previous: u64,
    pub number: u64,
}

impl Header {
    fn encode(&self) -> Zeroizing<[u8; FIELDS_BYTES]> {
        let mut bytes = Zeroizing::new([0; FIELDS_BYTES]);
        bytes[..PUBLIC_KEY_BYTES].copy_from_slice(&self.public.0);
        bytes[PUBLIC_KEY_BYTES..FIELDS_BYTES - 16].copy_from_slice(&self.ciphertext);
        bytes[FIELDS_BYTES - 16..FIELDS_BYTES - 8].copy_from_slice(&self.previous.to_be_bytes());
        bytes[FIELDS_BYTES - 8..FIELDS_BYTES].copy_from_slice(&self.number.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8; FIELDS_BYTES]) -> Result<Self, Error> {
        Ok(Self {
            public: PublicKeys(
                bytes[..PUBLIC_KEY_BYTES]
                    .try_into()
                    .map_err(|_| Error::Record)?,
            ),
            ciphertext: bytes[PUBLIC_KEY_BYTES..FIELDS_BYTES - 16]
                .try_into()
                .map_err(|_| Error::Record)?,
            previous: u64::from_be_bytes(
                bytes[FIELDS_BYTES - 16..FIELDS_BYTES - 8]
                    .try_into()
                    .map_err(|_| Error::Record)?,
            ),
            number: u64::from_be_bytes(
                bytes[FIELDS_BYTES - 8..FIELDS_BYTES]
                    .try_into()
                    .map_err(|_| Error::Record)?,
            ),
        })
    }

    pub fn turn(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.public.0.as_slice());
        hash.update(self.ciphertext);
        hash.update(self.previous.to_be_bytes());
        hash.finalize().into()
    }
}
