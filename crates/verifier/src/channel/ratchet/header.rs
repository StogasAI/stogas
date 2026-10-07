//! Fixed-width encrypted headers. Padding is canonical and every turn carries
//! both complete public keys and the complete KEM ciphertext.

use super::{
    Error, Secret,
    keys::{CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, PublicKeys},
};
use aes_gcm::{
    AesGcm,
    aead::{AeadInOut as _, KeyInit as _, consts::U16},
    aes::Aes256,
};
use sha2_v11::{Digest as _, Sha256};
use zeroize::Zeroizing;

const FIELDS_BYTES: usize = PUBLIC_KEY_BYTES + CIPHERTEXT_BYTES + 16;
const PADDED_BYTES: usize = FIELDS_BYTES.next_multiple_of(16);
pub const HEADER_BYTES: usize = 16 + PADDED_BYTES + 16;

pub(super) struct HeaderCipher(AesGcm<Aes256, U16>);

impl HeaderCipher {
    pub fn new(key: &Secret) -> Self {
        Self(AesGcm::new_from_slice(key.as_ref()).expect("fixed AES-256 key size"))
    }

    pub fn seal(&self, header: &Header, nonce: [u8; 16]) -> Result<Vec<u8>, Error> {
        let mut plaintext = header.encode();
        let tag = self
            .0
            .encrypt_inout_detached(
                &nonce.into(),
                super::PROTOCOL,
                plaintext.as_mut_slice().into(),
            )
            .map_err(|_| Error::Crypto)?;
        let mut output = Vec::with_capacity(HEADER_BYTES);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(plaintext.as_ref());
        output.extend_from_slice(&tag);
        Ok(output)
    }

    pub fn open(&self, encoded: &[u8]) -> Result<Header, Error> {
        if encoded.len() != HEADER_BYTES {
            return Err(Error::Record);
        }
        let mut plaintext = Zeroizing::new([0; PADDED_BYTES]);
        plaintext.copy_from_slice(&encoded[16..16 + PADDED_BYTES]);
        self.0
            .decrypt_inout_detached(
                encoded[..16].try_into().map_err(|_| Error::Record)?,
                super::PROTOCOL,
                plaintext.as_mut_slice().into(),
                encoded[16 + PADDED_BYTES..]
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
    fn encode(&self) -> Zeroizing<[u8; PADDED_BYTES]> {
        let mut bytes = Zeroizing::new([0; PADDED_BYTES]);
        bytes[..PUBLIC_KEY_BYTES].copy_from_slice(&self.public.0);
        bytes[PUBLIC_KEY_BYTES..FIELDS_BYTES - 16].copy_from_slice(&self.ciphertext);
        bytes[FIELDS_BYTES - 16..FIELDS_BYTES - 8].copy_from_slice(&self.previous.to_be_bytes());
        bytes[FIELDS_BYTES - 8..FIELDS_BYTES].copy_from_slice(&self.number.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8; PADDED_BYTES]) -> Result<Self, Error> {
        if bytes[FIELDS_BYTES..].iter().any(|byte| *byte != 0) {
            return Err(Error::Record);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn noncanonical_authenticated_padding_is_rejected() {
        let cipher = HeaderCipher::new(&Zeroizing::new([1; 32]));
        for index in FIELDS_BYTES..PADDED_BYTES {
            let mut plain = [0; PADDED_BYTES];
            plain[index] = 1;
            let nonce = [2; 16];
            let tag = cipher
                .0
                .encrypt_inout_detached(
                    &nonce.into(),
                    super::super::PROTOCOL,
                    plain.as_mut_slice().into(),
                )
                .unwrap();
            let encoded = [nonce.as_slice(), plain.as_slice(), tag.as_slice()].concat();
            assert!(matches!(cipher.open(&encoded), Err(Error::Record)));
        }
    }
}
