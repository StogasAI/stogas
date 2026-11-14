//! Lowercase hexadecimal, the only form this crate reads and writes.

use alloc::string::String;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    text
}

#[cfg(feature = "serde")]
pub fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

#[cfg(feature = "serde")]
const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// A 64-bit mask as `0x` and 16 lowercase digits, which keeps every bit exact in JavaScript.
#[cfg(feature = "serde")]
pub fn encode_mask(mask: u64) -> String {
    let mut text = String::from("0x");
    text.push_str(&encode(&mask.to_be_bytes()));
    text
}

#[cfg(feature = "serde")]
pub fn decode_mask(text: &str) -> Option<u64> {
    decode::<8>(text.strip_prefix("0x")?).map(u64::from_be_bytes)
}

/// `serde(with = ...)` forms of byte arrays and masks.
#[cfg(feature = "serde")]
pub mod serde {
    use alloc::{format, string::String, vec::Vec};

    use serde::{Deserializer, Serializer, de::Error as _};

    const MASK: &str = "expected 0x and 16 lowercase hexadecimal digits";

    fn bytes<'de, D: Deserializer<'de>, const N: usize>(text: &str) -> Result<[u8; N], D::Error> {
        super::decode(text).ok_or_else(|| {
            D::Error::custom(format!("expected {} lowercase hexadecimal digits", N * 2))
        })
    }

    fn mask<'de, D: Deserializer<'de>>(text: &str) -> Result<u64, D::Error> {
        super::decode_mask(text).ok_or_else(|| D::Error::custom(MASK))
    }

    pub mod option {
        use super::{Deserializer, Serializer, String};

        #[allow(
            clippy::ref_option,
            reason = "Serde passes a reference to the field to a serialize_with function."
        )]
        pub fn serialize<S: Serializer, const N: usize>(
            value: &Option<[u8; N]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_str(&crate::hex::encode(value)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
            deserializer: D,
        ) -> Result<Option<[u8; N]>, D::Error> {
            <Option<String> as serde::Deserialize>::deserialize(deserializer)?
                .map(|text| super::bytes::<D, N>(&text))
                .transpose()
        }
    }

    pub mod vec {
        use super::{Deserializer, Serializer, String, Vec};

        pub fn serialize<S: Serializer, const N: usize>(
            values: &[[u8; N]],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(values.iter().map(|value| crate::hex::encode(value)))
        }

        pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
            deserializer: D,
        ) -> Result<Vec<[u8; N]>, D::Error> {
            <Vec<String> as serde::Deserialize>::deserialize(deserializer)?
                .iter()
                .map(|text| super::bytes::<D, N>(text))
                .collect()
        }
    }

    pub mod mask {
        use super::{Deserializer, Serializer, String};

        #[allow(
            clippy::trivially_copy_pass_by_ref,
            reason = "Serde passes a reference to the field to a serialize_with function."
        )]
        pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&crate::hex::encode_mask(*value))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
            super::mask::<D>(&<String as serde::Deserialize>::deserialize(deserializer)?)
        }
    }

    pub mod mask_option {
        use super::{Deserializer, Serializer, String};

        #[allow(
            clippy::ref_option,
            reason = "Serde passes a reference to the field to a serialize_with function."
        )]
        pub fn serialize<S: Serializer>(
            value: &Option<u64>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => super::mask::serialize(value, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<u64>, D::Error> {
            <Option<String> as serde::Deserialize>::deserialize(deserializer)?
                .map(|text| super::mask::<D>(&text))
                .transpose()
        }
    }
}
