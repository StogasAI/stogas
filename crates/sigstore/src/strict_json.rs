use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::HashSet, fmt};

/// Parses one complete JSON value and rejects duplicate object keys.
///
/// # Errors
///
/// Returns an error for invalid JSON, trailing data, or a duplicate object key.
pub fn from_slice(input: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Parses like [`from_slice`], with up to `depth` nested arrays and objects where `serde_json`
/// alone stops at 127.
///
/// # Errors
///
/// Returns an error for invalid JSON, trailing data, a duplicate object key or deeper nesting.
pub fn from_slice_nested(input: &[u8], depth: usize) -> Result<Value, serde_json::Error> {
    if nesting(input) > depth {
        return Err(de::Error::custom("JSON nests too deeply"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    // The nesting was counted the way the parser will meet it: brackets outside strings.
    deserializer.disable_recursion_limit();
    let value = StrictValue.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// The deepest nesting of arrays and objects. Brackets in strings do not count, and a string
/// that never ends hides the rest, as it does from the parser.
fn nesting(input: &[u8]) -> usize {
    let (mut depth, mut deepest) = (0_usize, 0);
    let (mut string, mut escaped) = (false, false);
    for &byte in input {
        if string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => string = true,
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1024));
        while let Some(value) = sequence.next_element_seed(StrictValue)? {
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            output.insert(key, object.next_value_seed(StrictValue)?);
        }
        Ok(Value::Object(output))
    }
}
