use std::{
    collections::BTreeMap,
    io::{self, Read},
    path::{Path, PathBuf},
};

use serde::{
    Serialize,
    de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
pub const SHA256_HEX_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("input exceeds the configured maximum of {maximum} bytes")]
    InputTooLarge { maximum: usize },
    #[error("failed to read input: {0}")]
    Read(#[from] io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid SHA-256 hex value")]
    InvalidSha256,
    #[error("path must be a non-empty, safe relative path: {0}")]
    UnsafePath(String),
}

pub fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CanonicalError> {
    let read_limit = maximum.saturating_add(1);
    let mut bytes = Vec::new();
    reader.take(read_limit as u64).read_to_end(&mut bytes)?;

    if bytes.len() > maximum {
        return Err(CanonicalError::InputTooLarge { maximum });
    }

    Ok(bytes)
}

pub fn parse_strict_json(bytes: &[u8], maximum: usize) -> Result<Value, CanonicalError> {
    if bytes.len() > maximum {
        return Err(CanonicalError::InputTooLarge { maximum });
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

pub fn canonical_compact(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    Ok(serde_json::to_vec(&SortedJsonValue::from(value))?)
}

pub fn canonical_pretty_sorted(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut bytes = serde_json::to_vec_pretty(&SortedJsonValue::from(value))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn validate_sha256(value: &str) -> Result<(), CanonicalError> {
    if value.len() == SHA256_HEX_BYTES
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Ok(())
    } else {
        Err(CanonicalError::InvalidSha256)
    }
}

pub fn safe_relative_path(value: &str) -> Result<PathBuf, CanonicalError> {
    let bytes = value.as_bytes();
    let has_windows_drive_prefix =
        bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';

    if value.is_empty()
        || bytes.len() > 256
        || bytes.iter().any(|byte| byte.is_ascii_control())
        || value.contains('\\')
        || has_windows_drive_prefix
        || Path::new(value).is_absolute()
    {
        return Err(CanonicalError::UnsafePath(value.to_owned()));
    }

    let mut depth = 0usize;
    for segment in value.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(CanonicalError::UnsafePath(value.to_owned()));
        }
        depth += 1;
    }

    if depth > 16 {
        return Err(CanonicalError::UnsafePath(value.to_owned()));
    }

    Ok(PathBuf::from(value))
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(|number| StrictJsonValue(Value::Number(number)))
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJsonValue>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum SortedJsonValue<'a> {
    Null,
    Bool(bool),
    Number(&'a Number),
    String(&'a str),
    Array(Vec<SortedJsonValue<'a>>),
    Object(BTreeMap<&'a str, SortedJsonValue<'a>>),
}

impl<'a> From<&'a Value> for SortedJsonValue<'a> {
    fn from(value: &'a Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Bool(*value),
            Value::Number(value) => Self::Number(value),
            Value::String(value) => Self::String(value),
            Value::Array(values) => Self::Array(values.iter().map(Self::from).collect()),
            Value::Object(values) => Self::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.as_str(), Self::from(value)))
                    .collect(),
            ),
        }
    }
}
