use std::fmt;

use super::KeyProviderError;

pub const MAX_MAC_KEY_ID_BYTES: usize = 128;
pub const MIN_MAC_KEY_BYTES: usize = 32;

pub struct MacKey(Vec<u8>);

impl MacKey {
    pub fn new(key: Vec<u8>) -> Result<Self, KeyProviderError> {
        if key.len() < MIN_MAC_KEY_BYTES {
            return Err(KeyProviderError::InvalidMaterial);
        }
        Ok(Self(key))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacKey([REDACTED])")
    }
}

#[allow(dead_code)]
pub struct ActiveMacKey {
    key_id: String,
    key: MacKey,
}

impl ActiveMacKey {
    pub fn new(key_id: impl Into<String>, key: MacKey) -> Result<Self, KeyProviderError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > MAX_MAC_KEY_ID_BYTES
            || key.expose().len() < MIN_MAC_KEY_BYTES
        {
            return Err(KeyProviderError::InvalidMaterial);
        }
        Ok(Self { key_id, key })
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts(self) -> (String, MacKey) {
        (self.key_id, self.key)
    }
}

impl fmt::Debug for ActiveMacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveMacKey")
            .field("key_id", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

pub trait MacKeyProvider {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError>;
    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError>;
}
