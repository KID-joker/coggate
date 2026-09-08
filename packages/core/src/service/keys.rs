use std::fmt;

use zeroize::Zeroizing;

use super::KeyProviderError;

/// Maximum UTF-8 byte length accepted for a MAC key identifier.
pub const MAX_MAC_KEY_ID_BYTES: usize = crate::mac::MAX_MAC_KEY_ID_BYTES;
/// Minimum byte length accepted for HMAC key material.
pub const MIN_MAC_KEY_BYTES: usize = 32;

/// Validated HMAC key material whose debug representation is redacted.
///
/// Providers remain responsible for protecting key bytes at rest, in transit,
/// in process memory, and in their own diagnostics.
pub struct MacKey(Zeroizing<Vec<u8>>);

impl MacKey {
    /// Validates and wraps key bytes.
    ///
    /// Returns [`KeyProviderError::InvalidMaterial`] when fewer than
    /// [`MIN_MAC_KEY_BYTES`] bytes are supplied.
    pub fn new(key: Vec<u8>) -> Result<Self, KeyProviderError> {
        let key = Zeroizing::new(key);
        if key.len() < MIN_MAC_KEY_BYTES {
            return Err(KeyProviderError::InvalidMaterial);
        }
        Ok(Self(key))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for MacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacKey([REDACTED])")
    }
}

/// The active issuance key and its persisted identifier.
///
/// This value is only for new challenge issuance. Verification requests the
/// exact key recorded with a challenge through [`MacKeyProvider::key_by_id`].
pub struct ActiveMacKey {
    key_id: String,
    key: MacKey,
}

impl ActiveMacKey {
    /// Creates an active key after validating its nonempty, bounded identifier.
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

/// Supplies protected HMAC keys for challenge issuance and verification.
///
/// Implementations must protect key material and return only keys of at least
/// [`MIN_MAC_KEY_BYTES`]. [`MacKeyProvider::active_key`] selects a key only for
/// newly issued challenges. [`MacKeyProvider::key_by_id`] must perform an exact
/// lookup of the identifier stored in private challenge material and must not
/// fall back to the active key.
///
/// Rotated keys must remain available until every challenge that references
/// them has expired and left the lifecycle storage-retention horizon.
pub trait MacKeyProvider {
    /// Returns the active key identifier and material for new issuance.
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError>;
    /// Returns material for the exact persisted key identifier.
    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError>;
}

#[cfg(test)]
mod tests {
    use super::{ActiveMacKey, KeyProviderError, MIN_MAC_KEY_BYTES, MacKey};
    use zeroize::Zeroizing;

    #[test]
    fn mac_key_uses_zeroizing_owned_storage() {
        let key = MacKey::new(vec![7; MIN_MAC_KEY_BYTES]).unwrap();
        assert_eq!(key.expose(), &[7; MIN_MAC_KEY_BYTES]);
        let _: &Zeroizing<Vec<u8>> = &key.0;
    }

    #[test]
    fn active_key_rejects_short_key_material() {
        assert_eq!(
            ActiveMacKey::new("primary", MacKey(Zeroizing::new(vec![0; 31]))).map(|_| ()),
            Err(KeyProviderError::InvalidMaterial)
        );
    }
}
