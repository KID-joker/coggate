use sha2::{Digest, Sha256};

use crate::error::{ArenaError, ArenaResult};

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn random_token(bytes: usize) -> ArenaResult<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value).map_err(|_| ArenaError::Internal)?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        value,
    ))
}

pub fn random_id(prefix: &str) -> ArenaResult<String> {
    Ok(format!("{prefix}_{}", random_token(16)?))
}

pub fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

pub fn token_hash(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

pub fn ascii_trim(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && value[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && value[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &value[start..end]
}
