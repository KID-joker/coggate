use std::fmt;

use agentgate_contracts::{MAX_SECRET_LENGTH, MIN_SECRET_LENGTH};

use super::random::{OsRandom, RandomSource, sample_below};

const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub struct Secret(Vec<u8>);

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl Secret {
    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[expect(dead_code, reason = "consumed by the Phase 4 lifecycle API")]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

#[expect(dead_code, reason = "consumed by the Phase 4 lifecycle API")]
pub(crate) fn generate_secret() -> Result<Secret, super::GenerationError> {
    let mut random = OsRandom;
    generate_with(&mut random)
}

pub(crate) fn generate_with(
    random: &mut impl RandomSource,
) -> Result<Secret, super::GenerationError> {
    let minimum_length = usize::from(MIN_SECRET_LENGTH);
    let length_range = usize::from(MAX_SECRET_LENGTH - MIN_SECRET_LENGTH) + 1;
    let length = minimum_length + sample_below(random, length_range)?;
    let mut secret = Vec::with_capacity(length);

    for _ in 0..length {
        let index = sample_below(random, ALPHANUMERIC.len())?;
        secret.push(ALPHANUMERIC[index]);
    }

    Ok(Secret(secret))
}

#[cfg(test)]
use super::test_random::DeterministicRandom;

#[test]
fn generates_redacted_ascii_alphanumeric_secrets_within_policy_bounds() {
    let mut generated_lengths = std::collections::BTreeSet::new();

    for seed in 0_u8..=255 {
        let mut random = DeterministicRandom::new([seed; 32]);
        let secret = generate_with(&mut random).unwrap();

        assert!((8..=16).contains(&secret.len()));
        assert!(secret.expose().iter().all(u8::is_ascii_alphanumeric));
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        generated_lengths.insert(secret.len());
    }

    assert_eq!(generated_lengths, (8_usize..=16).collect());
}
