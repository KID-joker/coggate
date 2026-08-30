use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ContractError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Difficulty {
    Short,
    Medium,
    Hard,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeConfig {
    pub difficulty: Difficulty,
    pub secret_length: u8,
    pub fragment_count: u8,
    pub max_question_tokens: u16,
    pub ttl_seconds: u8,
    pub max_attempts: u8,
}

impl ChallengeConfig {
    pub const fn for_difficulty(difficulty: Difficulty) -> Self {
        match difficulty {
            Difficulty::Short => Self {
                difficulty,
                secret_length: 8,
                fragment_count: 3,
                max_question_tokens: 700,
                ttl_seconds: 5,
                max_attempts: 1,
            },
            Difficulty::Medium => Self {
                difficulty,
                secret_length: 10,
                fragment_count: 4,
                max_question_tokens: 1000,
                ttl_seconds: 8,
                max_attempts: 1,
            },
            Difficulty::Hard => Self {
                difficulty,
                secret_length: 12,
                fragment_count: 5,
                max_question_tokens: 1200,
                ttl_seconds: 12,
                max_attempts: 1,
            },
        }
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.difficulty == Difficulty::Hard {
            return Err(ContractError::UnsupportedDifficulty);
        }
        if !(8..=12).contains(&self.secret_length) {
            return Err(ContractError::InvalidConfiguration(
                "secret_length must be 8..=12",
            ));
        }
        if !(3..=5).contains(&self.fragment_count) {
            return Err(ContractError::InvalidConfiguration(
                "fragment_count must be 3..=5",
            ));
        }
        if !(500..=1200).contains(&self.max_question_tokens) {
            return Err(ContractError::InvalidConfiguration(
                "max_question_tokens must be 500..=1200",
            ));
        }
        if !(5..=12).contains(&self.ttl_seconds) {
            return Err(ContractError::InvalidConfiguration(
                "ttl_seconds must be 5..=12",
            ));
        }
        if !(1..=2).contains(&self.max_attempts) {
            return Err(ContractError::InvalidConfiguration(
                "max_attempts must be 1 or 2",
            ));
        }

        Ok(())
    }
}
