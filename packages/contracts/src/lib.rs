#![forbid(unsafe_code)]

mod challenge;
mod config;
mod error;

pub use challenge::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge, Submission};
pub use config::{ChallengeConfig, Difficulty};
pub use error::ContractError;

pub const GENERATOR_VERSION_V1: &str = "1.0";
