#![forbid(unsafe_code)]

mod challenge;
mod config;
mod error;
mod generation_policy;
mod schema;

pub use challenge::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge, Submission};
pub use config::{ChallengeConfig, Difficulty};
pub use error::ContractError;
pub use generation_policy::{
    CHALLENGE_TTL_SECONDS, MAX_SECRET_LENGTH, MIN_SECRET_LENGTH, fragment_count_for_secret_length,
};
pub use schema::{private_material_schema, public_challenge_schema, submission_schema};

pub const GENERATOR_VERSION_V1: &str = "1.0";
