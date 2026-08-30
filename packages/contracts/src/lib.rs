#![forbid(unsafe_code)]

mod challenge;
mod config;
mod error;
mod schema;

pub use challenge::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge, Submission};
pub use config::{ChallengeConfig, Difficulty};
pub use error::ContractError;
pub use schema::{private_material_schema, public_challenge_schema, submission_schema};

pub const GENERATOR_VERSION_V1: &str = "1.0";
