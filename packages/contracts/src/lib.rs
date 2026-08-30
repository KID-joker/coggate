#![forbid(unsafe_code)]

mod challenge;

pub use challenge::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge, Submission};

pub const GENERATOR_VERSION_V1: &str = "1.0";
