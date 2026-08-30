use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum AnswerEncoding {
    #[serde(rename = "base64url")]
    Base64Url,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicChallenge {
    pub challenge_id: String,
    pub generator_version: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub question: String,
    pub answer_encoding: AnswerEncoding,
}

#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateChallengeMaterial {
    pub challenge_id: String,
    pub generator_version: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub mac_key_id: String,
    pub answer_mac: String,
    pub answer_encoding: AnswerEncoding,
}

impl fmt::Debug for PrivateChallengeMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateChallengeMaterial")
            .field("challenge_id", &self.challenge_id)
            .field("generator_version", &self.generator_version)
            .field("nonce", &self.nonce)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("mac_key_id", &self.mac_key_id)
            .field("answer_mac", &"[REDACTED]")
            .field("answer_encoding", &self.answer_encoding)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub challenge_id: String,
    pub nonce: String,
    pub answer: String,
}

impl fmt::Debug for Submission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Submission")
            .field("challenge_id", &self.challenge_id)
            .field("nonce", &self.nonce)
            .field("answer", &"[REDACTED]")
            .finish()
    }
}
