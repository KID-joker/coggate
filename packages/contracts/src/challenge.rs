use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub challenge_id: String,
    pub nonce: String,
    pub answer: String,
}
