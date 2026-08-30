use agentgate_contracts::AnswerEncoding;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{CoreError, canonicalize_answer};

const DOMAIN: &[u8] = b"agentgate-answer-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacContext {
    pub challenge_id: String,
    pub generator_version: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub mac_key_id: String,
    pub answer_encoding: AnswerEncoding,
}

fn push_field(encoded: &mut Vec<u8>, field: &[u8]) {
    encoded.extend_from_slice(&(field.len() as u32).to_be_bytes());
    encoded.extend_from_slice(field);
}

pub fn compute_answer_mac(
    key: &[u8],
    context: &MacContext,
    answer: &str,
) -> Result<[u8; 32], CoreError> {
    if key.len() < 32 {
        return Err(CoreError::InvalidChallengeMaterial);
    }

    let canonical_answer = canonicalize_answer(context.answer_encoding, answer)?;
    let mut encoded = Vec::new();
    push_field(&mut encoded, DOMAIN);
    push_field(&mut encoded, context.challenge_id.as_bytes());
    push_field(&mut encoded, context.generator_version.as_bytes());
    push_field(&mut encoded, context.nonce.as_bytes());
    push_field(&mut encoded, &context.issued_at.to_be_bytes());
    push_field(&mut encoded, &context.expires_at.to_be_bytes());
    push_field(&mut encoded, context.mac_key_id.as_bytes());
    push_field(&mut encoded, b"base64url");
    push_field(&mut encoded, canonical_answer.as_bytes());

    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| CoreError::InvalidChallengeMaterial)?;
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}
