use agentgate_contracts::AnswerEncoding;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{CoreError, canonicalize_answer};

const DOMAIN: &[u8] = b"agentgate-answer-v1";
const MAX_CHALLENGE_ID_BYTES: usize = 128;
const MAX_GENERATOR_VERSION_BYTES: usize = 32;
const MAX_NONCE_BYTES: usize = 256;
pub(crate) const MAX_MAC_KEY_ID_BYTES: usize = 128;

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

fn answer_encoding_label(encoding: AnswerEncoding) -> &'static [u8] {
    match encoding {
        AnswerEncoding::Base64Url => b"base64url",
    }
}

pub(crate) fn validate_context_fields(
    challenge_id: &str,
    generator_version: &str,
    nonce: &str,
    mac_key_id: &str,
) -> Result<(), CoreError> {
    let fields = [
        (challenge_id.as_bytes(), MAX_CHALLENGE_ID_BYTES),
        (generator_version.as_bytes(), MAX_GENERATOR_VERSION_BYTES),
        (nonce.as_bytes(), MAX_NONCE_BYTES),
        (mac_key_id.as_bytes(), MAX_MAC_KEY_ID_BYTES),
    ];

    fields
        .into_iter()
        .all(|(field, limit)| field.len() <= limit)
        .then_some(())
        .ok_or(CoreError::InvalidChallengeMaterial)
}

fn push_field(mac: &mut Hmac<Sha256>, field: &[u8]) -> Result<(), CoreError> {
    let field_len = u32::try_from(field.len()).map_err(|_| CoreError::InvalidChallengeMaterial)?;
    mac.update(&field_len.to_be_bytes());
    mac.update(field);
    Ok(())
}

pub fn compute_answer_mac(
    key: &[u8],
    context: &MacContext,
    answer: &str,
) -> Result<[u8; 32], CoreError> {
    if key.len() < 32 {
        return Err(CoreError::InvalidChallengeMaterial);
    }

    validate_context_fields(
        &context.challenge_id,
        &context.generator_version,
        &context.nonce,
        &context.mac_key_id,
    )?;
    let canonical_answer = canonicalize_answer(context.answer_encoding, answer)?;
    let answer_encoding = answer_encoding_label(context.answer_encoding);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| CoreError::InvalidChallengeMaterial)?;
    push_field(&mut mac, DOMAIN)?;
    push_field(&mut mac, context.challenge_id.as_bytes())?;
    push_field(&mut mac, context.generator_version.as_bytes())?;
    push_field(&mut mac, context.nonce.as_bytes())?;
    push_field(&mut mac, &context.issued_at.to_be_bytes())?;
    push_field(&mut mac, &context.expires_at.to_be_bytes())?;
    push_field(&mut mac, context.mac_key_id.as_bytes())?;
    push_field(&mut mac, answer_encoding)?;
    push_field(&mut mac, canonical_answer.as_bytes())?;
    Ok(mac.finalize().into_bytes().into())
}
