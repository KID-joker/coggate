use agentgate_contracts::{PrivateChallengeMaterial, Submission};
use subtle::ConstantTimeEq;

use crate::{CoreError, MacContext, compute_answer_mac};

pub fn verify_answer(
    key: &[u8],
    stored: &PrivateChallengeMaterial,
    submission: &Submission,
) -> Result<(), CoreError> {
    if stored.challenge_id != submission.challenge_id || stored.nonce != submission.nonce {
        return Err(CoreError::InvalidChallengeMaterial);
    }

    let stored_mac: [u8; 32] = hex::decode(&stored.answer_mac)
        .map_err(|_| CoreError::InvalidChallengeMaterial)?
        .try_into()
        .map_err(|_| CoreError::InvalidChallengeMaterial)?;
    let context = MacContext {
        challenge_id: stored.challenge_id.clone(),
        generator_version: stored.generator_version.clone(),
        nonce: stored.nonce.clone(),
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
        mac_key_id: stored.mac_key_id.clone(),
        answer_encoding: stored.answer_encoding,
    };
    let candidate_mac = compute_answer_mac(key, &context, &submission.answer)?;

    if bool::from(candidate_mac.ct_eq(&stored_mac)) {
        Ok(())
    } else {
        Err(CoreError::AnswerMismatch)
    }
}
