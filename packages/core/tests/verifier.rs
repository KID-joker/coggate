use agentgate_core::{
    CoreError, MacContext, compute_answer_mac,
    contracts::{AnswerEncoding, PrivateChallengeMaterial, Submission},
    verify_answer,
};

const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const ANSWER: &str = "YUI5MmtM";

fn context() -> MacContext {
    MacContext {
        challenge_id: "019abc".to_owned(),
        generator_version: "1.0".to_owned(),
        nonce: "bm9uY2U".to_owned(),
        issued_at: 1_788_062_400,
        expires_at: 1_788_062_408,
        mac_key_id: "2026-08".to_owned(),
        answer_encoding: AnswerEncoding::Base64Url,
    }
}

fn material(context: &MacContext) -> PrivateChallengeMaterial {
    PrivateChallengeMaterial {
        challenge_id: context.challenge_id.clone(),
        generator_version: context.generator_version.clone(),
        nonce: context.nonce.clone(),
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        mac_key_id: context.mac_key_id.clone(),
        answer_mac: hex::encode(compute_answer_mac(KEY, context, ANSWER).unwrap()),
        answer_encoding: context.answer_encoding,
    }
}

fn submission(challenge_id: &str, nonce: &str) -> Submission {
    Submission {
        challenge_id: challenge_id.to_owned(),
        nonce: nonce.to_owned(),
        answer: ANSWER.to_owned(),
    }
}

#[test]
fn verifies_a_correct_submission() {
    let context = context();
    let stored = material(&context);
    let submission = submission(&context.challenge_id, &context.nonce);

    assert_eq!(verify_answer(KEY, &stored, &submission), Ok(()));
}

#[test]
fn rejects_a_nonce_changed_after_mac_creation() {
    let context = context();
    let mut stored = material(&context);
    stored.nonce = "Y2hhbmdlZA".to_owned();
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_a_mac_key_id_changed_after_mac_creation() {
    let context = context();
    let mut stored = material(&context);
    stored.mac_key_id = "2026-09".to_owned();
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_a_submission_for_another_challenge_before_comparison() {
    let context = context();
    let stored = material(&context);
    let submission = submission("other", &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::InvalidChallengeMaterial)
    );
}
