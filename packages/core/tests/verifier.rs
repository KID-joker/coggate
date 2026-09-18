use coggate_core::{
    CoreError, MacContext, compute_answer_mac,
    contracts::{AnswerEncoding, PrivateChallengeMaterial, Submission},
    verify_answer,
};

const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const WRONG_KEY: &[u8; 32] = b"abcdef0123456789abcdef0123456789";
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
fn matches_the_independently_computed_answer_mac_vector() {
    // Independently computed with Python 3 stdlib `hmac`, `hashlib`, and `struct`:
    // prefix each field with `struct.pack(">I", len(field))`, encode times with
    // `struct.pack(">q", time)`, join the fields, then call `hmac.new(key,
    // transcript, hashlib.sha256).hexdigest()`.
    assert_eq!(
        hex::encode(compute_answer_mac(KEY, &context(), ANSWER).unwrap()),
        "bcba0cdecfa6ccb1376d8b1894511e8f8d10eb1ef3c1b1aa799490330180be3f"
    );
    let legacy_digest = [
        "8f2828d022652cd0c7c322cd6a6bff93",
        "605dc19e44abb35494e737d778630cf9",
    ]
    .concat();
    assert_ne!(
        hex::encode(compute_answer_mac(KEY, &context(), ANSWER).unwrap()),
        legacy_digest
    );
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

#[test]
fn rejects_a_challenge_id_changed_after_mac_creation() {
    let context = context();
    let mut stored = material(&context);
    stored.challenge_id = "changed".to_owned();
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_a_generator_version_changed_after_mac_creation() {
    let context = context();
    let mut stored = material(&context);
    stored.generator_version = "1.1".to_owned();
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_an_issued_at_changed_after_mac_creation() {
    let context = context();
    let mut stored = material(&context);
    stored.issued_at += 1;
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_an_expires_at_changed_after_mac_creation() {
    let context = context();
    let mut stored = material(&context);
    stored.expires_at += 1;
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_a_wrong_key() {
    let context = context();
    let stored = material(&context);
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(WRONG_KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_a_wrong_answer() {
    let context = context();
    let stored = material(&context);
    let mut submission = submission(&stored.challenge_id, &stored.nonce);
    submission.answer = "YUI5MmtN".to_owned();

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::AnswerMismatch)
    );
}

#[test]
fn rejects_a_short_mac_key() {
    assert_eq!(
        compute_answer_mac(b"short", &context(), ANSWER),
        Err(CoreError::InvalidChallengeMaterial)
    );
}

#[test]
fn rejects_oversized_mac_context_fields() {
    let mut cases = [
        ("challenge_id", context()),
        ("generator_version", context()),
        ("nonce", context()),
        ("mac_key_id", context()),
    ];
    cases[0].1.challenge_id = "a".repeat(129);
    cases[1].1.generator_version = "a".repeat(33);
    cases[2].1.nonce = "a".repeat(257);
    cases[3].1.mac_key_id = "a".repeat(129);

    for (field, context) in cases {
        assert_eq!(
            compute_answer_mac(KEY, &context, ANSWER),
            Err(CoreError::InvalidChallengeMaterial),
            "oversized {field} should be rejected"
        );
    }
}

#[test]
fn rejects_malformed_answer_mac_hex() {
    let context = context();
    let mut stored = material(&context);
    stored.answer_mac = "g".repeat(64);
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::InvalidChallengeMaterial)
    );
}

#[test]
fn rejects_uppercase_answer_mac_hex() {
    let context = context();
    let mut stored = material(&context);
    stored.answer_mac = stored.answer_mac.to_ascii_uppercase();
    let submission = submission(&stored.challenge_id, &stored.nonce);

    assert_eq!(
        verify_answer(KEY, &stored, &submission),
        Err(CoreError::InvalidChallengeMaterial)
    );
}

#[test]
fn rejects_answer_macs_with_the_wrong_length() {
    let context = context();

    for answer_mac in ["0".repeat(62), "0".repeat(66)] {
        let mut stored = material(&context);
        stored.answer_mac = answer_mac;
        let submission = submission(&stored.challenge_id, &stored.nonce);

        assert_eq!(
            verify_answer(KEY, &stored, &submission),
            Err(CoreError::InvalidChallengeMaterial)
        );
    }
}
