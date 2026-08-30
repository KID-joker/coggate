use agentgate_core::{CoreError, canonicalize_answer, contracts::AnswerEncoding};

#[test]
fn preserves_a_canonical_base64url_answer() {
    assert_eq!(
        canonicalize_answer(AnswerEncoding::Base64Url, "YUI5MmtM"),
        Ok("YUI5MmtM".to_owned())
    );
}

#[test]
fn rejects_non_canonical_base64url_answers() {
    for answer in ["YQ==", "ab+c"] {
        assert_eq!(
            canonicalize_answer(AnswerEncoding::Base64Url, answer),
            Err(CoreError::InvalidAnswerEncoding)
        );
    }
}

#[test]
fn rejects_answers_outside_the_byte_length_limit() {
    for answer in [String::new(), "a".repeat(257)] {
        assert_eq!(
            canonicalize_answer(AnswerEncoding::Base64Url, &answer),
            Err(CoreError::InvalidAnswerEncoding)
        );
    }
}
