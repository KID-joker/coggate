use coggate_contracts::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge, Submission};
use serde_json::{Value, json};

#[test]
fn public_challenge_serializes_the_stable_protocol_fields() {
    let challenge = PublicChallenge {
        challenge_id: "019abc".to_owned(),
        generator_version: "1.0".to_owned(),
        nonce: "bm9uY2U".to_owned(),
        issued_at: 1_788_062_400,
        expires_at: 1_788_062_408,
        question: "What is 2 + 2?".to_owned(),
        answer_encoding: AnswerEncoding::Base64Url,
    };

    assert_eq!(
        serde_json::to_value(challenge).unwrap(),
        json!({
            "challenge_id": "019abc",
            "generator_version": "1.0",
            "nonce": "bm9uY2U",
            "issued_at": 1_788_062_400,
            "expires_at": 1_788_062_408,
            "question": "What is 2 + 2?",
            "answer_encoding": "base64url",
        })
    );
}

#[test]
fn submission_rejects_unknown_json_fields() {
    let submission = json!({
        "challenge_id": "019abc",
        "nonce": "bm9uY2U",
        "answer": "NA",
        "unexpected": true,
    });

    assert!(serde_json::from_value::<Submission>(submission).is_err());
}

#[test]
fn challenges_reject_unknown_json_fields() {
    let public_challenge = json!({
        "challenge_id": "019abc",
        "generator_version": "1.0",
        "nonce": "bm9uY2U",
        "issued_at": 1_788_062_400,
        "expires_at": 1_788_062_408,
        "question": "What is 2 + 2?",
        "answer_encoding": "base64url",
        "unexpected": true,
    });
    let private_material = json!({
        "challenge_id": "019abc",
        "generator_version": "1.0",
        "nonce": "bm9uY2U",
        "issued_at": 1_788_062_400,
        "expires_at": 1_788_062_408,
        "mac_key_id": "key-1",
        "answer_mac": "mac",
        "answer_encoding": "base64url",
        "unexpected": true,
    });

    assert!(serde_json::from_value::<PublicChallenge>(public_challenge).is_err());
    assert!(serde_json::from_value::<PrivateChallengeMaterial>(private_material).is_err());
}

#[test]
fn private_challenge_material_never_serializes_an_answer() {
    let material = PrivateChallengeMaterial {
        challenge_id: "019abc".to_owned(),
        generator_version: "1.0".to_owned(),
        nonce: "bm9uY2U".to_owned(),
        issued_at: 1_788_062_400,
        expires_at: 1_788_062_408,
        mac_key_id: "key-1".to_owned(),
        answer_mac: "mac".to_owned(),
        answer_encoding: AnswerEncoding::Base64Url,
    };

    let serialized: Value = serde_json::to_value(material).unwrap();

    assert!(serialized.get("answer").is_none());
    assert_eq!(
        serialized,
        json!({
            "challenge_id": "019abc",
            "generator_version": "1.0",
            "nonce": "bm9uY2U",
            "issued_at": 1_788_062_400,
            "expires_at": 1_788_062_408,
            "mac_key_id": "key-1",
            "answer_mac": "mac",
            "answer_encoding": "base64url",
        })
    );
}

#[test]
fn sensitive_challenge_debug_output_is_redacted() {
    let answer_mac_sentinel = "PRIVATE_MAC_SENTINEL_9f7b";
    let answer_sentinel = "SUBMISSION_ANSWER_SENTINEL_c31d";
    let material = PrivateChallengeMaterial {
        challenge_id: "019abc".to_owned(),
        generator_version: "1.0".to_owned(),
        nonce: "bm9uY2U".to_owned(),
        issued_at: 1_788_062_400,
        expires_at: 1_788_062_408,
        mac_key_id: "key-1".to_owned(),
        answer_mac: answer_mac_sentinel.to_owned(),
        answer_encoding: AnswerEncoding::Base64Url,
    };
    let submission = Submission {
        challenge_id: "019abc".to_owned(),
        nonce: "bm9uY2U".to_owned(),
        answer: answer_sentinel.to_owned(),
    };

    let material_debug = format!("{material:?}");
    let submission_debug = format!("{submission:?}");

    assert!(!material_debug.contains(answer_mac_sentinel));
    assert!(!submission_debug.contains(answer_sentinel));
    assert!(material_debug.contains("[REDACTED]"));
    assert!(submission_debug.contains("[REDACTED]"));
}
