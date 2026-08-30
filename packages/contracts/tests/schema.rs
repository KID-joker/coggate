use agentgate_contracts::{
    PublicChallenge, Submission, private_material_schema, public_challenge_schema,
    submission_schema,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn workspace_path(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read_json(relative: impl AsRef<Path>) -> Value {
    let path = workspace_path(relative);
    let contents = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&contents).unwrap()
}

fn schema_properties(schema: impl serde::Serialize) -> serde_json::Map<String, Value> {
    serde_json::to_value(schema)
        .unwrap()
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap()
}

#[test]
fn public_challenge_schema_contains_challenge_id() {
    let properties = schema_properties(public_challenge_schema());

    assert!(properties.contains_key("challenge_id"));
}

#[test]
fn private_material_schema_contains_only_the_answer_mac() {
    let properties = schema_properties(private_material_schema());

    assert!(properties.contains_key("answer_mac"));
    assert!(!properties.contains_key("answer"));
}

#[test]
fn submission_schema_contains_answer() {
    let properties = schema_properties(submission_schema());

    assert!(properties.contains_key("answer"));
}

#[test]
fn public_challenge_fixture_deserializes() {
    let fixture = read_json("fixtures/contracts/challenge.json");
    let challenge: PublicChallenge = serde_json::from_value(fixture).unwrap();

    assert_eq!(challenge.challenge_id, "019abc");
    assert_eq!(challenge.generator_version, "1.0");
    assert_eq!(challenge.nonce, "bm9uY2U");
    assert_eq!(challenge.issued_at, 1_788_062_400);
    assert_eq!(challenge.expires_at, 1_788_062_408);
    assert_eq!(challenge.question, "fragment beta consumes fragment alpha");
}

#[test]
fn submission_fixture_deserializes() {
    let fixture = read_json("fixtures/contracts/submission.json");
    let submission: Submission = serde_json::from_value(fixture).unwrap();

    assert_eq!(submission.challenge_id, "019abc");
    assert_eq!(submission.nonce, "bm9uY2U");
    assert_eq!(submission.answer, "YUI5MmtM");
}

#[test]
fn checked_in_schemas_match_the_contract_types() {
    let cases = [
        (
            "schemas/public-challenge.schema.json",
            serde_json::to_value(public_challenge_schema()).unwrap(),
        ),
        (
            "schemas/private-challenge-material.schema.json",
            serde_json::to_value(private_material_schema()).unwrap(),
        ),
        (
            "schemas/submission.schema.json",
            serde_json::to_value(submission_schema()).unwrap(),
        ),
    ];

    for (path, current) in cases {
        assert_eq!(read_json(path), current, "schema drift in {path}");
    }
}
