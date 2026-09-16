use std::io::Cursor;

use agentgate_benchmark::{
    corpus::Corpus,
    llm::{export_llm, export_llm_file, score_llm_results},
    manifest::{ProfileName, SuiteManifest},
};
use agentgate_core::generation::generate_benchmark_case;
use serde_json::{Value, json};

fn fixture() -> (SuiteManifest, Corpus) {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    (suite, corpus)
}

fn valid_lines(suite: &SuiteManifest, corpus: &Corpus, solved: usize) -> Vec<Value> {
    let profile = suite.profile(ProfileName::Quick).unwrap();
    let mut lines = vec![json!({
        "type": "run_header",
        "schema_version": 1,
        "suite_manifest_digest": suite.digest(),
        "generator_version": suite.generator_version(),
        "profile": "quick",
        "model_id": "test-model",
        "run_id": "run-1"
    })];
    for (index, case) in corpus.scored().iter().enumerate() {
        let mut record = json!({
            "type": "result",
            "case_id": case.id(),
            "question_digest": case.question_digest(),
            "status": "refused",
            "latency_ms": 10
        });
        if index < solved {
            let answer = generate_benchmark_case(
                suite.generator_version(),
                profile.scored_namespace().as_bytes(),
                index as u64,
            )
            .unwrap()
            .calibration_answer();
            record["status"] = json!("answered");
            record["answer"] = json!(answer.as_str());
        }
        lines.push(record);
    }
    lines
}

fn encode(lines: &[Value]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for line in lines {
        serde_json::to_writer(&mut encoded, line).unwrap();
        encoded.push(b'\n');
    }
    encoded
}

#[test]
fn exports_only_public_scored_cases_in_deterministic_order() {
    let (suite, corpus) = fixture();
    let mut first = Vec::new();
    export_llm(&mut first, &suite, ProfileName::Quick, &corpus).unwrap();
    let mut second = Vec::new();
    export_llm(&mut second, &suite, ProfileName::Quick, &corpus).unwrap();
    assert_eq!(first, second);

    let text = String::from_utf8(first).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 101);
    assert_eq!(records[0]["type"], "corpus_header");
    for (record, case) in records[1..].iter().zip(corpus.scored()) {
        assert_eq!(record["case_id"], case.id());
        assert_eq!(record["question"], case.question());
        assert_eq!(record["question_digest"], case.question_digest());
        assert!(record.get("answer").is_none());
        assert!(record.get("oracle").is_none());
    }
}

#[test]
fn atomically_exports_without_overwriting_an_existing_file() {
    let (suite, corpus) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("prompts.jsonl");

    export_llm_file(&output, &suite, ProfileName::Quick, &corpus).unwrap();
    let original = std::fs::read(&output).unwrap();
    assert!(export_llm_file(&output, &suite, ProfileName::Quick, &corpus).is_err());
    assert_eq!(std::fs::read(output).unwrap(), original);
}

#[test]
fn scores_complete_runs_at_and_around_the_threshold() {
    let (suite, corpus) = fixture();
    for (solved, qualified) in [(79, false), (80, true), (100, true)] {
        let bytes = encode(&valid_lines(&suite, &corpus, solved));
        let report =
            score_llm_results(Cursor::new(bytes), &suite, ProfileName::Quick, &corpus).unwrap();
        assert_eq!(report.solved(), solved);
        assert_eq!(report.qualified(), qualified);
    }
}

#[test]
fn rejects_malformed_or_incomplete_result_sets_as_a_unit() {
    let (suite, corpus) = fixture();
    let good = valid_lines(&suite, &corpus, 80);
    let rejects = |lines: Vec<Value>| {
        score_llm_results(
            Cursor::new(encode(&lines)),
            &suite,
            ProfileName::Quick,
            &corpus,
        )
        .is_err()
    };

    let mut changed = good.clone();
    changed[0]["unknown"] = json!(true);
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[1]["unknown"] = json!(true);
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed.push(changed[1].clone());
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed.pop();
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[1]["case_id"] = json!(format!("{:064x}", 9_999));
    assert!(rejects(changed));

    for (field, value) in [
        ("suite_manifest_digest", json!("0".repeat(64))),
        ("profile", json!("release")),
        ("generator_version", json!("0.0")),
    ] {
        let mut changed = good.clone();
        changed[0][field] = value;
        assert!(rejects(changed));
    }
    let mut changed = good.clone();
    changed[1]["question_digest"] = json!("0".repeat(64));
    assert!(rejects(changed));
}

#[test]
fn rejects_contradictory_and_oversized_records() {
    let (suite, corpus) = fixture();
    let good = valid_lines(&suite, &corpus, 80);
    let rejects = |lines: Vec<Value>| {
        score_llm_results(
            Cursor::new(encode(&lines)),
            &suite,
            ProfileName::Quick,
            &corpus,
        )
        .is_err()
    };

    let mut changed = good.clone();
    changed[81]["answer"] = json!("AA");
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[1].as_object_mut().unwrap().remove("answer");
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[0]["model_id"] = json!("m".repeat(129));
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[0]["run_id"] = json!("r".repeat(129));
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[1]["answer"] = json!("A".repeat(257));
    assert!(rejects(changed));
    let mut changed = good.clone();
    changed[1]["latency_ms"] = json!(3_600_001_u64);
    assert!(rejects(changed));
}

#[test]
fn rejects_invalid_utf8_overlong_lines_and_trailing_garbage() {
    let (suite, corpus) = fixture();
    let good = encode(&valid_lines(&suite, &corpus, 80));
    let rejects = |bytes: Vec<u8>| {
        score_llm_results(Cursor::new(bytes), &suite, ProfileName::Quick, &corpus).is_err()
    };

    let mut invalid_utf8 = good.clone();
    invalid_utf8[0] = 0xff;
    assert!(rejects(invalid_utf8));
    let mut overlong = good.clone();
    overlong.splice(0..0, vec![b' '; suite.limits().max_result_line_bytes() + 1]);
    assert!(rejects(overlong));
    let mut trailing = good;
    trailing.extend_from_slice(b"garbage\n");
    assert!(rejects(trailing));
}
