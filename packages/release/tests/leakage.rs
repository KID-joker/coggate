use std::{fs, path::Path};

use agentgate_release::{
    EvidenceSet, Receipt, assemble_bundle,
    cli::{EXIT_INPUT_OR_INFRASTRUCTURE, EXIT_SUCCESS, run_with_io},
    create_phase6a_receipt, verify_bundle, verify_phase6a_report,
};
use serde_json::Value;

#[allow(dead_code)]
mod support;

const SENTINELS: [&str; 7] = [
    "SENTINEL_question_9f7c",
    "SENTINEL_answer_b4d1",
    "SENTINEL_submitted_answer_7e2a",
    "SENTINEL_prompt_c83e",
    "SENTINEL_raw_response_a6b5",
    "SENTINEL_environment_1d09",
    r"C:\SENTINEL_windows_source_path_8cd2",
];

#[test]
fn payload_sentinels_never_reach_release_metadata_control_planes_or_public_debug_output() {
    let payload = SENTINELS.join("\n");
    let evidence = support::evidence_fixture(true, Some(payload.as_bytes()));
    let loaded = EvidenceSet::load(evidence.path(), support::COMMIT).unwrap();
    let decision = loaded.authorize().unwrap();
    let output = tempfile::tempdir().unwrap();
    let bundle = assemble_bundle(evidence.path(), output.path(), support::COMMIT).unwrap();
    let verified = verify_bundle(&bundle).unwrap();

    let raw_payload =
        fs::read(bundle.join("phase5d/x86_64-unknown-linux-gnu/artifact/smoke/abi_probe.c"))
            .unwrap();
    for sentinel in SENTINELS {
        assert!(
            String::from_utf8_lossy(&raw_payload).contains(sentinel),
            "fixture payload must contain {sentinel}"
        );
    }

    let mut public_text = vec![
        fs::read_to_string(bundle.join("manifest.json")).unwrap(),
        fs::read_to_string(bundle.join("SHA256SUMS")).unwrap(),
        format!("{loaded:?}\n{decision:?}\n{verified:?}"),
    ];
    for entry in fs::read_dir(bundle.join("receipts")).unwrap() {
        public_text.push(fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    let source_sentinels = append_portable_source_receipt(&mut public_text);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(
            ["verify", "--bundle", bundle.to_str().unwrap()],
            &mut stdout,
            &mut stderr,
        ),
        EXIT_SUCCESS
    );
    public_text.push(String::from_utf8(stdout).unwrap());
    public_text.push(String::from_utf8(stderr).unwrap());

    append_receipt_failure_output(&mut public_text, &payload);

    let cli_output = tempfile::tempdir().unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(
            [
                "assemble",
                "--commit",
                support::COMMIT,
                "--evidence",
                evidence.path().to_str().unwrap(),
                "--output",
                cli_output.path().to_str().unwrap(),
            ],
            &mut stdout,
            &mut stderr,
        ),
        EXIT_SUCCESS
    );
    public_text.push(String::from_utf8(stdout).unwrap());
    public_text.push(String::from_utf8(stderr).unwrap());

    let blocked = support::evidence_fixture(false, Some(payload.as_bytes()));
    let blocked_output = tempfile::tempdir().unwrap();
    let error =
        assemble_bundle(blocked.path(), blocked_output.path(), support::COMMIT).unwrap_err();
    public_text.push(format!("{error:?}"));
    public_text.push(error.to_string());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(
            [
                "assemble",
                "--commit",
                support::COMMIT,
                "--evidence",
                blocked.path().to_str().unwrap(),
                "--output",
                blocked_output.path().to_str().unwrap(),
            ],
            &mut stdout,
            &mut stderr,
        ),
        agentgate_release::cli::EXIT_BLOCKED
    );
    public_text.push(String::from_utf8(stdout).unwrap());
    public_text.push(String::from_utf8(stderr).unwrap());
    let invalid =
        EvidenceSet::load(Path::new("/SENTINEL_invalid_evidence"), support::COMMIT).unwrap_err();
    public_text.push(format!("{invalid:?}"));
    public_text.push(invalid.to_string());
    public_text.push(format!(
        "{:?}",
        verify_phase6a_report(payload.as_bytes()).unwrap_err()
    ));
    public_text.push(
        verify_phase6a_report(payload.as_bytes())
            .unwrap_err()
            .to_string(),
    );
    public_text.push(format!(
        "{:?}",
        Receipt::parse_and_verify(payload.as_bytes()).unwrap_err()
    ));
    public_text.push(
        Receipt::parse_and_verify(payload.as_bytes())
            .unwrap_err()
            .to_string(),
    );

    let invalid_evidence = support::evidence_fixture(true, Some(payload.as_bytes()));
    fs::write(
        invalid_evidence.path().join("unexpected"),
        payload.as_bytes(),
    )
    .unwrap();
    let invalid_output = tempfile::tempdir().unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(
            [
                "assemble",
                "--commit",
                support::COMMIT,
                "--evidence",
                invalid_evidence.path().to_str().unwrap(),
                "--output",
                invalid_output.path().to_str().unwrap(),
            ],
            &mut stdout,
            &mut stderr,
        ),
        EXIT_INPUT_OR_INFRASTRUCTURE
    );
    public_text.push(String::from_utf8(stdout).unwrap());
    public_text.push(String::from_utf8(stderr).unwrap());
    for value in public_text {
        assert_no_sentinels(&value);
        assert_no_values(&value, &source_sentinels);
    }
    assert_json_keys_are_public(&bundle);
}

fn append_portable_source_receipt(public_text: &mut Vec<String>) -> Vec<String> {
    let source = tempfile::tempdir().unwrap();
    let source_dir = source
        .path()
        .join("SENTINEL_question_9f7c")
        .join("SENTINEL_answer_b4d1")
        .join("SENTINEL_submitted_answer_7e2a")
        .join("SENTINEL_prompt_c83e")
        .join("SENTINEL_raw_response_a6b5")
        .join("SENTINEL_environment_1d09")
        .join("SENTINEL_windows_source_path_8cd2");
    fs::create_dir_all(&source_dir).unwrap();
    let report = source_dir.join("direct-release.json");
    let summary = source_dir.join("direct-release.md");
    let source_sentinels = vec![
        report.display().to_string(),
        summary.display().to_string(),
        "SENTINEL_windows_source_path_8cd2".to_owned(),
    ];
    fs::write(&report, support::signed_report("direct", 50)).unwrap();
    fs::write(&summary, b"# Release\nqualified: safe\n").unwrap();
    let receipt = create_phase6a_receipt(support::COMMIT, &report, &summary).unwrap();
    let receipt = String::from_utf8(receipt.to_canonical_json().unwrap()).unwrap();
    assert_no_values(&receipt, &source_sentinels);
    public_text.push(receipt);
    source_sentinels
}

fn append_receipt_failure_output(public_text: &mut Vec<String>, payload: &str) {
    let source = tempfile::tempdir().unwrap();
    let report = source.path().join("direct-release.json");
    let summary = source.path().join("direct-release.md");
    let output = source.path().join("receipt.json");
    fs::write(&report, support::signed_report("direct", 50)).unwrap();
    fs::write(&summary, format!("prompt: {payload}\n")).unwrap();
    let arguments = vec![
        "receipt".to_owned(),
        "phase6a".to_owned(),
        "--commit".to_owned(),
        support::COMMIT.to_owned(),
        "--report".to_owned(),
        report.display().to_string(),
        "--summary".to_owned(),
        summary.display().to_string(),
        "--output".to_owned(),
        output.display().to_string(),
    ];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(arguments, &mut stdout, &mut stderr),
        EXIT_INPUT_OR_INFRASTRUCTURE
    );
    public_text.push(String::from_utf8(stdout).unwrap());
    public_text.push(String::from_utf8(stderr).unwrap());
}

#[test]
fn unsafe_public_summaries_are_rejected_without_echoing_sensitive_content() {
    let source = tempfile::tempdir().unwrap();
    let report = source.path().join("direct-release.json");
    let summary = source.path().join("direct-release.md");
    fs::write(&report, support::signed_report("direct", 50)).unwrap();
    for forbidden in [
        "question",
        "answer",
        "prompt",
        "response",
        "environment",
        "source_path",
    ] {
        let content = format!("{forbidden}: SENTINEL_{forbidden}_summary\n");
        fs::write(&summary, &content).unwrap();
        let error = create_phase6a_receipt(support::COMMIT, &report, &summary).unwrap_err();
        assert!(!error.to_string().contains(&content));
        assert!(!format!("{error:?}").contains(&content));
    }
}

fn assert_no_sentinels(value: &str) {
    for sentinel in SENTINELS {
        assert!(
            !value.contains(sentinel),
            "metadata/control plane leaked {sentinel}"
        );
    }
}

fn assert_no_values(value: &str, forbidden: &[String]) {
    for sentinel in forbidden {
        assert!(
            !value.contains(sentinel),
            "metadata/control plane leaked {sentinel}"
        );
    }
}

fn assert_json_keys_are_public(root: &Path) {
    for path in json_paths(root) {
        let json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        reject_sensitive_keys(&json, &path);
    }
}

fn reject_sensitive_keys(value: &Value, path: &Path) {
    const FORBIDDEN: [&str; 6] = [
        "answer",
        "question",
        "prompt",
        "response",
        "environment",
        "source_path",
    ];
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                assert!(
                    !FORBIDDEN
                        .iter()
                        .any(|forbidden| key.eq_ignore_ascii_case(forbidden)),
                    "{} contains forbidden key {key}",
                    path.display(),
                );
                reject_sensitive_keys(child, path);
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_sensitive_keys(child, path);
            }
        }
        _ => {}
    }
}

fn json_paths(root: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            paths.extend(json_paths(&path));
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    paths
}
