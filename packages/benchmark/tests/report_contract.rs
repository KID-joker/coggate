use std::collections::BTreeMap;

use agentgate_benchmark::{
    baseline::{NoGuessReason, Outcome},
    manifest::{ProfileName, SuiteManifest},
    report::{QualificationReport, ReportBinding, ReportCase, verify_report, write_report_bundle},
};

fn cases(solved: usize) -> Vec<ReportCase> {
    (0..100)
        .map(|index| {
            let outcome = if index < solved {
                Outcome::Solved
            } else {
                Outcome::Unsolved
            };
            ReportCase::new(
                format!("{index:064x}"),
                outcome,
                (outcome == Outcome::Unsolved).then_some(NoGuessReason::NoCandidate),
                index as u64,
            )
            .unwrap()
        })
        .collect()
}

fn direct_report(solved: usize) -> QualificationReport {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let binding = ReportBinding::baseline(
        &suite,
        ProfileName::Quick,
        "direct",
        BTreeMap::from([("rustc".to_owned(), "1.85.0".to_owned())]),
    )
    .unwrap();
    QualificationReport::from_cases(binding, cases(solved)).unwrap()
}

#[test]
fn round_trips_and_verifies_the_exact_direct_threshold() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let report = direct_report(5);

    assert!(report.qualified());
    assert_eq!(report.solved(), 5);
    assert_eq!(report.total(), 100);
    assert_eq!(report.payload_digest().len(), 64);
    let json = report.to_canonical_json().unwrap();
    let verified = verify_report(&json, &suite).unwrap();
    assert_eq!(verified.payload_digest(), report.payload_digest());

    let failed = direct_report(6);
    assert!(!failed.qualified());
    assert_eq!(failed.failed_thresholds(), &["direct"]);
}

#[test]
fn rejects_unknown_fields_digest_tampering_and_summary_contradictions() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let json = direct_report(5).to_canonical_json().unwrap();

    let unknown = json.replacen('{', "{\"unknown\":true,", 1);
    assert!(verify_report(&unknown, &suite).is_err());

    let mut tampered: serde_json::Value = serde_json::from_str(&json).unwrap();
    tampered["cases"][0]["outcome"] = serde_json::json!("unsolved");
    assert!(verify_report(&serde_json::to_string(&tampered).unwrap(), &suite).is_err());

    let mut contradiction: serde_json::Value = serde_json::from_str(&json).unwrap();
    contradiction["summary"]["solved"] = serde_json::json!(4);
    assert!(verify_report(&serde_json::to_string(&contradiction).unwrap(), &suite).is_err());
}

#[test]
fn atomically_writes_verified_json_and_safe_markdown_without_overwrite() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let report = direct_report(5);
    let directory = tempfile::tempdir().unwrap();

    let paths = write_report_bundle(directory.path(), &report).unwrap();
    let json = std::fs::read_to_string(paths.json()).unwrap();
    let markdown = std::fs::read_to_string(paths.markdown()).unwrap();
    assert!(verify_report(&json, &suite).is_ok());
    assert!(markdown.contains("qualified: true"));
    for forbidden in ["question", "answer", "response", "environment"] {
        assert!(!json.contains(forbidden));
        assert!(!markdown.contains(forbidden));
    }
    assert!(write_report_bundle(directory.path(), &report).is_err());
    assert_eq!(std::fs::read_to_string(paths.json()).unwrap(), json);
}

#[test]
fn rejects_path_like_subjects_control_characters_and_unbounded_durations() {
    let suite = SuiteManifest::tracked_v1().unwrap();

    assert!(ReportBinding::llm(&suite, ProfileName::Quick, "vendor/model", "run-1").is_err());
    assert!(
        ReportBinding::baseline(
            &suite,
            ProfileName::Quick,
            "direct",
            BTreeMap::from([("rustc\nforged".to_owned(), "1.85.0".to_owned())]),
        )
        .is_err()
    );
    assert!(ReportCase::new(format!("{:064x}", 1), Outcome::Solved, None, 3_600_001,).is_err());
}
