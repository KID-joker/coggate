use std::collections::BTreeMap;

use coggate_benchmark::{
    baseline::{NoGuessReason, Outcome},
    corpus::Corpus,
    manifest::{ProfileName, SuiteManifest},
    report::ReportError,
    report::{QualificationReport, ReportBinding, ReportCase, verify_report, write_report_bundle},
};

fn tool_versions() -> BTreeMap<String, String> {
    ["c", "cpp", "go", "java", "rust"]
        .into_iter()
        .map(|tool| (tool.to_owned(), "test-version".to_owned()))
        .collect()
}

fn cases(profile: ProfileName, solved: usize) -> Vec<ReportCase> {
    let suite = SuiteManifest::tracked_v1().unwrap();
    Corpus::generate(&suite, profile)
        .unwrap()
        .scored()
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let outcome = if index < solved {
                Outcome::Solved
            } else {
                Outcome::Unsolved
            };
            ReportCase::new(
                case.id().to_owned(),
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
    let binding =
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", tool_versions()).unwrap();
    QualificationReport::from_cases(binding, cases(ProfileName::Quick, solved)).unwrap()
}

fn baseline_report(
    profile: ProfileName,
    subject: &str,
    tool_versions: BTreeMap<String, String>,
) -> QualificationReport {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let binding = ReportBinding::baseline(&suite, profile, subject, tool_versions).unwrap();
    QualificationReport::from_cases(binding, cases(profile, 0)).unwrap()
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

#[test]
fn rejects_arbitrary_and_reordered_case_ids() {
    let suite = SuiteManifest::tracked_v1().unwrap();

    let mut arbitrary = cases(ProfileName::Quick, 5);
    arbitrary[0] = ReportCase::new("0".repeat(64), Outcome::Solved, None, 0).unwrap();
    let binding =
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", tool_versions()).unwrap();
    let report = QualificationReport::from_cases(binding, arbitrary).unwrap();
    assert_eq!(
        verify_report(&report.to_canonical_json().unwrap(), &suite),
        Err(ReportError::InvalidCase)
    );

    let mut reordered = cases(ProfileName::Quick, 5);
    reordered.swap(0, 1);
    let binding =
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", tool_versions()).unwrap();
    let report = QualificationReport::from_cases(binding, reordered).unwrap();
    assert_eq!(
        verify_report(&report.to_canonical_json().unwrap(), &suite),
        Err(ReportError::InvalidCase)
    );
}

#[test]
fn rejects_a_same_index_release_case_id_in_a_quick_report() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let release_id = Corpus::generate(&suite, ProfileName::Release)
        .unwrap()
        .scored()[0]
        .id()
        .to_owned();
    let mut quick_cases = cases(ProfileName::Quick, 0);
    quick_cases[0] = ReportCase::new(
        release_id,
        Outcome::Unsolved,
        Some(NoGuessReason::NoCandidate),
        0,
    )
    .unwrap();
    let binding =
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", tool_versions()).unwrap();
    let report = QualificationReport::from_cases(binding, quick_cases).unwrap();
    assert_eq!(
        verify_report(&report.to_canonical_json().unwrap(), &suite),
        Err(ReportError::InvalidCase)
    );
}

#[test]
fn binds_tool_versions_exactly_to_the_direct_subject() {
    let suite = SuiteManifest::tracked_v1().unwrap();

    let mut missing = tool_versions();
    missing.remove("java");
    assert_eq!(
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", missing),
        Err(ReportError::InvalidBinding)
    );

    let mut wrong = tool_versions();
    wrong.remove("java");
    wrong.insert("python".to_owned(), "test-version".to_owned());
    assert_eq!(
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", wrong),
        Err(ReportError::InvalidBinding)
    );

    let mut extra = tool_versions();
    extra.insert("python".to_owned(), "test-version".to_owned());
    assert_eq!(
        ReportBinding::baseline(&suite, ProfileName::Quick, "direct", extra),
        Err(ReportError::InvalidBinding)
    );

    for subject in ["fingerprint", "regex", "simple_parser"] {
        assert_eq!(
            ReportBinding::baseline(
                &suite,
                ProfileName::Quick,
                subject,
                BTreeMap::from([("rust".to_owned(), "test-version".to_owned())]),
            ),
            Err(ReportError::InvalidBinding),
            "subject: {subject}"
        );
    }

    let report = baseline_report(ProfileName::Quick, "fingerprint", BTreeMap::new());
    let mut llm: serde_json::Value =
        serde_json::from_str(&report.to_canonical_json().unwrap()).unwrap();
    llm["binding"]["kind"] = serde_json::json!("llm");
    llm["binding"]["subject_id"] = serde_json::json!("model");
    llm["binding"]["subject_version"] = serde_json::json!("run-1");
    llm["binding"]["threshold"] = serde_json::json!({"comparison":"at_least","percent":80});
    llm["binding"]["tool_versions"] = serde_json::json!({"rust":"test-version"});
    assert_eq!(
        verify_report(&serde_json::to_string(&llm).unwrap(), &suite),
        Err(ReportError::InvalidBinding)
    );
}

#[test]
fn rejects_duplicate_summary_and_nested_binding_keys() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let json = direct_report(5).to_canonical_json().unwrap();

    let duplicate_solved = json.replacen("\"solved\":5", "\"solved\":5,\"solved\":5", 1);
    assert_eq!(
        verify_report(&duplicate_solved, &suite),
        Err(ReportError::InvalidJson)
    );

    let duplicate_tool_version = json.replacen(
        "\"tool_versions\":{\"c\":\"test-version\"",
        "\"tool_versions\":{\"c\":\"test-version\",\"c\":\"test-version\"",
        1,
    );
    assert_ne!(duplicate_tool_version, json);
    assert_eq!(
        verify_report(&duplicate_tool_version, &suite),
        Err(ReportError::InvalidJson)
    );
}
