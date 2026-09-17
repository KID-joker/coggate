use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Duration};

use agentgate_benchmark::{
    baseline::direct::DirectBaseline,
    corpus::Corpus,
    manifest::{ProfileName, SuiteManifest},
    process::{ProcessRunner, ToolId},
    qualification::qualify_baselines,
    report::verify_report,
};

fn rejecting_direct() -> DirectBaseline {
    let programs = ["c", "cpp", "go", "java", "rust"]
        .into_iter()
        .map(|name| (ToolId::new(name).unwrap(), PathBuf::from("/usr/bin/false")))
        .collect::<BTreeMap<_, _>>();
    DirectBaseline::new(
        ProcessRunner::new(
            std::env::temp_dir(),
            Duration::from_secs(1),
            64 * 1024,
            programs,
        )
        .unwrap(),
    )
}

#[test]
fn quick_corpus_is_reproducible_and_all_four_baselines_qualify() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let first = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let second = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    assert_eq!(first.public_fingerprints(), second.public_fingerprints());

    let reports = qualify_baselines(
        &suite,
        ProfileName::Quick,
        &first,
        &rejecting_direct(),
        ["c", "cpp", "go", "java", "rust"]
            .into_iter()
            .map(|tool| (tool.to_owned(), "fixed-rejection".to_owned()))
            .collect(),
    )
    .unwrap();
    assert_eq!(reports.len(), 4);
    for report in reports {
        assert!(
            report.qualified(),
            "{} exceeded its threshold",
            report.subject_id()
        );
        let json = report.to_canonical_json().unwrap();
        assert!(verify_report(&json, &suite).is_ok());
    }
}

#[test]
#[ignore = "requires the pinned C, C++, Rust, Go, and Java toolchains"]
fn real_quick_direct_qualification() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentgate-bench"))
        .args([
            "run-baselines",
            "--profile",
            "quick",
            "--output",
            directory.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", output);
}
