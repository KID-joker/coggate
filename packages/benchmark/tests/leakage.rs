use std::{path::PathBuf, time::Duration};

use coggate_benchmark::{
    baseline::direct::DirectBaseline,
    cli::run_with_io,
    corpus::Corpus,
    llm::export_llm,
    manifest::{ProfileName, SuiteManifest},
    process::{ProcessError, ProcessRunner, ToolId},
    qualification::qualify_baselines,
    report::write_report_bundle,
};
use coggate_core::generation::generate_benchmark_case;
use serde_json::Value;

fn answers(suite: &SuiteManifest) -> Vec<String> {
    let profile = suite.profile(ProfileName::Quick).unwrap();
    [profile.calibration_namespace(), profile.scored_namespace()]
        .into_iter()
        .flat_map(|namespace| {
            (0..10).map(move |index| {
                generate_benchmark_case(suite.generator_version(), namespace.as_bytes(), index)
                    .unwrap()
                    .calibration_answer()
                    .to_string()
            })
        })
        .collect()
}

fn rejecting_direct() -> DirectBaseline {
    let programs = ["c", "cpp", "go", "java", "rust"]
        .into_iter()
        .map(|name| (ToolId::new(name).unwrap(), PathBuf::from("/usr/bin/false")))
        .collect();
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

fn assert_absent(haystack: &str, secrets: &[String]) {
    for secret in secrets {
        assert!(!haystack.contains(secret), "secret leaked into artifact");
    }
}

fn assert_report_keys(value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                assert!(
                    ![
                        "answer",
                        "question",
                        "prompt",
                        "response",
                        "environment",
                        "path"
                    ]
                    .contains(&key.as_str()),
                    "forbidden report key: {key}"
                );
                assert_report_keys(value);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_report_keys),
        _ => {}
    }
}

#[test]
fn secrets_never_enter_public_artifacts_debug_or_cli_diagnostics() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let secrets = answers(&suite);

    let manifest = serde_json::to_string(&suite).unwrap();
    assert_absent(&manifest, &secrets);
    let debug = format!("{corpus:?} {:?}", ProcessError::ToolUnavailable);
    assert_absent(&debug, &secrets);

    let mut prompts = Vec::new();
    export_llm(&mut prompts, &suite, ProfileName::Quick, &corpus).unwrap();
    let prompts = String::from_utf8(prompts).unwrap();
    assert_absent(&prompts, &secrets);
    for line in prompts.lines().skip(1) {
        let value: Value = serde_json::from_str(line).unwrap();
        let object = value.as_object().unwrap();
        assert!(object.contains_key("question"));
        assert!(object.contains_key("question_digest"));
        assert!(!object.contains_key("answer"));
        assert!(!object.contains_key("oracle"));
    }

    let reports = qualify_baselines(
        &suite,
        ProfileName::Quick,
        &corpus,
        &rejecting_direct(),
        ["c", "cpp", "go", "java", "rust"]
            .into_iter()
            .map(|tool| (tool.to_owned(), "fixed-rejection".to_owned()))
            .collect(),
    )
    .unwrap();
    for report in reports {
        let json = report.to_canonical_json().unwrap();
        assert_absent(&json, &secrets);
        assert_report_keys(&serde_json::from_str(&json).unwrap());
        assert_absent(&format!("{report:?}"), &secrets);

        let directory = tempfile::tempdir().unwrap();
        let paths = write_report_bundle(directory.path(), &report).unwrap();
        let markdown = std::fs::read_to_string(paths.markdown()).unwrap();
        assert_absent(&markdown, &secrets);
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let _ = run_with_io(
        ["verify-report", "--input", "definitely-missing"],
        &mut stdout,
        &mut stderr,
    );
    assert_absent(&String::from_utf8(stdout).unwrap(), &secrets);
    assert_absent(&String::from_utf8(stderr).unwrap(), &secrets);
}
