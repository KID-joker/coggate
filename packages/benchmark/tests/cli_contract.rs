use std::{io, process::Command};

use coggate_benchmark::{
    baseline::{NoGuessReason, Outcome},
    cli::{EXIT_INTERNAL, run_with_io},
    corpus::Corpus,
    manifest::{ProfileName, SuiteManifest},
    report::{QualificationReport, ReportBinding, ReportCase, write_report_bundle},
};

fn command(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coggate-bench"))
        .args(arguments)
        .output()
        .unwrap()
}

fn direct_report(solved: usize) -> QualificationReport {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let binding = ReportBinding::baseline(
        &suite,
        ProfileName::Quick,
        "direct",
        ["c", "cpp", "go", "java", "rust"]
            .into_iter()
            .map(|tool| (tool.to_owned(), "test-version".to_owned()))
            .collect(),
    )
    .unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let cases = corpus
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
                0,
            )
            .unwrap()
        })
        .collect();
    QualificationReport::from_cases(binding, cases).unwrap()
}

#[test]
fn help_lists_exactly_the_four_public_commands() {
    let output = command(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    for name in ["run-baselines", "export-llm", "score-llm", "verify-report"] {
        assert_eq!(stdout.matches(name).count(), 1);
    }
    assert!(output.stderr.is_empty());
}

#[test]
fn rejects_unknown_commands_flags_and_missing_arguments() {
    for arguments in [
        vec!["unknown"],
        vec!["export-llm", "--profile", "quick", "--unknown", "x"],
        vec!["export-llm", "--profile", "quick"],
        vec!["run-baselines", "--profile", "other", "--output", "out"],
    ] {
        let output = command(&arguments);
        assert_eq!(output.status.code(), Some(3), "arguments: {arguments:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "phase6a: input_or_infrastructure\n"
        );
    }
}

#[test]
fn exports_llm_corpus_and_refuses_to_overwrite_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("prompts.jsonl");
    let path = path.to_str().unwrap();
    let arguments = ["export-llm", "--profile", "quick", "--output", path];

    let first = command(&arguments);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(first.stdout).unwrap(),
        "phase6a: export=OK profile=quick\n"
    );
    assert!(first.stderr.is_empty());
    let original = std::fs::read(path).unwrap();

    let second = command(&arguments);
    assert_eq!(second.status.code(), Some(3));
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn verifies_reports_and_uses_qualification_exit_code() {
    for (solved, expected_code, qualified) in [(5, 0, true), (6, 2, false)] {
        let directory = tempfile::tempdir().unwrap();
        let paths = write_report_bundle(directory.path(), &direct_report(solved)).unwrap();
        let output = command(&["verify-report", "--input", paths.json().to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(expected_code));
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("phase6a: report=VALID qualified={qualified}\n")
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn malformed_llm_input_uses_input_or_infrastructure_exit_code() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("results.jsonl");
    let output = directory.path().join("reports");
    std::fs::write(&input, b"not-json\n").unwrap();
    std::fs::create_dir(&output).unwrap();

    let result = command(&[
        "score-llm",
        "--profile",
        "quick",
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stdout.is_empty());
}

#[test]
fn output_failure_uses_internal_exit_code() {
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut broken = Broken;
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(["--help"], &mut broken, &mut stderr),
        EXIT_INTERNAL
    );
}
