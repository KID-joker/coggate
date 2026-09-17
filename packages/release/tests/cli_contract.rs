use std::{io, process::Command};

use agentgate_release::cli::{
    EXIT_AUTHORIZATION_BLOCKED, EXIT_INPUT_OR_INFRASTRUCTURE, EXIT_INTERNAL, EXIT_SUCCESS,
    run_with_io,
};

include!("evidence_contract.rs");

const HELP: &str = "AgentGate Phase 6B release gate\n\ncommands:\n  receipt phase5d --commit SHA --target TRIPLE --artifact DIR --output FILE\n  receipt sanitizer --commit SHA --rust-version VERSION --clang-version VERSION --output FILE\n  receipt phase6a --commit SHA --report JSON --summary MARKDOWN --output FILE\n  assemble --commit SHA --evidence DIR --output DIR\n  verify --bundle DIR\n";

fn command(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentgate-release"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn help_has_exactly_the_five_public_commands() {
    let output = command(&["--help"]);
    assert_eq!(output.status.code(), Some(EXIT_SUCCESS.into()));
    assert_eq!(output.stdout, HELP.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn parser_rejects_extra_help_and_every_invalid_flag_form() {
    for arguments in [
        vec!["--help", "assemble"],
        vec!["help"],
        vec!["receipt"],
        vec!["receipt", "other"],
        vec![
            "receipt",
            "sanitizer",
            "--commit",
            COMMIT,
            "--rust-version",
            "1",
            "--output",
            "x",
        ],
        vec![
            "receipt",
            "phase6a",
            "--commit",
            COMMIT,
            "--report",
            "x",
            "--summary",
            "y",
            "--unexpected",
            "z",
        ],
        vec![
            "receipt",
            "phase5d",
            "--commit",
            COMMIT,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--artifact",
            "x",
            "--output",
        ],
        vec![
            "receipt",
            "phase5d",
            "--commit",
            COMMIT,
            "--commit",
            COMMIT,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--artifact",
            "x",
            "--output",
            "y",
        ],
        vec![
            "receipt",
            "phase5d",
            "--commit",
            COMMIT,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--artifact=x",
            "--output",
            "y",
        ],
        vec![
            "receipt",
            "phase5d",
            "--commit",
            COMMIT,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--artifact",
            "",
            "--output",
            "y",
        ],
        vec![
            "receipt",
            "phase5d",
            "--commit",
            COMMIT,
            "--target",
            "other",
            "--artifact",
            "x",
            "--output",
            "y",
        ],
        vec![
            "receipt",
            "phase5d",
            "--commit",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--artifact",
            "x",
            "--output",
            "y",
        ],
        vec![
            "assemble",
            "--commit",
            "short",
            "--evidence",
            "x",
            "--output",
            "y",
        ],
        vec![
            "assemble",
            "--commit",
            COMMIT,
            "--evidence",
            "x",
            "--output",
            "y",
            "--output",
            "z",
        ],
        vec!["verify", "--output", "x"],
        vec!["verify", "--bundle", "x", "extra"],
    ] {
        let output = command(&arguments);
        assert_eq!(
            output.status.code(),
            Some(EXIT_INPUT_OR_INFRASTRUCTURE.into()),
            "{arguments:?}"
        );
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert_eq!(
            output.stderr, b"phase6b: input_or_infrastructure\n",
            "{arguments:?}"
        );
    }
}

#[test]
fn receipt_phase5d_accepts_each_fixed_target() {
    let fixture = evidence_fixture(true);
    let receipts = fixture.path().join("target-receipts");
    fs::create_dir(&receipts).unwrap();
    for target in [
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ] {
        let artifact = fixture.path().join("phase5d").join(target).join("artifact");
        let output = receipts.join(format!("{target}.json"));
        let result = command(&[
            "receipt",
            "phase5d",
            "--commit",
            COMMIT,
            "--target",
            target,
            "--artifact",
            artifact.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(result.status.code(), Some(0), "{target}");
        assert_eq!(
            result.stdout,
            format!("phase6b: receipt=OK kind=phase5d commit={COMMIT}\n").as_bytes(),
            "{target}"
        );
        assert!(result.stderr.is_empty(), "{target}");
    }
}

#[test]
fn writes_each_receipt_without_overwriting_existing_output() {
    let fixture = evidence_fixture(true);
    let receipts = fixture.path().join("new-receipts");
    fs::create_dir(&receipts).unwrap();

    let artifact = fixture
        .path()
        .join("phase5d/x86_64-unknown-linux-gnu/artifact");
    let phase5d = receipts.join("phase5d.json");
    let first = command(&[
        "receipt",
        "phase5d",
        "--commit",
        COMMIT,
        "--target",
        "x86_64-unknown-linux-gnu",
        "--artifact",
        artifact.to_str().unwrap(),
        "--output",
        phase5d.to_str().unwrap(),
    ]);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(
        first.stdout,
        format!("phase6b: receipt=OK kind=phase5d commit={COMMIT}\n").as_bytes()
    );
    assert!(first.stderr.is_empty());
    let original = fs::read(&phase5d).unwrap();
    let second = command(&[
        "receipt",
        "phase5d",
        "--commit",
        COMMIT,
        "--target",
        "x86_64-unknown-linux-gnu",
        "--artifact",
        artifact.to_str().unwrap(),
        "--output",
        phase5d.to_str().unwrap(),
    ]);
    assert_eq!(second.status.code(), Some(3));
    assert_eq!(fs::read(phase5d).unwrap(), original);

    let sanitizer = receipts.join("sanitizer.json");
    let sanitizer_output = command(&[
        "receipt",
        "sanitizer",
        "--commit",
        COMMIT,
        "--rust-version",
        "1.85.0",
        "--clang-version",
        "17.0.0",
        "--output",
        sanitizer.to_str().unwrap(),
    ]);
    assert_eq!(sanitizer_output.status.code(), Some(0));
    assert_eq!(
        sanitizer_output.stdout,
        format!("phase6b: receipt=OK kind=sanitizer commit={COMMIT}\n").as_bytes()
    );

    let report = fixture.path().join("source/direct-release.json");
    let summary = fixture.path().join("source/direct-release.md");
    fs::create_dir_all(report.parent().unwrap()).unwrap();
    fs::write(&report, signed(valid_report("direct", 50))).unwrap();
    fs::write(&summary, b"# Release\nqualified: safe\n").unwrap();
    let phase6a = receipts.join("phase6a.json");
    let phase6a_output = command(&[
        "receipt",
        "phase6a",
        "--commit",
        COMMIT,
        "--report",
        report.to_str().unwrap(),
        "--summary",
        summary.to_str().unwrap(),
        "--output",
        phase6a.to_str().unwrap(),
    ]);
    assert_eq!(phase6a_output.status.code(), Some(0));
    assert_eq!(
        phase6a_output.stdout,
        format!("phase6b: receipt=OK kind=phase6a commit={COMMIT}\n").as_bytes()
    );
}

#[test]
fn assembles_and_verifies_an_authorized_bundle() {
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();
    let assembled = command(&[
        "assemble",
        "--commit",
        COMMIT,
        "--evidence",
        evidence.path().to_str().unwrap(),
        "--output",
        output.path().to_str().unwrap(),
    ]);
    assert_eq!(assembled.status.code(), Some(0));
    assert_eq!(
        assembled.stdout,
        format!("phase6b: release=AUTHORIZED commit={COMMIT}\n").as_bytes()
    );
    assert!(assembled.stderr.is_empty());

    let verified = command(&[
        "verify",
        "--bundle",
        output.path().join("bundle").to_str().unwrap(),
    ]);
    assert_eq!(verified.status.code(), Some(0));
    assert_eq!(
        verified.stdout,
        format!("phase6b: bundle=VALID authorized=true commit={COMMIT}\n").as_bytes()
    );
    assert!(verified.stderr.is_empty());
}

#[test]
fn distinguishes_blocked_evidence_from_invalid_evidence() {
    let blocked = evidence_fixture(false);
    let blocked_output = tempfile::tempdir().unwrap();
    let result = command(&[
        "assemble",
        "--commit",
        COMMIT,
        "--evidence",
        blocked.path().to_str().unwrap(),
        "--output",
        blocked_output.path().to_str().unwrap(),
    ]);
    assert_eq!(
        result.status.code(),
        Some(EXIT_AUTHORIZATION_BLOCKED.into())
    );
    assert_eq!(result.stdout, b"phase6b: release=BLOCKED\n");
    assert!(result.stderr.is_empty());
    assert!(
        fs::read_dir(blocked_output.path())
            .unwrap()
            .next()
            .is_none()
    );

    fs::write(
        blocked
            .path()
            .join("phase5d/x86_64-unknown-linux-gnu/artifact/unlisted"),
        b"tampered",
    )
    .unwrap();
    let invalid_output = tempfile::tempdir().unwrap();
    let invalid = command(&[
        "assemble",
        "--commit",
        COMMIT,
        "--evidence",
        blocked.path().to_str().unwrap(),
        "--output",
        invalid_output.path().to_str().unwrap(),
    ]);
    assert_eq!(
        invalid.status.code(),
        Some(EXIT_INPUT_OR_INFRASTRUCTURE.into())
    );
    assert!(invalid.stdout.is_empty());
    assert_eq!(invalid.stderr, b"phase6b: input_or_infrastructure\n");
    assert!(
        fs::read_dir(invalid_output.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn output_writer_failures_are_internal() {
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut stdout = Broken;
    let mut stderr = Vec::new();
    assert_eq!(
        run_with_io(["--help"], &mut stdout, &mut stderr),
        EXIT_INTERNAL
    );
    assert_eq!(stderr, b"phase6b: internal\n");

    let mut stdout = Vec::new();
    let mut stderr = Broken;
    assert_eq!(
        run_with_io(["unknown"], &mut stdout, &mut stderr),
        EXIT_INTERNAL
    );

    struct FailsOnce {
        failed: bool,
        bytes: Vec<u8>,
    }
    impl io::Write for FailsOnce {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if !self.failed {
                self.failed = true;
                Err(io::Error::other("synthetic"))
            } else {
                self.bytes.extend_from_slice(buffer);
                Ok(buffer.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut stdout = Vec::new();
    let mut stderr = FailsOnce {
        failed: false,
        bytes: Vec::new(),
    };
    assert_eq!(
        run_with_io(["unknown"], &mut stdout, &mut stderr),
        EXIT_INTERNAL
    );
    assert_eq!(stderr.bytes, b"phase6b: internal\n");
}
