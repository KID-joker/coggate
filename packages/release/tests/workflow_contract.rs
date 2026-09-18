use std::{fs, path::PathBuf};

fn workflow() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(".github/workflows/phase6b.yml")).unwrap()
}

#[test]
fn phase6b_workflow_is_a_pinned_offline_release_gate() {
    let source = workflow();
    assert!(source.contains("on:\n  push:\n  pull_request:\n  workflow_dispatch:"));
    assert!(source.contains("permissions:\n  contents: read\n\nconcurrency:"));
    assert!(source.contains("cancel-in-progress: true"));
    assert!(source.contains("runs-on: ubuntu-24.04"));
    assert!(source.contains("timeout-minutes:"));
    assert!(source.contains("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"));
    assert!(source.contains("persist-credentials: false"));
    assert!(source.contains("rustup toolchain install 1.85.0 --profile minimal"));
    assert!(source.contains("rustup override set 1.85.0"));
    for command in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
        "cargo test -p coggate-release --test synthetic_release",
        "cargo test -p coggate-release --test leakage",
        "if cargo tree -p coggate-release | rg -q 'coggate-(benchmark|core)'; then exit 1; fi",
    ] {
        assert!(source.contains(command), "missing {command}");
    }
    let lower = source.to_ascii_lowercase();
    for forbidden in [
        "upload-artifact",
        "publish",
        "gh ",
        "secrets:",
        "packages: write",
        "contents: write",
    ] {
        assert!(!lower.contains(forbidden), "forbidden {forbidden}");
    }
    assert_eq!(source.matches("permissions:").count(), 1);
    assert!(
        !source
            .lines()
            .any(|line| line.trim_end().ends_with(": write"))
    );
    for line in source.lines().filter(|line| line.contains("uses:")) {
        let reference = line
            .split_once("uses:")
            .and_then(|(_, action)| action.trim().split('@').nth(1))
            .expect("uses action must have a pin");
        assert_eq!(reference.len(), 40, "unpinned action: {line}");
        assert!(
            reference
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
    assert!(!lower.contains("setup-rust"));
    assert!(!lower.contains("actions-rs/"));
    assert!(!lower.contains("action-gh-release"));
    assert!(!lower.contains("create-release"));
}
