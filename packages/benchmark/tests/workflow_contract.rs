use std::path::PathBuf;

fn workflow() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/phase6a.yml");
    std::fs::read_to_string(path).expect("Phase 6A workflow must exist")
}

#[test]
fn workflow_is_pinned_bounded_and_has_quick_and_manual_release_gates() {
    let source = workflow();
    assert!(source.contains("permissions:\n  contents: read\n\nconcurrency:"));
    assert!(source.contains("push:"));
    assert!(source.contains("pull_request:"));
    assert!(source.contains("workflow_dispatch:"));
    assert!(!source.contains("pull_request_target"));
    assert!(source.matches("timeout-minutes:").count() >= 2);
    assert!(source.contains("github.event_name == 'workflow_dispatch'"));

    for pinned in [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
        "actions/setup-java@dd06d9cba3e5552c54d9f8ea23572deb30010f7c",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ] {
        assert!(source.contains(pinned), "missing pinned action: {pinned}");
    }
    assert!(!source.contains("rust-toolchain@"));
    assert!(source.contains("rustup toolchain install 1.85.0 --profile minimal"));
    assert!(source.contains("rustup override set 1.85.0"));
    assert!(source.contains("sudo apt-get install --yes build-essential"));
    assert!(source.contains("go-version:"));
    assert!(source.contains("java-version:"));

    for command in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
        "cargo test -p agentgate-benchmark --test quick_qualification",
        "real_quick_direct_qualification -- --ignored --exact",
        "run-baselines --profile quick --output target/phase6a/quick",
        "run-baselines --profile release --output target/phase6a/release",
        "verify-report --input",
    ] {
        assert!(source.contains(command), "missing gate: {command}");
    }
    assert!(source.contains("target/phase6a/quick/*.json"));
    assert!(source.contains("target/phase6a/release/*.md"));
    assert!(source.contains("receipt phase6a --commit \"${{ github.sha }}\""));
    assert!(source.contains("mkdir -p target/phase6a/release/receipts"));
    for baseline in ["direct", "fingerprint", "regex", "simple_parser"] {
        assert!(source.contains(&format!("{baseline}-release.json")));
        assert!(source.contains(&format!("{baseline}-release.md")));
        assert!(source.contains(&format!("receipts/{baseline}.json")));
    }
    assert!(!source.contains("export-llm"));
    assert!(!source.contains("prompts.jsonl"));
    assert!(!source.contains("results.jsonl"));
    assert!(!source.contains("secrets."));
}

#[test]
fn every_uses_reference_is_a_full_commit_sha() {
    for line in workflow().lines().map(str::trim) {
        let Some(reference) = line.strip_prefix("uses: ") else {
            continue;
        };
        let sha = reference.rsplit_once('@').unwrap().1;
        assert_eq!(sha.len(), 40, "action is not SHA-pinned: {reference}");
        assert!(sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
