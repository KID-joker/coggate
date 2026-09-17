use std::{fs, path::PathBuf};

fn workflow(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name);
    fs::read_to_string(path).expect("producer workflow must exist")
}

fn top_level_mapping(source: &str, key: &str) -> String {
    let lines = source.lines().collect::<Vec<_>>();
    let marker = format!("{key}:");
    let start = lines
        .iter()
        .position(|line| *line == marker)
        .expect("top-level workflow mapping");
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find_map(|(index, line)| (!line.is_empty() && !line.starts_with(' ')).then_some(index))
        .unwrap_or(lines.len());
    let mut mapping = lines[start..end].to_vec();
    while mapping.last().is_some_and(|line| line.is_empty()) {
        mapping.pop();
    }
    format!("{}\n", mapping.join("\n"))
}

fn assert_secure_workflow(source: &str) {
    assert_eq!(
        top_level_mapping(source, "permissions"),
        "permissions:\n  contents: read\n"
    );
    assert!(!source.contains("pull_request_target"));
    assert!(!source.contains("secrets."));
    assert!(!source.contains("provider"));
    assert_eq!(
        source.matches("persist-credentials: false").count(),
        source.matches("uses: actions/checkout@").count(),
        "every checkout must disable persisted credentials"
    );
    for line in source.lines().map(str::trim) {
        let Some(reference) = line.strip_prefix("uses: ") else {
            continue;
        };
        let sha = reference
            .rsplit_once('@')
            .expect("action must have a ref")
            .1;
        assert_eq!(sha.len(), 40, "action is not SHA-pinned: {reference}");
        assert!(sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert!(
        source
            .lines()
            .filter(|line| line.contains("timeout-minutes:"))
            .count()
            >= 1
    );
}

#[test]
fn phase5d_receipts_follow_verification_and_upload_only_bounded_evidence() {
    let source = workflow("phase5d.yml");
    assert_secure_workflow(&source);
    let qualification_receipt = "receipt phase5d --commit \"${{ github.sha }}\" --target \"${{ matrix.target }}\" --artifact target/phase5d/${{ matrix.target }}/artifact --output target/phase5d/${{ matrix.target }}/receipts/receipt.json";
    assert!(source.contains(qualification_receipt));
    assert!(source.contains("test ! -e target/phase5d/${{ matrix.target }}/receipts/receipt.json"));
    assert!(source.contains("target/phase5d/${{ matrix.target }}/artifact\n            target/phase5d/${{ matrix.target }}/receipts/receipt.json"));
    assert!(
        source.find("Run qualification").unwrap()
            < source.find("Create qualification receipt").unwrap()
    );
    assert!(
        source.find("Run Windows qualification").unwrap()
            < source.find("Create qualification receipt").unwrap()
    );
    assert!(source.contains("receipt sanitizer --commit \"${{ github.sha }}\" --rust-version \"$rust_version\" --clang-version \"$clang_version\" --output target/phase5d/sanitizers/receipts/receipt.json"));
    assert!(source.contains("rustc --version"));
    assert!(source.contains("clang --version"));
    assert!(source.contains("sed -nE"));
    assert!(source.contains("target/phase5d/sanitizers/receipts/receipt.json"));
}

#[test]
fn phase6a_manual_release_binds_each_safe_report_pair_without_llm_leakage() {
    let source = workflow("phase6a.yml");
    assert_secure_workflow(&source);
    let release = source.split("  release:\n").nth(1).expect("release job");
    assert!(release.contains("if: always()"));
    assert!(
        release.find("Verify release reports").unwrap()
            < release.find("Create release receipts").unwrap()
    );
    assert!(
        release.find("Create release receipts").unwrap()
            < release.find("Upload release reports").unwrap()
    );
    for name in ["direct", "fingerprint", "regex", "simple_parser"] {
        assert!(release.contains(&format!("{name}-release.json")));
        assert!(release.contains(&format!("{name}-release.md")));
        assert!(release.contains(&format!("receipts/{name}.json")));
    }
    assert!(release.contains("receipt phase6a --commit \"${{ github.sha }}\""));
    assert!(release.contains("test -f \"$path\" || exit 1"));
    assert!(!release.contains("test -f \"$path\" || exit 0"));
    assert!(release.contains("test ! -e target/phase6a/release/receipts/direct.json"));
    assert!(release.contains("target/phase6a/release/receipts/direct.json"));
    for forbidden in [
        "export-llm",
        "prompts.jsonl",
        "results.jsonl",
        "provider",
        "secrets.",
        "answers",
        "questions",
    ] {
        assert!(!source.contains(forbidden), "workflow leaks {forbidden}");
    }
}
