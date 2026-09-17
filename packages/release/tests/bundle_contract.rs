// Reuse the complete, independently-valid evidence fixture without coupling the
// public bundle API to test-only construction details.
include!("evidence_contract.rs");

use agentgate_release::{BundleError, assemble_bundle, verify_bundle};

#[test]
fn assembles_and_independently_verifies_a_canonical_offline_bundle() {
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();

    let bundle = assemble_bundle(evidence.path(), output.path(), COMMIT).unwrap();
    assert_eq!(bundle, output.path().join("bundle"));
    let names = fs::read_dir(&bundle)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        std::collections::BTreeSet::from([
            "SHA256SUMS".to_owned(),
            "manifest.json".to_owned(),
            "suite".to_owned(),
            "receipts".to_owned(),
            "phase5d".to_owned(),
            "phase6a".to_owned(),
        ])
    );
    let verified = verify_bundle(&bundle).unwrap();
    assert!(verified.authorized());
    assert_eq!(verified.commit(), COMMIT);
    assert_eq!(verified.agentgate_version(), "0.1.0");
    assert_eq!(verified.abi_version(), 1);
    assert_eq!(verified.generator_version(), "1.0");
    assert_eq!(verified.suite_manifest_digest(), SUITE_DIGEST);
    assert_eq!(verified.receipts().len(), 9);
    assert!(
        !fs::read(bundle.join("manifest.json"))
            .unwrap()
            .ends_with(b"\n")
    );
    assert_eq!(
        fs::read(bundle.join("suite/v1.json")).unwrap(),
        include_bytes!("../../../benchmarks/suites/v1.json")
    );
}

#[test]
fn refuses_an_existing_destination_without_overwriting_it() {
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();
    fs::create_dir(output.path().join("bundle")).unwrap();
    fs::write(output.path().join("bundle/keep"), b"preserve").unwrap();
    assert!(assemble_bundle(evidence.path(), output.path(), COMMIT).is_err());
    assert_eq!(
        fs::read(output.path().join("bundle/keep")).unwrap(),
        b"preserve"
    );
}

#[test]
fn blocked_evidence_creates_neither_a_bundle_nor_staging_directory() {
    let evidence = evidence_fixture(false);
    let output = tempfile::tempdir().unwrap();
    assert_eq!(
        assemble_bundle(evidence.path(), output.path(), COMMIT),
        Err(BundleError::Blocked)
    );
    assert!(fs::read_dir(output.path()).unwrap().next().is_none());
}

#[test]
fn verification_rejects_payload_and_top_level_layout_mutations() {
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();
    let bundle = assemble_bundle(evidence.path(), output.path(), COMMIT).unwrap();
    fs::write(bundle.join("unexpected"), b"x").unwrap();
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn verification_rejects_reordered_or_noncanonical_checksums() {
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();
    let bundle = assemble_bundle(evidence.path(), output.path(), COMMIT).unwrap();
    let sums = bundle.join("SHA256SUMS");
    let mut lines = String::from_utf8(fs::read(&sums).unwrap())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.swap(0, 1);
    fs::write(sums, format!("{}\n", lines.join("\n"))).unwrap();
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn verification_does_not_trust_a_canonical_authorized_flag() {
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();
    let bundle = assemble_bundle(evidence.path(), output.path(), COMMIT).unwrap();
    let manifest = bundle.join("manifest.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["authorized"] = json!(false);
    let bytes = agentgate_release::canonical::canonical_compact(&value).unwrap();
    fs::write(&manifest, &bytes).unwrap();
    let sums = bundle.join("SHA256SUMS");
    let mut lines = String::from_utf8(fs::read(&sums).unwrap())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let digest = agentgate_release::canonical::sha256_hex(&bytes);
    let line = lines
        .iter_mut()
        .find(|line| line.ends_with("  manifest.json"))
        .unwrap();
    *line = format!("{digest}  manifest.json");
    lines.sort();
    fs::write(sums, format!("{}\n", lines.join("\n"))).unwrap();
    assert!(verify_bundle(&bundle).is_err());
}

#[cfg(unix)]
#[test]
fn verification_rejects_a_symlink_before_following_it() {
    use std::os::unix::fs::symlink;
    let evidence = evidence_fixture(true);
    let output = tempfile::tempdir().unwrap();
    let bundle = assemble_bundle(evidence.path(), output.path(), COMMIT).unwrap();
    let target = bundle.join("receipts/direct.json");
    let moved = bundle.join("receipts/moved.json");
    fs::rename(&target, &moved).unwrap();
    symlink(&moved, &target).unwrap();
    assert!(verify_bundle(&bundle).is_err());
}
