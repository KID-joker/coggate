use std::fs;

use agentgate_release::{
    EvidenceSet, assemble_bundle,
    cli::{EXIT_BLOCKED, run_with_io},
    verify_bundle,
};

mod support;

#[test]
fn assembles_the_complete_fixed_evidence_set_reproducibly_and_verifies_from_disk() {
    let evidence = support::evidence_fixture(true, None);
    let loaded = EvidenceSet::load(evidence.path(), support::COMMIT).unwrap();
    let decision = loaded.authorize().unwrap();
    let first_parent = tempfile::tempdir().unwrap();
    let second_parent = tempfile::tempdir().unwrap();
    let first = assemble_bundle(evidence.path(), first_parent.path(), support::COMMIT).unwrap();
    let second = assemble_bundle(evidence.path(), second_parent.path(), support::COMMIT).unwrap();

    let first_verified = verify_bundle(&first).unwrap();
    let second_verified = verify_bundle(&second).unwrap();
    assert!(first_verified.authorized());
    assert!(second_verified.authorized());
    assert_eq!(first_verified.commit(), support::COMMIT);
    assert_eq!(first_verified.receipts(), second_verified.receipts());
    assert_eq!(first_verified.receipts().len(), 9);
    assert_eq!(
        first_verified.receipts(),
        &decision
            .receipt_digests()
            .iter()
            .map(|(role, digest)| agentgate_release::BundleReceipt {
                role: role.clone(),
                digest: digest.clone()
            })
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        fs::read(first.join("manifest.json")).unwrap(),
        fs::read(second.join("manifest.json")).unwrap()
    );
    assert_eq!(
        fs::read(first.join("SHA256SUMS")).unwrap(),
        fs::read(second.join("SHA256SUMS")).unwrap()
    );
}

#[test]
fn rejects_a_validly_reissued_receipt_with_a_different_commit() {
    let evidence = support::evidence_fixture(true, None);
    support::mutate_receipt_commit(evidence.path(), "linux");
    assert!(EvidenceSet::load(evidence.path(), support::COMMIT).is_err());
    let output = tempfile::tempdir().unwrap();
    assert!(assemble_bundle(evidence.path(), output.path(), support::COMMIT).is_err());
    assert!(fs::read_dir(output.path()).unwrap().next().is_none());
}

#[test]
fn rejects_a_payload_changed_after_its_receipt_was_issued() {
    let evidence = support::evidence_fixture(true, None);
    fs::write(
        evidence
            .path()
            .join("phase5d/x86_64-unknown-linux-gnu/artifact/smoke/abi_probe.c"),
        b"changed after receipt\n",
    )
    .unwrap();
    assert!(EvidenceSet::load(evidence.path(), support::COMMIT).is_err());
    let output = tempfile::tempdir().unwrap();
    assert!(assemble_bundle(evidence.path(), output.path(), support::COMMIT).is_err());
    assert!(fs::read_dir(output.path()).unwrap().next().is_none());
}

#[test]
fn unqualified_llm_report_blocks_the_cli_without_a_bundle_or_staging_residue() {
    let evidence = support::evidence_fixture(true, None);
    support::replace_llm_report(evidence.path(), 799);
    let output = tempfile::tempdir().unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let arguments = vec![
        "assemble".to_owned(),
        "--commit".to_owned(),
        support::COMMIT.to_owned(),
        "--evidence".to_owned(),
        evidence.path().display().to_string(),
        "--output".to_owned(),
        output.path().display().to_string(),
    ];
    assert_eq!(
        run_with_io(arguments, &mut stdout, &mut stderr),
        EXIT_BLOCKED
    );
    assert_eq!(stdout, b"phase6b: release=BLOCKED\n");
    assert!(stderr.is_empty());
    assert!(fs::read_dir(output.path()).unwrap().next().is_none());
}
