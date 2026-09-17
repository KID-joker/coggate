use std::fs;

use agentgate_release::receipt::{
    EvidenceBinding, FileBinding, Phase5dBinding, Phase6aBinding, Receipt, ReceiptError,
    ReportRole, SanitizerBinding, write_receipt,
};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn files(paths: &[&str]) -> Vec<FileBinding> {
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| FileBinding::new(*path, (index + 1) as u64, "a".repeat(64)).unwrap())
        .collect()
}

fn phase6a() -> Receipt {
    Receipt::new_phase6a(
        COMMIT,
        Phase6aBinding {
            suite_version: "1.0".into(),
            generator_version: "1.0".into(),
            manifest_digest: "a".repeat(64),
            profile: "release".into(),
            role: ReportRole::Direct,
            subject_id: "direct".into(),
            payload_digest: "b".repeat(64),
            qualified: true,
        },
        vec![
            FileBinding::new("report.json", 12, "c".repeat(64)).unwrap(),
            FileBinding::new("report.md", 8, "d".repeat(64)).unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn all_evidence_kinds_have_fixed_producers_and_exact_file_counts() {
    let artifact = Receipt::new_phase5d_artifact(
        COMMIT,
        Phase5dBinding {
            platform: "linux".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            profile: "release".into(),
            artifact_name: "agentgate".into(),
            manifest_version: "1.0".into(),
            manifest_digest: "a".repeat(64),
        },
        files(&["artifact-manifest.json", "artifact.bin"]),
    )
    .unwrap();
    let sanitizer = Receipt::new_phase5d_sanitizer(
        COMMIT,
        SanitizerBinding {
            platform: "linux".into(),
            profile: "release".into(),
            report_version: "1.0".into(),
            payload_digest: "b".repeat(64),
            qualified: true,
        },
        files(&["sanitizer-report.json"]),
    )
    .unwrap();
    let report = phase6a();

    assert_eq!(artifact.producer_id(), "phase5d");
    assert_eq!(sanitizer.producer_id(), "phase5d");
    assert_eq!(report.producer_id(), "phase6a");
    assert!(
        Receipt::new_phase5d_artifact(
            COMMIT,
            match artifact.evidence() {
                EvidenceBinding::Phase5dArtifact(binding) => binding.clone(),
                _ => unreachable!(),
            },
            files(&["artifact.bin"]),
        )
        .is_err()
    );
}

#[test]
fn phase6a_receipt_is_canonical_and_domain_separated() {
    let receipt = phase6a();
    let encoded = receipt.to_canonical_json().unwrap();
    assert!(!encoded.ends_with(b"\n"));
    assert_eq!(
        Receipt::parse_and_verify(&encoded).unwrap().digest(),
        receipt.digest()
    );
    assert_ne!(
        receipt.digest(),
        agentgate_release::canonical::sha256_hex(&encoded)
    );
}

#[test]
fn receipt_rejects_invalid_ordering_and_constructor_inputs() {
    assert!(FileBinding::new("../report.json", 1, "a".repeat(64)).is_err());
    assert!(FileBinding::new("report.json", 0, "a".repeat(64)).is_err());
    assert!(
        Receipt::new_phase6a(
            COMMIT,
            match phase6a().evidence() {
                EvidenceBinding::Phase6aReport(binding) => binding.clone(),
                _ => unreachable!(),
            },
            vec![
                FileBinding::new("report.md", 8, "d".repeat(64)).unwrap(),
                FileBinding::new("report.json", 12, "c".repeat(64)).unwrap(),
            ],
        )
        .is_err()
    );
    assert!(
        Receipt::new_phase6a(
            "0123456789abcdef0123456789abcdef0123456A",
            match phase6a().evidence() {
                EvidenceBinding::Phase6aReport(binding) => binding.clone(),
                _ => unreachable!(),
            },
            files(&["report.json", "report.md"])
        )
        .is_err()
    );
}

#[test]
fn parser_revalidates_each_authenticated_field_and_rejects_ambiguous_json() {
    let receipt = phase6a();
    let encoded = String::from_utf8(receipt.to_canonical_json().unwrap()).unwrap();
    let digest = receipt.digest().to_owned();
    for (needle, replacement) in [
        ("\"schema_version\":1", "\"schema_version\":2"),
        ("phase6a_report", "unknown_report"),
        (COMMIT, "1123456789abcdef0123456789abcdef01234567"),
        ("\"id\":\"phase6a\"", "\"id\":\"other\""),
        ("report.json", "zzz.json"),
        ("\"size\":12", "\"size\":13"),
        (&"c".repeat(64), &"e".repeat(64)),
        ("\"suite_version\":\"1.0\"", "\"suite_version\":\"2.0\""),
        (&digest, &"0".repeat(64)),
    ] {
        let mutated = encoded.replacen(needle, replacement, 1);
        assert!(
            Receipt::parse_and_verify(mutated.as_bytes()).is_err(),
            "{needle}"
        );
    }

    for invalid in [
        encoded.replacen("report.md", "report.json", 1),
        encoded.replacen("\"files\":[{\"hash\":\"c", "\"files\":[{\"hash\":\"d", 1),
        encoded.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"extra\":true",
            1,
        ),
        encoded.replacen(
            "\"profile\":\"release\"",
            "\"profile\":\"release\",\"extra\":true",
            1,
        ),
        encoded.replacen(
            "\"kind\":\"phase6a_report\"",
            "\"kind\":\"phase6a_report\",\"extra\":true",
            1,
        ),
        encoded.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        ),
        encoded.replacen(
            "\"profile\":\"release\"",
            "\"profile\":\"release\",\"profile\":\"release\"",
            1,
        ),
    ] {
        assert!(Receipt::parse_and_verify(invalid.as_bytes()).is_err());
    }
}

#[test]
fn writer_is_atomic_and_never_clobbers_an_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("receipt.json");
    let receipt = phase6a();
    write_receipt(&destination, &receipt).unwrap();
    let first = fs::read(&destination).unwrap();
    assert_eq!(first.last(), Some(&b'\n'));

    assert!(matches!(
        write_receipt(&destination, &receipt),
        Err(ReceiptError::DestinationExists)
    ));
    assert_eq!(fs::read(&destination).unwrap(), first);
}
