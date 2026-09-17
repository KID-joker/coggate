use std::fs;

use agentgate_release::canonical::{MAX_METADATA_BYTES, canonical_compact, sha256_hex};
use agentgate_release::receipt::{
    EvidenceBinding, FileBinding, Phase5dBinding, Phase6aBinding, Receipt, ReceiptError,
    ReportRole, SanitizerBinding, write_receipt,
};
use serde_json::{Value, json};

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

fn phase5d_artifact() -> Receipt {
    Receipt::new_phase5d_artifact(
        COMMIT,
        Phase5dBinding {
            platform: "Linux".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            profile: "release".into(),
            artifact_name: "agentgate".into(),
            manifest_version: "0.1.0".into(),
            abi_version: 1,
            tree_digest: "b".repeat(64),
            manifest_digest: "a".repeat(64),
        },
        files(&["artifact-manifest.json", "artifact.bin"]),
    )
    .unwrap()
}

fn phase5d_sanitizer() -> Receipt {
    Receipt::new_phase5d_sanitizer(
        COMMIT,
        SanitizerBinding {
            platform: "linux".into(),
            target: "x86_64".into(),
            profile: "release".into(),
            rust_version: "1.85.0".into(),
            clang_version: "17.0.0".into(),
            passed: true,
        },
        vec![],
    )
    .unwrap()
}

fn receipt_value(receipt: &Receipt) -> Value {
    serde_json::from_slice(&receipt.to_canonical_json().unwrap()).unwrap()
}

fn digest_for_payload(payload: &Value) -> String {
    let canonical_payload = canonical_compact(payload).unwrap();
    let mut bytes = b"agentgate-release-receipt-v1".to_vec();
    bytes.extend_from_slice(&canonical_payload);
    sha256_hex(&bytes)
}

fn recanonicalize_with_recomputed_digest(mut value: Value) -> Vec<u8> {
    let object = value.as_object_mut().unwrap();
    object.remove("evidence_digest").unwrap();
    let digest = digest_for_payload(&value);
    value["evidence_digest"] = Value::String(digest);
    canonical_compact(&value).unwrap()
}

fn assert_authenticated_mutation_rejected(receipt: &Receipt, mutate: impl FnOnce(&mut Value)) {
    let mut value = receipt_value(receipt);
    mutate(&mut value);
    let encoded = recanonicalize_with_recomputed_digest(value);
    assert!(Receipt::parse_and_verify(&encoded).is_err());
}

fn kind_name(evidence: &EvidenceBinding) -> &'static str {
    match evidence {
        EvidenceBinding::Phase5dArtifact(_) => "phase5d_artifact",
        EvidenceBinding::Phase5dSanitizer(_) => "phase5d_sanitizer",
        EvidenceBinding::Phase6aReport(_) => "phase6a_report",
    }
}

#[test]
fn all_evidence_kinds_have_fixed_producers_and_exact_file_counts() {
    let artifact = phase5d_artifact();
    let sanitizer = phase5d_sanitizer();
    let report = phase6a();

    for (receipt, expected_producer, expected_count, expected_kind) in [
        (&artifact, "phase5d", 2, "phase5d_artifact"),
        (&sanitizer, "phase5d", 0, "phase5d_sanitizer"),
        (&report, "phase6a", 2, "phase6a_report"),
    ] {
        let encoded = receipt.to_canonical_json().unwrap();
        let parsed = Receipt::parse_and_verify(&encoded).unwrap();
        assert_eq!(parsed.producer_id(), expected_producer);
        assert_eq!(parsed.producer().verifier(), "phase6b-receipt-v1");
        assert_eq!(parsed.files().len(), expected_count);
        assert_eq!(
            kind_name(parsed.evidence()),
            expected_kind,
            "round trip changed evidence kind"
        );
    }
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
    let mut payload = receipt_value(&receipt);
    let supplied_digest = payload
        .as_object_mut()
        .unwrap()
        .remove("evidence_digest")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(digest_for_payload(&payload), supplied_digest);
    assert_eq!(receipt.digest(), supplied_digest);
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
fn parser_revalidates_authenticated_invariants_after_digest_recomputation() {
    let receipt = phase6a();
    for mutate in [
        |value: &mut Value| value["files"][0]["size"] = json!(0),
        |value: &mut Value| value["files"][0]["hash"] = json!("a".repeat(63)),
        |value: &mut Value| value["files"][0]["hash"] = json!("A".repeat(64)),
        |value: &mut Value| value["evidence"]["binding"]["subject_id"] = json!("x\u{1}"),
        |value: &mut Value| value["evidence"]["binding"]["suite_version"] = json!("x".repeat(129)),
        |value: &mut Value| value["producer"]["id"] = json!("phase5d"),
        |value: &mut Value| value["producer"]["verifier"] = json!("other"),
        |value: &mut Value| value["files"].as_array_mut().unwrap().swap(0, 1),
        |value: &mut Value| value["files"][1]["path"] = json!("report.json"),
        |value: &mut Value| {
            value["files"].as_array_mut().unwrap().pop();
        },
    ] {
        assert_authenticated_mutation_rejected(&receipt, mutate);
    }
}

#[test]
fn parser_rejects_identity_mutations() {
    let receipt = phase6a();

    assert_authenticated_mutation_rejected(&receipt, |value| {
        value["schema_version"] = json!(2);
        assert_eq!(value["schema_version"], json!(2));
    });
    assert_authenticated_mutation_rejected(&receipt, |value| {
        value["commit"] = json!("0123456789abcdef0123456789abcdef0123456A");
        assert_eq!(
            value["commit"],
            json!("0123456789abcdef0123456789abcdef0123456A")
        );
    });
    assert_authenticated_mutation_rejected(&receipt, |value| {
        value["evidence"]["kind"] = json!("unsupported_report");
        assert_eq!(value["evidence"]["kind"], json!("unsupported_report"));
    });

    let mut value = receipt_value(&receipt);
    value["evidence_digest"] = json!("0".repeat(64));
    assert_eq!(value["evidence_digest"], json!("0".repeat(64)));
    let encoded = canonical_compact(&value).unwrap();
    assert!(Receipt::parse_and_verify(&encoded).is_err());
}

#[test]
fn parser_rejects_noncanonical_and_ambiguous_inputs() {
    let receipt = phase6a();
    let encoded = receipt.to_canonical_json().unwrap();
    let encoded_text = String::from_utf8(encoded.clone()).unwrap();
    assert!(Receipt::parse_and_verify(&vec![b' '; MAX_METADATA_BYTES + 1]).is_err());
    assert!(Receipt::parse_and_verify(b"{").is_err());
    assert!(Receipt::parse_and_verify(format!("{encoded_text} null").as_bytes()).is_err());
    assert!(Receipt::parse_and_verify(format!(" {encoded_text}").as_bytes()).is_err());

    let value = receipt_value(&receipt);
    let object = value.as_object().unwrap();
    let key_reordered = format!(
        "{{\"schema_version\":{},\"commit\":{},\"producer\":{},\"evidence\":{},\"files\":{},\"evidence_digest\":{}}}",
        canonical_compact(&object["schema_version"])
            .unwrap()
            .escape_ascii(),
        canonical_compact(&object["commit"]).unwrap().escape_ascii(),
        canonical_compact(&object["producer"])
            .unwrap()
            .escape_ascii(),
        canonical_compact(&object["evidence"])
            .unwrap()
            .escape_ascii(),
        canonical_compact(&object["files"]).unwrap().escape_ascii(),
        canonical_compact(&object["evidence_digest"])
            .unwrap()
            .escape_ascii(),
    );
    assert!(Receipt::parse_and_verify(key_reordered.as_bytes()).is_err());

    let duplicate = format!("{{\"schema_version\":1,{}", &encoded_text[1..]);
    assert!(Receipt::parse_and_verify(duplicate.as_bytes()).is_err());

    for mutate in [
        |value: &mut Value| {
            value
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), json!(true));
        },
        |value: &mut Value| {
            value["evidence"]["binding"]
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), json!(true));
        },
    ] {
        let encoded = recanonicalize_with_recomputed_digest(receipt_value(&receipt));
        let mut value: Value = serde_json::from_slice(&encoded).unwrap();
        mutate(&mut value);
        let encoded = recanonicalize_with_recomputed_digest(value);
        assert!(Receipt::parse_and_verify(&encoded).is_err());
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

#[test]
fn persisted_receipt_wire_format_requires_exactly_one_terminal_lf() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("receipt.json");
    let receipt = phase6a();
    write_receipt(&destination, &receipt).unwrap();
    let written = fs::read(&destination).unwrap();

    let parsed = Receipt::parse_written_and_verify(&written).unwrap();
    assert_eq!(parsed.digest(), receipt.digest());

    let canonical = receipt.to_canonical_json().unwrap();
    assert!(Receipt::parse_written_and_verify(&canonical).is_err());

    let mut double_lf = written.clone();
    double_lf.push(b'\n');
    assert!(Receipt::parse_written_and_verify(&double_lf).is_err());

    let mut crlf = canonical.clone();
    crlf.extend_from_slice(b"\r\n");
    assert!(Receipt::parse_written_and_verify(&crlf).is_err());

    let mut trailing = written;
    trailing.extend_from_slice(b"trailing\n");
    assert!(Receipt::parse_written_and_verify(&trailing).is_err());
}
