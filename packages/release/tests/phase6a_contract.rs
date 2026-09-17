use std::collections::BTreeMap;

use agentgate_release::{ReportRole, verify_phase6a_report};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REPORT_DOMAIN: &[u8] = b"agentgate-benchmark-report-v1";
const MANIFEST_DOMAIN: &[u8] = b"agentgate-suite-manifest-v1";
const CASE_DOMAIN: &[u8] = b"agentgate-benchmark-case-v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    suite_version: String,
    generator_version: String,
    profiles: BTreeMap<String, Profile>,
    thresholds: BTreeMap<String, Threshold>,
    baseline_versions: BTreeMap<String, String>,
    limits: Limits,
    tools: BTreeMap<String, String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    scored_cases: usize,
    calibration_cases: usize,
    scored_namespace: String,
    calibration_namespace: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Threshold {
    comparison: String,
    percent: u8,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_question_bytes: usize,
    max_result_line_bytes: usize,
    process_timeout_ms: u64,
    max_process_output_bytes: usize,
}

fn manifest_digest() -> String {
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../benchmarks/suites/v1.json")).unwrap();
    let mut bytes = MANIFEST_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(&manifest).unwrap());
    hex::encode(Sha256::digest(bytes))
}

fn case_id(index: usize) -> String {
    let digest = manifest_digest();
    let mut hash = Sha256::new();
    hash.update(CASE_DOMAIN);
    hash.update((digest.len() as u64).to_be_bytes());
    hash.update(digest.as_bytes());
    hash.update((b"scored".len() as u64).to_be_bytes());
    hash.update(b"scored");
    hash.update((index as u64).to_be_bytes());
    hex::encode(hash.finalize())
}

fn valid_report(subject: &str, solved: usize) -> Value {
    let kind = if subject == "llm-model" {
        "llm"
    } else {
        "baseline"
    };
    let version = if kind == "llm" { "run-1" } else { "1.0" };
    let tools = if subject == "direct" {
        json!({"c":"cc 1.0","cpp":"c++ 1.0","go":"go1.23.6","java":"openjdk 21","rust":"rustc 1.85.0"})
    } else {
        json!({})
    };
    let cases: Vec<Value> = (0..1000).map(|index| {
        if index < solved { json!({"case_id":case_id(index),"outcome":"solved","reason":null,"duration_ms":index}) }
        else { json!({"case_id":case_id(index),"outcome":"unsolved","reason":"no_candidate","duration_ms":index}) }
    }).collect();
    let threshold = match subject {
        "llm-model" => json!({"comparison":"at_least","percent":80}),
        "direct" => json!({"comparison":"at_most","percent":5}),
        _ => json!({"comparison":"at_most","percent":1}),
    };
    let qualified = match subject {
        "llm-model" => solved >= 800,
        "direct" => solved <= 50,
        _ => solved <= 10,
    };
    let failed = if qualified {
        json!([])
    } else {
        json!([subject])
    };
    json!({"schema_version":1,"binding":{"suite_version":"1.0","generator_version":"1.0","profile":"release","manifest_digest":manifest_digest(),"kind":kind,"subject_id":subject,"subject_version":version,"threshold":threshold,"tool_versions":tools},"cases":cases,"summary":{"total":1000,"solved":solved,"qualified":qualified,"failed_thresholds":failed},"payload_digest":""})
}

fn producer_json(value: &Value, digest: Option<&str>) -> Vec<u8> {
    let binding = &value["binding"];
    let cases = value["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            format!(
                "{{\"case_id\":{},\"outcome\":{},\"reason\":{},\"duration_ms\":{}}}",
                case["case_id"], case["outcome"], case["reason"], case["duration_ms"]
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let summary = &value["summary"];
    let payload_digest = digest
        .map(|value| serde_json::to_string(value).unwrap())
        .unwrap_or_else(|| "\"\"".to_owned());
    format!(
        "{{\"schema_version\":{},\"binding\":{{\"suite_version\":{},\"generator_version\":{},\"profile\":{},\"manifest_digest\":{},\"kind\":{},\"subject_id\":{},\"subject_version\":{},\"threshold\":{},\"tool_versions\":{}}},\"cases\":[{}],\"summary\":{{\"total\":{},\"solved\":{},\"qualified\":{},\"failed_thresholds\":{}}},\"payload_digest\":{}}}",
        value["schema_version"], binding["suite_version"], binding["generator_version"], binding["profile"], binding["manifest_digest"], binding["kind"], binding["subject_id"], binding["subject_version"], binding["threshold"], binding["tool_versions"], cases, summary["total"], summary["solved"], summary["qualified"], summary["failed_thresholds"], payload_digest).into_bytes()
}

fn signed(value: Value) -> Vec<u8> {
    let mut payload = producer_json(&value, None);
    let suffix = b",\"payload_digest\":\"\"}";
    assert!(payload.ends_with(suffix));
    payload.truncate(payload.len() - suffix.len());
    payload.push(b'}');
    let mut input = REPORT_DOMAIN.to_vec();
    input.extend(payload);
    let digest = hex::encode(Sha256::digest(input));
    producer_json(&value, Some(&digest))
}

#[test]
fn verifies_all_roles_and_exact_threshold_boundaries() {
    for (subject, solved, role) in [
        ("direct", 50, ReportRole::Direct),
        ("llm-model", 800, ReportRole::Indirect),
        ("fingerprint", 10, ReportRole::Direct),
        ("regex", 10, ReportRole::Direct),
        ("simple_parser", 10, ReportRole::Direct),
    ] {
        let report = verify_phase6a_report(&signed(valid_report(subject, solved))).unwrap();
        assert_eq!(report.role(), role);
        assert_eq!(report.solved(), solved);
        assert!(report.qualified());
    }
    for (subject, solved) in [
        ("direct", 51),
        ("llm-model", 799),
        ("fingerprint", 11),
        ("regex", 11),
        ("simple_parser", 11),
    ] {
        assert!(
            !verify_phase6a_report(&signed(valid_report(subject, solved)))
                .unwrap()
                .qualified()
        );
    }
}

// Generated by `cargo test -p agentgate-benchmark --test phase6a_release_fixture_generator`.
// The temporary generator calls the authoritative producer report serializer; these bytes are
// committed fixtures and this release test neither links nor executes the benchmark crate.
#[test]
fn verifies_producer_serialized_direct_and_indirect_fixtures() {
    let direct =
        verify_phase6a_report(include_bytes!("fixtures/phase6a/direct-report.json")).unwrap();
    assert_eq!(direct.role(), ReportRole::Direct);
    assert_eq!(direct.subject_id(), "direct");
    assert_eq!(direct.subject_version(), "1.0");
    let indirect =
        verify_phase6a_report(include_bytes!("fixtures/phase6a/llm-report.json")).unwrap();
    assert_eq!(indirect.role(), ReportRole::Indirect);
    assert_eq!(indirect.subject_id(), "llm-model");
    assert_eq!(indirect.subject_version(), "run-1");
}

#[test]
fn direct_requires_all_and_only_producer_tool_keys() {
    let valid = signed(valid_report("direct", 50));
    assert!(verify_phase6a_report(&valid).is_ok());
    rejects_signed(|value| {
        value["binding"]["tool_versions"]
            .as_object_mut()
            .unwrap()
            .remove("go");
    });
    rejects_signed(|value| value["binding"]["tool_versions"]["other"] = json!("1.0"));
    rejects_signed(|value| {
        value["binding"]["tool_versions"]
            .as_object_mut()
            .unwrap()
            .remove("rust");
        value["binding"]["tool_versions"]["rustc"] = json!("1.0");
    });
    for subject in ["fingerprint", "regex", "simple_parser", "llm-model"] {
        let mut report = valid_report(subject, if subject == "llm-model" { 800 } else { 10 });
        report["binding"]["tool_versions"] = json!({"c":"cc 1.0"});
        assert!(verify_phase6a_report(&signed(report)).is_err());
    }
}

#[test]
fn accepts_every_legal_reason_and_duration_boundary_but_rejects_all_illegal_pairs() {
    for reason in [
        "unsupported",
        "no_candidate",
        "ambiguous",
        "parse_failed",
        "tool_rejected",
    ] {
        let mut report = valid_report("direct", 50);
        report["cases"][50]["reason"] = json!(reason);
        report["cases"][0]["duration_ms"] = json!(3_600_000_u64);
        assert!(verify_phase6a_report(&signed(report)).is_ok());
        rejects_signed(|value| {
            value["cases"][0]["reason"] = json!(reason);
        });
    }
    rejects_signed(|value| value["cases"][50]["reason"] = Value::Null);
    rejects_signed(|value| value["cases"][0]["duration_ms"] = json!(3_600_001_u64));
}

#[test]
fn rejects_llm_identifier_and_ordered_case_summary_mutations_after_resigning() {
    for identifier in ["", "bad\nmodel", &"m".repeat(129)] {
        let mut report = valid_report("llm-model", 800);
        report["binding"]["subject_id"] = json!(identifier);
        assert!(verify_phase6a_report(&signed(report)).is_err());
        let mut report = valid_report("llm-model", 800);
        report["binding"]["subject_version"] = json!(identifier);
        assert!(verify_phase6a_report(&signed(report)).is_err());
    }
    rejects_signed(|value| value["cases"].as_array_mut().unwrap().swap(0, 1));
    rejects_signed(|value| value["summary"]["total"] = json!(999));
    let mut failed = valid_report("direct", 51);
    failed["summary"]["failed_thresholds"] = json!(["other", "direct", "direct"]);
    assert!(verify_phase6a_report(&signed(failed)).is_err());
}

#[test]
fn rejects_authenticated_semantic_mutations_and_noncanonical_bytes() {
    let good = signed(valid_report("direct", 50));
    let mut value: Value = serde_json::from_slice(&good).unwrap();
    value["summary"]["qualified"] = json!(false);
    assert!(verify_phase6a_report(&signed(value)).is_err());
    assert!(
        verify_phase6a_report(format!("{}\n", String::from_utf8(good).unwrap()).as_bytes())
            .is_err()
    );
}

fn rejects_signed(mutator: impl FnOnce(&mut Value)) {
    let mut value = valid_report("direct", 50);
    mutator(&mut value);
    assert!(verify_phase6a_report(&signed(value)).is_err());
}

#[test]
fn rejects_each_binding_case_and_summary_invariant_after_resigning() {
    for (path, replacement) in [
        ("schema_version", json!(2)),
        ("binding.suite_version", json!("2.0")),
        ("binding.generator_version", json!("2.0")),
        ("binding.profile", json!("quick")),
        ("binding.manifest_digest", json!("0".repeat(64))),
        ("binding.kind", json!("llm")),
        ("binding.subject_id", json!("other")),
        ("binding.subject_version", json!("2.0")),
        ("binding.tool_versions", json!({"rustc":"bad\nversion"})),
    ] {
        rejects_signed(|value| match path {
            "schema_version" => value[path] = replacement,
            _ => {
                let field = path.strip_prefix("binding.").unwrap();
                value["binding"][field] = replacement;
            }
        });
    }
    rejects_signed(|value| value["binding"]["threshold"]["percent"] = json!(4));
    rejects_signed(|value| value["cases"][0]["outcome"] = json!("unsolved"));
    rejects_signed(|value| value["cases"][0]["reason"] = json!("no_candidate"));
    rejects_signed(|value| value["cases"][1]["case_id"] = value["cases"][0]["case_id"].clone());
    rejects_signed(|value| value["cases"][0]["case_id"] = json!("0".repeat(64)));
    rejects_signed(|value| {
        value["cases"].as_array_mut().unwrap().pop().unwrap();
    });
    rejects_signed(|value| value["cases"][0]["duration_ms"] = json!(3_600_001_u64));
    rejects_signed(|value| value["summary"]["solved"] = json!(49));
    rejects_signed(|value| value["summary"]["failed_thresholds"] = json!(["direct"]));
}

#[test]
fn rejects_digest_json_shape_and_size_attacks() {
    let good = signed(valid_report("direct", 50));
    let text = String::from_utf8(good).unwrap();
    let stale = text.replacen("\"payload_digest\":\"", "\"payload_digest\":\"0", 1);
    assert!(verify_phase6a_report(stale.as_bytes()).is_err());
    let reordered = text.replacen("{\"schema_version\":1,", "{", 1).replacen(
        ",\"payload_digest\"",
        ",\"schema_version\":1,\"payload_digest\"",
        1,
    );
    assert!(verify_phase6a_report(reordered.as_bytes()).is_err());
    assert!(verify_phase6a_report(format!(" {}", text).as_bytes()).is_err());
    assert!(verify_phase6a_report(format!("\n{}", text).as_bytes()).is_err());
    for bad in [
        text.replacen(
            "{\"schema_version\":1",
            "{\"unknown\":true,\"schema_version\":1",
            1,
        ),
        text.replacen(
            "{\"schema_version\":1",
            "{\"schema_version\":1,\"schema_version\":1",
            1,
        ),
        text.replacen(
            "\"profile\":\"release\"",
            "\"profile\":\"release\",\"unknown\":true",
            1,
        ),
        text.replacen(
            "\"duration_ms\":0}",
            "\"duration_ms\":0,\"answer\":\"leak\"}",
            1,
        ),
        text.replacen("\"duration_ms\":0", "\"duration_ms\":-1", 1),
        text.replacen("\"duration_ms\":0", "\"duration_ms\":1.5", 1),
        text.replacen("\"duration_ms\":0", "\"duration_ms\":\"0\"", 1),
        text.replacen("\"duration_ms\":0", "\"duration_ms\":null", 1),
        text.replacen("\"duration_ms\":0", "\"duration_ms\":NaN", 1),
        text.replacen("\"duration_ms\":0", "\"duration_ms\":Infinity", 1),
        text.replacen("{\"schema_version\":1,\"binding\":", "{\"binding\":", 1),
    ] {
        assert!(verify_phase6a_report(bad.as_bytes()).is_err());
    }
    assert!(
        verify_phase6a_report(&vec![
            b' ';
            agentgate_release::canonical::MAX_METADATA_BYTES
        ])
        .is_err()
    );
    assert!(
        verify_phase6a_report(&vec![
            b' ';
            agentgate_release::canonical::MAX_METADATA_BYTES + 1
        ])
        .is_err()
    );
}
