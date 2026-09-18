use std::{collections::BTreeMap, env, fs, path::PathBuf, process::Command};

use coggate_release::{Phase6aError, ReportRole, verify_phase6a_report};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REPORT_DOMAIN: &[u8] = b"coggate:benchmark-report:v1";
const MANIFEST_DOMAIN: &[u8] = b"coggate:suite-manifest:v1";
const CASE_DOMAIN: &[u8] = b"coggate:benchmark-case:v1";
const RELEASE_SCORED_NAMESPACE: &[u8] = b"phase6a-release-scored-v1";

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
    hash.update((RELEASE_SCORED_NAMESPACE.len() as u64).to_be_bytes());
    hash.update(RELEASE_SCORED_NAMESPACE);
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
    json!({"schema_version":1,"binding":{"suite_version":"1.1","generator_version":"1.0","profile":"release","manifest_digest":manifest_digest(),"kind":kind,"subject_id":subject,"subject_version":version,"threshold":threshold,"tool_versions":tools},"cases":cases,"summary":{"total":1000,"solved":solved,"qualified":qualified,"failed_thresholds":failed},"payload_digest":""})
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
    rejects_signed(|value| value["binding"]["tool_versions"]["rust"] = json!("rustc\nforged"));
    rejects_signed(|value| value["binding"]["tool_versions"]["rust"] = json!("r".repeat(129)));
    for subject in ["fingerprint", "regex", "simple_parser", "llm-model"] {
        let mut report = valid_report(subject, if subject == "llm-model" { 800 } else { 10 });
        report["binding"]["tool_versions"] = json!({"c":"cc 1.0"});
        assert!(verify_phase6a_report(&signed(report)).is_err());
    }
}

fn only_json_report(directory: &std::path::Path) -> PathBuf {
    let reports = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            !name.starts_with('.')
                && entry.file_type().unwrap().is_file()
                && !entry.file_type().unwrap().is_symlink()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1, "expected exactly one Phase6A JSON report");
    reports.into_iter().next().unwrap()
}

#[test]
fn cli_report_discovery_accepts_a_non_default_model_stem_only() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("vendor-model-release.json"), b"{}").unwrap();
    fs::write(directory.path().join(".temporary.json"), b"{}").unwrap();
    assert_eq!(
        only_json_report(directory.path()).file_name().unwrap(),
        "vendor-model-release.json"
    );
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
fn rejects_an_independently_signed_extra_case_and_each_failed_threshold_shape() {
    rejects_signed(|value| {
        let extra = value["cases"][999].clone();
        value["cases"].as_array_mut().unwrap().push(extra);
        value["cases"][1000]["case_id"] = json!(case_id(1000));
    });
    // The contract has cardinality zero or one; multi-entry lists are duplicate or extra.
    for thresholds in [
        json!([]),
        json!(["direct", "direct"]),
        json!(["other"]),
        json!(["direct", "other"]),
    ] {
        let mut failed = valid_report("direct", 51);
        failed["summary"]["failed_thresholds"] = thresholds;
        assert!(verify_phase6a_report(&signed(failed)).is_err());
    }
}

// Task9 CI invokes this explicitly with --ignored after provisioning pinned toolchains and a
// real scored LLM exchange. It is intentionally outside the normal synthetic release gate.
#[test]
#[ignore = "requires pinned Phase6A toolchains and scored LLM input"]
fn real_phase6a_cli_parity() {
    let binary = env::var_os("COGGATE_PHASE6A_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/coggate-bench")
        });
    assert!(
        binary.is_file(),
        "Phase6A CLI binary is required: {}",
        binary.display()
    );
    let baselines = tempfile::tempdir().unwrap();
    let outcome = Command::new(&binary)
        .args(["run-baselines", "--profile", "release", "--output"])
        .arg(baselines.path())
        .output()
        .unwrap();
    assert!(
        outcome.status.success(),
        "run-baselines failed: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let direct = fs::read(baselines.path().join("direct-release.json")).unwrap();
    assert_eq!(
        verify_phase6a_report(&direct).unwrap().role(),
        ReportRole::Direct
    );
    let input = env::var_os("COGGATE_PHASE6A_LLM_INPUT")
        .map(PathBuf::from)
        .expect("COGGATE_PHASE6A_LLM_INPUT must name a valid 1000-case scored LLM input");
    let llm = tempfile::tempdir().unwrap();
    let outcome = Command::new(&binary)
        .args(["score-llm", "--profile", "release", "--input"])
        .arg(input)
        .arg("--output")
        .arg(llm.path())
        .output()
        .unwrap();
    assert!(
        outcome.status.success(),
        "score-llm failed: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let report = fs::read(only_json_report(llm.path())).unwrap();
    assert_eq!(
        verify_phase6a_report(&report).unwrap().role(),
        ReportRole::Indirect
    );
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
    let valid = signed(valid_report("direct", 50));
    assert!(valid.len() <= coggate_release::canonical::MAX_METADATA_BYTES);
    assert!(verify_phase6a_report(&valid).is_ok());
    let exact = vec![b' '; coggate_release::canonical::MAX_METADATA_BYTES];
    assert_ne!(
        verify_phase6a_report(&exact).unwrap_err(),
        Phase6aError::InputTooLarge
    );
    let plus_one = vec![b' '; coggate_release::canonical::MAX_METADATA_BYTES + 1];
    assert_eq!(
        verify_phase6a_report(&plus_one).unwrap_err(),
        Phase6aError::InputTooLarge
    );
}
