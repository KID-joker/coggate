use std::{collections::BTreeMap, fmt::Write as _, fs, path::Path};

use coggate_release::{
    DecisionError, EvidenceSet, Target,
    canonical::{canonical_pretty_sorted, sha256_hex},
    create_phase5d_receipt, create_phase6a_receipt, create_sanitizer_receipt,
    receipt::write_receipt,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const SUITE_DIGEST: &str = "2a8ca741f05cad9fc902c849015ce7d678442f7669fc80a170733758b57aa8f5";
const RELEASE_SCORED_NAMESPACE: &[u8] = b"phase6a-release-scored-v1";

#[test]
fn load_rejects_an_invalid_commit_before_reading_the_layout() {
    assert!(EvidenceSet::load(Path::new("/does-not-matter"), "not-a-commit").is_err());
}

#[test]
fn loads_the_fixed_complete_layout_and_authorizes_qualified_evidence() {
    let fixture = evidence_fixture(true);
    let loaded = EvidenceSet::load(fixture.path(), COMMIT).unwrap();
    let decision = loaded.authorize().unwrap();
    assert!(decision.authorized());
    assert_eq!(decision.commit(), COMMIT);
    assert_eq!(decision.coggate_version(), "0.1.0");
    assert_eq!(decision.abi_version(), 1);
    assert_eq!(decision.generator_version(), "1.0");
    assert_eq!(decision.receipt_digests().len(), 9);
    loaded.revalidate(fixture.path()).unwrap();
}

#[test]
fn accepts_an_arbitrary_verified_llm_model_id_as_the_llm_role() {
    let fixture = evidence_fixture(true);
    let report_path = fixture.path().join("phase6a/llm/report.json");
    let summary_path = fixture.path().join("phase6a/llm/report.md");
    let mut report = valid_report("gpt-5.6-release", 800);
    report["binding"]["kind"] = json!("llm");
    report["binding"]["subject_version"] = json!("run-2026-09-17");
    report["binding"]["threshold"] = json!({"comparison":"at_least","percent":80});
    report["summary"]["qualified"] = json!(true);
    report["summary"]["failed_thresholds"] = json!([]);
    let source = fixture.path().join("gpt-5.6-release-release.json");
    let source_summary = fixture.path().join("gpt-5.6-release-release.md");
    fs::write(&source, signed(report)).unwrap();
    fs::copy(&summary_path, &source_summary).unwrap();
    let receipt = create_phase6a_receipt(COMMIT, &source, &source_summary).unwrap();
    fs::copy(&source, &report_path).unwrap();
    fs::remove_file(source).unwrap();
    fs::remove_file(source_summary).unwrap();
    fs::remove_file(fixture.path().join("receipts/llm.json")).unwrap();
    write_receipt(&fixture.path().join("receipts/llm.json"), &receipt).unwrap();

    assert!(
        EvidenceSet::load(fixture.path(), COMMIT)
            .unwrap()
            .authorize()
            .unwrap()
            .authorized()
    );
}

#[test]
fn unqualified_evidence_loads_but_blocks_in_sorted_subject_order() {
    let fixture = evidence_fixture(false);
    let loaded = EvidenceSet::load(fixture.path(), COMMIT).unwrap();
    assert_eq!(
        loaded.authorize(),
        Err(DecisionError::Blocked {
            roles: vec!["direct".into()]
        })
    );
}

#[test]
fn rejects_missing_or_extra_layout_entries_and_report_symlinks() {
    let fixture = evidence_fixture(true);
    fs::remove_file(fixture.path().join("receipts/llm.json")).unwrap();
    assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());

    let fixture = evidence_fixture(true);
    fs::write(fixture.path().join("receipts/extra.json"), b"x").unwrap();
    assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());

    let fixture = evidence_fixture(true);
    fs::write(
        fixture.path().join("phase6a/direct/report.json"),
        b"replacement before load",
    )
    .unwrap();
    assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let fixture = evidence_fixture(true);
        let report = fixture.path().join("phase6a/direct/report.json");
        let replacement = fixture.path().join("phase6a/direct/replacement.json");
        fs::rename(&report, &replacement).unwrap();
        symlink(&replacement, &report).unwrap();
        assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());
    }
}

#[test]
fn rejects_changed_receipt_bindings_and_never_turns_invalid_evidence_into_a_block() {
    let fixture = evidence_fixture(false);
    let path = fixture.path().join("receipts/direct.json");
    let bytes = fs::read(&path).unwrap();
    let mut value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap()).unwrap();
    value["commit"] = json!("fedcba9876543210fedcba9876543210fedcba98");
    rewrite_receipt(&path, value);
    assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());
}

#[test]
fn rejects_every_cross_binding_mutation_in_a_reissued_receipt() {
    for (receipt, field, altered) in [
        ("linux.json", "target", json!("x86_64-apple-darwin")),
        ("linux.json", "abi_version", json!(2)),
        ("linux.json", "manifest_version", json!("0.1.1")),
        ("linux.json", "tree_digest", json!("f".repeat(64))),
        ("linux.json", "manifest_digest", json!("e".repeat(64))),
        ("direct.json", "suite_version", json!("2.0")),
        ("direct.json", "generator_version", json!("2.0")),
        ("direct.json", "profile", json!("quick")),
        ("direct.json", "subject_id", json!("fingerprint")),
    ] {
        let fixture = evidence_fixture(true);
        let path = fixture.path().join("receipts").join(receipt);
        mutate_receipt(&path, |value| value["evidence"]["binding"][field] = altered);
        assert!(
            EvidenceSet::load(fixture.path(), COMMIT).is_err(),
            "{receipt}"
        );
    }

    let fixture = evidence_fixture(true);
    let path = fixture.path().join("receipts/direct.json");
    mutate_receipt(&path, |value| {
        value["files"][0]["hash"] = json!("d".repeat(64))
    });
    assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());

    let fixture = evidence_fixture(true);
    fs::write(
        fixture
            .path()
            .join("phase5d/x86_64-unknown-linux-gnu/artifact/unlisted"),
        b"unlisted payload",
    )
    .unwrap();
    assert!(EvidenceSet::load(fixture.path(), COMMIT).is_err());
}

fn evidence_fixture(qualified: bool) -> TempDir {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("receipts")).unwrap();
    fs::create_dir_all(root.join("phase5d")).unwrap();
    fs::create_dir_all(root.join("phase6a")).unwrap();
    for (receipt_name, dir, target) in [
        ("linux", "x86_64-unknown-linux-gnu", Target::LinuxX86_64),
        ("macos", "x86_64-apple-darwin", Target::MacosX86_64),
        ("windows", "x86_64-pc-windows-msvc", Target::WindowsX86_64),
    ] {
        let artifact = root.join("phase5d").join(dir).join("artifact");
        build_artifact(&artifact, target);
        let receipt = create_phase5d_receipt(COMMIT, target, &artifact).unwrap();
        write_receipt(
            &root.join("receipts").join(format!("{receipt_name}.json")),
            &receipt,
        )
        .unwrap();
    }
    let sanitizer = create_sanitizer_receipt(COMMIT, "1.85.0", "17.0.0").unwrap();
    write_receipt(&root.join("receipts/sanitizer.json"), &sanitizer).unwrap();
    for (directory, subject) in [
        ("direct", "direct"),
        ("fingerprint", "fingerprint"),
        ("regex", "regex"),
        ("simple_parser", "simple_parser"),
        ("llm", "llm-model"),
    ] {
        let source = root.join("source").join(directory);
        fs::create_dir_all(&source).unwrap();
        let report = source.join(format!("{subject}-release.json"));
        let summary = source.join(format!("{subject}-release.md"));
        let solved = if subject == "llm-model" {
            800
        } else if subject == "direct" && !qualified {
            51
        } else if subject == "direct" {
            50
        } else {
            10
        };
        fs::write(&report, signed(valid_report(subject, solved))).unwrap();
        fs::write(&summary, "# Release\nqualified: safe\n").unwrap();
        let receipt = create_phase6a_receipt(COMMIT, &report, &summary).unwrap();
        let destination = root.join("phase6a").join(directory);
        fs::create_dir(&destination).unwrap();
        fs::copy(&report, destination.join("report.json")).unwrap();
        fs::copy(&summary, destination.join("report.md")).unwrap();
        write_receipt(
            &root.join("receipts").join(format!("{directory}.json")),
            &receipt,
        )
        .unwrap();
    }
    fs::remove_dir_all(root.join("source")).unwrap();
    temp
}

fn target_details(
    target: Target,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
) {
    match target {
        Target::LinuxX86_64 => (
            "Linux",
            "x86_64",
            "x86_64-unknown-linux-gnu",
            "libcoggate_ffi.so",
            "libcoggate_ffi.a",
            None,
            "libcoggate_jni.so",
        ),
        Target::MacosX86_64 => (
            "Darwin",
            "x86_64",
            "x86_64-apple-darwin",
            "libcoggate_ffi.dylib",
            "libcoggate_ffi.a",
            None,
            "libcoggate_jni.dylib",
        ),
        Target::WindowsX86_64 => (
            "Windows",
            "x86_64",
            "x86_64-pc-windows-msvc",
            "coggate_ffi.dll",
            "coggate_ffi.lib",
            Some("coggate_ffi.dll.lib"),
            "coggate_jni.dll",
        ),
    }
}

fn artifact_paths(target: Target) -> Vec<String> {
    let (_, _, _, shared, static_lib, import, jni) = target_details(target);
    let mut paths = vec![
        "include/coggate.h".into(),
        format!("native/{shared}"),
        format!("native/{static_lib}"),
        "go/go.mod".into(),
        "go/coggate/bindings.go".into(),
        "go/examples/complete/main.go".into(),
        "java/coggate-java-0.1.0-SNAPSHOT.jar".into(),
        format!("java/{jni}"),
        format!("java/{shared}"),
        "java/examples/Complete.java".into(),
        "node/package.json".into(),
        "node/lib/index.js".into(),
        "node/examples/complete.js".into(),
        "node/build/Release/coggate.node".into(),
        format!("node/build/Release/{shared}"),
        "smoke/abi_probe.c".into(),
        "smoke/abi_probe.cpp".into(),
    ];
    if let Some(import) = import {
        paths.push(format!("native/{import}"));
    }
    paths.sort();
    paths
}

fn build_artifact(root: &Path, target: Target) {
    for path in artifact_paths(target) {
        write(root, &path, format!("payload:{path}\n").as_bytes());
    }
    let (os, arch, triple, _, _, _, _) = target_details(target);
    let paths = artifact_paths(target);
    let files = paths.iter().map(|path| {
        let bytes = fs::read(root.join(path)).unwrap();
        json!({"kind": artifact_kind(path), "path": path, "sha256": sha256_hex(&bytes), "size": bytes.len()})
    }).collect::<Vec<_>>();
    let manifest = canonical_pretty_sorted(&json!({"schema_version":1,"coggate_version":"0.1.0","abi_version":1,"target":{"os":os,"arch":arch,"triple":triple},"tools":artifact_tools(),"files":files})).unwrap();
    write(root, "manifest.json", &manifest);
    let mut names = paths;
    names.push("manifest.json".into());
    names.sort();
    let mut sums = String::new();
    for name in names {
        writeln!(
            sums,
            "{}  {name}",
            sha256_hex(&fs::read(root.join(&name)).unwrap())
        )
        .unwrap();
    }
    write(root, "SHA256SUMS", sums.as_bytes());
}

fn artifact_kind(path: &str) -> &'static str {
    if path == "include/coggate.h" {
        "header"
    } else if path.starts_with("native/") {
        "native-library"
    } else if path.ends_with(".jar") {
        "java-archive"
    } else if path.ends_with(".so")
        || path.ends_with(".dylib")
        || path.ends_with(".dll")
        || path.ends_with(".node")
        || path.ends_with(".lib")
        || path.ends_with(".a")
    {
        "runtime-binary"
    } else if path.starts_with("smoke/") {
        "smoke-source"
    } else if path.ends_with(".go") || path.ends_with(".java") || path.ends_with(".js") {
        "source"
    } else {
        "metadata"
    }
}

fn artifact_tools() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("cargo", "1.85.0"),
        ("rustc", "1.85.0"),
        ("python", "3.11.0"),
        ("go", "1.24.0"),
        ("java", "17.0.0"),
        ("javac", "17.0.0"),
        ("cmake", "3.26.0"),
        ("ctest", "3.26.0"),
        ("maven", "3.9.0"),
        ("node", "22.18.0"),
        ("node_api", "9"),
        ("node_gyp", "12.1.0"),
        ("cc", "17.0.0"),
        ("cxx", "17.0.0"),
    ])
}
fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn case_id(index: usize) -> String {
    let mut hash = Sha256::new();
    hash.update(b"coggate:benchmark-case:v1");
    hash.update((SUITE_DIGEST.len() as u64).to_be_bytes());
    hash.update(SUITE_DIGEST.as_bytes());
    hash.update((b"scored".len() as u64).to_be_bytes());
    hash.update(b"scored");
    hash.update((RELEASE_SCORED_NAMESPACE.len() as u64).to_be_bytes());
    hash.update(RELEASE_SCORED_NAMESPACE);
    hash.update((index as u64).to_be_bytes());
    hex::encode(hash.finalize())
}
fn valid_report(subject: &str, solved: usize) -> Value {
    let llm = subject == "llm-model";
    let threshold = if llm {
        json!({"comparison":"at_least","percent":80})
    } else if subject == "direct" {
        json!({"comparison":"at_most","percent":5})
    } else {
        json!({"comparison":"at_most","percent":1})
    };
    let qualified = if llm {
        solved >= 800
    } else if subject == "direct" {
        solved <= 50
    } else {
        solved <= 10
    };
    let tools = if subject == "direct" {
        json!({"c":"cc 1.0","cpp":"c++ 1.0","go":"go1.23.6","java":"openjdk 21","rust":"rustc 1.85.0"})
    } else {
        json!({})
    };
    let cases = (0..1000).map(|index| if index < solved { json!({"case_id":case_id(index),"outcome":"solved","reason":null,"duration_ms":index}) } else { json!({"case_id":case_id(index),"outcome":"unsolved","reason":"no_candidate","duration_ms":index}) }).collect::<Vec<_>>();
    json!({"schema_version":1,"binding":{"suite_version":"1.1","generator_version":"1.0","profile":"release","manifest_digest":SUITE_DIGEST,"kind":if llm {"llm"} else {"baseline"},"subject_id":subject,"subject_version":if llm {"run-1"} else {"1.0"},"threshold":threshold,"tool_versions":tools},"cases":cases,"summary":{"total":1000,"solved":solved,"qualified":qualified,"failed_thresholds":if qualified {json!([])} else {json!([subject])}},"payload_digest":""})
}
fn report_json(value: &Value, digest: Option<&str>) -> Vec<u8> {
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
    format!("{{\"schema_version\":{},\"binding\":{{\"suite_version\":{},\"generator_version\":{},\"profile\":{},\"manifest_digest\":{},\"kind\":{},\"subject_id\":{},\"subject_version\":{},\"threshold\":{},\"tool_versions\":{}}},\"cases\":[{}],\"summary\":{{\"total\":{},\"solved\":{},\"qualified\":{},\"failed_thresholds\":{}}},\"payload_digest\":{}}}",value["schema_version"],binding["suite_version"],binding["generator_version"],binding["profile"],binding["manifest_digest"],binding["kind"],binding["subject_id"],binding["subject_version"],binding["threshold"],binding["tool_versions"],cases,summary["total"],summary["solved"],summary["qualified"],summary["failed_thresholds"],digest.map(|value|serde_json::to_string(value).unwrap()).unwrap_or_else(||"\"\"".into())).into_bytes()
}
fn signed(value: Value) -> Vec<u8> {
    let mut payload = report_json(&value, None);
    payload.truncate(payload.len() - b",\"payload_digest\":\"\"}".len());
    payload.push(b'}');
    let mut input = b"coggate:benchmark-report:v1".to_vec();
    input.extend(payload);
    report_json(&value, Some(&hex::encode(Sha256::digest(input))))
}

fn rewrite_receipt(path: &Path, mut value: Value) {
    value.as_object_mut().unwrap().remove("evidence_digest");
    let mut bytes = b"coggate:release-receipt:v1".to_vec();
    bytes.extend(coggate_release::canonical::canonical_compact(&value).unwrap());
    value["evidence_digest"] = json!(sha256_hex(&bytes));
    let mut encoded = coggate_release::canonical::canonical_compact(&value).unwrap();
    encoded.push(b'\n');
    fs::write(path, encoded).unwrap();
}

fn mutate_receipt(path: &Path, mutate: impl FnOnce(&mut Value)) {
    let bytes = fs::read(path).unwrap();
    let mut value: Value = serde_json::from_slice(bytes.strip_suffix(b"\n").unwrap()).unwrap();
    mutate(&mut value);
    rewrite_receipt(path, value);
}
