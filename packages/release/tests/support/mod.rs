use std::{collections::BTreeMap, fmt::Write as _, fs, path::Path};

use coggate_release::{
    Target,
    canonical::{canonical_pretty_sorted, sha256_hex},
    create_phase5d_receipt, create_phase6a_receipt, create_sanitizer_receipt,
    receipt::write_receipt,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

pub const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const SUITE_DIGEST: &str = "2a8ca741f05cad9fc902c849015ce7d678442f7669fc80a170733758b57aa8f5";
const RELEASE_SCORED_NAMESPACE: &[u8] = b"phase6a-release-scored-v1";

pub fn evidence_fixture(qualified: bool, payload: Option<&[u8]>) -> TempDir {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("receipts")).unwrap();
    fs::create_dir_all(root.join("phase5d")).unwrap();
    fs::create_dir_all(root.join("phase6a")).unwrap();
    for (role, directory, target) in [
        ("linux", "x86_64-unknown-linux-gnu", Target::LinuxX86_64),
        ("macos", "x86_64-apple-darwin", Target::MacosX86_64),
        ("windows", "x86_64-pc-windows-msvc", Target::WindowsX86_64),
    ] {
        let artifact = root.join("phase5d").join(directory).join("artifact");
        build_artifact(&artifact, target, payload);
        write_receipt(
            &root.join("receipts").join(format!("{role}.json")),
            &create_phase5d_receipt(COMMIT, target, &artifact).unwrap(),
        )
        .unwrap();
    }
    write_receipt(
        &root.join("receipts/sanitizer.json"),
        &create_sanitizer_receipt(COMMIT, "1.85.0", "17.0.0").unwrap(),
    )
    .unwrap();
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
        fs::write(&report, signed_report(subject, solved)).unwrap();
        fs::write(&summary, b"# Release\nqualified: safe\n").unwrap();
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

pub fn replace_llm_report(root: &Path, solved: usize) {
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("llm-model-release.json");
    let summary = source_dir.path().join("llm-model-release.md");
    fs::write(&source, signed_report("llm-model", solved)).unwrap();
    fs::write(&summary, b"# Release\nqualified: false\n").unwrap();
    let receipt = create_phase6a_receipt(COMMIT, &source, &summary).unwrap();
    fs::copy(&source, root.join("phase6a/llm/report.json")).unwrap();
    fs::copy(&summary, root.join("phase6a/llm/report.md")).unwrap();
    write_reissued_receipt(&root.join("receipts/llm.json"), &receipt);
}

pub fn mutate_receipt_commit(root: &Path, role: &str) {
    let (directory, target) = match role {
        "linux" => ("x86_64-unknown-linux-gnu", Target::LinuxX86_64),
        "macos" => ("x86_64-apple-darwin", Target::MacosX86_64),
        "windows" => ("x86_64-pc-windows-msvc", Target::WindowsX86_64),
        _ => panic!("test helper requires a Phase 5D receipt"),
    };
    let receipt = create_phase5d_receipt(
        "fedcba9876543210fedcba9876543210fedcba98",
        target,
        &root.join("phase5d").join(directory).join("artifact"),
    )
    .unwrap();
    write_reissued_receipt(
        &root.join("receipts").join(format!("{role}.json")),
        &receipt,
    );
}

pub fn signed_report(subject: &str, solved: usize) -> Vec<u8> {
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
    let cases = (0..1000).map(|index| {
        if index < solved {
            json!({"case_id":case_id(index),"outcome":"solved","reason":null,"duration_ms":index})
        } else {
            json!({"case_id":case_id(index),"outcome":"unsolved","reason":"no_candidate","duration_ms":index})
        }
    }).collect::<Vec<_>>();
    let report = json!({
        "schema_version":1,
        "binding":{"suite_version":"1.1","generator_version":"1.0","profile":"release","manifest_digest":SUITE_DIGEST,"kind":if llm {"llm"} else {"baseline"},"subject_id":subject,"subject_version":if llm {"run-1"} else {"1.0"},"threshold":threshold,"tool_versions":tools},
        "cases":cases,
        "summary":{"total":1000,"solved":solved,"qualified":qualified,"failed_thresholds":if qualified {json!([])} else {json!([subject])}},
        "payload_digest":""
    });
    let mut unsigned = report_json(&report, None);
    unsigned.truncate(unsigned.len() - b",\"payload_digest\":\"\"}".len());
    unsigned.push(b'}');
    let mut input = b"coggate:benchmark-report:v1".to_vec();
    input.extend(unsigned);
    report_json(&report, Some(&hex::encode(Sha256::digest(input))))
}

pub fn write_reissued_receipt(path: &Path, receipt: &coggate_release::Receipt) {
    let _ = fs::remove_file(path);
    write_receipt(path, receipt).unwrap();
}

fn report_json(report: &Value, digest: Option<&str>) -> Vec<u8> {
    let binding = &report["binding"];
    let cases = report["cases"]
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
    let summary = &report["summary"];
    format!(
        "{{\"schema_version\":{},\"binding\":{{\"suite_version\":{},\"generator_version\":{},\"profile\":{},\"manifest_digest\":{},\"kind\":{},\"subject_id\":{},\"subject_version\":{},\"threshold\":{},\"tool_versions\":{}}},\"cases\":[{}],\"summary\":{{\"total\":{},\"solved\":{},\"qualified\":{},\"failed_thresholds\":{}}},\"payload_digest\":{}}}",
        report["schema_version"], binding["suite_version"], binding["generator_version"], binding["profile"], binding["manifest_digest"], binding["kind"], binding["subject_id"], binding["subject_version"], binding["threshold"], binding["tool_versions"], cases, summary["total"], summary["solved"], summary["qualified"], summary["failed_thresholds"], digest.map(|value| serde_json::to_string(value).unwrap()).unwrap_or_else(|| "\"\"".into())
    ).into_bytes()
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

fn build_artifact(root: &Path, target: Target, payload: Option<&[u8]>) {
    for path in artifact_paths(target) {
        if path == "smoke/abi_probe.c" {
            write(
                root,
                &path,
                payload.unwrap_or(b"payload:smoke/abi_probe.c\n"),
            );
        } else if path == "node/package.json" {
            write(root, &path, br#"{"name":"coggate"}"#);
        } else {
            write(root, &path, format!("payload:{path}\n").as_bytes());
        }
    }
    let paths = artifact_paths(target);
    let (os, arch, triple) = (target.os(), target.arch(), target.triple());
    let files = paths.iter().map(|path| {
        let bytes = fs::read(root.join(path)).unwrap();
        json!({"kind":artifact_kind(path),"path":path,"sha256":sha256_hex(&bytes),"size":bytes.len()})
    }).collect::<Vec<_>>();
    write(
        root,
        "manifest.json",
        &canonical_pretty_sorted(&json!({
            "schema_version":1,"coggate_version":"0.1.0","abi_version":1,
            "target":{"os":os,"arch":arch,"triple":triple},"tools":artifact_tools(),"files":files
        }))
        .unwrap(),
    );
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

fn artifact_paths(target: Target) -> Vec<String> {
    let shared = match target {
        Target::LinuxX86_64 => "libcoggate_ffi.so",
        Target::MacosX86_64 => "libcoggate_ffi.dylib",
        Target::WindowsX86_64 => "coggate_ffi.dll",
    };
    let static_lib = if target == Target::WindowsX86_64 {
        "coggate_ffi.lib"
    } else {
        "libcoggate_ffi.a"
    };
    let jni = match target {
        Target::LinuxX86_64 => "libcoggate_jni.so",
        Target::MacosX86_64 => "libcoggate_jni.dylib",
        Target::WindowsX86_64 => "coggate_jni.dll",
    };
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
        "node/README.md".into(),
        "node/scripts/verify-package.mjs".into(),
        "node/lib/index.js".into(),
        "node/examples/complete.js".into(),
        "node/build/Release/coggate.node".into(),
        format!("node/build/Release/{shared}"),
        "smoke/abi_probe.c".into(),
        "smoke/abi_probe.cpp".into(),
    ];
    if target == Target::WindowsX86_64 {
        paths.push("native/coggate_ffi.dll.lib".into());
    }
    paths.sort();
    paths
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
