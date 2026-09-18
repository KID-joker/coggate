use std::{collections::BTreeMap, fmt::Write as _, fs, path::Path};

use coggate_release::{
    EvidenceBinding, Target,
    canonical::{canonical_pretty_sorted, sha256_hex},
    create_phase5d_receipt, create_phase6a_receipt, create_sanitizer_receipt,
    verify_phase5d_artifact, verify_phase6a_report,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
// Fixed verifier-compatible value for this entirely synthetic report fixture.
const SYNTHETIC_SUITE_DIGEST: &str =
    "2a8ca741f05cad9fc902c849015ce7d678442f7669fc80a170733758b57aa8f5";
const RELEASE_SCORED_NAMESPACE: &[u8] = b"phase6a-release-scored-v1";

#[test]
fn sanitizer_producer_creates_a_self_verifying_payload_free_receipt() {
    let receipt = create_sanitizer_receipt(COMMIT, "1.85.0", "17.0.0").unwrap();
    assert!(receipt.files().is_empty());
    let encoded = receipt.to_canonical_json().unwrap();
    assert_eq!(
        coggate_release::Receipt::parse_and_verify(&encoded).unwrap(),
        receipt
    );
}

#[test]
fn sanitizer_rejects_invalid_versions_and_commit() {
    for version in [
        "",
        ".1",
        "1.",
        "1..2",
        "1-a",
        "1\n2",
        "123456789012345678901234567890123",
    ] {
        assert!(create_sanitizer_receipt(COMMIT, version, "17.0.0").is_err());
        assert!(create_sanitizer_receipt(COMMIT, "1.85.0", version).is_err());
    }
    assert!(create_sanitizer_receipt("not-a-commit", "1.85.0", "17.0.0").is_err());
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn phase5d_paths() -> Vec<&'static str> {
    vec![
        "include/coggate.h",
        "native/libcoggate_ffi.so",
        "native/libcoggate_ffi.a",
        "go/go.mod",
        "go/coggate/bindings.go",
        "go/examples/complete/main.go",
        "java/coggate-java-0.1.0-SNAPSHOT.jar",
        "java/libcoggate_jni.so",
        "java/libcoggate_ffi.so",
        "java/examples/Complete.java",
        "node/package.json",
        "node/README.md",
        "node/scripts/verify-package.mjs",
        "node/lib/index.js",
        "node/examples/complete.js",
        "node/build/Release/coggate.node",
        "node/build/Release/libcoggate_ffi.so",
        "smoke/abi_probe.c",
        "smoke/abi_probe.cpp",
    ]
}

fn phase5d_kind(path: &str) -> &'static str {
    if path == "include/coggate.h" {
        "header"
    } else if path.starts_with("native/") {
        "native-library"
    } else if path.ends_with(".jar") {
        "java-archive"
    } else if path.ends_with(".so") || path.ends_with(".a") || path.ends_with(".node") {
        "runtime-binary"
    } else if path.starts_with("smoke/") {
        "smoke-source"
    } else if path.ends_with(".go") || path.ends_with(".java") || path.ends_with(".js") {
        "source"
    } else {
        "metadata"
    }
}

fn phase5d_tools() -> BTreeMap<&'static str, &'static str> {
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

fn phase5d_fixture() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("artifact");
    fs::create_dir(&root).unwrap();
    let mut paths = phase5d_paths();
    paths.sort();
    for path in &paths {
        write(&root, path, format!("payload:{path}\n").as_bytes());
    }
    let files = paths.iter().map(|path| {
        let bytes = fs::read(root.join(path)).unwrap();
        json!({"kind":phase5d_kind(path),"path":path,"sha256":sha256_hex(&bytes),"size":bytes.len()})
    }).collect::<Vec<_>>();
    let manifest = json!({
        "abi_version":1,"coggate_version":"0.1.0","files":files,"schema_version":1,
        "target":{"arch":"x86_64","os":"Linux","triple":"x86_64-unknown-linux-gnu"},
        "tools":phase5d_tools()
    });
    let manifest = canonical_pretty_sorted(&manifest).unwrap();
    write(&root, "manifest.json", &manifest);
    let mut checksum_paths = paths
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    checksum_paths.push("manifest.json".to_owned());
    checksum_paths.sort();
    let mut sums = String::new();
    for path in checksum_paths {
        writeln!(
            sums,
            "{}  {path}",
            sha256_hex(&fs::read(root.join(&path)).unwrap())
        )
        .unwrap();
    }
    write(&root, "SHA256SUMS", sums.as_bytes());
    (tmp, root)
}

#[test]
fn phase5d_producer_binds_verifier_metadata_without_source_paths() {
    let (_tmp, root) = phase5d_fixture();
    let receipt = create_phase5d_receipt(COMMIT, Target::LinuxX86_64, &root).unwrap();
    let verified = verify_phase5d_artifact(&root, Target::LinuxX86_64).unwrap();
    let value: Value = serde_json::from_slice(&receipt.to_canonical_json().unwrap()).unwrap();
    assert_eq!(value["files"][0]["path"], "SHA256SUMS");
    assert_eq!(value["files"][1]["path"], "manifest.json");
    assert_eq!(
        value["evidence"]["binding"]["tree_digest"],
        verified.tree_digest()
    );
    assert_eq!(
        value["evidence"]["binding"]["manifest_digest"],
        verified.manifest_file().sha256()
    );
    assert!(
        !receipt
            .to_canonical_json()
            .unwrap()
            .windows(root.to_string_lossy().len())
            .any(|window| window == root.to_string_lossy().as_bytes())
    );
    assert!(create_phase5d_receipt(COMMIT, Target::MacosX86_64, &root).is_err());
}

#[test]
#[cfg(unix)]
fn phase5d_producer_rejects_a_symlinked_artifact_root() {
    use std::os::unix::fs::symlink;
    let (_tmp, root) = phase5d_fixture();
    let link_parent = TempDir::new().unwrap();
    let link = link_parent.path().join("artifact-link");
    symlink(&root, &link).unwrap();
    assert!(create_phase5d_receipt(COMMIT, Target::LinuxX86_64, &link).is_err());
}

fn case_id(index: usize) -> String {
    let mut hash = Sha256::new();
    hash.update(b"coggate:benchmark-case:v1");
    hash.update((SYNTHETIC_SUITE_DIGEST.len() as u64).to_be_bytes());
    hash.update(SYNTHETIC_SUITE_DIGEST.as_bytes());
    hash.update((b"scored".len() as u64).to_be_bytes());
    hash.update(b"scored");
    hash.update((RELEASE_SCORED_NAMESPACE.len() as u64).to_be_bytes());
    hash.update(RELEASE_SCORED_NAMESPACE);
    hash.update((index as u64).to_be_bytes());
    hex::encode(hash.finalize())
}

fn signed_report(subject: &str, solved: usize) -> Vec<u8> {
    let cases = (0..1000).map(|index| {
        if index < solved { json!({"case_id":case_id(index),"outcome":"solved","reason":null,"duration_ms":index}) }
        else { json!({"case_id":case_id(index),"outcome":"unsolved","reason":"no_candidate","duration_ms":index}) }
    }).collect::<Vec<_>>();
    let value = json!({
        "schema_version":1,
        "binding":{"suite_version":"1.1","generator_version":"1.0","profile":"release","manifest_digest":SYNTHETIC_SUITE_DIGEST,"kind":"baseline","subject_id":subject,"subject_version":"1.0","threshold":{"comparison":"at_most","percent":5},"tool_versions":{"c":"cc 1.0","cpp":"c++ 1.0","go":"go1.23.6","java":"openjdk 21","rust":"rustc 1.85.0"}},
        "cases":cases,
        "summary":{"total":1000,"solved":solved,"qualified":solved <= 50,"failed_thresholds":if solved <= 50 { json!([]) } else { json!([subject]) }},
        "payload_digest":""
    });
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
    let without_digest = format!(
        "{{\"schema_version\":{},\"binding\":{{\"suite_version\":{},\"generator_version\":{},\"profile\":{},\"manifest_digest\":{},\"kind\":{},\"subject_id\":{},\"subject_version\":{},\"threshold\":{},\"tool_versions\":{}}},\"cases\":[{}],\"summary\":{{\"total\":{},\"solved\":{},\"qualified\":{},\"failed_thresholds\":{}}}}}",
        value["schema_version"],
        binding["suite_version"],
        binding["generator_version"],
        binding["profile"],
        binding["manifest_digest"],
        binding["kind"],
        binding["subject_id"],
        binding["subject_version"],
        binding["threshold"],
        binding["tool_versions"],
        cases,
        summary["total"],
        summary["solved"],
        summary["qualified"],
        summary["failed_thresholds"]
    );
    let mut input = b"coggate:benchmark-report:v1".to_vec();
    input.extend(without_digest.as_bytes());
    let digest = hex::encode(Sha256::digest(input));
    format!(
        "{},\"payload_digest\":\"{}\"}}",
        &without_digest[..without_digest.len() - 1],
        digest
    )
    .into_bytes()
}

#[test]
fn phase6a_producer_binds_verified_report_and_safe_summary() {
    let tmp = TempDir::new().unwrap();
    let report = tmp.path().join("direct-release.json");
    let summary = tmp.path().join("direct-release.md");
    fs::write(&report, signed_report("direct", 51)).unwrap();
    fs::write(&summary, "# Release\nqualified: false\n").unwrap();
    let receipt = create_phase6a_receipt(COMMIT, &report, &summary).unwrap();
    let verified = verify_phase6a_report(&fs::read(&report).unwrap()).unwrap();
    let encoded = receipt.to_canonical_json().unwrap();
    assert!(!String::from_utf8_lossy(&encoded).contains(&*tmp.path().to_string_lossy()));
    match receipt.evidence() {
        EvidenceBinding::Phase6aReport(binding) => {
            assert_eq!(binding.payload_digest, verified.payload_digest());
            assert_eq!(binding.qualified, verified.qualified());
        }
        _ => panic!("wrong receipt evidence"),
    }
    assert_eq!(receipt.files()[0].path(), "report.json");
    assert_eq!(receipt.files()[1].path(), "report.md");
}

#[test]
fn phase6a_producer_rejects_unsafe_summary_and_filename_mismatch_without_leaking_paths() {
    let tmp = TempDir::new().unwrap();
    let report = tmp.path().join("direct-release.json");
    let summary = tmp.path().join("direct-release.md");
    fs::write(&report, signed_report("direct", 50)).unwrap();
    fs::write(&summary, "prompt: hidden\n").unwrap();
    let error = create_phase6a_receipt(COMMIT, &report, &summary).unwrap_err();
    assert!(!error.to_string().contains(&*tmp.path().to_string_lossy()));
    for unsafe_summary in [
        "/",
        "/ \n",
        "\\",
        "\\ \n",
        "path: /tmp/evidence\n",
        "path: \\\\server\\share\n",
        "path: C:\\evidence\n",
    ] {
        fs::write(&summary, unsafe_summary).unwrap();
        assert!(create_phase6a_receipt(COMMIT, &report, &summary).is_err());
    }
    fs::write(&summary, "# Release\nqualified: true\n").unwrap();
    let wrong = tmp.path().join("other-release.md");
    fs::rename(&summary, &wrong).unwrap();
    assert!(create_phase6a_receipt(COMMIT, &report, &wrong).is_err());
}
