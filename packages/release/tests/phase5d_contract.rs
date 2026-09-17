use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use agentgate_release::{
    Phase5dError, Target,
    canonical::{canonical_compact, canonical_pretty_sorted, sha256_hex},
    verify_phase5d_artifact,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const DOMAIN: &[u8] = b"agentgate-phase5d-tree-v1";
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;

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
            "libagentgate_ffi.so",
            "libagentgate_ffi.a",
            None,
            "libagentgate_jni.so",
        ),
        Target::MacosX86_64 => (
            "Darwin",
            "x86_64",
            "x86_64-apple-darwin",
            "libagentgate_ffi.dylib",
            "libagentgate_ffi.a",
            None,
            "libagentgate_jni.dylib",
        ),
        Target::WindowsX86_64 => (
            "Windows",
            "x86_64",
            "x86_64-pc-windows-msvc",
            "agentgate_ffi.dll",
            "agentgate_ffi.lib",
            Some("agentgate_ffi.dll.lib"),
            "agentgate_jni.dll",
        ),
    }
}

fn tools() -> BTreeMap<&'static str, &'static str> {
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

fn paths_for(target: Target) -> Vec<String> {
    let (_, _, _, shared, static_lib, import, jni) = target_details(target);
    let mut paths = vec![
        "include/agentgate.h".to_owned(),
        format!("native/{shared}"),
        format!("native/{static_lib}"),
        "go/go.mod".to_owned(),
        "go/agentgate/bindings.go".to_owned(),
        "go/examples/complete/main.go".to_owned(),
        "java/agentgate-java-0.1.0-SNAPSHOT.jar".to_owned(),
        format!("java/{jni}"),
        format!("java/{shared}"),
        "java/examples/Complete.java".to_owned(),
        "node/package.json".to_owned(),
        "node/lib/index.js".to_owned(),
        "node/examples/complete.js".to_owned(),
        "node/build/Release/agentgate.node".to_owned(),
        format!("node/build/Release/{shared}"),
        "smoke/abi_probe.c".to_owned(),
        "smoke/abi_probe.cpp".to_owned(),
    ];
    if let Some(import) = import {
        paths.push(format!("native/{import}"));
    }
    paths.sort();
    paths
}

fn payload_paths(root: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read fixture directory") {
            let entry = entry.expect("fixture entry");
            let name = entry.file_name().into_string().expect("UTF-8 fixture name");
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let file_type = entry.file_type().expect("fixture type");
            if file_type.is_dir() {
                pending.push((entry.path(), relative));
            } else if file_type.is_file() && relative != "manifest.json" && relative != "SHA256SUMS"
            {
                paths.push(relative);
            }
        }
    }
    paths.sort();
    paths
}

fn kind(path: &str) -> &'static str {
    if path == "include/agentgate.h" {
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
    } else if path.starts_with("smoke/") && (path.ends_with(".c") || path.ends_with(".cpp")) {
        "smoke-source"
    } else if path.ends_with(".go") || path.ends_with(".java") || path.ends_with(".js") {
        "source"
    } else {
        "metadata"
    }
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture directory");
    fs::write(path, bytes).expect("write fixture file");
}

fn manifest_value(root: &Path, target: Target) -> Value {
    let (os, arch, triple, _, _, _, _) = target_details(target);
    let files = payload_paths(root).into_iter().map(|path| {
        let bytes = fs::read(root.join(&path)).expect("read payload");
        json!({"kind": kind(&path), "path": path, "sha256": sha256_hex(&bytes), "size": bytes.len()})
    }).collect::<Vec<_>>();
    json!({
        "abi_version": 1,
        "agentgate_version": "0.1.0",
        "files": files,
        "schema_version": 1,
        "target": {"arch": arch, "os": os, "triple": triple},
        "tools": tools(),
    })
}

fn write_metadata(root: &Path, target: Target) {
    let manifest =
        canonical_pretty_sorted(&manifest_value(root, target)).expect("canonical manifest");
    write(root, "manifest.json", &manifest);
    let mut checksum_paths = payload_paths(root);
    checksum_paths.push("manifest.json".to_owned());
    checksum_paths.sort();
    let mut checksums = String::new();
    for path in checksum_paths {
        checksums.push_str(&sha256_hex(
            &fs::read(root.join(&path)).expect("checksum input"),
        ));
        checksums.push_str("  ");
        checksums.push_str(&path);
        checksums.push('\n');
    }
    write(root, "SHA256SUMS", checksums.as_bytes());
}

fn rewrite_manifest_sizes_and_checksums(root: &Path, target: Target) {
    let _ = target;
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("fixture manifest"))
            .expect("parse fixture manifest");
    for entry in manifest["files"].as_array_mut().expect("fixture files") {
        let path = entry["path"].as_str().expect("fixture path");
        entry["size"] = json!(
            fs::metadata(root.join(path))
                .expect("fixture payload metadata")
                .len()
        );
        entry["sha256"] = json!("0".repeat(64));
    }
    let bytes = canonical_pretty_sorted(&manifest).expect("canonical size fixture manifest");
    write(root, "manifest.json", &bytes);
    let mut paths = payload_paths(root);
    paths.push("manifest.json".to_owned());
    paths.sort();
    let mut text = String::new();
    for path in paths {
        let digest = if path == "manifest.json" {
            sha256_hex(&bytes)
        } else {
            "0".repeat(64)
        };
        text.push_str(&digest);
        text.push_str("  ");
        text.push_str(&path);
        text.push('\n');
    }
    write(root, "SHA256SUMS", text.as_bytes());
}

fn fixture(target: Target) -> (TempDir, PathBuf) {
    let directory = TempDir::new().expect("temporary artifact root");
    let root = directory.path().join("artifact");
    fs::create_dir(&root).expect("create artifact root");
    for path in paths_for(target) {
        write(&root, &path, format!("payload:{path}\n").as_bytes());
    }
    write_metadata(&root, target);
    (directory, root)
}

fn expected_tree_digest(root: &Path, target: Target) -> String {
    let tuples = paths_for(target)
        .into_iter()
        .map(|path| {
            let bytes = fs::read(root.join(&path)).expect("read digest input");
            json!([path, bytes.len(), sha256_hex(&bytes)])
        })
        .collect::<Vec<_>>();
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(canonical_compact(&Value::Array(tuples)).expect("canonical tuples"));
    sha256_hex(&bytes)
}

fn assert_rejected(root: &Path, target: Target) {
    assert!(
        verify_phase5d_artifact(root, target).is_err(),
        "mutation must be rejected"
    );
}

#[test]
fn verifies_exact_linux_macos_and_windows_artifacts() {
    for target in [
        Target::LinuxX86_64,
        Target::MacosX86_64,
        Target::WindowsX86_64,
    ] {
        let (_tmp, root) = fixture(target);
        let artifact = verify_phase5d_artifact(&root, target).expect("valid artifact");
        assert_eq!(artifact.target(), target);
        assert_eq!(artifact.agentgate_version(), "0.1.0");
        assert_eq!(artifact.abi_version(), 1);
        assert_eq!(artifact.target_triple(), target_details(target).2);
        assert_eq!(artifact.tool_versions().len(), 14);
        assert_eq!(artifact.files().len(), paths_for(target).len());
        assert_eq!(artifact.tree_digest().len(), 64);
        assert_eq!(artifact.tree_digest(), expected_tree_digest(&root, target));
    }
}

#[test]
fn rejects_manifest_schema_and_canonicality_mutations() {
    for mutation in [
        "unknown",
        "duplicate",
        "noncanonical",
        "wrong_kind",
        "negative",
        "fraction",
        "oversized",
        "bad_hash",
        "wrong_target",
        "unsupported_target",
    ] {
        let (_tmp, root) = fixture(Target::LinuxX86_64);
        let original = fs::read_to_string(root.join("manifest.json")).expect("manifest text");
        let changed = match mutation {
            "unknown" => {
                let mut value: Value =
                    serde_json::from_str(&original).expect("parse fixture manifest");
                value["unknown"] = json!(true);
                String::from_utf8(
                    canonical_pretty_sorted(&value).expect("canonical unknown fixture"),
                )
                .expect("UTF-8 canonical manifest")
            }
            "duplicate" => original.replacen(
                "  \"abi_version\": 1,\n",
                "  \"abi_version\": 1,\n  \"abi_version\": 1,\n",
                1,
            ),
            "noncanonical" => original.replace("\n", "\r\n"),
            "wrong_kind" => original.replacen("\"kind\": \"header\"", "\"kind\": \"source\"", 1),
            "negative" => original.replacen("\"size\": 28", "\"size\": -1", 1),
            "fraction" => original.replacen("\"size\": 28", "\"size\": 1.5", 1),
            "oversized" => original.replacen("\"size\": 28", "\"size\": 18446744073709551616", 1),
            "bad_hash" => original.replacen("\"sha256\": \"", "\"sha256\": \"A", 1),
            "wrong_target" => original.replace("x86_64-unknown-linux-gnu", "x86_64-apple-darwin"),
            "unsupported_target" => original.replace("\"os\": \"Linux\"", "\"os\": \"FreeBSD\""),
            _ => unreachable!(),
        };
        assert_ne!(original, changed, "{mutation} must mutate the manifest");
        write(&root, "manifest.json", changed.as_bytes());
        assert_rejected(&root, Target::LinuxX86_64);
    }
}

#[test]
fn rejects_payload_checksum_and_layout_mutations() {
    for mutation in [
        "missing",
        "extra",
        "unsafe",
        "unsorted",
        "duplicate",
        "checksum_missing",
        "checksum_extra",
        "checksum_bad",
        "checksum_unsorted",
        "checksum_duplicate",
        "checksum_malformed",
        "checksum_unicode",
        "checksum_crlf",
        "content",
        "replacement",
        "wrong_hash",
    ] {
        let (_tmp, root) = fixture(Target::LinuxX86_64);
        match mutation {
            "missing" => fs::remove_file(root.join("go/go.mod")).expect("remove payload"),
            "extra" => write(&root, "extra.bin", b"extra"),
            "unsafe" | "unsorted" | "duplicate" => {
                let mut value: Value = serde_json::from_slice(
                    &fs::read(root.join("manifest.json")).expect("manifest"),
                )
                .expect("parse manifest");
                let files = value["files"].as_array_mut().expect("files array");
                match mutation {
                    "unsafe" => files[0]["path"] = json!("../escape"),
                    "unsorted" => files.swap(0, 1),
                    "duplicate" => files[1]["path"] = files[0]["path"].clone(),
                    _ => unreachable!(),
                }
                write(
                    &root,
                    "manifest.json",
                    &canonical_pretty_sorted(&value).expect("canonical changed manifest"),
                );
            }
            "checksum_missing" => {
                let mut lines = fs::read_to_string(root.join("SHA256SUMS"))
                    .expect("checksums")
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                lines.remove(0);
                write(
                    &root,
                    "SHA256SUMS",
                    format!("{}\n", lines.join("\n")).as_bytes(),
                );
            }
            "checksum_extra" => {
                let mut text = fs::read_to_string(root.join("SHA256SUMS")).expect("checksums");
                text.push_str(&format!("{}  zzz\n", sha256_hex(b"extra")));
                write(&root, "SHA256SUMS", text.as_bytes());
            }
            "checksum_bad" => {
                let text = fs::read_to_string(root.join("SHA256SUMS")).expect("checksums");
                let suffix = text.split_once("  ").expect("checksum separator").1;
                let text = format!("{}  {suffix}", "g".repeat(64));
                write(&root, "SHA256SUMS", text.as_bytes());
            }
            "checksum_unsorted" => {
                let mut lines = fs::read_to_string(root.join("SHA256SUMS"))
                    .expect("checksums")
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                lines.swap(0, 1);
                write(
                    &root,
                    "SHA256SUMS",
                    format!("{}\n", lines.join("\n")).as_bytes(),
                );
            }
            "checksum_duplicate" => {
                let line = fs::read_to_string(root.join("SHA256SUMS"))
                    .expect("checksums")
                    .lines()
                    .next()
                    .expect("line")
                    .to_owned();
                let text = format!("{line}\n{line}\n");
                write(&root, "SHA256SUMS", text.as_bytes());
            }
            "checksum_malformed" => write(&root, "SHA256SUMS", b"not a checksum\n"),
            "checksum_unicode" => {
                let text = format!("{}\u{e9}  include/agentgate.h\n", "0".repeat(63));
                write(&root, "SHA256SUMS", text.as_bytes());
            }
            "checksum_crlf" => {
                let text = fs::read_to_string(root.join("SHA256SUMS"))
                    .expect("checksums")
                    .replace('\n', "\r\n");
                write(&root, "SHA256SUMS", text.as_bytes());
            }
            "content" => write(&root, "include/agentgate.h", b"mutated content"),
            "replacement" => {
                fs::remove_file(root.join("include/agentgate.h")).expect("remove regular file");
                write(&root, "include/agentgate.h", b"replacement regular file");
            }
            "wrong_hash" => {
                let mut value: Value = serde_json::from_slice(
                    &fs::read(root.join("manifest.json")).expect("manifest"),
                )
                .expect("parse manifest");
                value["files"][0]["sha256"] = json!("0".repeat(64));
                write(
                    &root,
                    "manifest.json",
                    &canonical_pretty_sorted(&value).expect("canonical changed manifest"),
                );
            }
            _ => unreachable!(),
        }
        assert_rejected(&root, Target::LinuxX86_64);
    }
}

#[test]
fn rejects_missing_or_extra_tool_versions_and_windows_import_layout_mismatches() {
    for mutation in [
        "tool_missing",
        "tool_extra",
        "windows_import_missing",
        "windows_import_wrong",
    ] {
        let target = if mutation.starts_with("windows") {
            Target::WindowsX86_64
        } else {
            Target::LinuxX86_64
        };
        let (_tmp, root) = fixture(target);
        match mutation {
            "tool_missing" | "tool_extra" => {
                let mut value: Value = serde_json::from_slice(
                    &fs::read(root.join("manifest.json")).expect("manifest"),
                )
                .expect("parse manifest");
                let tools = value["tools"].as_object_mut().expect("tools object");
                if mutation == "tool_missing" {
                    tools.remove("cargo");
                } else {
                    tools.insert("extra".to_owned(), json!("1.0"));
                }
                write(
                    &root,
                    "manifest.json",
                    &canonical_pretty_sorted(&value).expect("canonical manifest"),
                );
            }
            "windows_import_missing" => fs::remove_file(root.join("native/agentgate_ffi.dll.lib"))
                .expect("remove import library"),
            "windows_import_wrong" => {
                fs::rename(
                    root.join("native/agentgate_ffi.dll.lib"),
                    root.join("native/agentgate_ffi.import.lib"),
                )
                .expect("rename import library");
                write_metadata(&root, target);
            }
            _ => unreachable!(),
        }
        assert_rejected(&root, target);
    }
}

#[test]
fn rejects_file_count_and_sparse_size_limits_before_reading_payloads() {
    let (_tmp, root) = fixture(Target::LinuxX86_64);
    let additions = 256 - paths_for(Target::LinuxX86_64).len() - 2;
    for index in 0..additions {
        write(&root, &format!("node/lib/extra-{index}.js"), b"x");
    }
    write_metadata(&root, Target::LinuxX86_64);
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64)
            .expect("256 files are permitted")
            .files()
            .len()
            + 2,
        256
    );
    write(&root, "node/lib/one-too-many.js", b"x");
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64),
        Err(Phase5dError::FileLimit)
    );

    let (_tmp, root) = fixture(Target::LinuxX86_64);
    for index in 0..257 {
        fs::create_dir(root.join(format!("empty-{index}"))).expect("create empty directory");
    }
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64),
        Err(Phase5dError::DirectoryLimit)
    );

    let (_tmp, root) = fixture(Target::LinuxX86_64);
    fs::create_dir_all(root.join("go/agentgate/unlisted-empty"))
        .expect("create extra empty directory");
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64),
        Err(Phase5dError::UnexpectedDirectory)
    );

    let (_tmp, root) = fixture(Target::LinuxX86_64);
    fs::OpenOptions::new()
        .write(true)
        .open(root.join("include/agentgate.h"))
        .expect("open sparse payload")
        .set_len(MAX_PAYLOAD_BYTES + 1)
        .expect("make sparse payload");
    rewrite_manifest_sizes_and_checksums(&root, Target::LinuxX86_64);
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64),
        Err(Phase5dError::SizeLimit)
    );

    let (_tmp, root) = fixture(Target::LinuxX86_64);
    let payloads = paths_for(Target::LinuxX86_64);
    for path in payloads.iter().take(5) {
        fs::OpenOptions::new()
            .write(true)
            .open(root.join(path))
            .expect("open sparse aggregate payload")
            .set_len(MAX_PAYLOAD_BYTES - (8 * 1024 * 1024))
            .expect("make sparse aggregate payload");
    }
    let sparse_size = fs::metadata(root.join(&payloads[0]))
        .expect("sparse aggregate metadata")
        .len();
    assert!(sparse_size <= MAX_PAYLOAD_BYTES);
    assert!(sparse_size.saturating_mul(5) > MAX_TOTAL_PAYLOAD_BYTES);
    rewrite_manifest_sizes_and_checksums(&root, Target::LinuxX86_64);
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64),
        Err(Phase5dError::SizeLimit)
    );

    let (_tmp, root) = fixture(Target::LinuxX86_64);
    fs::OpenOptions::new()
        .write(true)
        .open(root.join("manifest.json"))
        .expect("open metadata")
        .set_len((8 * 1024 * 1024) + 1)
        .expect("make oversized metadata");
    assert_eq!(
        verify_phase5d_artifact(&root, Target::LinuxX86_64),
        Err(Phase5dError::MetadataLimit)
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_root_directories_and_files() {
    use std::os::unix::fs::symlink;
    for mutation in ["root", "directory", "file"] {
        let (tmp, root) = fixture(Target::LinuxX86_64);
        let check_root = match mutation {
            "root" => {
                let link = tmp.path().join("artifact-link");
                symlink(&root, &link).expect("symlink root");
                link
            }
            "directory" => {
                fs::rename(root.join("go"), root.join("go-real")).expect("move directory");
                symlink(root.join("go-real"), root.join("go")).expect("symlink directory");
                root.clone()
            }
            "file" => {
                fs::rename(
                    root.join("include/agentgate.h"),
                    root.join("include/agentgate-real.h"),
                )
                .expect("move file");
                symlink(
                    root.join("include/agentgate-real.h"),
                    root.join("include/agentgate.h"),
                )
                .expect("symlink file");
                root.clone()
            }
            _ => unreachable!(),
        };
        assert_rejected(&check_root, Target::LinuxX86_64);
    }
}

#[test]
#[ignore = "requires AGENTGATE_PHASE5D_ARTIFACT containing a compatible Phase 5D artifact"]
fn real_phase5d_artifact() {
    let mut candidates = std::env::var("AGENTGATE_PHASE5D_ARTIFACT")
        .ok()
        .map(PathBuf::from)
        .into_iter()
        .collect::<Vec<_>>();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    if let Ok(entries) = fs::read_dir(repo.join("target/phase5d")) {
        for entry in entries.flatten() {
            let artifact = entry.path().join("artifact");
            if artifact.join("manifest.json").is_file() {
                candidates.push(artifact);
            }
        }
    }
    for root in candidates {
        for target in [
            Target::LinuxX86_64,
            Target::MacosX86_64,
            Target::WindowsX86_64,
        ] {
            if verify_phase5d_artifact(&root, target).is_ok() {
                return;
            }
        }
    }
    panic!(
        "no compatible local Phase 5D artifact found; set AGENTGATE_PHASE5D_ARTIFACT or build target/phase5d/*/artifact"
    );
}
