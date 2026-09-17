//! Independent, fail-closed verification of Phase 5D platform artifacts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical::{
    MAX_METADATA_BYTES, canonical_compact, canonical_pretty_sorted, parse_strict_json,
    safe_relative_path, validate_sha256,
};

const VERSION: &str = "0.1.0";
const ABI_VERSION: u32 = 1;
const MANIFEST: &str = "manifest.json";
const CHECKSUMS: &str = "SHA256SUMS";
const MAX_FILES: usize = 256;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;
const TREE_DOMAIN: &[u8] = b"agentgate-phase5d-tree-v1";
const READ_BUFFER_BYTES: usize = 1024 * 1024;

const TOOL_KEYS: [&str; 14] = [
    "cargo", "cc", "cmake", "ctest", "cxx", "go", "java", "javac", "maven", "node", "node_api",
    "node_gyp", "python", "rustc",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    LinuxX86_64,
    MacosX86_64,
    WindowsX86_64,
}

impl Target {
    pub fn os(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "Linux",
            Self::MacosX86_64 => "Darwin",
            Self::WindowsX86_64 => "Windows",
        }
    }

    pub fn arch(self) -> &'static str {
        "x86_64"
    }

    pub fn triple(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Self::MacosX86_64 => "x86_64-apple-darwin",
            Self::WindowsX86_64 => "x86_64-pc-windows-msvc",
        }
    }

    fn shared_name(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "libagentgate_ffi.so",
            Self::MacosX86_64 => "libagentgate_ffi.dylib",
            Self::WindowsX86_64 => "agentgate_ffi.dll",
        }
    }

    fn static_name(self) -> &'static str {
        match self {
            Self::LinuxX86_64 | Self::MacosX86_64 => "libagentgate_ffi.a",
            Self::WindowsX86_64 => "agentgate_ffi.lib",
        }
    }

    fn import_name(self) -> Option<&'static str> {
        match self {
            Self::WindowsX86_64 => Some("agentgate_ffi.dll.lib"),
            Self::LinuxX86_64 | Self::MacosX86_64 => None,
        }
    }

    fn jni_name(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "libagentgate_jni.so",
            Self::MacosX86_64 => "libagentgate_jni.dylib",
            Self::WindowsX86_64 => "agentgate_jni.dll",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFile {
    path: String,
    size: u64,
    sha256: String,
}

impl VerifiedFile {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedArtifact {
    target: Target,
    agentgate_version: String,
    abi_version: u32,
    tool_versions: BTreeMap<String, String>,
    files: Vec<VerifiedFile>,
    tree_digest: String,
}

impl VerifiedArtifact {
    pub fn target(&self) -> Target {
        self.target
    }
    pub fn agentgate_version(&self) -> &str {
        &self.agentgate_version
    }
    pub fn abi_version(&self) -> u32 {
        self.abi_version
    }
    pub fn tool_versions(&self) -> &BTreeMap<String, String> {
        &self.tool_versions
    }
    pub fn files(&self) -> &[VerifiedFile] {
        &self.files
    }
    pub fn tree_digest(&self) -> &str {
        &self.tree_digest
    }
    pub fn target_os(&self) -> &'static str {
        self.target.os()
    }
    pub fn target_triple(&self) -> &'static str {
        self.target.triple()
    }
}

#[derive(Debug, Error)]
pub enum Phase5dError {
    #[error("Phase 5D artifact is invalid")]
    Invalid,
    #[error("Phase 5D artifact could not be read")]
    Io,
    #[error("Phase 5D artifact changed while being verified")]
    Changed,
}

#[derive(Clone)]
struct Identity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_ns: i128,
}

impl Identity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
                change_ns: i128::from(metadata.ctime()) * 1_000_000_000
                    + i128::from(metadata.ctime_nsec()),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.modified == other.modified && {
            #[cfg(unix)]
            {
                self.device == other.device
                    && self.inode == other.inode
                    && self.change_ns == other.change_ns
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
    }
}

struct DiskFile {
    path: PathBuf,
    identity: Identity,
}

#[derive(Clone)]
struct ManifestFile {
    path: String,
    size: u64,
    sha256: String,
}

/// Verify an artifact without relying on the Phase 5D producer or its verdict.
pub fn verify_phase5d_artifact(
    root: &Path,
    expected: Target,
) -> Result<VerifiedArtifact, Phase5dError> {
    let root_identity = require_directory(root)?;
    let mut directories = vec![(root.to_path_buf(), root_identity)];
    let disk = walk_tree(root, &mut directories)?;
    if disk.len() > MAX_FILES {
        return Err(Phase5dError::Invalid);
    }

    let manifest_disk = disk.get(MANIFEST).ok_or(Phase5dError::Invalid)?;
    let checksum_disk = disk.get(CHECKSUMS).ok_or(Phase5dError::Invalid)?;
    let manifest_bytes = read_metadata(manifest_disk)?;
    let checksum_bytes = read_metadata(checksum_disk)?;
    let (files, tools) = validate_manifest(&manifest_bytes, expected)?;

    let expected_paths = files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    let actual_payload = disk
        .keys()
        .filter(|path| path.as_str() != MANIFEST && path.as_str() != CHECKSUMS)
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_paths != actual_payload {
        return Err(Phase5dError::Invalid);
    }

    let mut total = 0_u64;
    for file in &files {
        if file.size > MAX_PAYLOAD_BYTES {
            return Err(Phase5dError::Invalid);
        }
        total = total.checked_add(file.size).ok_or(Phase5dError::Invalid)?;
        if total > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(Phase5dError::Invalid);
        }
        let disk_file = disk.get(&file.path).ok_or(Phase5dError::Invalid)?;
        if disk_file.identity.len > MAX_PAYLOAD_BYTES || disk_file.identity.len != file.size {
            return Err(Phase5dError::Invalid);
        }
    }

    let mut verified = Vec::with_capacity(files.len());
    for file in &files {
        let disk_file = disk.get(&file.path).ok_or(Phase5dError::Invalid)?;
        let (size, digest) = hash_checked(disk_file, root, &directories, MAX_PAYLOAD_BYTES)?;
        if size != file.size || digest != file.sha256 {
            return Err(Phase5dError::Invalid);
        }
        verified.push(VerifiedFile {
            path: file.path.clone(),
            size,
            sha256: digest,
        });
    }
    let manifest_hash =
        hash_checked(manifest_disk, root, &directories, MAX_METADATA_BYTES as u64)?.1;
    let checksums = parse_checksums(&checksum_bytes)?;
    let wanted_checksums = actual_payload
        .into_iter()
        .chain(std::iter::once(MANIFEST.to_owned()))
        .collect::<BTreeSet<_>>();
    if checksums.keys().cloned().collect::<BTreeSet<_>>() != wanted_checksums {
        return Err(Phase5dError::Invalid);
    }
    for file in &verified {
        if checksums
            .get(file.path())
            .is_none_or(|digest| digest != file.sha256())
        {
            return Err(Phase5dError::Invalid);
        }
    }
    if checksums
        .get(MANIFEST)
        .is_none_or(|digest| digest != &manifest_hash)
    {
        return Err(Phase5dError::Invalid);
    }

    // SHA256SUMS is intentionally not self-hashed, so give it its own final
    // handle-identity check before accepting the parsed bytes.
    let _ = hash_checked(checksum_disk, root, &directories, MAX_METADATA_BYTES as u64)?;
    verify_directories(root, &directories)?;
    let tree_digest = tree_digest(&verified)?;
    Ok(VerifiedArtifact {
        target: expected,
        agentgate_version: VERSION.to_owned(),
        abi_version: ABI_VERSION,
        tool_versions: tools,
        files: verified,
        tree_digest,
    })
}

fn require_directory(path: &Path) -> Result<Identity, Phase5dError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Phase5dError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Phase5dError::Invalid);
    }
    Ok(Identity::from_metadata(&metadata))
}

fn walk_tree(
    root: &Path,
    directories: &mut Vec<(PathBuf, Identity)>,
) -> Result<BTreeMap<String, DiskFile>, Phase5dError> {
    let mut files = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|_| Phase5dError::Io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Phase5dError::Io)?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Phase5dError::Invalid)?;
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            safe_relative_path(&relative).map_err(|_| Phase5dError::Invalid)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| Phase5dError::Io)?;
            if metadata.file_type().is_symlink() {
                return Err(Phase5dError::Invalid);
            }
            if metadata.is_dir() {
                directories.push((path.clone(), Identity::from_metadata(&metadata)));
                pending.push((path, relative));
            } else if metadata.is_file() {
                if files
                    .insert(
                        relative,
                        DiskFile {
                            path,
                            identity: Identity::from_metadata(&metadata),
                        },
                    )
                    .is_some()
                {
                    return Err(Phase5dError::Invalid);
                }
            } else {
                return Err(Phase5dError::Invalid);
            }
        }
    }
    Ok(files)
}

fn read_metadata(file: &DiskFile) -> Result<Vec<u8>, Phase5dError> {
    if file.identity.len > MAX_METADATA_BYTES as u64 {
        return Err(Phase5dError::Invalid);
    }
    let (bytes, _) = read_checked(file, None, MAX_METADATA_BYTES as u64)?;
    Ok(bytes)
}

fn read_checked(
    file: &DiskFile,
    root: Option<&Path>,
    maximum: u64,
) -> Result<(Vec<u8>, String), Phase5dError> {
    let before = fs::symlink_metadata(&file.path).map_err(|_| Phase5dError::Io)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || Identity::from_metadata(&before) != file.identity
    {
        return Err(Phase5dError::Changed);
    }
    let mut opened = File::open(&file.path).map_err(|_| Phase5dError::Io)?;
    let opened_metadata = opened.metadata().map_err(|_| Phase5dError::Io)?;
    if !opened_metadata.is_file()
        || Identity::from_metadata(&opened_metadata) != file.identity
        || opened_metadata.len() > maximum
    {
        return Err(Phase5dError::Changed);
    }
    let capacity = usize::try_from(opened_metadata.len()).map_err(|_| Phase5dError::Invalid)?;
    let mut bytes = Vec::with_capacity(capacity);
    opened
        .by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Phase5dError::Io)?;
    if bytes.len() as u64 > maximum {
        return Err(Phase5dError::Invalid);
    }
    let after = fs::symlink_metadata(&file.path).map_err(|_| Phase5dError::Io)?;
    let after_open = opened.metadata().map_err(|_| Phase5dError::Io)?;
    if after.file_type().is_symlink()
        || Identity::from_metadata(&after) != file.identity
        || Identity::from_metadata(&after_open) != file.identity
    {
        return Err(Phase5dError::Changed);
    }
    if let Some(root) = root {
        let _ = require_directory(root)?;
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, digest))
}

fn hash_checked(
    file: &DiskFile,
    root: &Path,
    directories: &[(PathBuf, Identity)],
    maximum: u64,
) -> Result<(u64, String), Phase5dError> {
    let before = fs::symlink_metadata(&file.path).map_err(|_| Phase5dError::Io)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || Identity::from_metadata(&before) != file.identity
        || before.len() > maximum
    {
        return Err(Phase5dError::Changed);
    }
    let mut opened = File::open(&file.path).map_err(|_| Phase5dError::Io)?;
    let opened_metadata = opened.metadata().map_err(|_| Phase5dError::Io)?;
    if !opened_metadata.is_file()
        || Identity::from_metadata(&opened_metadata) != file.identity
        || opened_metadata.len() > maximum
    {
        return Err(Phase5dError::Changed);
    }
    let mut digest = Sha256::new();
    let mut seen = 0_u64;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        let count = opened.read(&mut buffer).map_err(|_| Phase5dError::Io)?;
        if count == 0 {
            break;
        }
        seen = seen
            .checked_add(u64::try_from(count).map_err(|_| Phase5dError::Invalid)?)
            .ok_or(Phase5dError::Invalid)?;
        if seen > maximum {
            return Err(Phase5dError::Invalid);
        }
        digest.update(&buffer[..count]);
    }
    if seen != file.identity.len {
        return Err(Phase5dError::Changed);
    }
    let after = fs::symlink_metadata(&file.path).map_err(|_| Phase5dError::Io)?;
    let after_open = opened.metadata().map_err(|_| Phase5dError::Io)?;
    if after.file_type().is_symlink()
        || Identity::from_metadata(&after) != file.identity
        || Identity::from_metadata(&after_open) != file.identity
    {
        return Err(Phase5dError::Changed);
    }
    verify_directories(root, directories)?;
    Ok((seen, hex::encode(digest.finalize())))
}

fn verify_directories(
    root: &Path,
    directories: &[(PathBuf, Identity)],
) -> Result<(), Phase5dError> {
    for (path, identity) in directories {
        let metadata = fs::symlink_metadata(path).map_err(|_| Phase5dError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || Identity::from_metadata(&metadata) != *identity
        {
            return Err(Phase5dError::Changed);
        }
    }
    let _ = require_directory(root)?;
    Ok(())
}

fn validate_manifest(
    bytes: &[u8],
    expected: Target,
) -> Result<(Vec<ManifestFile>, BTreeMap<String, String>), Phase5dError> {
    let value = parse_strict_json(bytes, MAX_METADATA_BYTES).map_err(|_| Phase5dError::Invalid)?;
    if canonical_pretty_sorted(&value).map_err(|_| Phase5dError::Invalid)? != bytes {
        return Err(Phase5dError::Invalid);
    }
    let object = value.as_object().ok_or(Phase5dError::Invalid)?;
    let keys = [
        "schema_version",
        "agentgate_version",
        "abi_version",
        "target",
        "tools",
        "files",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys {
        return Err(Phase5dError::Invalid);
    }
    if object.get("schema_version").and_then(Value::as_u64) != Some(1)
        || object.get("agentgate_version").and_then(Value::as_str) != Some(VERSION)
        || object.get("abi_version").and_then(Value::as_u64) != Some(u64::from(ABI_VERSION))
    {
        return Err(Phase5dError::Invalid);
    }
    validate_target(object.get("target").ok_or(Phase5dError::Invalid)?, expected)?;
    let tools = validate_tools(object.get("tools").ok_or(Phase5dError::Invalid)?)?;
    let files = validate_files(object.get("files").ok_or(Phase5dError::Invalid)?, expected)?;
    Ok((files, tools))
}

fn validate_target(value: &Value, expected: Target) -> Result<(), Phase5dError> {
    let object = value.as_object().ok_or(Phase5dError::Invalid)?;
    let keys = ["os", "arch", "triple"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys
        || object.get("os").and_then(Value::as_str) != Some(expected.os())
        || object.get("arch").and_then(Value::as_str) != Some(expected.arch())
        || object.get("triple").and_then(Value::as_str) != Some(expected.triple())
    {
        return Err(Phase5dError::Invalid);
    }
    Ok(())
}

fn validate_tools(value: &Value) -> Result<BTreeMap<String, String>, Phase5dError> {
    let object = value.as_object().ok_or(Phase5dError::Invalid)?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != TOOL_KEYS.into_iter().collect()
    {
        return Err(Phase5dError::Invalid);
    }
    let mut tools = BTreeMap::new();
    for key in TOOL_KEYS {
        let version = object
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Phase5dError::Invalid)?;
        if !valid_version(version) {
            return Err(Phase5dError::Invalid);
        }
        tools.insert(key.to_owned(), version.to_owned());
    }
    Ok(tools)
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_files(value: &Value, target: Target) -> Result<Vec<ManifestFile>, Phase5dError> {
    let array = value.as_array().ok_or(Phase5dError::Invalid)?;
    if array.len() > MAX_FILES {
        return Err(Phase5dError::Invalid);
    }
    let mut previous = None::<String>;
    let mut files = Vec::with_capacity(array.len());
    for entry in array {
        let object = entry.as_object().ok_or(Phase5dError::Invalid)?;
        let keys = ["path", "kind", "size", "sha256"]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys {
            return Err(Phase5dError::Invalid);
        }
        let path = object
            .get("path")
            .and_then(Value::as_str)
            .ok_or(Phase5dError::Invalid)?;
        if path == MANIFEST
            || path == CHECKSUMS
            || path
                .split('/')
                .any(|part| part == MANIFEST || part == CHECKSUMS)
        {
            return Err(Phase5dError::Invalid);
        }
        safe_relative_path(path).map_err(|_| Phase5dError::Invalid)?;
        if previous.as_deref().is_some_and(|last| path <= last) {
            return Err(Phase5dError::Invalid);
        }
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(Phase5dError::Invalid)?;
        if kind != artifact_kind(path) {
            return Err(Phase5dError::Invalid);
        }
        let size = object
            .get("size")
            .and_then(Value::as_u64)
            .ok_or(Phase5dError::Invalid)?;
        let sha256 = object
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or(Phase5dError::Invalid)?;
        validate_sha256(sha256).map_err(|_| Phase5dError::Invalid)?;
        previous = Some(path.to_owned());
        files.push(ManifestFile {
            path: path.to_owned(),
            size,
            sha256: sha256.to_owned(),
        });
    }
    validate_layout(&files, target)?;
    Ok(files)
}

fn artifact_kind(path: &str) -> &'static str {
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

fn validate_layout(files: &[ManifestFile], target: Target) -> Result<(), Phase5dError> {
    let paths = files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut required = BTreeSet::from([
        "include/agentgate.h".to_owned(),
        format!("native/{}", target.shared_name()),
        format!("native/{}", target.static_name()),
        "go/go.mod".to_owned(),
        "java/agentgate-java-0.1.0-SNAPSHOT.jar".to_owned(),
        format!("java/{}", target.jni_name()),
        format!("java/{}", target.shared_name()),
        "java/examples/Complete.java".to_owned(),
        "node/package.json".to_owned(),
        "node/examples/complete.js".to_owned(),
        "node/build/Release/agentgate.node".to_owned(),
        format!("node/build/Release/{}", target.shared_name()),
        "smoke/abi_probe.c".to_owned(),
        "smoke/abi_probe.cpp".to_owned(),
    ]);
    if let Some(import) = target.import_name() {
        required.insert(format!("native/{import}"));
    }
    if !required.iter().all(|path| paths.contains(path.as_str())) {
        return Err(Phase5dError::Invalid);
    }
    let groups = ["go/agentgate/", "go/examples/complete/", "node/lib/"];
    if groups
        .iter()
        .any(|group| !paths.iter().any(|path| path.starts_with(group)))
    {
        return Err(Phase5dError::Invalid);
    }
    for path in paths {
        if !required.contains(path) && !groups.iter().any(|group| path.starts_with(group)) {
            return Err(Phase5dError::Invalid);
        }
    }
    Ok(())
}

fn parse_checksums(bytes: &[u8]) -> Result<BTreeMap<String, String>, Phase5dError> {
    let text = std::str::from_utf8(bytes).map_err(|_| Phase5dError::Invalid)?;
    if text.is_empty() || !text.ends_with('\n') || text.contains('\r') {
        return Err(Phase5dError::Invalid);
    }
    let mut entries = BTreeMap::new();
    let mut previous = None::<String>;
    for line in text.trim_end_matches('\n').split('\n') {
        let raw = line.as_bytes();
        if raw.len() < 67 || raw.get(64..66) != Some(b"  ") {
            return Err(Phase5dError::Invalid);
        }
        let digest = std::str::from_utf8(&raw[..64]).map_err(|_| Phase5dError::Invalid)?;
        let path = std::str::from_utf8(&raw[66..]).map_err(|_| Phase5dError::Invalid)?;
        validate_sha256(digest).map_err(|_| Phase5dError::Invalid)?;
        if path == CHECKSUMS || path.is_empty() {
            return Err(Phase5dError::Invalid);
        }
        if path != MANIFEST {
            safe_relative_path(path).map_err(|_| Phase5dError::Invalid)?;
            if path
                .split('/')
                .any(|part| part == MANIFEST || part == CHECKSUMS)
            {
                return Err(Phase5dError::Invalid);
            }
        }
        if previous.as_deref().is_some_and(|last| path <= last)
            || entries.insert(path.to_owned(), digest.to_owned()).is_some()
        {
            return Err(Phase5dError::Invalid);
        }
        previous = Some(path.to_owned());
    }
    let mut canonical = String::new();
    for (path, digest) in &entries {
        canonical.push_str(digest);
        canonical.push_str("  ");
        canonical.push_str(path);
        canonical.push('\n');
    }
    if canonical.as_bytes() != bytes {
        return Err(Phase5dError::Invalid);
    }
    Ok(entries)
}

fn tree_digest(files: &[VerifiedFile]) -> Result<String, Phase5dError> {
    let tuples = files
        .iter()
        .map(|file| {
            Value::Array(vec![
                Value::String(file.path.clone()),
                Value::from(file.size),
                Value::String(file.sha256.clone()),
            ])
        })
        .collect();
    let mut bytes = TREE_DOMAIN.to_vec();
    bytes.extend(canonical_compact(&Value::Array(tuples)).map_err(|_| Phase5dError::Invalid)?);
    Ok(hex::encode(Sha256::digest(bytes)))
}
