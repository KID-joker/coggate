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
const MAX_PATH_DEPTH: usize = 16;
const MAX_PAYLOAD_FILES: usize = MAX_FILES - 2;
const MAX_DIRECTORIES: usize = MAX_FILES * (MAX_PATH_DEPTH - 1) + 1;
const MAX_ENTRIES: usize = MAX_FILES + MAX_DIRECTORIES;
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Phase5dError {
    #[error("Phase 5D artifact is invalid")]
    Invalid,
    #[error("Phase 5D artifact could not be read")]
    Io,
    #[error("Phase 5D artifact changed while being verified")]
    Changed,
    #[error("Phase 5D artifact has too many regular files")]
    FileLimit,
    #[error("Phase 5D artifact has too many directories")]
    DirectoryLimit,
    #[error("Phase 5D artifact has too many entries")]
    EntryLimit,
    #[error("Phase 5D artifact metadata exceeds its limit")]
    MetadataLimit,
    #[error("Phase 5D artifact payload sizes exceed their limit")]
    SizeLimit,
    #[error("Phase 5D artifact has an unlisted directory")]
    UnexpectedDirectory,
    #[error("Phase 5D artifact file hash does not match")]
    HashMismatch,
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
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
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
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                attributes: metadata.file_attributes(),
                creation_time: metadata.creation_time(),
                last_write_time: metadata.last_write_time(),
                volume_serial: 0,
                file_index: 0,
            }
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }
}

fn identity_for_path(path: &Path, metadata: &Metadata) -> Result<Identity, Phase5dError> {
    #[cfg(windows)]
    {
        windows_identity_for_path(path, metadata)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(Identity::from_metadata(metadata))
    }
}

fn identity_for_open_file(file: &File, metadata: &Metadata) -> Result<Identity, Phase5dError> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the borrowed raw handle remains owned by `file`; `info` is writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(Phase5dError::Io);
        }
        if (info.dwFileAttributes & 0x400) != 0 {
            return Err(Phase5dError::Invalid);
        }
        let mut identity = Identity::from_metadata(metadata);
        identity.volume_serial = info.dwVolumeSerialNumber;
        identity.file_index =
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        Ok(identity)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(Identity::from_metadata(metadata))
    }
}

#[cfg(windows)]
fn windows_identity_for_path(path: &Path, metadata: &Metadata) -> Result<Identity, Phase5dError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            GetFileInformationByHandle, OPEN_EXISTING,
        },
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: NUL-terminated path is owned for the call; no security attributes/template handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Phase5dError::Io);
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is valid until CloseHandle and `info` is a valid writable buffer.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) } != 0;
    // SAFETY: handle was returned by CreateFileW exactly once above.
    unsafe {
        CloseHandle(handle);
    }
    if !ok || (info.dwFileAttributes & 0x400) != 0 {
        return Err(Phase5dError::Invalid);
    }
    use std::os::windows::fs::MetadataExt;
    Ok(Identity {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        attributes: info.dwFileAttributes,
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
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
            #[cfg(all(not(unix), not(windows)))]
            {
                true
            }
            #[cfg(windows)]
            {
                self.attributes == other.attributes
                    && self.creation_time == other.creation_time
                    && self.last_write_time == other.last_write_time
                    && self.volume_serial == other.volume_serial
                    && self.file_index == other.file_index
            }
        }
    }
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Reparse points must be rejected before any handle is opened.
        (metadata.file_attributes() & 0x400) != 0
    }
    #[cfg(not(windows))]
    {
        false
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
    verify_phase5d_artifact_inner(root, expected, |_| {})
}

fn verify_phase5d_artifact_inner(
    root: &Path,
    expected: Target,
    after_snapshot: impl FnOnce(&Path),
) -> Result<VerifiedArtifact, Phase5dError> {
    let root_identity = require_directory(root)?;
    let mut directories = vec![(root.to_path_buf(), root_identity)];
    let disk = walk_tree(root, &mut directories)?;
    after_snapshot(root);

    let manifest_disk = disk.get(MANIFEST).ok_or(Phase5dError::Invalid)?;
    let checksum_disk = disk.get(CHECKSUMS).ok_or(Phase5dError::Invalid)?;
    let manifest_bytes = read_metadata(manifest_disk)?;
    let checksum_bytes = read_metadata(checksum_disk)?;
    let (files, tools) = validate_manifest(&manifest_bytes, expected)?;

    validate_directories(&directories, &files)?;

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

    validate_size_limits(files.iter().map(|file| file.size))?;
    for file in &files {
        let disk_file = disk.get(&file.path).ok_or(Phase5dError::Invalid)?;
        if disk_file.identity.len > MAX_PAYLOAD_BYTES {
            return Err(Phase5dError::SizeLimit);
        }
        if disk_file.identity.len != file.size {
            return Err(Phase5dError::Invalid);
        }
    }

    let mut verified = Vec::with_capacity(files.len());
    for file in &files {
        let disk_file = disk.get(&file.path).ok_or(Phase5dError::Invalid)?;
        let (size, digest) = hash_checked(disk_file, root, &directories, MAX_PAYLOAD_BYTES)?;
        if size != file.size {
            return Err(Phase5dError::Invalid);
        }
        if digest != file.sha256 {
            return Err(Phase5dError::HashMismatch);
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
    let (checksum_size, checksum_hash) =
        hash_checked(checksum_disk, root, &directories, MAX_METADATA_BYTES as u64)?;
    if checksum_size
        != u64::try_from(checksum_bytes.len()).map_err(|_| Phase5dError::MetadataLimit)?
        || checksum_hash != hex::encode(Sha256::digest(&checksum_bytes))
    {
        return Err(Phase5dError::Changed);
    }
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
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(Phase5dError::Invalid);
    }
    identity_for_path(path, &metadata)
}

fn validate_size_limits(sizes: impl IntoIterator<Item = u64>) -> Result<(), Phase5dError> {
    let mut total = 0_u64;
    for size in sizes {
        if size > MAX_PAYLOAD_BYTES {
            return Err(Phase5dError::SizeLimit);
        }
        total = total.checked_add(size).ok_or(Phase5dError::SizeLimit)?;
        if total > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(Phase5dError::SizeLimit);
        }
    }
    Ok(())
}

fn validate_directories(
    directories: &[(PathBuf, Identity)],
    files: &[ManifestFile],
) -> Result<(), Phase5dError> {
    let mut expected = BTreeSet::from([String::new()]);
    for file in files {
        let mut current = String::new();
        for part in file
            .path
            .split('/')
            .take(file.path.split('/').count().saturating_sub(1))
        {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(part);
            expected.insert(current.clone());
        }
    }
    let root = directories
        .first()
        .map(|(path, _)| path)
        .ok_or(Phase5dError::Invalid)?;
    let actual = directories
        .iter()
        .map(|(path, _)| {
            if path == root {
                Ok(String::new())
            } else {
                path.strip_prefix(root)
                    .ok()
                    .and_then(|relative| relative.to_str())
                    .map(|value| value.replace(std::path::MAIN_SEPARATOR, "/"))
                    .ok_or(Phase5dError::UnexpectedDirectory)
            }
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected {
        return Err(Phase5dError::UnexpectedDirectory);
    }
    Ok(())
}

fn walk_tree(
    root: &Path,
    directories: &mut Vec<(PathBuf, Identity)>,
) -> Result<BTreeMap<String, DiskFile>, Phase5dError> {
    let mut files = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    let mut entries = 0_usize;
    while let Some((directory, prefix)) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| Phase5dError::Io)? {
            entries = entries.checked_add(1).ok_or(Phase5dError::EntryLimit)?;
            if entries > MAX_ENTRIES {
                return Err(Phase5dError::EntryLimit);
            }
            let entry = entry.map_err(|_| Phase5dError::Io)?;
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
            if is_link_or_reparse(&metadata) {
                return Err(Phase5dError::Invalid);
            }
            if metadata.is_dir() {
                if directories.len() >= MAX_DIRECTORIES {
                    return Err(Phase5dError::DirectoryLimit);
                }
                directories.push((path.clone(), identity_for_path(&path, &metadata)?));
                pending.push((path, relative));
            } else if metadata.is_file() {
                if files.len() >= MAX_FILES {
                    return Err(Phase5dError::FileLimit);
                }
                let identity = identity_for_path(&path, &metadata)?;
                if files
                    .insert(relative, DiskFile { path, identity })
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
    validate_metadata_size(file.identity.len)?;
    let (bytes, _) = read_checked(file, None, MAX_METADATA_BYTES as u64)?;
    Ok(bytes)
}

fn validate_metadata_size(size: u64) -> Result<(), Phase5dError> {
    if size > MAX_METADATA_BYTES as u64 {
        Err(Phase5dError::MetadataLimit)
    } else {
        Ok(())
    }
}

fn read_checked(
    file: &DiskFile,
    root: Option<&Path>,
    maximum: u64,
) -> Result<(Vec<u8>, String), Phase5dError> {
    let before = fs::symlink_metadata(&file.path).map_err(|_| Phase5dError::Io)?;
    if is_link_or_reparse(&before)
        || !before.is_file()
        || identity_for_path(&file.path, &before)? != file.identity
    {
        return Err(Phase5dError::Changed);
    }
    let mut opened = File::open(&file.path).map_err(|_| Phase5dError::Io)?;
    let opened_metadata = opened.metadata().map_err(|_| Phase5dError::Io)?;
    if !opened_metadata.is_file()
        || identity_for_open_file(&opened, &opened_metadata)? != file.identity
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
    if is_link_or_reparse(&after)
        || identity_for_path(&file.path, &after)? != file.identity
        || identity_for_open_file(&opened, &after_open)? != file.identity
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
    if is_link_or_reparse(&before)
        || !before.is_file()
        || identity_for_path(&file.path, &before)? != file.identity
        || before.len() > maximum
    {
        return Err(Phase5dError::Changed);
    }
    let mut opened = File::open(&file.path).map_err(|_| Phase5dError::Io)?;
    let opened_metadata = opened.metadata().map_err(|_| Phase5dError::Io)?;
    if !opened_metadata.is_file()
        || identity_for_open_file(&opened, &opened_metadata)? != file.identity
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
    if is_link_or_reparse(&after)
        || identity_for_path(&file.path, &after)? != file.identity
        || identity_for_open_file(&opened, &after_open)? != file.identity
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
        if is_link_or_reparse(&metadata)
            || !metadata.is_dir()
            || identity_for_path(path, &metadata)? != *identity
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
    if array.len() > MAX_PAYLOAD_FILES {
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
        validate_payload_path(path)?;
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

fn validate_payload_path(path: &str) -> Result<(), Phase5dError> {
    if path == MANIFEST
        || path == CHECKSUMS
        || path
            .split('/')
            .any(|part| part == MANIFEST || part == CHECKSUMS)
    {
        return Err(Phase5dError::Invalid);
    }
    safe_relative_path(path).map_err(|_| Phase5dError::Invalid)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn exact_limits_and_path_depth_are_enforced_before_payload_reads() {
        assert_eq!(validate_size_limits([MAX_PAYLOAD_BYTES]), Ok(()));
        assert_eq!(
            validate_size_limits([MAX_PAYLOAD_BYTES + 1]),
            Err(Phase5dError::SizeLimit)
        );
        assert_eq!(validate_size_limits([MAX_PAYLOAD_BYTES; 4]), Ok(()));
        assert_eq!(
            validate_size_limits([
                MAX_PAYLOAD_BYTES,
                MAX_PAYLOAD_BYTES,
                MAX_PAYLOAD_BYTES,
                MAX_PAYLOAD_BYTES,
                1
            ]),
            Err(Phase5dError::SizeLimit)
        );
        assert_eq!(
            validate_size_limits([u64::MAX, 1]),
            Err(Phase5dError::SizeLimit)
        );
        assert_eq!(validate_metadata_size(MAX_METADATA_BYTES as u64), Ok(()));
        assert_eq!(
            validate_metadata_size((MAX_METADATA_BYTES as u64) + 1),
            Err(Phase5dError::MetadataLimit)
        );
        assert_eq!(
            validate_payload_path(&std::iter::repeat_n("a", 16).collect::<Vec<_>>().join("/")),
            Ok(())
        );
        assert_eq!(
            validate_payload_path(&std::iter::repeat_n("a", 17).collect::<Vec<_>>().join("/")),
            Err(Phase5dError::Invalid)
        );
    }

    #[test]
    fn post_snapshot_regular_file_replacement_is_changed_not_hash_mismatch() {
        let root = minimal_linux_artifact();
        let result = verify_phase5d_artifact_inner(&root, Target::LinuxX86_64, |root| {
            let payload = root.join("include/agentgate.h");
            let replacement = root.join("include/replacement.h");
            fs::write(&replacement, b"x").unwrap();
            fs::remove_file(&payload).unwrap();
            fs::rename(replacement, payload).unwrap();
        });
        assert_eq!(result, Err(Phase5dError::Changed));
    }

    fn minimal_linux_artifact() -> std::path::PathBuf {
        let root = TempDir::new().unwrap().keep().join("artifact");
        fs::create_dir(&root).unwrap();
        let paths = [
            "include/agentgate.h",
            "native/libagentgate_ffi.so",
            "native/libagentgate_ffi.a",
            "go/go.mod",
            "go/agentgate/a.go",
            "go/examples/complete/a.go",
            "java/agentgate-java-0.1.0-SNAPSHOT.jar",
            "java/libagentgate_jni.so",
            "java/libagentgate_ffi.so",
            "java/examples/Complete.java",
            "node/package.json",
            "node/lib/a.js",
            "node/examples/complete.js",
            "node/build/Release/agentgate.node",
            "node/build/Release/libagentgate_ffi.so",
            "smoke/abi_probe.c",
            "smoke/abi_probe.cpp",
        ];
        for path in paths {
            let full = root.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, b"x").unwrap();
        }
        let tools = TOOL_KEYS
            .into_iter()
            .map(|key| (key.to_owned(), Value::String("1".into())))
            .collect();
        let mut sorted_paths = paths.to_vec();
        sorted_paths.sort();
        let files: Vec<_> = sorted_paths.into_iter().map(|path| serde_json::json!({"path":path,"kind":artifact_kind(path),"size":1,"sha256":hex::encode(Sha256::digest(b"x"))})).collect();
        let manifest = serde_json::json!({"schema_version":1,"agentgate_version":VERSION,"abi_version":1,"target":{"os":"Linux","arch":"x86_64","triple":"x86_64-unknown-linux-gnu"},"tools":Value::Object(tools),"files":files});
        let manifest = canonical_pretty_sorted(&manifest).unwrap();
        fs::write(root.join(MANIFEST), &manifest).unwrap();
        let mut entries = paths
            .into_iter()
            .map(|path| (path, hex::encode(Sha256::digest(b"x"))))
            .collect::<Vec<_>>();
        entries.push((MANIFEST, hex::encode(Sha256::digest(&manifest))));
        entries.sort_by_key(|(path, _)| *path);
        let mut checksums = String::new();
        for (path, digest) in entries {
            checksums.push_str(&digest);
            checksums.push_str("  ");
            checksums.push_str(path);
            checksums.push('\n');
        }
        fs::write(root.join(CHECKSUMS), checksums).unwrap();
        root
    }
}
