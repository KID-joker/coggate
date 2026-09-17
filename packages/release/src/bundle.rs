//! Self-verifying, offline release bundles.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, Metadata},
    io::Write,
    path::{Path, PathBuf},
};

use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DecisionError, EvidenceSet,
    canonical::{
        MAX_METADATA_BYTES, canonical_compact, parse_strict_json, safe_relative_path, sha256_hex,
        validate_sha256,
    },
    producer::read_stable_regular,
};

const BUNDLE: &str = "bundle";
const MANIFEST: &str = "manifest.json";
const SUMS: &str = "SHA256SUMS";
const SUITE: &str = "suite/v1.json";
const EVIDENCE_DIRS: [&str; 3] = ["receipts", "phase5d", "phase6a"];
const RECEIPT_ROLES: [&str; 9] = [
    "direct",
    "fingerprint",
    "linux",
    "llm",
    "macos",
    "regex",
    "sanitizer",
    "simple_parser",
    "windows",
];
const MAX_FILES: usize = 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BundleError {
    #[error("release authorization is blocked")]
    Blocked,
    #[error("release bundle input is invalid")]
    InvalidInput,
    #[error("release bundle destination already exists")]
    DestinationExists,
    #[error("release bundle operation failed")]
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleReceipt {
    pub role: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u8,
    pub commit: String,
    pub agentgate_version: String,
    pub abi_version: u32,
    pub generator_version: String,
    pub suite_manifest_digest: String,
    pub authorized: bool,
    pub receipts: Vec<BundleReceipt>,
    pub files: Vec<BundleFile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    manifest: BundleManifest,
}

impl VerifiedBundle {
    pub fn authorized(&self) -> bool {
        self.manifest.authorized
    }
    pub fn commit(&self) -> &str {
        &self.manifest.commit
    }
    pub fn agentgate_version(&self) -> &str {
        &self.manifest.agentgate_version
    }
    pub fn abi_version(&self) -> u32 {
        self.manifest.abi_version
    }
    pub fn generator_version(&self) -> &str {
        &self.manifest.generator_version
    }
    pub fn suite_manifest_digest(&self) -> &str {
        &self.manifest.suite_manifest_digest
    }
    pub fn receipts(&self) -> &[BundleReceipt] {
        &self.manifest.receipts
    }
    pub fn files(&self) -> &[BundleFile] {
        &self.manifest.files
    }
}

/// Assemble a single immutable directory named `bundle` beneath `output_parent`.
///
/// `output_parent` must be trusted not to be concurrently modified by a same-user adversary.
/// Identity checks detect observed replacement before and after staged operations, but pathname
/// APIs cannot eliminate a replacement strictly between kernel calls.
pub fn assemble_bundle(
    evidence_root: &Path,
    output_parent: &Path,
    commit: &str,
) -> Result<PathBuf, BundleError> {
    require_real_dir(output_parent)?;
    let requested_destination = output_parent.join(BUNDLE);
    let output_parent = fs::canonicalize(output_parent).map_err(|_| BundleError::InvalidInput)?;
    require_real_dir(&output_parent)?;
    let ancestor_identities = capture_ancestors(&output_parent)?;
    let destination = output_parent.join(BUNDLE);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(BundleError::DestinationExists);
    }

    let evidence =
        EvidenceSet::load(evidence_root, commit).map_err(|_| BundleError::InvalidInput)?;
    let decision = evidence.authorize().map_err(|error| match error {
        DecisionError::Blocked { .. } => BundleError::Blocked,
    })?;
    // This is deliberately immediately before staging: authorization facts must still bind the
    // source that will be copied, while verification below distrusts the staging bytes again.
    evidence
        .revalidate(evidence_root)
        .map_err(|_| BundleError::InvalidInput)?;

    let (staging, identity) = create_staging(&output_parent)?;
    let mut published = false;
    let result = (|| {
        assert_owned(&staging, &identity)?;
        assert_ancestors(&ancestor_identities)?;
        let mut copy_budget = CopyBudget::default();
        for directory in EVIDENCE_DIRS {
            copy_tree(
                &evidence_root.join(directory),
                &staging.join(directory),
                0,
                &mut copy_budget,
                &staging,
                &identity,
            )?;
        }
        assert_owned(&staging, &identity)?;
        assert_ancestors(&ancestor_identities)?;
        write_file(
            &staging,
            &identity,
            &staging.join(SUITE),
            include_bytes!("../../../benchmarks/suites/v1.json"),
        )?;
        assert_owned(&staging, &identity)?;
        assert_ancestors(&ancestor_identities)?;
        let files = payload_files(&staging)?;
        let manifest = BundleManifest {
            schema_version: 1,
            commit: decision.commit().to_owned(),
            agentgate_version: decision.agentgate_version().to_owned(),
            abi_version: decision.abi_version(),
            generator_version: decision.generator_version().to_owned(),
            suite_manifest_digest: decision.suite_manifest_digest().to_owned(),
            authorized: true,
            receipts: decision
                .receipt_digests()
                .iter()
                .map(|(role, digest)| BundleReceipt {
                    role: role.clone(),
                    digest: digest.clone(),
                })
                .collect(),
            files,
        };
        write_manifest(&staging, &identity, &staging.join(MANIFEST), &manifest)?;
        write_sums(&staging, &identity, &manifest.files)?;
        sync_tree(&staging)?;
        assert_owned(&staging, &identity)?;
        assert_ancestors(&ancestor_identities)?;
        verify_bundle(&staging)?;
        assert_owned(&staging, &identity)?;
        assert_ancestors(&ancestor_identities)?;
        publish_no_replace(&staging, &destination)?;
        published = true;
        assert_ancestors(&ancestor_identities)?;
        if staging_identity(&destination)? != identity {
            return Err(BundleError::Internal);
        }
        let published = verify_bundle(&destination)?;
        if published.manifest != manifest {
            return Err(BundleError::Internal);
        }
        Ok(())
    })();
    if result.is_err() {
        if published {
            cleanup_owned(&destination, &identity);
        } else {
            cleanup_owned(&staging, &identity);
        }
    }
    result.map(|()| requested_destination)
}

/// Verify every byte and authorization fact in an untrusted bundle directory.
pub fn verify_bundle(root: &Path) -> Result<VerifiedBundle, BundleError> {
    require_real_dir(root)?;
    exact_children(
        root,
        &[
            (MANIFEST, false),
            (SUMS, false),
            ("suite", true),
            ("receipts", true),
            ("phase5d", true),
            ("phase6a", true),
        ],
    )?;
    exact_children(&root.join("suite"), &[("v1.json", false)])?;
    let all = walk_regular(root)?;
    let expected_top = BTreeSet::from([MANIFEST.to_owned(), SUMS.to_owned(), SUITE.to_owned()]);
    if !all.contains_key(MANIFEST) || !all.contains_key(SUMS) || !all.contains_key(SUITE) {
        return Err(BundleError::InvalidInput);
    }
    if read_regular(&root.join(SUITE), MAX_METADATA_BYTES as u64)?
        != include_bytes!("../../../benchmarks/suites/v1.json")
    {
        return Err(BundleError::InvalidInput);
    }
    let manifest_bytes = read_regular(&root.join(MANIFEST), MAX_METADATA_BYTES as u64)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let payload = all
        .iter()
        .filter(|(path, _)| path.as_str() != MANIFEST && path.as_str() != SUMS)
        .map(|(path, bytes)| {
            Ok(BundleFile {
                path: path.clone(),
                size: *bytes,
                sha256: hash_path(&root.join(path))?,
            })
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    if payload != manifest.files {
        return Err(BundleError::InvalidInput);
    }
    let allowed: BTreeSet<_> = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    if !allowed.contains(SUITE)
        || !all
            .keys()
            .all(|path| expected_top.contains(path) || allowed.contains(path.as_str()))
    {
        return Err(BundleError::InvalidInput);
    }
    verify_sums(root, &all)?;

    let evidence = EvidenceSet::load_bundle_root(root, &manifest.commit)
        .map_err(|_| BundleError::InvalidInput)?;
    let decision = evidence
        .authorize()
        .map_err(|_| BundleError::InvalidInput)?;
    if !manifest.authorized
        || manifest.commit != decision.commit()
        || manifest.agentgate_version != decision.agentgate_version()
        || manifest.abi_version != decision.abi_version()
        || manifest.generator_version != decision.generator_version()
        || manifest.suite_manifest_digest != decision.suite_manifest_digest()
    {
        return Err(BundleError::InvalidInput);
    }
    let receipts = decision
        .receipt_digests()
        .iter()
        .map(|(role, digest)| BundleReceipt {
            role: role.clone(),
            digest: digest.clone(),
        })
        .collect::<Vec<_>>();
    if manifest.receipts != receipts {
        return Err(BundleError::InvalidInput);
    }
    Ok(VerifiedBundle { manifest })
}

fn parse_manifest(bytes: &[u8]) -> Result<BundleManifest, BundleError> {
    let value =
        parse_strict_json(bytes, MAX_METADATA_BYTES).map_err(|_| BundleError::InvalidInput)?;
    let manifest: BundleManifest =
        serde_json::from_value(value).map_err(|_| BundleError::InvalidInput)?;
    let canonical =
        canonical_compact(&serde_json::to_value(&manifest).map_err(|_| BundleError::Internal)?)
            .map_err(|_| BundleError::Internal)?;
    if canonical != bytes {
        return Err(BundleError::InvalidInput);
    }
    Ok(manifest)
}

fn validate_manifest(manifest: &BundleManifest) -> Result<(), BundleError> {
    if manifest.schema_version != 1
        || !manifest.authorized
        || !valid_commit(&manifest.commit)
        || manifest.agentgate_version.is_empty()
        || manifest.generator_version.is_empty()
    {
        return Err(BundleError::InvalidInput);
    }
    validate_sha256(&manifest.suite_manifest_digest).map_err(|_| BundleError::InvalidInput)?;
    if manifest.receipts.len() != RECEIPT_ROLES.len()
        || manifest
            .receipts
            .iter()
            .map(|item| item.role.as_str())
            .collect::<Vec<_>>()
            != RECEIPT_ROLES
    {
        return Err(BundleError::InvalidInput);
    }
    for receipt in &manifest.receipts {
        validate_sha256(&receipt.digest).map_err(|_| BundleError::InvalidInput)?;
    }
    if manifest.files.is_empty() || manifest.files.len() > MAX_FILES {
        return Err(BundleError::InvalidInput);
    }
    let mut prior = "";
    for file in &manifest.files {
        safe_relative_path(&file.path).map_err(|_| BundleError::InvalidInput)?;
        if file.path.as_str() <= prior
            || (!EVIDENCE_DIRS
                .iter()
                .any(|dir| file.path.starts_with(&format!("{dir}/")))
                && file.path != SUITE)
            || file.size > MAX_FILE_BYTES
        {
            return Err(BundleError::InvalidInput);
        }
        validate_sha256(&file.sha256).map_err(|_| BundleError::InvalidInput)?;
        prior = &file.path;
    }
    Ok(())
}

fn write_manifest(
    staging: &Path,
    identity: &StagingIdentity,
    path: &Path,
    manifest: &BundleManifest,
) -> Result<(), BundleError> {
    validate_manifest(manifest)?;
    let bytes =
        canonical_compact(&serde_json::to_value(manifest).map_err(|_| BundleError::Internal)?)
            .map_err(|_| BundleError::Internal)?;
    write_file(staging, identity, path, &bytes)
}

fn write_sums(
    root: &Path,
    identity: &StagingIdentity,
    files: &[BundleFile],
) -> Result<(), BundleError> {
    let mut entries = files
        .iter()
        .map(|file| (file.path.clone(), file.sha256.clone()))
        .collect::<Vec<_>>();
    entries.push((MANIFEST.to_owned(), hash_path(&root.join(MANIFEST))?));
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    write_file(root, identity, &root.join(SUMS), &sums_bytes(&entries)?)
}

fn verify_sums(root: &Path, all: &BTreeMap<String, u64>) -> Result<(), BundleError> {
    let bytes = read_regular(&root.join(SUMS), MAX_METADATA_BYTES as u64)?;
    let entries = all
        .keys()
        .filter(|path| path.as_str() != SUMS)
        .map(|path| Ok((path.clone(), hash_path(&root.join(path))?)))
        .collect::<Result<Vec<_>, BundleError>>()?;
    if bytes == sums_bytes(&entries)? {
        Ok(())
    } else {
        Err(BundleError::InvalidInput)
    }
}

fn sums_bytes(entries: &[(String, String)]) -> Result<Vec<u8>, BundleError> {
    if entries.is_empty() || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(BundleError::InvalidInput);
    }
    let mut text = String::new();
    for (path, digest) in entries {
        safe_relative_path(path).map_err(|_| BundleError::InvalidInput)?;
        validate_sha256(digest).map_err(|_| BundleError::InvalidInput)?;
        use std::fmt::Write as _;
        writeln!(text, "{digest}  {path}").map_err(|_| BundleError::Internal)?;
    }
    Ok(text.into_bytes())
}

fn payload_files(root: &Path) -> Result<Vec<BundleFile>, BundleError> {
    walk_regular(root)?
        .into_iter()
        .filter(|(path, _)| {
            EVIDENCE_DIRS
                .iter()
                .any(|dir| path.starts_with(&format!("{dir}/")))
                || path == SUITE
        })
        .map(|(path, size)| {
            Ok(BundleFile {
                sha256: hash_path(&root.join(&path))?,
                path,
                size,
            })
        })
        .collect()
}

#[derive(Default)]
struct CopyBudget {
    files: usize,
    directories: usize,
    bytes: u64,
}
fn copy_tree(
    source: &Path,
    destination: &Path,
    depth: usize,
    budget: &mut CopyBudget,
    staging: &Path,
    identity: &StagingIdentity,
) -> Result<(), BundleError> {
    assert_owned(staging, identity)?;
    if depth > 16 || budget.directories >= MAX_FILES.saturating_mul(16) {
        return Err(BundleError::InvalidInput);
    }
    budget.directories += 1;
    let metadata = fs::symlink_metadata(source).map_err(|_| BundleError::InvalidInput)?;
    if link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(BundleError::InvalidInput);
    }
    let parent = destination.parent().ok_or(BundleError::Internal)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| BundleError::Internal)?;
    if link_or_reparse(&parent_metadata) || !parent_metadata.is_dir() {
        return Err(BundleError::Internal);
    }
    match fs::create_dir(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(BundleError::Internal),
    }
    let destination_metadata =
        fs::symlink_metadata(destination).map_err(|_| BundleError::Internal)?;
    if link_or_reparse(&destination_metadata) || !destination_metadata.is_dir() {
        return Err(BundleError::Internal);
    }
    assert_owned(staging, identity)?;
    for entry in fs::read_dir(source).map_err(|_| BundleError::InvalidInput)? {
        let entry = entry.map_err(|_| BundleError::InvalidInput)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| BundleError::InvalidInput)?;
        let target = destination.join(entry.file_name());
        if link_or_reparse(&metadata) {
            return Err(BundleError::InvalidInput);
        }
        if metadata.is_dir() {
            copy_tree(&entry.path(), &target, depth + 1, budget, staging, identity)?;
        } else if metadata.is_file() {
            if budget.files >= MAX_FILES
                || budget
                    .bytes
                    .checked_add(metadata.len())
                    .ok_or(BundleError::InvalidInput)?
                    > MAX_TOTAL_BYTES
            {
                return Err(BundleError::InvalidInput);
            }
            budget.files += 1;
            budget.bytes += metadata.len();
            copy_regular(&entry.path(), &target, metadata.len(), staging, identity)?;
        } else {
            return Err(BundleError::InvalidInput);
        }
    }
    Ok(())
}

fn copy_regular(
    source: &Path,
    target: &Path,
    len: u64,
    staging: &Path,
    identity: &StagingIdentity,
) -> Result<(), BundleError> {
    if len > MAX_FILE_BYTES {
        return Err(BundleError::InvalidInput);
    }
    let bytes = read_stable_regular(
        source,
        usize::try_from(len).map_err(|_| BundleError::InvalidInput)?,
    )
    .map_err(|_| BundleError::InvalidInput)?;
    if u64::try_from(bytes.len()).ok() != Some(len) {
        return Err(BundleError::InvalidInput);
    }
    write_file(staging, identity, target, &bytes)
}

fn walk_regular(root: &Path) -> Result<BTreeMap<String, u64>, BundleError> {
    let mut result = BTreeMap::new();
    let mut total = 0u64;
    let mut directories = 0usize;
    walk_inner(root, root, 0, &mut directories, &mut result, &mut total)?;
    if result.len() > MAX_FILES || total > MAX_TOTAL_BYTES {
        return Err(BundleError::InvalidInput);
    }
    Ok(result)
}
fn walk_inner(
    root: &Path,
    dir: &Path,
    depth: usize,
    directories: &mut usize,
    out: &mut BTreeMap<String, u64>,
    total: &mut u64,
) -> Result<(), BundleError> {
    if depth > 16 || *directories >= MAX_FILES.saturating_mul(16) {
        return Err(BundleError::InvalidInput);
    }
    *directories += 1;
    let metadata = fs::symlink_metadata(dir).map_err(|_| BundleError::InvalidInput)?;
    if link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(BundleError::InvalidInput);
    }
    for entry in fs::read_dir(dir).map_err(|_| BundleError::InvalidInput)? {
        let entry = entry.map_err(|_| BundleError::InvalidInput)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| BundleError::InvalidInput)?;
        if link_or_reparse(&metadata) {
            return Err(BundleError::InvalidInput);
        }
        if metadata.is_dir() {
            walk_inner(root, &path, depth + 1, directories, out, total)?;
        } else if metadata.is_file() {
            if metadata.len() > MAX_FILE_BYTES {
                return Err(BundleError::InvalidInput);
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| BundleError::InvalidInput)?;
            let string = relative
                .to_str()
                .ok_or(BundleError::InvalidInput)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            safe_relative_path(&string).map_err(|_| BundleError::InvalidInput)?;
            if out.insert(string, metadata.len()).is_some() {
                return Err(BundleError::InvalidInput);
            }
            *total = total
                .checked_add(metadata.len())
                .ok_or(BundleError::InvalidInput)?;
        } else {
            return Err(BundleError::InvalidInput);
        }
    }
    Ok(())
}

fn read_regular(path: &Path, max: u64) -> Result<Vec<u8>, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::InvalidInput)?;
    if link_or_reparse(&metadata) || !metadata.is_file() || metadata.len() > max {
        return Err(BundleError::InvalidInput);
    }
    read_stable_regular(
        path,
        usize::try_from(max).map_err(|_| BundleError::InvalidInput)?,
    )
    .map_err(|_| BundleError::InvalidInput)
}
fn hash_path(path: &Path) -> Result<String, BundleError> {
    Ok(sha256_hex(&read_regular(path, MAX_FILE_BYTES)?))
}
fn write_file(
    staging: &Path,
    identity: &StagingIdentity,
    path: &Path,
    bytes: &[u8],
) -> Result<(), BundleError> {
    assert_owned(staging, identity)?;
    let parent = path.parent().ok_or(BundleError::Internal)?;
    fs::create_dir_all(parent).map_err(|_| BundleError::Internal)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| BundleError::Internal)?;
    if link_or_reparse(&parent_metadata) || !parent_metadata.is_dir() {
        return Err(BundleError::Internal);
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| BundleError::Internal)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| BundleError::Internal)?;
    assert_owned(staging, identity)
}

fn require_real_dir(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::InvalidInput)?;
    if link_or_reparse(&metadata) || !metadata.is_dir() {
        Err(BundleError::InvalidInput)
    } else {
        Ok(())
    }
}
fn exact_children(dir: &Path, expected: &[(&str, bool)]) -> Result<(), BundleError> {
    require_real_dir(dir)?;
    let actual = fs::read_dir(dir)
        .map_err(|_| BundleError::InvalidInput)?
        .map(|entry| {
            let entry = entry.map_err(|_| BundleError::InvalidInput)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BundleError::InvalidInput)?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| BundleError::InvalidInput)?;
            if link_or_reparse(&metadata) {
                return Err(BundleError::InvalidInput);
            }
            Ok((name, metadata.is_dir()))
        })
        .collect::<Result<BTreeSet<_>, BundleError>>()?;
    let wanted = expected
        .iter()
        .map(|(name, is_dir)| ((*name).to_owned(), *is_dir))
        .collect();
    if actual == wanted {
        Ok(())
    } else {
        Err(BundleError::InvalidInput)
    }
}
fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        (metadata.file_attributes() & 0x400) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StagingIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume: u32,
    #[cfg(windows)]
    index: u64,
}
fn staging_identity(path: &Path) -> Result<StagingIdentity, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::Internal)?;
    if link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(BundleError::Internal);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(StagingIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::Win32::{
                Foundation::HANDLE,
                Storage::FileSystem::{
                    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
                    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
                },
            };
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
                .map_err(|_| BundleError::Internal)?;
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: `file` owns a live directory handle and `info` is writable.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0
            {
                return Err(BundleError::Internal);
            }
            if (info.dwFileAttributes & 0x400) != 0 {
                return Err(BundleError::Internal);
            }
            Ok(StagingIdentity {
                volume: info.dwVolumeSerialNumber,
                index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            })
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            Ok(StagingIdentity {})
        }
    }
}
fn create_staging(parent: &Path) -> Result<(PathBuf, StagingIdentity), BundleError> {
    for _ in 0..32 {
        let mut token = [0u8; 16];
        random_fill(&mut token).map_err(|_| BundleError::Internal)?;
        let path = parent.join(format!(".bundle.tmp-{}", hex::encode(token)));
        match fs::create_dir(&path) {
            Ok(()) => {
                let identity = staging_identity(&path)?;
                return Ok((path, identity));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(BundleError::Internal),
        }
    }
    Err(BundleError::Internal)
}
fn cleanup_owned(path: &Path, identity: &StagingIdentity) {
    if staging_identity(path).ok().as_ref() == Some(identity) {
        let _ = remove_owned_tree(path);
    }
}
fn assert_owned(path: &Path, identity: &StagingIdentity) -> Result<(), BundleError> {
    if staging_identity(path).ok().as_ref() == Some(identity) {
        Ok(())
    } else {
        Err(BundleError::Internal)
    }
}
fn capture_ancestors(path: &Path) -> Result<Vec<(PathBuf, StagingIdentity)>, BundleError> {
    path.ancestors()
        .map(|ancestor| Ok((ancestor.to_owned(), staging_identity(ancestor)?)))
        .collect()
}
fn assert_ancestors(ancestors: &[(PathBuf, StagingIdentity)]) -> Result<(), BundleError> {
    for (path, identity) in ancestors {
        assert_owned(path, identity)?;
    }
    Ok(())
}
fn remove_owned_tree(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::Internal)?;
    if link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(BundleError::Internal);
    }
    for entry in fs::read_dir(path).map_err(|_| BundleError::Internal)? {
        let entry = entry.map_err(|_| BundleError::Internal)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| BundleError::Internal)?;
        if link_or_reparse(&metadata) {
            return Err(BundleError::Internal);
        }
        if metadata.is_dir() {
            remove_owned_tree(&entry.path())?;
        } else if metadata.is_file() {
            fs::remove_file(entry.path()).map_err(|_| BundleError::Internal)?;
        } else {
            return Err(BundleError::Internal);
        }
    }
    fs::remove_dir(path).map_err(|_| BundleError::Internal)
}
fn sync_tree(root: &Path) -> Result<(), BundleError> {
    for path in walk_regular(root)?.keys() {
        File::open(root.join(path))
            .and_then(|file| file.sync_all())
            .map_err(|_| BundleError::Internal)?;
    }
    sync_directories(root)?;
    Ok(())
}
fn sync_directories(directory: &Path) -> Result<(), BundleError> {
    for entry in fs::read_dir(directory).map_err(|_| BundleError::Internal)? {
        let entry = entry.map_err(|_| BundleError::Internal)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| BundleError::Internal)?;
        if link_or_reparse(&metadata) {
            return Err(BundleError::Internal);
        }
        if metadata.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    #[cfg(unix)]
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| BundleError::Internal)?;
    Ok(())
}

fn publish_no_replace(staging: &Path, destination: &Path) -> Result<(), BundleError> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" {
            fn renamex_np(from: *const i8, to: *const i8, flags: u32) -> i32;
        }
        let from =
            CString::new(staging.as_os_str().as_bytes()).map_err(|_| BundleError::Internal)?;
        let to =
            CString::new(destination.as_os_str().as_bytes()).map_err(|_| BundleError::Internal)?;
        let result = unsafe { renamex_np(from.as_ptr(), to.as_ptr(), 0x0000_0004) };
        if result == 0 {
            Ok(())
        } else if fs::symlink_metadata(destination).is_ok() {
            Err(BundleError::DestinationExists)
        } else {
            Err(BundleError::Internal)
        }
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "arm"
        )
    ))]
    {
        use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" {
            fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
        }
        let from =
            CString::new(staging.as_os_str().as_bytes()).map_err(|_| BundleError::Internal)?;
        let to =
            CString::new(destination.as_os_str().as_bytes()).map_err(|_| BundleError::Internal)?;
        #[cfg(target_arch = "x86_64")]
        const RENAMEAT2_SYSCALL: std::ffi::c_long = 316;
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        const RENAMEAT2_SYSCALL: std::ffi::c_long = 276;
        #[cfg(target_arch = "arm")]
        const RENAMEAT2_SYSCALL: std::ffi::c_long = 382;
        let result = unsafe {
            syscall(
                RENAMEAT2_SYSCALL,
                -100i32,
                from.as_ptr(),
                -100i32,
                to.as_ptr(),
                1u32,
            )
        };
        if result == 0 {
            Ok(())
        } else if fs::symlink_metadata(destination).is_ok() {
            Err(BundleError::DestinationExists)
        } else {
            Err(BundleError::Internal)
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        let from = staging
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let to = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // SAFETY: both vectors are live NUL-terminated paths. Zero flags deliberately omits
        // MOVEFILE_REPLACE_EXISTING, so an existing destination cannot be replaced.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } != 0 {
            Ok(())
        } else if fs::symlink_metadata(destination).is_ok() {
            Err(BundleError::DestinationExists)
        } else {
            Err(BundleError::Internal)
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        windows,
        all(
            any(target_os = "linux", target_os = "android"),
            any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "riscv64",
                target_arch = "arm"
            )
        )
    )))]
    {
        let _ = (staging, destination);
        Err(BundleError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::{cleanup_owned, create_staging};
    use std::fs;

    #[test]
    fn cleanup_preserves_a_replaced_staging_path() {
        let parent = tempfile::tempdir().unwrap();
        let (staging, identity) = create_staging(parent.path()).unwrap();
        let moved = parent.path().join("original");
        fs::rename(&staging, &moved).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("preserve"), b"replacement").unwrap();
        cleanup_owned(&staging, &identity);
        assert_eq!(fs::read(staging.join("preserve")).unwrap(), b"replacement");
    }
}
