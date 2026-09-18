//! Fail-closed loading and authorization of the fixed Phase 6B evidence set.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, Metadata},
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{
    EvidenceBinding, FileBinding, Receipt, ReportRole, Target,
    canonical::{MAX_METADATA_BYTES, sha256_hex},
    phase5d::verify_phase5d_artifact,
    phase6a::verify_phase6a_report,
    producer::{read_stable_regular, validate_summary},
};

const REPORT_SUMMARY_MAX_BYTES: usize = 1024 * 1024;
const RECEIPT_ROLES: [&str; 9] = [
    "linux",
    "macos",
    "windows",
    "sanitizer",
    "direct",
    "fingerprint",
    "regex",
    "simple_parser",
    "llm",
];
const RECEIPT_FILES: [&str; 9] = [
    "linux.json",
    "macos.json",
    "windows.json",
    "sanitizer.json",
    "direct.json",
    "fingerprint.json",
    "regex.json",
    "simple_parser.json",
    "llm.json",
];
const REPORTS: [(&str, Option<&str>, ReportRole); 5] = [
    ("direct", Some("direct"), ReportRole::Direct),
    ("fingerprint", Some("fingerprint"), ReportRole::Direct),
    ("regex", Some("regex"), ReportRole::Direct),
    ("simple_parser", Some("simple_parser"), ReportRole::Direct),
    ("llm", None, ReportRole::Indirect),
];
const ARTIFACTS: [(&str, &str, Target); 3] = [
    ("linux", "x86_64-unknown-linux-gnu", Target::LinuxX86_64),
    ("macos", "x86_64-apple-darwin", Target::MacosX86_64),
    ("windows", "x86_64-pc-windows-msvc", Target::WindowsX86_64),
];

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("release evidence is invalid")]
    Invalid,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecisionError {
    #[error("release authorization is blocked")]
    Blocked { roles: Vec<String> },
}

/// Immutable release facts captured only after the complete fixed layout has verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSet {
    commit: String,
    coggate_version: String,
    abi_version: u32,
    generator_version: String,
    suite_manifest_digest: String,
    receipt_digests: BTreeMap<String, String>,
    qualified: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseDecision {
    commit: String,
    coggate_version: String,
    abi_version: u32,
    generator_version: String,
    suite_manifest_digest: String,
    receipt_digests: BTreeMap<String, String>,
    authorized: bool,
}

impl ReleaseDecision {
    pub fn commit(&self) -> &str {
        &self.commit
    }
    pub fn coggate_version(&self) -> &str {
        &self.coggate_version
    }
    pub fn abi_version(&self) -> u32 {
        self.abi_version
    }
    pub fn generator_version(&self) -> &str {
        &self.generator_version
    }
    pub fn suite_manifest_digest(&self) -> &str {
        &self.suite_manifest_digest
    }
    pub fn receipt_digests(&self) -> &BTreeMap<String, String> {
        &self.receipt_digests
    }
    pub fn authorized(&self) -> bool {
        self.authorized
    }
}

impl EvidenceSet {
    pub fn load(root: &Path, commit: &str) -> Result<Self, EvidenceError> {
        Self::load_inner(root, commit, false)
    }

    /// Bundle roots add only bundle metadata and the tracked suite beside evidence.
    pub(crate) fn load_bundle_root(root: &Path, commit: &str) -> Result<Self, EvidenceError> {
        Self::load_inner(root, commit, true)
    }

    fn load_inner(root: &Path, commit: &str, bundle_root: bool) -> Result<Self, EvidenceError> {
        if !valid_commit(commit) {
            return Err(EvidenceError::Invalid);
        }
        let mut watched = Vec::new();
        watch_root(root, &mut watched)?;
        exact_tree(root, &mut watched, bundle_root)?;

        let receipts = receipt_map(root, commit)?;
        let mut receipt_digests = BTreeMap::new();
        for role in RECEIPT_ROLES {
            receipt_digests.insert(role.to_owned(), receipts[role].digest().to_owned());
        }

        let mut version: Option<String> = None;
        let mut abi: Option<u32> = None;
        for (role, target_dir, target) in ARTIFACTS {
            let artifact = root.join("phase5d").join(target_dir).join("artifact");
            let verified =
                verify_phase5d_artifact(&artifact, target).map_err(|_| EvidenceError::Invalid)?;
            let receipt = &receipts[role];
            let EvidenceBinding::Phase5dArtifact(binding) = receipt.evidence() else {
                return Err(EvidenceError::Invalid);
            };
            if receipt.producer_id() != "phase5d"
                || binding.platform != verified.target_os()
                || binding.target != verified.target_triple()
                || binding.profile != "release"
                || binding.artifact_name != "coggate"
                || binding.manifest_version != verified.coggate_version()
                || binding.abi_version != verified.abi_version()
                || binding.tree_digest != verified.tree_digest()
                || binding.manifest_digest != verified.manifest_file().sha256()
                || verified.coggate_version() != "0.1.0"
                || verified.abi_version() != 1
            {
                return Err(EvidenceError::Invalid);
            }
            expected_files(
                receipt.files(),
                [
                    ("SHA256SUMS", verified.checksums_file()),
                    ("manifest.json", verified.manifest_file()),
                ],
            )?;
            match (&version, &abi) {
                (Some(existing), Some(existing_abi)) => {
                    if existing != verified.coggate_version()
                        || *existing_abi != verified.abi_version()
                    {
                        return Err(EvidenceError::Invalid);
                    }
                }
                (None, None) => {
                    version = Some(verified.coggate_version().to_owned());
                    abi = Some(verified.abi_version());
                }
                _ => return Err(EvidenceError::Invalid),
            }
        }

        let sanitizer = &receipts["sanitizer"];
        let EvidenceBinding::Phase5dSanitizer(binding) = sanitizer.evidence() else {
            return Err(EvidenceError::Invalid);
        };
        if sanitizer.producer_id() != "phase5d"
            || !sanitizer.files().is_empty()
            || binding.platform != "linux"
            || binding.target != "x86_64"
            || binding.profile != "release"
            || !binding.passed
        {
            return Err(EvidenceError::Invalid);
        }

        let mut suite: Option<String> = None;
        let mut generator: Option<String> = None;
        let mut manifest: Option<String> = None;
        let mut qualified = BTreeMap::new();
        for (directory, expected_subject, role) in REPORTS {
            let dir = root.join("phase6a").join(directory);
            let report_bytes = read_stable_regular(&dir.join("report.json"), MAX_METADATA_BYTES)
                .map_err(|_| EvidenceError::Invalid)?;
            let summary_bytes =
                read_stable_regular(&dir.join("report.md"), REPORT_SUMMARY_MAX_BYTES)
                    .map_err(|_| EvidenceError::Invalid)?;
            validate_summary(&summary_bytes).map_err(|_| EvidenceError::Invalid)?;
            let report =
                verify_phase6a_report(&report_bytes).map_err(|_| EvidenceError::Invalid)?;
            let receipt = &receipts[directory];
            let EvidenceBinding::Phase6aReport(binding) = receipt.evidence() else {
                return Err(EvidenceError::Invalid);
            };
            if receipt.producer_id() != "phase6a"
                || expected_subject.is_some_and(|subject| report.subject_id() != subject)
                || report.role() != role
                || binding.suite_version != report.suite_version()
                || binding.generator_version != report.generator_version()
                || binding.manifest_digest != report.manifest_digest()
                || binding.profile != "release"
                || binding.role != role
                || binding.subject_id != report.subject_id()
                || binding.payload_digest != report.payload_digest()
                || binding.qualified != report.qualified()
            {
                return Err(EvidenceError::Invalid);
            }
            let report_size =
                u64::try_from(report_bytes.len()).map_err(|_| EvidenceError::Invalid)?;
            let summary_size =
                u64::try_from(summary_bytes.len()).map_err(|_| EvidenceError::Invalid)?;
            expected_file_hashes(
                receipt.files(),
                [
                    ("report.json", report_size, sha256_hex(&report_bytes)),
                    ("report.md", summary_size, sha256_hex(&summary_bytes)),
                ],
            )?;
            if qualified
                .insert(directory.to_owned(), report.qualified())
                .is_some()
            {
                return Err(EvidenceError::Invalid);
            }
            match (&suite, &generator, &manifest) {
                (Some(existing_suite), Some(existing_generator), Some(existing_manifest)) => {
                    if existing_suite != report.suite_version()
                        || existing_generator != report.generator_version()
                        || existing_manifest != report.manifest_digest()
                    {
                        return Err(EvidenceError::Invalid);
                    }
                }
                (None, None, None) => {
                    suite = Some(report.suite_version().to_owned());
                    generator = Some(report.generator_version().to_owned());
                    manifest = Some(report.manifest_digest().to_owned());
                }
                _ => return Err(EvidenceError::Invalid),
            }
        }
        if qualified
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["direct", "fingerprint", "llm", "regex", "simple_parser"])
        {
            return Err(EvidenceError::Invalid);
        }
        recheck_watched(&watched)?;
        Ok(Self {
            commit: commit.to_owned(),
            coggate_version: version.ok_or(EvidenceError::Invalid)?,
            abi_version: abi.ok_or(EvidenceError::Invalid)?,
            generator_version: generator.ok_or(EvidenceError::Invalid)?,
            suite_manifest_digest: manifest.ok_or(EvidenceError::Invalid)?,
            receipt_digests,
            qualified,
        })
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }
    pub fn revalidate(&self, root: &Path) -> Result<(), EvidenceError> {
        if Self::load(root, &self.commit)? == *self {
            Ok(())
        } else {
            Err(EvidenceError::Invalid)
        }
    }
    pub fn authorize(&self) -> Result<ReleaseDecision, DecisionError> {
        let roles: Vec<String> = self
            .qualified
            .iter()
            .filter_map(|(role, qualified)| (!qualified).then_some(role.clone()))
            .collect();
        if !roles.is_empty() {
            return Err(DecisionError::Blocked { roles });
        }
        Ok(ReleaseDecision {
            commit: self.commit.clone(),
            coggate_version: self.coggate_version.clone(),
            abi_version: self.abi_version,
            generator_version: self.generator_version.clone(),
            suite_manifest_digest: self.suite_manifest_digest.clone(),
            receipt_digests: self.receipt_digests.clone(),
            authorized: true,
        })
    }
}

fn receipt_map(root: &Path, commit: &str) -> Result<BTreeMap<String, Receipt>, EvidenceError> {
    let mut result = BTreeMap::new();
    for role in RECEIPT_ROLES {
        let bytes = read_stable_regular(
            &root.join("receipts").join(format!("{role}.json")),
            crate::receipt::MAX_WRITTEN_RECEIPT_BYTES,
        )
        .map_err(|_| EvidenceError::Invalid)?;
        let receipt =
            Receipt::parse_written_and_verify(&bytes).map_err(|_| EvidenceError::Invalid)?;
        if receipt.commit() != commit || result.insert(role.to_owned(), receipt).is_some() {
            return Err(EvidenceError::Invalid);
        }
    }
    Ok(result)
}

fn expected_files<const N: usize>(
    actual: &[FileBinding],
    expected: [(&str, &crate::VerifiedFile); N],
) -> Result<(), EvidenceError> {
    expected_file_hashes(
        actual,
        expected.map(|(path, file)| (path, file.size(), file.sha256().to_owned())),
    )
}

fn expected_file_hashes<const N: usize>(
    actual: &[FileBinding],
    expected: [(&str, u64, String); N],
) -> Result<(), EvidenceError> {
    if actual.len() != N {
        return Err(EvidenceError::Invalid);
    }
    let actual = actual
        .iter()
        .map(|file| (file.path(), file.size(), file.hash()))
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|(path, size, hash)| (*path, *size, hash.as_str()))
        .collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(EvidenceError::Invalid)
    }
}

fn valid_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirIdentity {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_ns: i128,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
}

fn dir_identity(path: &Path, metadata: &Metadata) -> Result<DirIdentity, EvidenceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        Ok(DirIdentity {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            device: metadata.dev(),
            inode: metadata.ino(),
            change_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
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
        // SAFETY: `wide` is NUL-terminated and the returned handle is closed exactly once.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(EvidenceError::Invalid);
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` is live and `info` is writable.
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) } != 0;
        // SAFETY: `handle` is closed exactly once.
        unsafe { CloseHandle(handle) };
        if !ok || (info.dwFileAttributes & 0x400) != 0 {
            return Err(EvidenceError::Invalid);
        }
        Ok(DirIdentity {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            volume_serial: info.dwVolumeSerialNumber,
            file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = path;
        Ok(DirIdentity {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

fn watch_dir(path: &Path, watched: &mut Vec<(PathBuf, DirIdentity)>) -> Result<(), EvidenceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| EvidenceError::Invalid)?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(EvidenceError::Invalid);
    }
    watched.push((path.to_owned(), dir_identity(path, &metadata)?));
    Ok(())
}

fn watch_root(root: &Path, watched: &mut Vec<(PathBuf, DirIdentity)>) -> Result<(), EvidenceError> {
    watch_dir(root, watched)
}

fn exact_tree(
    root: &Path,
    watched: &mut Vec<(PathBuf, DirIdentity)>,
    bundle_root: bool,
) -> Result<(), EvidenceError> {
    let mut root_children = vec![("receipts", true), ("phase5d", true), ("phase6a", true)];
    if bundle_root {
        root_children.extend([
            ("manifest.json", false),
            ("SHA256SUMS", false),
            ("suite", true),
        ]);
    }
    exact_children(root, &root_children, watched)?;
    let receipts = root.join("receipts");
    exact_children(&receipts, &RECEIPT_FILES.map(|name| (name, false)), watched)?;
    let phase5d = root.join("phase5d");
    exact_children(
        &phase5d,
        &ARTIFACTS.map(|(_, directory, _)| (directory, true)),
        watched,
    )?;
    for (_, directory, _) in ARTIFACTS {
        exact_children(&phase5d.join(directory), &[("artifact", true)], watched)?;
    }
    let phase6a = root.join("phase6a");
    exact_children(
        &phase6a,
        &REPORTS.map(|(directory, _, _)| (directory, true)),
        watched,
    )?;
    for (directory, _, _) in REPORTS {
        exact_children(
            &phase6a.join(directory),
            &[("report.json", false), ("report.md", false)],
            watched,
        )?;
    }
    Ok(())
}

fn exact_children(
    dir: &Path,
    expected: &[(&str, bool)],
    watched: &mut Vec<(PathBuf, DirIdentity)>,
) -> Result<(), EvidenceError> {
    watch_dir(dir, watched)?;
    let wanted = expected
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(dir).map_err(|_| EvidenceError::Invalid)? {
        let entry = entry.map_err(|_| EvidenceError::Invalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| EvidenceError::Invalid)?;
        if !wanted.contains(name.as_str()) || !found.insert(name.clone()) {
            return Err(EvidenceError::Invalid);
        }
        let expected_dir = expected
            .iter()
            .find(|(expected_name, _)| *expected_name == name)
            .ok_or(EvidenceError::Invalid)?
            .1;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| EvidenceError::Invalid)?;
        if is_link_or_reparse(&metadata)
            || (expected_dir && !metadata.is_dir())
            || (!expected_dir && !metadata.is_file())
        {
            return Err(EvidenceError::Invalid);
        }
    }
    if found.iter().map(String::as_str).collect::<BTreeSet<_>>() != wanted {
        return Err(EvidenceError::Invalid);
    }
    Ok(())
}

fn recheck_watched(watched: &[(PathBuf, DirIdentity)]) -> Result<(), EvidenceError> {
    for (path, identity) in watched {
        let metadata = fs::symlink_metadata(path).map_err(|_| EvidenceError::Invalid)?;
        if is_link_or_reparse(&metadata)
            || !metadata.is_dir()
            || dir_identity(path, &metadata)? != *identity
        {
            return Err(EvidenceError::Invalid);
        }
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
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
