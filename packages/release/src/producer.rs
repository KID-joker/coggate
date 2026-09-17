//! Receipt producers that bind independently verified release evidence to a commit.

use std::{
    fs::{self, File, Metadata},
    path::Path,
};

use thiserror::Error;

use crate::{
    Target,
    canonical::{MAX_METADATA_BYTES, read_bounded, sha256_hex},
    phase5d::verify_phase5d_artifact,
    phase6a::verify_phase6a_report,
    receipt::{FileBinding, Phase5dBinding, Phase6aBinding, Receipt, SanitizerBinding},
};

const MAX_REPORT_BYTES: usize = MAX_METADATA_BYTES;
const MAX_SUMMARY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProducerError {
    #[error("release evidence is invalid")]
    Invalid,
    #[error("release evidence could not be read")]
    Io,
    #[error("release evidence changed while being read")]
    Changed,
}

/// Creates a Phase 5D artifact receipt from independently verified artifact metadata.
pub fn create_phase5d_receipt(
    commit: &str,
    target: Target,
    artifact: &Path,
) -> Result<Receipt, ProducerError> {
    let verified = verify_phase5d_artifact(artifact, target).map_err(|_| ProducerError::Invalid)?;
    if verified.target() != target {
        return Err(ProducerError::Invalid);
    }

    let manifest = verified.manifest_file();
    let checksums = verified.checksums_file();
    let files = vec![
        file_binding(checksums.path(), checksums.size(), checksums.sha256())?,
        file_binding(manifest.path(), manifest.size(), manifest.sha256())?,
    ];
    Receipt::new_phase5d_artifact(
        commit,
        Phase5dBinding {
            platform: verified.target_os().to_owned(),
            target: verified.target_triple().to_owned(),
            profile: "release".to_owned(),
            artifact_name: "agentgate".to_owned(),
            manifest_version: verified.agentgate_version().to_owned(),
            abi_version: verified.abi_version(),
            tree_digest: verified.tree_digest().to_owned(),
            manifest_digest: manifest.sha256().to_owned(),
        },
        files,
    )
    .map_err(|_| ProducerError::Invalid)
}

/// Creates the payload-free receipt for the fixed Phase 5D sanitizer qualification gate.
pub fn create_sanitizer_receipt(
    commit: &str,
    rust_version: &str,
    clang_version: &str,
) -> Result<Receipt, ProducerError> {
    Receipt::new_phase5d_sanitizer(
        commit,
        SanitizerBinding {
            platform: "linux".to_owned(),
            target: "x86_64".to_owned(),
            profile: "release".to_owned(),
            rust_version: rust_version.to_owned(),
            clang_version: clang_version.to_owned(),
            passed: true,
        },
        Vec::new(),
    )
    .map_err(|_| ProducerError::Invalid)
}

/// Creates a Phase 6A integrity receipt from canonical report bytes and a safe public summary.
pub fn create_phase6a_receipt(
    commit: &str,
    report: &Path,
    summary: &Path,
) -> Result<Receipt, ProducerError> {
    let report_name = logical_name(report)?;
    let summary_name = logical_name(summary)?;
    let report_bytes = read_stable_regular(report, MAX_REPORT_BYTES)?;
    let summary_bytes = read_stable_regular(summary, MAX_SUMMARY_BYTES)?;
    validate_summary(&summary_bytes)?;

    let verified = verify_phase6a_report(&report_bytes).map_err(|_| ProducerError::Invalid)?;
    let subject = verified.subject_id();
    if report_name != format!("{subject}-release.json")
        || summary_name != format!("{subject}-release.md")
    {
        return Err(ProducerError::Invalid);
    }
    let report_size = u64::try_from(report_bytes.len()).map_err(|_| ProducerError::Invalid)?;
    let summary_size = u64::try_from(summary_bytes.len()).map_err(|_| ProducerError::Invalid)?;
    let mut files = vec![
        file_binding("report.json", report_size, &sha256_hex(&report_bytes))?,
        file_binding("report.md", summary_size, &sha256_hex(&summary_bytes))?,
    ];
    files.sort_by(|left, right| left.path().cmp(right.path()));

    Receipt::new_phase6a(
        commit,
        Phase6aBinding {
            suite_version: verified.suite_version().to_owned(),
            generator_version: verified.generator_version().to_owned(),
            manifest_digest: verified.manifest_digest().to_owned(),
            profile: "release".to_owned(),
            role: verified.role(),
            subject_id: subject.to_owned(),
            payload_digest: verified.payload_digest().to_owned(),
            qualified: verified.qualified(),
        },
        files,
    )
    .map_err(|_| ProducerError::Invalid)
}

fn file_binding(path: &str, size: u64, hash: &str) -> Result<FileBinding, ProducerError> {
    FileBinding::new(path, size, hash).map_err(|_| ProducerError::Invalid)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    len: u64,
    modified: Option<std::time::SystemTime>,
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

impl FileIdentity {
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

fn identity_for_path(path: &Path, metadata: &Metadata) -> Result<FileIdentity, ProducerError> {
    #[cfg(windows)]
    {
        windows_identity_for_path(path, metadata)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(FileIdentity::from_metadata(metadata))
    }
}

fn identity_for_open_file(file: &File, metadata: &Metadata) -> Result<FileIdentity, ProducerError> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the raw handle is borrowed from `file` for this call and `info` is writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(ProducerError::Io);
        }
        if (info.dwFileAttributes & 0x400) != 0 {
            return Err(ProducerError::Invalid);
        }
        let mut identity = FileIdentity::from_metadata(metadata);
        identity.volume_serial = info.dwVolumeSerialNumber;
        identity.file_index =
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        Ok(identity)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(FileIdentity::from_metadata(metadata))
    }
}

#[cfg(windows)]
fn windows_identity_for_path(
    path: &Path,
    metadata: &Metadata,
) -> Result<FileIdentity, ProducerError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
            OPEN_EXISTING,
        },
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: `wide` is a live, NUL-terminated path; no security/template pointers are used.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ProducerError::Io);
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` remains valid until the matching CloseHandle; `info` is writable.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) } != 0;
    // SAFETY: `handle` was returned by CreateFileW and is closed exactly once here.
    unsafe { CloseHandle(handle) };
    if !ok {
        return Err(ProducerError::Io);
    }
    if (info.dwFileAttributes & 0x400) != 0 {
        return Err(ProducerError::Invalid);
    }
    let mut identity = FileIdentity::from_metadata(metadata);
    identity.volume_serial = info.dwVolumeSerialNumber;
    identity.file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok(identity)
}

pub(crate) fn read_stable_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, ProducerError> {
    let before = fs::symlink_metadata(path).map_err(|_| ProducerError::Io)?;
    if is_link_or_reparse(&before) || !before.is_file() || before.len() > maximum as u64 {
        return Err(ProducerError::Invalid);
    }
    let before_identity = identity_for_path(path, &before)?;
    let mut file = open_read_locked(path)?;
    let opened = file.metadata().map_err(|_| ProducerError::Io)?;
    let opened_identity = identity_for_open_file(&file, &opened)?;
    if !opened.is_file() || opened_identity != before_identity {
        return Err(ProducerError::Changed);
    }
    let bytes = read_bounded(&mut file, maximum).map_err(|_| ProducerError::Invalid)?;
    let opened_after = file.metadata().map_err(|_| ProducerError::Io)?;
    if !opened_after.is_file() || identity_for_open_file(&file, &opened_after)? != opened_identity {
        return Err(ProducerError::Changed);
    }
    let after = fs::symlink_metadata(path).map_err(|_| ProducerError::Io)?;
    if is_link_or_reparse(&after)
        || !after.is_file()
        || identity_for_path(path, &after)? != before_identity
    {
        return Err(ProducerError::Changed);
    }
    Ok(bytes)
}

fn open_read_locked(path: &Path) -> Result<File, ProducerError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|_| ProducerError::Io)
    }
    #[cfg(not(windows))]
    {
        File::open(path).map_err(|_| ProducerError::Io)
    }
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

fn logical_name(path: &Path) -> Result<String, ProducerError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or(ProducerError::Invalid)?;
    if name.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ProducerError::Invalid);
    }
    Ok(name.to_owned())
}

pub(crate) fn validate_summary(bytes: &[u8]) -> Result<(), ProducerError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProducerError::Invalid)?;
    let lower = text.to_ascii_lowercase();
    if [
        "answer",
        "question",
        "prompt",
        "response",
        "environment",
        "source_path",
    ]
    .iter()
    .any(|sentinel| lower.contains(sentinel))
        || bytes
            .iter()
            .any(|byte| *byte == 0 || (*byte).is_ascii_control() && *byte != b'\n')
        || contains_path_like_content(text)
    {
        return Err(ProducerError::Invalid);
    }
    Ok(())
}

fn contains_path_like_content(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.contains(&b'/')
        || bytes.contains(&b'\\')
        || bytes.windows(3).any(|triple| {
            triple[0].is_ascii_alphabetic()
                && triple[1] == b':'
                && (triple[2] == b'/' || triple[2] == b'\\')
        })
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{
        identity_for_open_file, identity_for_path, is_link_or_reparse, open_read_locked,
        read_stable_regular,
    };
    use std::{fs, os::windows::fs::symlink_file};
    use tempfile::TempDir;

    #[test]
    fn opened_handle_identity_matches_the_path_and_reparse_points_are_rejected() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("regular");
        fs::write(&file_path, b"evidence").unwrap();
        let before = fs::symlink_metadata(&file_path).unwrap();
        let expected = identity_for_path(&file_path, &before).unwrap();
        let file = fs::File::open(&file_path).unwrap();
        assert_eq!(
            identity_for_open_file(&file, &file.metadata().unwrap()).unwrap(),
            expected
        );
        assert_eq!(read_stable_regular(&file_path, 64).unwrap(), b"evidence");
        let lock = open_read_locked(&file_path).unwrap();
        assert!(fs::OpenOptions::new().write(true).open(&file_path).is_err());
        drop(lock);

        let reparse = temp.path().join("reparse");
        match symlink_file(&file_path, &reparse) {
            Ok(()) => {
                let metadata = fs::symlink_metadata(reparse).unwrap();
                assert!(is_link_or_reparse(&metadata));
                assert!(matches!(
                    read_stable_regular(&reparse, 64),
                    Err(super::ProducerError::Invalid)
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("unexpected symlink error: {error}"),
        }
    }
}
