//! Canonical, self-authenticating release evidence receipts.

use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{
    MAX_METADATA_BYTES, canonical_compact, parse_strict_json, read_bounded, safe_relative_path,
    sha256_hex, validate_sha256,
};

const SCHEMA_VERSION: u8 = 1;
const RECEIPT_DOMAIN: &[u8] = b"coggate:release-receipt:v1";
const VERIFIER_ID: &str = "phase6b-receipt-v1";
const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_WRITTEN_RECEIPT_BYTES: usize = MAX_METADATA_BYTES + 1;

/// The fixed number of bound sidecar files for a Phase 5D artifact receipt.
pub const PHASE5D_ARTIFACT_FILE_COUNT: usize = 2;
/// The fixed number of bound sidecar files for a Phase 5D sanitizer receipt.
pub const PHASE5D_SANITIZER_FILE_COUNT: usize = 0;
/// The fixed number of bound sidecar files for a Phase 6A report receipt.
pub const PHASE6A_REPORT_FILE_COUNT: usize = 2;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("receipt data is invalid")]
    Invalid,
    #[error("receipt JSON is invalid")]
    Json,
    #[error("receipt is not canonical")]
    NonCanonical,
    #[error("receipt destination already exists")]
    DestinationExists,
    #[error("receipt parent directory is invalid")]
    InvalidParent,
    #[error("receipt I/O failed")]
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportRole {
    Direct,
    Indirect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5dBinding {
    pub platform: String,
    pub target: String,
    pub profile: String,
    pub artifact_name: String,
    pub manifest_version: String,
    pub abi_version: u32,
    pub tree_digest: String,
    pub manifest_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerBinding {
    pub platform: String,
    pub target: String,
    pub profile: String,
    pub rust_version: String,
    pub clang_version: String,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase6aBinding {
    pub suite_version: String,
    pub generator_version: String,
    pub manifest_digest: String,
    pub profile: String,
    pub role: ReportRole,
    pub subject_id: String,
    pub payload_digest: String,
    pub qualified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "binding",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EvidenceBinding {
    Phase5dArtifact(Phase5dBinding),
    Phase5dSanitizer(SanitizerBinding),
    Phase6aReport(Phase6aBinding),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileBinding {
    path: String,
    size: u64,
    hash: String,
}

impl FileBinding {
    pub fn new(
        path: impl Into<String>,
        size: u64,
        hash: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        let binding = Self {
            path: path.into(),
            size,
            hash: hash.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        safe_relative_path(&self.path).map_err(|_| ReceiptError::Invalid)?;
        if self.size == 0 {
            return Err(ReceiptError::Invalid);
        }
        valid_hash(&self.hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Producer {
    id: String,
    verifier: String,
}

impl Producer {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    fn fixed(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            verifier: VERIFIER_ID.to_owned(),
        }
    }

    fn validate_for(&self, evidence: &EvidenceBinding) -> Result<(), ReceiptError> {
        let expected = match evidence {
            EvidenceBinding::Phase5dArtifact(_) | EvidenceBinding::Phase5dSanitizer(_) => "phase5d",
            EvidenceBinding::Phase6aReport(_) => "phase6a",
        };
        if self.id == expected && self.verifier == VERIFIER_ID {
            Ok(())
        } else {
            Err(ReceiptError::Invalid)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Receipt {
    schema_version: u8,
    commit: String,
    producer: Producer,
    evidence: EvidenceBinding,
    files: Vec<FileBinding>,
    evidence_digest: String,
}

impl Receipt {
    pub fn new_phase5d_artifact(
        commit: impl Into<String>,
        binding: Phase5dBinding,
        files: Vec<FileBinding>,
    ) -> Result<Self, ReceiptError> {
        Self::new(
            commit.into(),
            Producer::fixed("phase5d"),
            EvidenceBinding::Phase5dArtifact(binding),
            files,
        )
    }

    pub fn new_phase5d_sanitizer(
        commit: impl Into<String>,
        binding: SanitizerBinding,
        files: Vec<FileBinding>,
    ) -> Result<Self, ReceiptError> {
        Self::new(
            commit.into(),
            Producer::fixed("phase5d"),
            EvidenceBinding::Phase5dSanitizer(binding),
            files,
        )
    }

    pub fn new_phase6a(
        commit: impl Into<String>,
        binding: Phase6aBinding,
        files: Vec<FileBinding>,
    ) -> Result<Self, ReceiptError> {
        Self::new(
            commit.into(),
            Producer::fixed("phase6a"),
            EvidenceBinding::Phase6aReport(binding),
            files,
        )
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }
    pub fn producer(&self) -> &Producer {
        &self.producer
    }
    pub fn producer_id(&self) -> &str {
        self.producer.id()
    }
    pub fn evidence(&self) -> &EvidenceBinding {
        &self.evidence
    }
    pub fn files(&self) -> &[FileBinding] {
        &self.files
    }
    pub fn digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ReceiptError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|_| ReceiptError::Json)?;
        canonical_compact(&value).map_err(|_| ReceiptError::Json)
    }

    pub fn parse_and_verify(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let value = parse_strict_json(bytes, MAX_METADATA_BYTES).map_err(|_| ReceiptError::Json)?;
        let raw: RawReceipt = serde_json::from_value(value).map_err(|_| ReceiptError::Json)?;
        let receipt = Self::from_raw(raw);
        receipt.validate()?;
        let canonical = receipt.to_canonical_json()?;
        if canonical != bytes {
            return Err(ReceiptError::NonCanonical);
        }
        Ok(receipt)
    }

    /// Verifies bytes read from a receipt sidecar written by [`write_receipt`].
    ///
    /// The persisted wire format is canonical JSON followed by exactly one line-feed byte.
    pub fn parse_written_and_verify(bytes: &[u8]) -> Result<Self, ReceiptError> {
        if bytes.len() > MAX_WRITTEN_RECEIPT_BYTES {
            return Err(ReceiptError::Invalid);
        }
        let canonical = bytes.strip_suffix(b"\n").ok_or(ReceiptError::Invalid)?;
        if canonical.ends_with(b"\n") || canonical.ends_with(b"\r") {
            return Err(ReceiptError::Invalid);
        }
        Self::parse_and_verify(canonical)
    }

    fn new(
        commit: String,
        producer: Producer,
        evidence: EvidenceBinding,
        files: Vec<FileBinding>,
    ) -> Result<Self, ReceiptError> {
        let mut receipt = Self {
            schema_version: SCHEMA_VERSION,
            commit,
            producer,
            evidence,
            files,
            evidence_digest: String::new(),
        };
        receipt.validate_without_digest()?;
        receipt.evidence_digest = receipt.computed_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn from_raw(raw: RawReceipt) -> Self {
        Self {
            schema_version: raw.schema_version,
            commit: raw.commit,
            producer: Producer {
                id: raw.producer.id,
                verifier: raw.producer.verifier,
            },
            evidence: raw.evidence,
            files: raw
                .files
                .into_iter()
                .map(|file| FileBinding {
                    path: file.path,
                    size: file.size,
                    hash: file.hash,
                })
                .collect(),
            evidence_digest: raw.evidence_digest,
        }
    }

    fn computed_digest(&self) -> Result<String, ReceiptError> {
        let payload = ReceiptPayload::from(self);
        let value = serde_json::to_value(payload).map_err(|_| ReceiptError::Json)?;
        let canonical = canonical_compact(&value).map_err(|_| ReceiptError::Json)?;
        let mut input = Vec::with_capacity(RECEIPT_DOMAIN.len() + canonical.len());
        input.extend_from_slice(RECEIPT_DOMAIN);
        input.extend_from_slice(&canonical);
        Ok(sha256_hex(&input))
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        self.validate_without_digest()?;
        valid_hash(&self.evidence_digest)?;
        if self.computed_digest()? != self.evidence_digest {
            return Err(ReceiptError::Invalid);
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), ReceiptError> {
        if self.schema_version != SCHEMA_VERSION || !valid_commit(&self.commit) {
            return Err(ReceiptError::Invalid);
        }
        self.producer.validate_for(&self.evidence)?;
        validate_evidence(&self.evidence)?;
        let expected_count = match self.evidence {
            EvidenceBinding::Phase5dArtifact(_) => PHASE5D_ARTIFACT_FILE_COUNT,
            EvidenceBinding::Phase5dSanitizer(_) => PHASE5D_SANITIZER_FILE_COUNT,
            EvidenceBinding::Phase6aReport(_) => PHASE6A_REPORT_FILE_COUNT,
        };
        if self.files.len() != expected_count {
            return Err(ReceiptError::Invalid);
        }
        let mut prior = None;
        for file in &self.files {
            file.validate()?;
            if prior.is_some_and(|path| path >= file.path.as_str()) {
                return Err(ReceiptError::Invalid);
            }
            prior = Some(file.path.as_str());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReceipt {
    schema_version: u8,
    commit: String,
    producer: RawProducer,
    evidence: EvidenceBinding,
    files: Vec<RawFileBinding>,
    evidence_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProducer {
    id: String,
    verifier: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileBinding {
    path: String,
    size: u64,
    hash: String,
}

#[derive(Serialize)]
struct ReceiptPayload<'a> {
    schema_version: u8,
    commit: &'a str,
    producer: &'a Producer,
    evidence: &'a EvidenceBinding,
    files: &'a [FileBinding],
}

impl<'a> From<&'a Receipt> for ReceiptPayload<'a> {
    fn from(receipt: &'a Receipt) -> Self {
        Self {
            schema_version: receipt.schema_version,
            commit: &receipt.commit,
            producer: &receipt.producer,
            evidence: &receipt.evidence,
            files: &receipt.files,
        }
    }
}

/// Atomically publishes a receipt sidecar without replacing an existing destination.
///
/// The parent/output directory is trusted and must not be concurrently replaced. This provides
/// atomic visibility and no-clobber publication, not portable power-loss durability.
pub fn write_receipt(path: &Path, receipt: &Receipt) -> Result<(), ReceiptError> {
    receipt.validate()?;
    let parent = receipt_parent(path);
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ReceiptError::InvalidParent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(ReceiptError::InvalidParent);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(ReceiptError::DestinationExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ReceiptError::Io),
    }

    let canonical = receipt.to_canonical_json()?;
    let mut expected = canonical.clone();
    expected.push(b'\n');
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| ReceiptError::Io)?;
    temporary
        .write_all(&expected)
        .map_err(|_| ReceiptError::Io)?;
    temporary.flush().map_err(|_| ReceiptError::Io)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| ReceiptError::Io)?;

    let file = temporary.as_file_mut();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ReceiptError::Io)?;
    let actual = read_bounded(file, MAX_WRITTEN_RECEIPT_BYTES).map_err(|_| ReceiptError::Io)?;
    if actual != expected || !actual.ends_with(b"\n") {
        return Err(ReceiptError::Io);
    }
    if Receipt::parse_written_and_verify(&actual)? != *receipt {
        return Err(ReceiptError::Invalid);
    }

    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            ReceiptError::DestinationExists
        } else {
            ReceiptError::Io
        }
    })?;
    Ok(())
}

fn receipt_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn validate_evidence(evidence: &EvidenceBinding) -> Result<(), ReceiptError> {
    match evidence {
        EvidenceBinding::Phase5dArtifact(binding) => {
            if !matches!(
                (binding.platform.as_str(), binding.target.as_str()),
                ("Linux", "x86_64-unknown-linux-gnu")
                    | ("Darwin", "x86_64-apple-darwin")
                    | ("Windows", "x86_64-pc-windows-msvc")
            ) || binding.profile != "release"
                || binding.artifact_name != "coggate"
                || binding.manifest_version != "0.1.0"
                || binding.abi_version != 1
            {
                return Err(ReceiptError::Invalid);
            }
            valid_hash(&binding.tree_digest)?;
            valid_hash(&binding.manifest_digest)
        }
        EvidenceBinding::Phase5dSanitizer(binding) => {
            if binding.platform != "linux"
                || binding.target != "x86_64"
                || binding.profile != "release"
                || !binding.passed
            {
                return Err(ReceiptError::Invalid);
            }
            valid_numeric_dot_version(&binding.rust_version)?;
            valid_numeric_dot_version(&binding.clang_version)
        }
        EvidenceBinding::Phase6aReport(binding) => {
            valid_version(&binding.suite_version)?;
            valid_version(&binding.generator_version)?;
            valid_hash(&binding.manifest_digest)?;
            if binding.profile != "release" {
                return Err(ReceiptError::Invalid);
            }
            valid_identifier(&binding.subject_id)?;
            valid_hash(&binding.payload_digest)
        }
    }
}

fn valid_identifier(value: &str) -> Result<(), ReceiptError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        Err(ReceiptError::Invalid)
    } else {
        Ok(())
    }
}

fn valid_version(value: &str) -> Result<(), ReceiptError> {
    valid_identifier(value)
}

fn valid_numeric_dot_version(value: &str) -> Result<(), ReceiptError> {
    if value.is_empty()
        || value.len() > 32
        || value.starts_with('.')
        || value.ends_with('.')
        || value
            .split('.')
            .any(|segment| segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()))
    {
        Err(ReceiptError::Invalid)
    } else {
        Ok(())
    }
}

fn valid_hash(value: &str) -> Result<(), ReceiptError> {
    validate_sha256(value).map_err(|_| ReceiptError::Invalid)
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::receipt_parent;
    use std::path::Path;

    #[test]
    fn lexical_empty_parent_uses_current_directory() {
        assert_eq!(receipt_parent(Path::new("receipt.json")), Path::new("."));
    }
}
