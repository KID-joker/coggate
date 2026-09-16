use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    baseline::{NoGuessReason, Outcome},
    manifest::{ProfileName, SuiteManifest, Threshold},
};

const REPORT_DOMAIN: &[u8] = b"agentgate-benchmark-report-v1";
const MAX_SUBJECT_BYTES: usize = 128;
const MAX_TOOL_ENTRIES: usize = 16;
const MAX_TOOL_FIELD_BYTES: usize = 128;
const MAX_CASE_DURATION_MS: u64 = 3_600_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Baseline,
    Llm,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportBinding {
    suite_version: String,
    generator_version: String,
    profile: ProfileName,
    manifest_digest: String,
    kind: ReportKind,
    subject_id: String,
    subject_version: String,
    threshold: Threshold,
    tool_versions: BTreeMap<String, String>,
}

impl ReportBinding {
    pub fn baseline(
        suite: &SuiteManifest,
        profile: ProfileName,
        baseline: &str,
        tool_versions: BTreeMap<String, String>,
    ) -> Result<Self, ReportError> {
        let subject_version = suite
            .baseline_version(baseline)
            .ok_or(ReportError::InvalidBinding)?;
        let threshold = suite
            .threshold(baseline)
            .ok_or(ReportError::InvalidBinding)?;
        let binding = Self {
            suite_version: suite.suite_version().to_owned(),
            generator_version: suite.generator_version().to_owned(),
            profile,
            manifest_digest: suite.digest().to_owned(),
            kind: ReportKind::Baseline,
            subject_id: baseline.to_owned(),
            subject_version: subject_version.to_owned(),
            threshold,
            tool_versions,
        };
        binding.validate(suite)?;
        Ok(binding)
    }

    pub fn llm(
        suite: &SuiteManifest,
        profile: ProfileName,
        model_id: &str,
        run_id: &str,
    ) -> Result<Self, ReportError> {
        let binding = Self {
            suite_version: suite.suite_version().to_owned(),
            generator_version: suite.generator_version().to_owned(),
            profile,
            manifest_digest: suite.digest().to_owned(),
            kind: ReportKind::Llm,
            subject_id: model_id.to_owned(),
            subject_version: run_id.to_owned(),
            threshold: suite.threshold("llm").ok_or(ReportError::InvalidBinding)?,
            tool_versions: BTreeMap::new(),
        };
        binding.validate(suite)?;
        Ok(binding)
    }

    pub const fn profile(&self) -> ProfileName {
        self.profile
    }

    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    fn validate(&self, suite: &SuiteManifest) -> Result<(), ReportError> {
        if self.suite_version != suite.suite_version()
            || self.generator_version != suite.generator_version()
            || self.manifest_digest != suite.digest()
            || self.subject_id.is_empty()
            || self.subject_id.len() > MAX_SUBJECT_BYTES
            || self.subject_version.is_empty()
            || self.subject_version.len() > MAX_SUBJECT_BYTES
            || !self.subject_id.bytes().all(is_safe_identifier_byte)
            || !self.subject_version.bytes().all(is_safe_identifier_byte)
            || self.tool_versions.len() > MAX_TOOL_ENTRIES
            || self.tool_versions.iter().any(|(name, version)| {
                name.is_empty()
                    || name.len() > MAX_TOOL_FIELD_BYTES
                    || version.is_empty()
                    || version.len() > MAX_TOOL_FIELD_BYTES
                    || !name.bytes().all(is_safe_tool_field_byte)
                    || !version.bytes().all(is_safe_tool_field_byte)
            })
        {
            return Err(ReportError::InvalidBinding);
        }
        let expected_threshold = match self.kind {
            ReportKind::Baseline => suite.threshold(&self.subject_id),
            ReportKind::Llm => suite.threshold("llm"),
        }
        .ok_or(ReportError::InvalidBinding)?;
        if self.threshold != expected_threshold
            || suite.profile(self.profile).is_none()
            || (self.kind == ReportKind::Baseline
                && suite.baseline_version(&self.subject_id) != Some(self.subject_version.as_str()))
        {
            return Err(ReportError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportCase {
    case_id: String,
    outcome: Outcome,
    reason: Option<NoGuessReason>,
    duration_ms: u64,
}

impl ReportCase {
    pub fn new(
        case_id: String,
        outcome: Outcome,
        reason: Option<NoGuessReason>,
        duration_ms: u64,
    ) -> Result<Self, ReportError> {
        let case = Self {
            case_id,
            outcome,
            reason,
            duration_ms,
        };
        case.validate()?;
        Ok(case)
    }

    fn validate(&self) -> Result<(), ReportError> {
        let valid_id = self.case_id.len() == 64
            && self
                .case_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let valid_reason = matches!(
            (self.outcome, self.reason),
            (Outcome::Solved, None) | (Outcome::Unsolved, Some(_))
        );
        if valid_id && valid_reason && self.duration_ms <= MAX_CASE_DURATION_MS {
            Ok(())
        } else {
            Err(ReportError::InvalidCase)
        }
    }
}

fn is_safe_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn is_safe_tool_field_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || byte.is_ascii_whitespace() && byte == b' '
        || matches!(byte, b'_' | b'-' | b'.' | b'+' | b':' | b'(' | b')')
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReportSummary {
    total: usize,
    solved: usize,
    qualified: bool,
    failed_thresholds: Vec<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReport {
    schema_version: u8,
    binding: ReportBinding,
    cases: Vec<ReportCase>,
    summary: ReportSummary,
    payload_digest: String,
}

impl QualificationReport {
    pub fn from_cases(binding: ReportBinding, cases: Vec<ReportCase>) -> Result<Self, ReportError> {
        let solved = cases
            .iter()
            .filter(|case| case.outcome == Outcome::Solved)
            .count();
        let qualified = binding
            .threshold
            .evaluate(solved, cases.len())
            .map_err(|_| ReportError::InvalidSummary)?;
        let failed_thresholds = if qualified {
            Vec::new()
        } else {
            vec![binding.subject_id.clone()]
        };
        let mut report = Self {
            schema_version: 1,
            binding,
            summary: ReportSummary {
                total: cases.len(),
                solved,
                qualified,
                failed_thresholds,
            },
            cases,
            payload_digest: String::new(),
        };
        report.validate_structure()?;
        report.payload_digest = report.compute_digest()?;
        Ok(report)
    }

    pub const fn qualified(&self) -> bool {
        self.summary.qualified
    }

    pub const fn solved(&self) -> usize {
        self.summary.solved
    }

    pub const fn total(&self) -> usize {
        self.summary.total
    }

    pub fn failed_thresholds(&self) -> &[String] {
        &self.summary.failed_thresholds
    }

    pub fn subject_id(&self) -> &str {
        self.binding.subject_id()
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub fn to_canonical_json(&self) -> Result<String, ReportError> {
        serde_json::to_string(self).map_err(|_| ReportError::Serialization)
    }

    fn compute_digest(&self) -> Result<String, ReportError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: u8,
            binding: &'a ReportBinding,
            cases: &'a [ReportCase],
            summary: &'a ReportSummary,
        }
        let bytes = serde_json::to_vec(&Payload {
            schema_version: self.schema_version,
            binding: &self.binding,
            cases: &self.cases,
            summary: &self.summary,
        })
        .map_err(|_| ReportError::Serialization)?;
        let mut hash = Sha256::new();
        hash.update(REPORT_DOMAIN);
        hash.update(bytes);
        Ok(hex::encode(hash.finalize()))
    }

    fn validate_structure(&self) -> Result<(), ReportError> {
        if self.schema_version != 1 || self.cases.is_empty() {
            return Err(ReportError::InvalidSummary);
        }
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if !ids.insert(case.case_id.as_str()) {
                return Err(ReportError::DuplicateCase);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for QualificationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationReport")
            .field("binding", &self.binding)
            .field("total", &self.total())
            .field("solved", &self.solved())
            .field("qualified", &self.qualified())
            .field("payload_digest", &self.payload_digest)
            .finish()
    }
}

pub fn verify_report(
    source: &str,
    suite: &SuiteManifest,
) -> Result<QualificationReport, ReportError> {
    let report: QualificationReport =
        serde_json::from_str(source).map_err(|_| ReportError::InvalidJson)?;
    report.binding.validate(suite)?;
    report.validate_structure()?;
    let expected_total = suite
        .profile(report.binding.profile)
        .ok_or(ReportError::InvalidBinding)?
        .scored_cases();
    let solved = report
        .cases
        .iter()
        .filter(|case| case.outcome == Outcome::Solved)
        .count();
    let qualified = report
        .binding
        .threshold
        .evaluate(solved, report.cases.len())
        .map_err(|_| ReportError::InvalidSummary)?;
    let failed = if qualified {
        Vec::new()
    } else {
        vec![report.binding.subject_id.clone()]
    };
    if report.cases.len() != expected_total
        || report.summary.total != report.cases.len()
        || report.summary.solved != solved
        || report.summary.qualified != qualified
        || report.summary.failed_thresholds != failed
        || report.payload_digest != report.compute_digest()?
    {
        return Err(ReportError::InvalidSummary);
    }
    Ok(report)
}

pub struct ReportPaths {
    json: PathBuf,
    markdown: PathBuf,
}

impl ReportPaths {
    pub fn json(&self) -> &Path {
        &self.json
    }

    pub fn markdown(&self) -> &Path {
        &self.markdown
    }
}

pub fn write_report_bundle(
    directory: &Path,
    report: &QualificationReport,
) -> Result<ReportPaths, ReportError> {
    if !directory.is_dir() {
        return Err(ReportError::Io);
    }
    let stem = format!(
        "{}-{}",
        report.binding.subject_id,
        report.binding.profile.as_str()
    );
    let json = directory.join(format!("{stem}.json"));
    let markdown = directory.join(format!("{stem}.md"));
    if json.exists() || markdown.exists() {
        return Err(ReportError::DestinationExists);
    }
    let json_temp = directory.join(format!(".{stem}.json.tmp"));
    let markdown_temp = directory.join(format!(".{stem}.md.tmp"));
    let json_source = report.to_canonical_json()?;
    let markdown_source = markdown_summary(report);

    write_new(&json_temp, json_source.as_bytes())?;
    if verify_report(
        &fs::read_to_string(&json_temp).map_err(|_| ReportError::Io)?,
        &SuiteManifest::tracked_v1().map_err(|_| ReportError::InvalidBinding)?,
    )
    .is_err()
    {
        let _ = fs::remove_file(&json_temp);
        return Err(ReportError::InvalidSummary);
    }
    if let Err(error) = write_new(&markdown_temp, markdown_source.as_bytes()) {
        let _ = fs::remove_file(&json_temp);
        return Err(error);
    }
    if fs::rename(&json_temp, &json).is_err() {
        let _ = fs::remove_file(&json_temp);
        let _ = fs::remove_file(&markdown_temp);
        return Err(ReportError::Io);
    }
    if fs::rename(&markdown_temp, &markdown).is_err() {
        let _ = fs::remove_file(&json);
        let _ = fs::remove_file(&markdown_temp);
        return Err(ReportError::Io);
    }
    Ok(ReportPaths { json, markdown })
}

fn write_new(path: &Path, contents: &[u8]) -> Result<(), ReportError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ReportError::Io)?;
    file.write_all(contents).map_err(|_| ReportError::Io)?;
    file.flush().map_err(|_| ReportError::Io)?;
    file.sync_all().map_err(|_| ReportError::Io)
}

fn markdown_summary(report: &QualificationReport) -> String {
    format!(
        "# AgentGate benchmark report\n\nsubject: {}\nprofile: {}\ntotal: {}\nsolved: {}\nqualified: {}\npayload digest: {}\n",
        report.binding.subject_id,
        report.binding.profile.as_str(),
        report.total(),
        report.solved(),
        report.qualified(),
        report.payload_digest,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReportError {
    #[error("invalid report binding")]
    InvalidBinding,
    #[error("invalid report case")]
    InvalidCase,
    #[error("duplicate report case")]
    DuplicateCase,
    #[error("invalid report summary")]
    InvalidSummary,
    #[error("invalid report JSON")]
    InvalidJson,
    #[error("report serialization failed")]
    Serialization,
    #[error("report destination exists")]
    DestinationExists,
    #[error("report I/O failed")]
    Io,
}
