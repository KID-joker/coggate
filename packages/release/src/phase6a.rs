//! Independent verifier for canonical Phase 6A qualification reports.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canonical::{MAX_METADATA_BYTES, parse_strict_json, validate_sha256},
    receipt::ReportRole,
};

const TRACKED_V1: &str = include_str!("../../../benchmarks/suites/v1.json");
const REPORT_DOMAIN: &[u8] = b"agentgate-benchmark-report-v1";
const MANIFEST_DOMAIN: &[u8] = b"agentgate-suite-manifest-v1";
const CASE_DOMAIN: &[u8] = b"agentgate-benchmark-case-v1";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TOOL_ENTRIES: usize = 16;
const MAX_TOOL_FIELD_BYTES: usize = 128;
const MAX_CASE_DURATION_MS: u64 = 3_600_000;
const RELEASE_CASES: usize = 1_000;

#[derive(Debug, Error)]
pub enum Phase6aError {
    #[error("invalid Phase 6A report")]
    Invalid,
    #[error("Phase 6A report is not canonical")]
    NonCanonical,
}

/// A Phase 6A report verified against the release verifier's tracked suite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReport {
    role: ReportRole,
    subject_id: String,
    subject_version: String,
    suite_version: String,
    generator_version: String,
    manifest_digest: String,
    payload_digest: String,
    solved: usize,
    total: usize,
    qualified: bool,
    kind: ReportKind,
}

impl VerifiedReport {
    pub fn role(&self) -> ReportRole {
        self.role.clone()
    }
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
    pub fn subject_version(&self) -> &str {
        &self.subject_version
    }
    pub fn suite_version(&self) -> &str {
        &self.suite_version
    }
    pub fn generator_version(&self) -> &str {
        &self.generator_version
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }
    pub const fn solved(&self) -> usize {
        self.solved
    }
    pub const fn total(&self) -> usize {
        self.total
    }
    pub const fn qualified(&self) -> bool {
        self.qualified
    }
    pub const fn kind(&self) -> ReportKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Baseline,
    Llm,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u8,
    binding: Binding,
    cases: Vec<ReportCase>,
    summary: Summary,
    payload_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    suite_version: String,
    generator_version: String,
    profile: String,
    manifest_digest: String,
    kind: ReportKind,
    subject_id: String,
    subject_version: String,
    threshold: Threshold,
    tool_versions: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Threshold {
    comparison: Comparison,
    percent: u8,
}

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Comparison {
    AtMost,
    AtLeast,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReportCase {
    case_id: String,
    outcome: Outcome,
    reason: Option<Reason>,
    duration_ms: u64,
}

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Solved,
    Unsolved,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    Unsupported,
    NoCandidate,
    Ambiguous,
    ParseFailed,
    ToolRejected,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    total: usize,
    solved: usize,
    qualified: bool,
    failed_thresholds: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    suite_version: String,
    generator_version: String,
    profiles: BTreeMap<String, Profile>,
    thresholds: BTreeMap<String, Threshold>,
    baseline_versions: BTreeMap<String, String>,
    limits: Limits,
    tools: BTreeMap<String, String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    scored_cases: usize,
    calibration_cases: usize,
    scored_namespace: String,
    calibration_namespace: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_question_bytes: usize,
    max_result_line_bytes: usize,
    process_timeout_ms: u64,
    max_process_output_bytes: usize,
}

/// Verifies a canonical Phase 6A report without loading producer crates.
pub fn verify_phase6a_report(bytes: &[u8]) -> Result<VerifiedReport, Phase6aError> {
    let value = parse_strict_json(bytes, MAX_METADATA_BYTES).map_err(|_| Phase6aError::Invalid)?;
    let report: Report = serde_json::from_value(value).map_err(|_| Phase6aError::Invalid)?;
    if serde_json::to_vec(&report).map_err(|_| Phase6aError::Invalid)? != bytes {
        return Err(Phase6aError::NonCanonical);
    }
    let suite = tracked_suite()?;
    validate_report(&report, &suite)?;
    Ok(VerifiedReport {
        role: match report.binding.kind {
            ReportKind::Baseline => ReportRole::Direct,
            ReportKind::Llm => ReportRole::Indirect,
        },
        subject_id: report.binding.subject_id,
        subject_version: report.binding.subject_version,
        suite_version: report.binding.suite_version,
        generator_version: report.binding.generator_version,
        manifest_digest: report.binding.manifest_digest,
        payload_digest: report.payload_digest,
        solved: report.summary.solved,
        total: report.summary.total,
        qualified: report.summary.qualified,
        kind: report.binding.kind,
    })
}

fn tracked_suite() -> Result<Manifest, Phase6aError> {
    let value = parse_strict_json(TRACKED_V1.as_bytes(), MAX_METADATA_BYTES)
        .map_err(|_| Phase6aError::Invalid)?;
    let suite: Manifest = serde_json::from_value(value).map_err(|_| Phase6aError::Invalid)?;
    if suite.schema_version != 1
        || suite.suite_version != "1.0"
        || suite.generator_version != "1.0"
        || suite.profiles.get("release").is_none_or(|profile| {
            profile.scored_cases != RELEASE_CASES || profile.calibration_cases != RELEASE_CASES
        })
        || suite.thresholds != expected_thresholds()
        || suite.baseline_versions != expected_baselines()
        || suite.tools != expected_tools()
    {
        return Err(Phase6aError::Invalid);
    }
    Ok(suite)
}

fn validate_report(report: &Report, suite: &Manifest) -> Result<(), Phase6aError> {
    let manifest_digest = manifest_digest(suite)?;
    if report.schema_version != 1
        || report.binding.suite_version != suite.suite_version
        || report.binding.generator_version != suite.generator_version
        || report.binding.profile != "release"
        || report.binding.manifest_digest != manifest_digest
        || !safe_identifier(&report.binding.subject_id)
        || !safe_identifier(&report.binding.subject_version)
        || !safe_tools(&report.binding.tool_versions)
        || report.cases.len() != RELEASE_CASES
        || report.summary.total != RELEASE_CASES
        || validate_sha256(&report.payload_digest).is_err()
    {
        return Err(Phase6aError::Invalid);
    }
    let expected_threshold = match report.binding.kind {
        ReportKind::Baseline => {
            if report.binding.subject_version
                != suite
                    .baseline_versions
                    .get(&report.binding.subject_id)
                    .ok_or(Phase6aError::Invalid)?
                    .as_str()
            {
                return Err(Phase6aError::Invalid);
            }
            suite
                .thresholds
                .get(&report.binding.subject_id)
                .copied()
                .ok_or(Phase6aError::Invalid)?
        }
        ReportKind::Llm => {
            if !report.binding.tool_versions.is_empty() {
                return Err(Phase6aError::Invalid);
            }
            *suite.thresholds.get("llm").ok_or(Phase6aError::Invalid)?
        }
    };
    if report.binding.threshold != expected_threshold {
        return Err(Phase6aError::Invalid);
    }
    let mut solved = 0usize;
    for (index, case) in report.cases.iter().enumerate() {
        if case.case_id != case_id(&manifest_digest, index)
            || case.duration_ms > MAX_CASE_DURATION_MS
            || !matches!(
                (case.outcome, case.reason),
                (Outcome::Solved, None) | (Outcome::Unsolved, Some(_))
            )
        {
            return Err(Phase6aError::Invalid);
        }
        if case.outcome == Outcome::Solved {
            solved += 1;
        }
    }
    let qualified = evaluate(expected_threshold, solved, RELEASE_CASES)?;
    let failed = if qualified {
        Vec::new()
    } else {
        vec![report.binding.subject_id.clone()]
    };
    if report.summary.solved != solved
        || report.summary.qualified != qualified
        || report.summary.failed_thresholds != failed
    {
        return Err(Phase6aError::Invalid);
    }
    let payload = Payload::from(report);
    let canonical = serde_json::to_vec(&payload).map_err(|_| Phase6aError::Invalid)?;
    let mut digest_input = REPORT_DOMAIN.to_vec();
    digest_input.extend(canonical);
    if hex::encode(Sha256::digest(digest_input)) != report.payload_digest {
        return Err(Phase6aError::Invalid);
    }
    Ok(())
}

#[derive(Serialize)]
struct Payload<'a> {
    schema_version: u8,
    binding: &'a Binding,
    cases: &'a [ReportCase],
    summary: &'a Summary,
}
impl<'a> From<&'a Report> for Payload<'a> {
    fn from(report: &'a Report) -> Self {
        Self {
            schema_version: report.schema_version,
            binding: &report.binding,
            cases: &report.cases,
            summary: &report.summary,
        }
    }
}

fn manifest_digest(suite: &Manifest) -> Result<String, Phase6aError> {
    let canonical = serde_json::to_vec(suite).map_err(|_| Phase6aError::Invalid)?;
    let mut input = MANIFEST_DOMAIN.to_vec();
    input.extend(canonical);
    Ok(hex::encode(Sha256::digest(input)))
}
fn case_id(manifest_digest: &str, index: usize) -> String {
    let mut hash = Sha256::new();
    hash.update(CASE_DOMAIN);
    hash.update((manifest_digest.len() as u64).to_be_bytes());
    hash.update(manifest_digest.as_bytes());
    hash.update((b"scored".len() as u64).to_be_bytes());
    hash.update(b"scored");
    hash.update((index as u64).to_be_bytes());
    hex::encode(hash.finalize())
}
fn evaluate(threshold: Threshold, solved: usize, total: usize) -> Result<bool, Phase6aError> {
    let left = solved.checked_mul(100).ok_or(Phase6aError::Invalid)?;
    let right = total
        .checked_mul(usize::from(threshold.percent))
        .ok_or(Phase6aError::Invalid)?;
    Ok(match threshold.comparison {
        Comparison::AtMost => left <= right,
        Comparison::AtLeast => left >= right,
    })
}
fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
fn safe_tools(tools: &BTreeMap<String, String>) -> bool {
    tools.len() <= MAX_TOOL_ENTRIES
        && tools
            .iter()
            .all(|(name, version)| safe_tool(name) && safe_tool(version))
}
fn safe_tool(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOOL_FIELD_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b' '
                || matches!(byte, b'_' | b'-' | b'.' | b'+' | b':' | b'(' | b')')
        })
}
fn expected_thresholds() -> BTreeMap<String, Threshold> {
    BTreeMap::from([
        (
            "direct".into(),
            Threshold {
                comparison: Comparison::AtMost,
                percent: 5,
            },
        ),
        (
            "fingerprint".into(),
            Threshold {
                comparison: Comparison::AtMost,
                percent: 1,
            },
        ),
        (
            "llm".into(),
            Threshold {
                comparison: Comparison::AtLeast,
                percent: 80,
            },
        ),
        (
            "regex".into(),
            Threshold {
                comparison: Comparison::AtMost,
                percent: 1,
            },
        ),
        (
            "simple_parser".into(),
            Threshold {
                comparison: Comparison::AtMost,
                percent: 1,
            },
        ),
    ])
}
fn expected_baselines() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("direct".into(), "1.0".into()),
        ("fingerprint".into(), "1.0".into()),
        ("regex".into(), "1.0".into()),
        ("simple_parser".into(), "1.0".into()),
    ])
}
fn expected_tools() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("c".into(), "cc".into()),
        ("cpp".into(), "c++".into()),
        ("go".into(), "go".into()),
        ("java".into(), "java".into()),
        ("rust".into(), "rustc".into()),
    ])
}
