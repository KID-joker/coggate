use coggate_contracts::PublicChallenge;
use serde::{Deserialize, Serialize};

pub const DAILY_LIMIT: i64 = 10;

pub const TERMINAL_STATUSES: &[&str] = &[
    "COMPILE_ERROR",
    "RUNTIME_ERROR",
    "TIMED_OUT",
    "OUTPUT_LIMIT_EXCEEDED",
    "INVALID_OUTPUT",
    "CHALLENGE_EXPIRED",
    "WRONG_ANSWER",
    "PASSED",
    "CORRECT_BUT_LOST_RACE",
    "ARENA_CLOSED",
    "INTERNAL_ERROR",
];

pub fn is_terminal(status: &str) -> bool {
    TERMINAL_STATUSES.contains(&status)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    C,
    Cpp,
    Rust,
    Go,
    Java,
    Python,
    Node,
}

impl Language {
    pub const ALL: [Self; 7] = [
        Self::C,
        Self::Cpp,
        Self::Rust,
        Self::Go,
        Self::Java,
        Self::Python,
        Self::Node,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Java => "java",
            Self::Python => "python",
            Self::Node => "node",
        }
    }
}

impl std::str::FromStr for Language {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "c" => Ok(Self::C),
            "cpp" => Ok(Self::Cpp),
            "rust" => Ok(Self::Rust),
            "go" => Ok(Self::Go),
            "java" => Ok(Self::Java),
            "python" => Ok(Self::Python),
            "node" => Ok(Self::Node),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub github_id: i64,
    pub github_login: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Winner {
    pub github_login: String,
    pub profile_url: String,
    pub submission_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArenaView {
    pub round_id: String,
    pub epoch: i64,
    pub status: String,
    pub sdk_version: String,
    pub sdk_commit: String,
    pub generator_version: String,
    pub supported_languages: Vec<&'static str>,
    pub daily_limit: i64,
    pub source_limit_bytes: usize,
    pub winner: Option<Winner>,
    pub issue_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreviewView {
    pub round_id: String,
    pub epoch: i64,
    pub challenge: PublicChallenge,
}

#[derive(Clone, Debug)]
pub struct Round {
    pub id: String,
    pub epoch: i64,
    pub status: String,
    pub sdk_version: String,
    pub sdk_commit: String,
    pub generator_version: String,
    pub runner_manifest_digest: String,
}

#[derive(Clone, Debug)]
pub struct ClaimedSubmission {
    pub id: String,
    pub round_id: String,
    pub epoch: i64,
    pub github_id: i64,
    pub github_login: String,
    pub language: Language,
    pub source: String,
    pub lease_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QuotaView {
    pub used_today: i64,
    pub remaining_today: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionView {
    pub compile_ms: Option<i64>,
    pub run_ms: Option<i64>,
    pub exit_code: Option<i32>,
    pub compile_output: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub output_encoding: Option<String>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SubmissionView {
    pub submission_id: String,
    pub status: String,
    pub language: String,
    pub source_sha256: String,
    pub challenge: Option<PublicChallenge>,
    pub execution: ExecutionView,
    pub verification_disposition: Option<String>,
    pub quota: QuotaView,
    pub arena_status: String,
    pub winner: Option<Winner>,
}

#[derive(Clone, Debug)]
pub struct AcceptedSubmission {
    pub id: String,
    pub created: bool,
    pub quota: QuotaView,
}

#[derive(Clone, Debug)]
pub struct IssueWork {
    pub event_id: String,
    pub attempt_count: i64,
    pub round_id: String,
    pub epoch: i64,
    pub sdk_version: String,
    pub sdk_commit: String,
    pub generator_version: String,
    pub submission_id: String,
    pub github_login: String,
    pub language: String,
    pub source: String,
    pub source_sha256: String,
    pub compile_ms: Option<i64>,
    pub run_ms: Option<i64>,
    pub runner_image_digest: String,
}
