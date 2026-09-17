use std::{fmt, time::Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::corpus::CorpusCase;

pub mod direct;
pub mod fingerprint;
pub mod regex_extract;
pub mod simple_parser;

pub enum Prediction {
    Guess(Zeroizing<String>),
    NoGuess(NoGuessReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BaselineError {
    #[error("baseline infrastructure failed")]
    Infrastructure,
}

impl fmt::Debug for Prediction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guess(_) => formatter.debug_tuple("Guess").field(&"[REDACTED]").finish(),
            Self::NoGuess(reason) => formatter.debug_tuple("NoGuess").field(reason).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoGuessReason {
    Unsupported,
    NoCandidate,
    Ambiguous,
    ParseFailed,
    ToolRejected,
}

pub trait Baseline {
    fn id(&self) -> &'static str;
    fn predict(&self, case: &CorpusCase) -> Result<Prediction, BaselineError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Solved,
    Unsolved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseResult {
    case_id: String,
    outcome: Outcome,
    reason: Option<NoGuessReason>,
    duration_ms: u64,
}

impl CaseResult {
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub const fn reason(&self) -> Option<NoGuessReason> {
        self.reason
    }

    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
}

pub fn score_baseline(
    baseline: &impl Baseline,
    cases: &[CorpusCase],
) -> Result<Vec<CaseResult>, BaselineError> {
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let started = Instant::now();
        let prediction = baseline.predict(case)?;
        let (outcome, reason) = match prediction {
            Prediction::Guess(answer) if case.oracle_matches(&answer) => (Outcome::Solved, None),
            Prediction::Guess(_) => (Outcome::Unsolved, Some(NoGuessReason::NoCandidate)),
            Prediction::NoGuess(reason) => (Outcome::Unsolved, Some(reason)),
        };
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        results.push(CaseResult {
            case_id: case.id().to_owned(),
            outcome,
            reason,
            duration_ms,
        });
    }
    Ok(results)
}
