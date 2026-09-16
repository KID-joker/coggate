use std::{fmt, time::Instant};

use zeroize::Zeroizing;

use crate::corpus::CorpusCase;

pub mod fingerprint;
pub mod regex_extract;
pub mod simple_parser;

pub enum Prediction {
    Guess(Zeroizing<String>),
    NoGuess(NoGuessReason),
}

impl fmt::Debug for Prediction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guess(_) => formatter.debug_tuple("Guess").field(&"[REDACTED]").finish(),
            Self::NoGuess(reason) => formatter.debug_tuple("NoGuess").field(reason).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoGuessReason {
    Unsupported,
    NoCandidate,
    Ambiguous,
    ParseFailed,
    ToolRejected,
}

pub trait Baseline {
    fn id(&self) -> &'static str;
    fn predict(&self, case: &CorpusCase) -> Prediction;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

pub fn score_baseline(baseline: &impl Baseline, cases: &[CorpusCase]) -> Vec<CaseResult> {
    cases
        .iter()
        .map(|case| {
            let started = Instant::now();
            let prediction = baseline.predict(case);
            let (outcome, reason) = match prediction {
                Prediction::Guess(answer) if case.oracle_matches(&answer) => {
                    (Outcome::Solved, None)
                }
                Prediction::Guess(_) => (Outcome::Unsolved, Some(NoGuessReason::NoCandidate)),
                Prediction::NoGuess(reason) => (Outcome::Unsolved, Some(reason)),
            };
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            CaseResult {
                case_id: case.id().to_owned(),
                outcome,
                reason,
                duration_ms,
            }
        })
        .collect()
}
