use std::fmt;

use agentgate_core::{
    canonicalize_answer, contracts::AnswerEncoding, generation::MAX_QUESTION_BYTES,
};
use regex::Regex;
use zeroize::Zeroizing;

use super::{Baseline, NoGuessReason, Prediction};
use crate::corpus::CorpusCase;

const MAX_MATCHES: usize = 16;
const ANSWER_PATTERN: &str = concat!(
    r#"(?im)(?:final[ _-]?answer|requested[ _-]?result|answer|result)"#,
    r#"\s*[:=]\s*["']?([A-Za-z0-9_-]{2,256})["']?"#,
);

pub struct RegexBaseline {
    pattern: Regex,
}

impl RegexBaseline {
    pub fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: Regex::new(ANSWER_PATTERN)?,
        })
    }

    pub fn predict_text(&self, question: &str) -> Prediction {
        if question.len() > MAX_QUESTION_BYTES {
            return Prediction::NoGuess(NoGuessReason::Unsupported);
        }

        let mut candidate: Option<Zeroizing<String>> = None;
        for (index, captures) in self.pattern.captures_iter(question).enumerate() {
            if index >= MAX_MATCHES {
                return Prediction::NoGuess(NoGuessReason::Unsupported);
            }
            let Some(value) = captures.get(1) else {
                return Prediction::NoGuess(NoGuessReason::ParseFailed);
            };
            let Ok(value) = canonicalize_answer(AnswerEncoding::Base64Url, value.as_str()) else {
                continue;
            };
            let value = Zeroizing::new(value);
            if let Some(existing) = &candidate {
                if existing.as_str() != value.as_str() {
                    return Prediction::NoGuess(NoGuessReason::Ambiguous);
                }
            } else {
                candidate = Some(value);
            }
        }

        candidate.map_or(
            Prediction::NoGuess(NoGuessReason::NoCandidate),
            Prediction::Guess,
        )
    }
}

impl Baseline for RegexBaseline {
    fn id(&self) -> &'static str {
        "regex"
    }

    fn predict(&self, case: &CorpusCase) -> Prediction {
        self.predict_text(case.question())
    }
}

impl fmt::Debug for RegexBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegexBaseline")
            .field("pattern", &"[FIXED]")
            .finish()
    }
}
