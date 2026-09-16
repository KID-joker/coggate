use std::{collections::BTreeMap, fmt};

use agentgate_core::generation::MAX_QUESTION_BYTES;
use agentgate_core::{canonicalize_answer, contracts::AnswerEncoding};
use zeroize::Zeroizing;

use super::{Baseline, NoGuessReason, Prediction};
use crate::corpus::CorpusCase;

const PRESERVED_IDENTIFIERS: &[&str] = &[
    "add_u8",
    "auto",
    "base64url_decode_no_pad",
    "base64url_no_pad",
    "byte",
    "bytes",
    "bytes_ascii",
    "concat",
    "conditional_order",
    "even_bytes",
    "exports",
    "fn",
    "func",
    "function",
    "hex_decode_lower",
    "hex_lower",
    "let",
    "odd_bytes",
    "permute",
    "return",
    "reverse",
    "rotate_left",
    "rotate_left_derived",
    "rotate_right",
    "sha256_prefix",
    "slice",
    "sub_u8",
    "xor_repeat",
];

enum Entry {
    Unique(Zeroizing<String>),
    Ambiguous,
}

pub struct FingerprintBaseline {
    entries: BTreeMap<String, Entry>,
}

impl FingerprintBaseline {
    pub fn train(cases: &[CorpusCase]) -> Self {
        let examples = cases
            .iter()
            .map(|case| (case.question(), case.calibration_answer()));
        Self::from_owned_examples(examples)
    }

    pub fn from_examples<'a>(
        examples: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, FingerprintError> {
        let owned = examples
            .into_iter()
            .map(|(question, answer)| {
                let answer = canonicalize_answer(AnswerEncoding::Base64Url, answer)
                    .map_err(|_| FingerprintError::InvalidAnswer)?;
                Ok((question, Zeroizing::new(answer)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_owned_examples(owned))
    }

    fn from_owned_examples<'a>(
        examples: impl IntoIterator<Item = (&'a str, Zeroizing<String>)>,
    ) -> Self {
        let mut entries = BTreeMap::new();
        for (question, answer) in examples {
            let Some(fingerprint) = normalize(question) else {
                continue;
            };
            match entries.entry(fingerprint) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Entry::Unique(answer));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let conflicts = match entry.get() {
                        Entry::Unique(existing) => existing.as_str() != answer.as_str(),
                        Entry::Ambiguous => false,
                    };
                    if conflicts {
                        entry.insert(Entry::Ambiguous);
                    }
                }
            }
        }
        Self { entries }
    }

    pub fn predict_text(&self, question: &str) -> Prediction {
        let Some(fingerprint) = normalize(question) else {
            return Prediction::NoGuess(NoGuessReason::Unsupported);
        };
        match self.entries.get(&fingerprint) {
            Some(Entry::Unique(answer)) => {
                Prediction::Guess(Zeroizing::new(answer.as_str().to_owned()))
            }
            Some(Entry::Ambiguous) => Prediction::NoGuess(NoGuessReason::Ambiguous),
            None => Prediction::NoGuess(NoGuessReason::NoCandidate),
        }
    }
}

impl Baseline for FingerprintBaseline {
    fn id(&self) -> &'static str {
        "fingerprint"
    }

    fn predict(&self, case: &CorpusCase) -> Prediction {
        self.predict_text(case.question())
    }
}

impl fmt::Debug for FingerprintBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ambiguous = self
            .entries
            .values()
            .filter(|entry| matches!(entry, Entry::Ambiguous))
            .count();
        formatter
            .debug_struct("FingerprintBaseline")
            .field("entries", &self.entries.len())
            .field("ambiguous", &ambiguous)
            .finish()
    }
}

fn normalize(question: &str) -> Option<String> {
    if question.len() > MAX_QUESTION_BYTES {
        return None;
    }
    let bytes = question.as_bytes();
    let mut output = String::with_capacity(bytes.len());
    let mut index = 0;
    let mut pending_space = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            pending_space = !output.is_empty();
            index += 1;
            continue;
        }
        if pending_space {
            output.push(' ');
            pending_space = false;
        }

        if byte == b'"' || byte == b'\'' {
            let quote = byte;
            index += 1;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            if index == bytes.len() {
                return None;
            }
            index += 1;
            output.push('S');
        } else if byte.is_ascii_digit() {
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            output.push('N');
        } else if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            let identifier = std::str::from_utf8(&bytes[start..index]).ok()?;
            if PRESERVED_IDENTIFIERS.binary_search(&identifier).is_ok() {
                output.push_str(identifier);
            } else {
                output.push('I');
            }
        } else if byte.is_ascii() {
            output.push(char::from(byte));
            index += 1;
        } else {
            return None;
        }
    }
    Some(output.trim().to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FingerprintError {
    #[error("invalid fingerprint calibration answer")]
    InvalidAnswer,
}
