use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, Read, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{
    baseline::{NoGuessReason, Outcome},
    corpus::{Corpus, CorpusCase},
    manifest::{ProfileName, SuiteManifest},
    report::{QualificationReport, ReportBinding, ReportCase},
};

const MAX_ID_BYTES: usize = 128;
const MAX_ANSWER_BYTES: usize = 256;
const MAX_LATENCY_MS: u64 = 3_600_000;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CorpusHeader<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    schema_version: u8,
    suite_manifest_digest: &'a str,
    generator_version: &'a str,
    profile: ProfileName,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PublicCase<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    case_id: &'a str,
    generator_version: &'a str,
    question: &'a str,
    question_digest: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunHeader {
    #[serde(rename = "type")]
    record_type: String,
    schema_version: u8,
    suite_manifest_digest: String,
    generator_version: String,
    profile: ProfileName,
    model_id: String,
    run_id: String,
}

enum ImportedOutcome {
    Answered {
        answer: Zeroizing<String>,
        latency_ms: u64,
    },
    Timeout {
        latency_ms: u64,
    },
    ModelError {
        latency_ms: u64,
    },
    Refused {
        latency_ms: u64,
    },
}

impl ImportedOutcome {
    const fn latency_ms(&self) -> u64 {
        match self {
            Self::Answered { latency_ms, .. }
            | Self::Timeout { latency_ms }
            | Self::ModelError { latency_ms }
            | Self::Refused { latency_ms } => *latency_ms,
        }
    }
}

struct ImportedResult {
    case_id: String,
    question_digest: String,
    outcome: ImportedOutcome,
}

pub fn export_llm(
    mut writer: impl Write,
    suite: &SuiteManifest,
    profile: ProfileName,
    corpus: &Corpus,
) -> Result<(), LlmError> {
    validate_corpus(suite, profile, corpus)?;
    write_json_line(
        &mut writer,
        &CorpusHeader {
            record_type: "corpus_header",
            schema_version: 1,
            suite_manifest_digest: suite.digest(),
            generator_version: suite.generator_version(),
            profile,
        },
    )?;
    for case in corpus.scored() {
        if case.question().len() > suite.limits().max_question_bytes() {
            return Err(LlmError::InvalidCorpus);
        }
        write_json_line(
            &mut writer,
            &PublicCase {
                record_type: "case",
                case_id: case.id(),
                generator_version: suite.generator_version(),
                question: case.question(),
                question_digest: case.question_digest(),
            },
        )?;
    }
    writer.flush().map_err(|_| LlmError::Io)
}

pub fn export_llm_file(
    path: &Path,
    suite: &SuiteManifest,
    profile: ProfileName,
    corpus: &Corpus,
) -> Result<(), LlmError> {
    if path.exists() {
        return Err(LlmError::DestinationExists);
    }
    let parent = path.parent().ok_or(LlmError::Io)?;
    if !parent.is_dir() {
        return Err(LlmError::Io);
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| LlmError::Io)?;
    export_llm(&mut temporary, suite, profile, corpus)?;
    temporary.as_file().sync_all().map_err(|_| LlmError::Io)?;
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            LlmError::DestinationExists
        } else {
            LlmError::Io
        }
    })?;
    Ok(())
}

pub fn score_llm_results(
    mut reader: impl BufRead,
    suite: &SuiteManifest,
    profile: ProfileName,
    corpus: &Corpus,
) -> Result<QualificationReport, LlmError> {
    validate_corpus(suite, profile, corpus)?;
    let limit = suite.limits().max_result_line_bytes();
    let header_line = read_line_bounded(&mut reader, limit)?.ok_or(LlmError::MissingHeader)?;
    let header: RunHeader =
        serde_json::from_slice(&header_line).map_err(|_| LlmError::InvalidJson)?;
    if header.record_type != "run_header"
        || header.schema_version != 1
        || header.suite_manifest_digest != suite.digest()
        || header.generator_version != suite.generator_version()
        || header.profile != profile
        || header.model_id.len() > MAX_ID_BYTES
        || header.run_id.len() > MAX_ID_BYTES
    {
        return Err(LlmError::BindingMismatch);
    }
    let binding = ReportBinding::llm(suite, profile, &header.model_id, &header.run_id)
        .map_err(|_| LlmError::InvalidIdentifier)?;

    let expected: BTreeMap<&str, (usize, &CorpusCase)> = corpus
        .scored()
        .iter()
        .enumerate()
        .map(|(index, case)| (case.id(), (index, case)))
        .collect();
    let mut seen = BTreeSet::new();
    let mut cases = vec![None; corpus.scored().len()];

    while let Some(line) = read_line_bounded(&mut reader, limit)? {
        let imported = parse_result(&line)?;
        if !seen.insert(imported.case_id.clone()) {
            return Err(LlmError::DuplicateCase);
        }
        let (index, case) = expected
            .get(imported.case_id.as_str())
            .copied()
            .ok_or(LlmError::UnknownCase)?;
        if imported.question_digest != case.question_digest() {
            return Err(LlmError::QuestionMismatch);
        }
        let duration_ms = imported.outcome.latency_ms();
        let (outcome, reason) = match imported.outcome {
            ImportedOutcome::Answered { answer, .. } if case.oracle_matches(&answer) => {
                (Outcome::Solved, None)
            }
            ImportedOutcome::Answered { .. } => {
                (Outcome::Unsolved, Some(NoGuessReason::NoCandidate))
            }
            ImportedOutcome::Timeout { .. } => {
                (Outcome::Unsolved, Some(NoGuessReason::ToolRejected))
            }
            ImportedOutcome::ModelError { .. } => {
                (Outcome::Unsolved, Some(NoGuessReason::ParseFailed))
            }
            ImportedOutcome::Refused { .. } => {
                (Outcome::Unsolved, Some(NoGuessReason::Unsupported))
            }
        };
        cases[index] = Some(
            ReportCase::new(imported.case_id, outcome, reason, duration_ms)
                .map_err(|_| LlmError::InvalidResult)?,
        );
    }
    if seen.len() != expected.len() {
        return Err(LlmError::MissingCase);
    }
    let cases = cases
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(LlmError::MissingCase)?;
    QualificationReport::from_cases(binding, cases).map_err(|_| LlmError::InvalidResult)
}

fn validate_corpus(
    suite: &SuiteManifest,
    profile: ProfileName,
    corpus: &Corpus,
) -> Result<(), LlmError> {
    let expected = suite
        .profile(profile)
        .ok_or(LlmError::InvalidCorpus)?
        .scored_cases();
    if corpus.scored().len() == expected {
        Ok(())
    } else {
        Err(LlmError::InvalidCorpus)
    }
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> Result<(), LlmError> {
    serde_json::to_writer(&mut *writer, value).map_err(|_| LlmError::Io)?;
    writer.write_all(b"\n").map_err(|_| LlmError::Io)
}

fn read_line_bounded(
    reader: &mut impl BufRead,
    maximum: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, LlmError> {
    let take_limit = u64::try_from(maximum)
        .map_err(|_| LlmError::LineTooLong)?
        .checked_add(2)
        .ok_or(LlmError::LineTooLong)?;
    let mut line = Zeroizing::new(Vec::new());
    let read = Read::by_ref(reader)
        .take(take_limit)
        .read_until(b'\n', &mut line)
        .map_err(|_| LlmError::Io)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        return Err(LlmError::InvalidJson);
    }
    if line.is_empty() || line.len() > maximum {
        return Err(if line.len() > maximum {
            LlmError::LineTooLong
        } else {
            LlmError::InvalidJson
        });
    }
    std::str::from_utf8(&line).map_err(|_| LlmError::InvalidUtf8)?;
    Ok(Some(line))
}

fn parse_result(line: &[u8]) -> Result<ImportedResult, LlmError> {
    let value: Value = serde_json::from_slice(line).map_err(|_| LlmError::InvalidJson)?;
    let mut object = match value {
        Value::Object(object) => object,
        _ => return Err(LlmError::InvalidResult),
    };
    let status = string_field(&mut object, "status")?;
    let allowed: BTreeSet<&str> = match status.as_str() {
        "answered" => [
            "type",
            "case_id",
            "question_digest",
            "status",
            "answer",
            "latency_ms",
        ]
        .into_iter()
        .collect(),
        "timeout" | "model_error" | "refused" => {
            ["type", "case_id", "question_digest", "status", "latency_ms"]
                .into_iter()
                .collect()
        }
        _ => return Err(LlmError::InvalidResult),
    };
    if object.keys().any(|key| !allowed.contains(key.as_str())) || object.len() != allowed.len() - 1
    {
        return Err(LlmError::InvalidResult);
    }
    let record_type = string_field(&mut object, "type")?;
    let case_id = string_field(&mut object, "case_id")?;
    let question_digest = string_field(&mut object, "question_digest")?;
    let latency_ms = integer_field(&mut object, "latency_ms")?;
    if record_type != "result"
        || case_id.len() != 64
        || !is_lower_hex(&case_id)
        || question_digest.len() != 64
        || !is_lower_hex(&question_digest)
        || latency_ms > MAX_LATENCY_MS
    {
        return Err(LlmError::InvalidResult);
    }
    let outcome = match status.as_str() {
        "answered" => {
            let answer = string_field(&mut object, "answer")?;
            if answer.len() > MAX_ANSWER_BYTES {
                return Err(LlmError::InvalidResult);
            }
            ImportedOutcome::Answered {
                answer: Zeroizing::new(answer),
                latency_ms,
            }
        }
        "timeout" => ImportedOutcome::Timeout { latency_ms },
        "model_error" => ImportedOutcome::ModelError { latency_ms },
        "refused" => ImportedOutcome::Refused { latency_ms },
        _ => return Err(LlmError::InvalidResult),
    };
    if !object.is_empty() {
        return Err(LlmError::InvalidResult);
    }
    Ok(ImportedResult {
        case_id,
        question_digest,
        outcome,
    })
}

fn string_field(object: &mut Map<String, Value>, key: &str) -> Result<String, LlmError> {
    match object.remove(key) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(LlmError::InvalidResult),
    }
}

fn integer_field(object: &mut Map<String, Value>, key: &str) -> Result<u64, LlmError> {
    match object.remove(key) {
        Some(Value::Number(value)) => value.as_u64().ok_or(LlmError::InvalidResult),
        _ => Err(LlmError::InvalidResult),
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LlmError {
    #[error("invalid benchmark corpus")]
    InvalidCorpus,
    #[error("missing result header")]
    MissingHeader,
    #[error("invalid JSONL record")]
    InvalidJson,
    #[error("invalid UTF-8")]
    InvalidUtf8,
    #[error("JSONL line exceeds the configured bound")]
    LineTooLong,
    #[error("result binding does not match the benchmark suite")]
    BindingMismatch,
    #[error("invalid model or run identifier")]
    InvalidIdentifier,
    #[error("invalid result record")]
    InvalidResult,
    #[error("duplicate result case")]
    DuplicateCase,
    #[error("unknown result case")]
    UnknownCase,
    #[error("result question digest mismatch")]
    QuestionMismatch,
    #[error("result set is incomplete")]
    MissingCase,
    #[error("destination already exists")]
    DestinationExists,
    #[error("LLM exchange I/O failed")]
    Io,
}
