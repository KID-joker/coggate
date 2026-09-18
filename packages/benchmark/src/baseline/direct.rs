use std::fmt;

use coggate_core::{
    canonicalize_answer, contracts::AnswerEncoding, generation::MAX_QUESTION_BYTES,
};
use zeroize::Zeroizing;

use super::{Baseline, BaselineError, NoGuessReason, Prediction};
use crate::{
    corpus::CorpusCase,
    process::{CommandSpec, ProcessOutcome, ProcessRunner, ProcessWorkspace, ToolId},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FragmentLanguage {
    C,
    Cpp,
    Rust,
    Go,
    Java,
    Pseudocode,
}

pub struct DisplayFragment {
    language: FragmentLanguage,
    body: String,
}

impl DisplayFragment {
    pub const fn language(&self) -> FragmentLanguage {
        self.language
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

impl fmt::Debug for DisplayFragment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplayFragment")
            .field("language", &self.language)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub struct DirectBaseline {
    runner: ProcessRunner,
}

impl DirectBaseline {
    pub const fn new(runner: ProcessRunner) -> Self {
        Self { runner }
    }

    pub fn predict_text(&self, question: &str) -> Result<Prediction, BaselineError> {
        if question.len() > MAX_QUESTION_BYTES {
            return Ok(Prediction::NoGuess(NoGuessReason::Unsupported));
        }
        let Ok(fragments) = extract_fragments(question) else {
            return Ok(Prediction::NoGuess(NoGuessReason::ParseFailed));
        };
        let executable = fragments
            .iter()
            .filter(|fragment| fragment.language != FragmentLanguage::Pseudocode)
            .collect::<Vec<_>>();
        if executable.is_empty() {
            return Ok(Prediction::NoGuess(NoGuessReason::Unsupported));
        }

        let mut candidate: Option<Zeroizing<String>> = None;
        for fragment in executable {
            let mut workspace = self
                .runner
                .workspace()
                .map_err(|_| BaselineError::Infrastructure)?;
            let result = run_fragment(&mut workspace, fragment);
            let cleanup = workspace.close();
            let value = result.map_err(|_| BaselineError::Infrastructure)?;
            cleanup.map_err(|_| BaselineError::Infrastructure)?;
            let Some(value) = value else {
                continue;
            };
            if let Some(existing) = &candidate {
                if existing.as_str() != value.as_str() {
                    return Ok(Prediction::NoGuess(NoGuessReason::Ambiguous));
                }
            } else {
                candidate = Some(value);
            }
        }

        Ok(candidate.map_or(
            Prediction::NoGuess(NoGuessReason::ToolRejected),
            Prediction::Guess,
        ))
    }
}

impl Baseline for DirectBaseline {
    fn id(&self) -> &'static str {
        "direct"
    }

    fn predict(&self, case: &CorpusCase) -> Result<Prediction, BaselineError> {
        self.predict_text(case.question())
    }
}

impl fmt::Debug for DirectBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBaseline")
            .field("runner", &self.runner)
            .finish()
    }
}

pub fn extract_fragments(question: &str) -> Result<Vec<DisplayFragment>, DirectError> {
    if question.len() > MAX_QUESTION_BYTES {
        return Err(DirectError::InvalidQuestion);
    }
    let mut fragments = Vec::new();
    let mut current: Option<DisplayFragment> = None;
    for line in question.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "Dependency clues:" || trimmed == "Display order is not evaluation order." {
            break;
        }
        if let Some(language) = parse_header(trimmed) {
            if let Some(fragment) = current.take() {
                if fragment.body.is_empty() {
                    return Err(DirectError::InvalidQuestion);
                }
                fragments.push(fragment);
            }
            current = Some(DisplayFragment {
                language,
                body: String::new(),
            });
        } else if let Some(fragment) = &mut current {
            fragment.body.push_str(line);
        }
    }
    if let Some(fragment) = current {
        if fragment.body.is_empty() {
            return Err(DirectError::InvalidQuestion);
        }
        fragments.push(fragment);
    }
    if fragments.is_empty() || fragments.len() > 6 {
        Err(DirectError::InvalidQuestion)
    } else {
        Ok(fragments)
    }
}

fn parse_header(line: &str) -> Option<FragmentLanguage> {
    let inner = line.strip_prefix("[Fragment ")?.strip_suffix(']')?;
    let (number, language) = inner.split_once(" — ")?;
    let number: usize = number.parse().ok()?;
    if number == 0 || number > 6 {
        return None;
    }
    match language {
        "C" => Some(FragmentLanguage::C),
        "C++" => Some(FragmentLanguage::Cpp),
        "Rust" => Some(FragmentLanguage::Rust),
        "Go" => Some(FragmentLanguage::Go),
        "Java" => Some(FragmentLanguage::Java),
        "Pseudocode" => Some(FragmentLanguage::Pseudocode),
        _ => None,
    }
}

fn run_fragment(
    workspace: &mut ProcessWorkspace<'_>,
    fragment: &DisplayFragment,
) -> Result<Option<Zeroizing<String>>, crate::process::ProcessError> {
    let plan = command_plan(fragment.language)?;
    workspace.write_file(plan.file_name, fragment.body.as_bytes())?;

    match plan.execution {
        Execution::One(spec) => candidate_from_result(workspace.run(&spec)?),
        Execution::Compile { spec, artifact } => {
            let result = workspace.run(&spec)?;
            match result.outcome() {
                ProcessOutcome::Exited(0) => {}
                ProcessOutcome::Exited(_) | ProcessOutcome::TimedOut => return Ok(None),
            }
            let run_spec = CommandSpec::local(artifact, std::iter::empty::<&str>())?;
            candidate_from_result(workspace.run(&run_spec)?)
        }
    }
}

struct FragmentCommandPlan {
    file_name: &'static str,
    execution: Execution,
}

enum Execution {
    One(CommandSpec),
    Compile {
        spec: CommandSpec,
        artifact: &'static str,
    },
}

fn command_plan(
    language: FragmentLanguage,
) -> Result<FragmentCommandPlan, crate::process::ProcessError> {
    let plan = match language {
        FragmentLanguage::C => FragmentCommandPlan {
            file_name: "fragment.c",
            execution: Execution::Compile {
                spec: CommandSpec::new(ToolId::new("c")?, ["fragment.c", "-o", artifact_name()])?,
                artifact: artifact_name(),
            },
        },
        FragmentLanguage::Cpp => FragmentCommandPlan {
            file_name: "fragment.cpp",
            execution: Execution::Compile {
                spec: CommandSpec::new(
                    ToolId::new("cpp")?,
                    ["fragment.cpp", "-o", artifact_name()],
                )?,
                artifact: artifact_name(),
            },
        },
        FragmentLanguage::Rust => FragmentCommandPlan {
            file_name: "fragment.rs",
            execution: Execution::Compile {
                spec: CommandSpec::new(
                    ToolId::new("rust")?,
                    ["fragment.rs", "-o", artifact_name()],
                )?,
                artifact: artifact_name(),
            },
        },
        FragmentLanguage::Go => FragmentCommandPlan {
            file_name: "fragment.go",
            execution: Execution::One(CommandSpec::new(
                ToolId::new("go")?,
                ["run", "fragment.go"],
            )?),
        },
        FragmentLanguage::Java => FragmentCommandPlan {
            file_name: "Fragment.java",
            execution: Execution::One(CommandSpec::new(ToolId::new("java")?, ["Fragment.java"])?),
        },
        FragmentLanguage::Pseudocode => {
            return Err(crate::process::ProcessError::InvalidCommand);
        }
    };
    Ok(plan)
}

#[cfg(windows)]
const fn artifact_name() -> &'static str {
    "fragment.exe"
}

#[cfg(not(windows))]
const fn artifact_name() -> &'static str {
    "fragment"
}

fn candidate_from_result(
    result: crate::process::ProcessResult,
) -> Result<Option<Zeroizing<String>>, crate::process::ProcessError> {
    match result.outcome() {
        ProcessOutcome::Exited(0) => {}
        ProcessOutcome::Exited(_) | ProcessOutcome::TimedOut => return Ok(None),
    }
    let stdout = std::str::from_utf8(result.stdout())
        .map_err(|_| crate::process::ProcessError::Output)?
        .trim();
    let Ok(candidate) = canonicalize_answer(AnswerEncoding::Base64Url, stdout) else {
        return Ok(None);
    };
    Ok(Some(Zeroizing::new(candidate)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DirectError {
    #[error("invalid direct execution question")]
    InvalidQuestion,
}
