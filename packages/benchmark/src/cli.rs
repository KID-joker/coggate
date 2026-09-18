use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    baseline::direct::DirectBaseline,
    corpus::Corpus,
    llm::{export_llm_file, score_llm_results},
    manifest::{ProfileName, SuiteManifest},
    process::{CommandSpec, ProcessOutcome, ProcessRunner, ToolId},
    qualification::{QualificationError, qualify_baselines},
    report::{QualificationReport, verify_report, write_report_bundle},
};

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_QUALIFICATION_FAILED: u8 = 2;
pub const EXIT_INPUT_OR_INFRASTRUCTURE: u8 = 3;
pub const EXIT_INTERNAL: u8 = 4;

const HELP: &str = "CogGate Phase 6A adversarial benchmark\n\ncommands:\n  run-baselines --profile quick|release --output DIR\n  export-llm --profile quick|release --output FILE\n  score-llm --profile quick|release --input FILE --output DIR\n  verify-report --input FILE\n";
const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

pub fn run_with_io<I, S>(args: I, stdout: &mut impl Write, stderr: &mut impl Write) -> u8
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect::<Vec<_>>();
    let result = parse(&args).and_then(execute);
    match result {
        Ok(outcome) => {
            if stdout.write_all(outcome.message.as_bytes()).is_err() {
                let _ = stderr.write_all(b"phase6a: internal\n");
                EXIT_INTERNAL
            } else {
                outcome.code
            }
        }
        Err(CliError::InputOrInfrastructure) => {
            if stderr
                .write_all(b"phase6a: input_or_infrastructure\n")
                .is_err()
            {
                EXIT_INTERNAL
            } else {
                EXIT_INPUT_OR_INFRASTRUCTURE
            }
        }
        Err(CliError::Internal) => {
            let _ = stderr.write_all(b"phase6a: internal\n");
            EXIT_INTERNAL
        }
    }
}

enum ParsedCommand {
    Help,
    RunBaselines {
        profile: ProfileName,
        output: PathBuf,
    },
    ExportLlm {
        profile: ProfileName,
        output: PathBuf,
    },
    ScoreLlm {
        profile: ProfileName,
        input: PathBuf,
        output: PathBuf,
    },
    VerifyReport {
        input: PathBuf,
    },
}

struct CommandOutcome {
    code: u8,
    message: String,
}

#[derive(Clone, Copy)]
enum CliError {
    InputOrInfrastructure,
    Internal,
}

fn parse(args: &[String]) -> Result<ParsedCommand, CliError> {
    match args.first().map(String::as_str) {
        Some("--help") if args.len() == 1 => Ok(ParsedCommand::Help),
        Some("run-baselines") => {
            let flags = parse_flags(&args[1..], &["--profile", "--output"])?;
            Ok(ParsedCommand::RunBaselines {
                profile: parse_profile(flags["--profile"])?,
                output: PathBuf::from(&flags["--output"]),
            })
        }
        Some("export-llm") => {
            let flags = parse_flags(&args[1..], &["--profile", "--output"])?;
            Ok(ParsedCommand::ExportLlm {
                profile: parse_profile(flags["--profile"])?,
                output: PathBuf::from(&flags["--output"]),
            })
        }
        Some("score-llm") => {
            let flags = parse_flags(&args[1..], &["--profile", "--input", "--output"])?;
            Ok(ParsedCommand::ScoreLlm {
                profile: parse_profile(flags["--profile"])?,
                input: PathBuf::from(&flags["--input"]),
                output: PathBuf::from(&flags["--output"]),
            })
        }
        Some("verify-report") => {
            let flags = parse_flags(&args[1..], &["--input"])?;
            Ok(ParsedCommand::VerifyReport {
                input: PathBuf::from(&flags["--input"]),
            })
        }
        _ => Err(CliError::InputOrInfrastructure),
    }
}

fn parse_flags<'a>(
    arguments: &'a [String],
    expected: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, CliError> {
    if arguments.len() != expected.len() * 2 {
        return Err(CliError::InputOrInfrastructure);
    }
    let mut flags = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = pair[0].as_str();
        if !expected.contains(&name)
            || pair[1].is_empty()
            || flags.insert(name, pair[1].as_str()).is_some()
        {
            return Err(CliError::InputOrInfrastructure);
        }
    }
    if flags.len() == expected.len() {
        Ok(flags)
    } else {
        Err(CliError::InputOrInfrastructure)
    }
}

fn parse_profile(value: &str) -> Result<ProfileName, CliError> {
    match value {
        "quick" => Ok(ProfileName::Quick),
        "release" => Ok(ProfileName::Release),
        _ => Err(CliError::InputOrInfrastructure),
    }
}

fn execute(command: ParsedCommand) -> Result<CommandOutcome, CliError> {
    if matches!(command, ParsedCommand::Help) {
        return Ok(CommandOutcome {
            code: EXIT_SUCCESS,
            message: HELP.to_owned(),
        });
    }
    let suite = SuiteManifest::tracked_v1().map_err(|_| CliError::Internal)?;
    match command {
        ParsedCommand::Help => unreachable!(),
        ParsedCommand::ExportLlm { profile, output } => {
            let corpus = Corpus::generate(&suite, profile).map_err(|_| CliError::Internal)?;
            export_llm_file(&output, &suite, profile, &corpus)
                .map_err(|_| CliError::InputOrInfrastructure)?;
            Ok(success(format!(
                "phase6a: export=OK profile={}\n",
                profile.as_str()
            )))
        }
        ParsedCommand::ScoreLlm {
            profile,
            input,
            output,
        } => {
            require_output_directory(&output)?;
            let file = File::open(input).map_err(|_| CliError::InputOrInfrastructure)?;
            let corpus = Corpus::generate(&suite, profile).map_err(|_| CliError::Internal)?;
            let report = score_llm_results(BufReader::new(file), &suite, profile, &corpus)
                .map_err(|_| CliError::InputOrInfrastructure)?;
            write_report_bundle(&output, &report).map_err(|_| CliError::InputOrInfrastructure)?;
            Ok(qualification(
                report.qualified(),
                format!("phase6a: llm=COMPLETE qualified={}\n", report.qualified()),
            ))
        }
        ParsedCommand::VerifyReport { input } => {
            let bytes = fs::read(input).map_err(|_| CliError::InputOrInfrastructure)?;
            if bytes.len() > MAX_REPORT_BYTES {
                return Err(CliError::InputOrInfrastructure);
            }
            let source =
                std::str::from_utf8(&bytes).map_err(|_| CliError::InputOrInfrastructure)?;
            let report =
                verify_report(source, &suite).map_err(|_| CliError::InputOrInfrastructure)?;
            Ok(qualification(
                report.qualified(),
                format!("phase6a: report=VALID qualified={}\n", report.qualified()),
            ))
        }
        ParsedCommand::RunBaselines { profile, output } => run_baselines(&suite, profile, &output),
    }
}

fn run_baselines(
    suite: &SuiteManifest,
    profile: ProfileName,
    output: &Path,
) -> Result<CommandOutcome, CliError> {
    require_output_directory(output)?;
    for name in ["direct", "fingerprint", "regex", "simple_parser"] {
        if output
            .join(format!("{name}-{}.json", profile.as_str()))
            .exists()
            || output
                .join(format!("{name}-{}.md", profile.as_str()))
                .exists()
        {
            return Err(CliError::InputOrInfrastructure);
        }
    }
    let summary_path = output.join("phase6a-summary.md");
    if summary_path.exists() {
        return Err(CliError::InputOrInfrastructure);
    }

    let corpus = Corpus::generate(suite, profile).map_err(|_| CliError::Internal)?;
    let (runner, versions) = production_runner(suite)?;
    let direct = DirectBaseline::new(runner);
    let reports = qualify_baselines(suite, profile, &corpus, &direct, versions)
        .map_err(cli_error_for_qualification)?;
    for report in &reports {
        write_report_bundle(output, report).map_err(|_| CliError::InputOrInfrastructure)?;
    }
    write_aggregate(&summary_path, &reports)?;
    let qualified = reports.iter().all(QualificationReport::qualified);
    Ok(qualification(
        qualified,
        format!("phase6a: baselines=COMPLETE qualified={qualified}\n"),
    ))
}

fn cli_error_for_qualification(error: QualificationError) -> CliError {
    match qualification_error_exit_code(error) {
        EXIT_INPUT_OR_INFRASTRUCTURE => CliError::InputOrInfrastructure,
        _ => CliError::Internal,
    }
}

const fn qualification_error_exit_code(error: QualificationError) -> u8 {
    match error {
        QualificationError::Baseline(_) => EXIT_INPUT_OR_INFRASTRUCTURE,
        QualificationError::InvalidCorpus | QualificationError::Composition => EXIT_INTERNAL,
    }
}

fn production_runner(
    suite: &SuiteManifest,
) -> Result<(ProcessRunner, BTreeMap<String, String>), CliError> {
    let programs = suite
        .tools()
        .iter()
        .map(|(id, program)| {
            Ok((
                ToolId::new(id).map_err(|_| CliError::Internal)?,
                PathBuf::from(program),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CliError>>()?;
    let runner = ProcessRunner::new(
        std::env::temp_dir(),
        Duration::from_millis(suite.limits().process_timeout_ms()),
        suite.limits().max_process_output_bytes(),
        programs,
    )
    .map_err(|_| CliError::InputOrInfrastructure)?;
    let mut versions = BTreeMap::new();
    for id in suite.tools().keys() {
        let argument = match id.as_str() {
            "go" => "version",
            "java" => "-version",
            _ => "--version",
        };
        let mut workspace = runner
            .workspace()
            .map_err(|_| CliError::InputOrInfrastructure)?;
        let spec = CommandSpec::new(ToolId::new(id).map_err(|_| CliError::Internal)?, [argument])
            .map_err(|_| CliError::Internal)?;
        let result = workspace
            .run(&spec)
            .map_err(|_| CliError::InputOrInfrastructure)?;
        workspace
            .close()
            .map_err(|_| CliError::InputOrInfrastructure)?;
        if result.outcome() != ProcessOutcome::Exited(0) {
            return Err(CliError::InputOrInfrastructure);
        }
        let source = if result.stdout().is_empty() {
            result.stderr()
        } else {
            result.stdout()
        };
        versions.insert(id.clone(), sanitize_version(source));
    }
    Ok((runner, versions))
}

fn sanitize_version(source: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(source);
    let first = decoded.lines().next().unwrap_or("available");
    let mut output = first
        .chars()
        .take(120)
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || matches!(character, ' ' | '_' | '-' | '.' | '+' | ':' | '(' | ')')
            {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if output.is_empty() {
        output.push_str("available");
    }
    output
}

fn write_aggregate(path: &Path, reports: &[QualificationReport]) -> Result<(), CliError> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().ok_or(CliError::InputOrInfrastructure)?)
            .map_err(|_| CliError::InputOrInfrastructure)?;
    writeln!(temporary, "# CogGate Phase 6A baseline summary")
        .map_err(|_| CliError::InputOrInfrastructure)?;
    writeln!(temporary).map_err(|_| CliError::InputOrInfrastructure)?;
    for report in reports {
        writeln!(
            temporary,
            "- {}: solved {}/{}; qualified: {}",
            report.subject_id(),
            report.solved(),
            report.total(),
            report.qualified()
        )
        .map_err(|_| CliError::InputOrInfrastructure)?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| CliError::InputOrInfrastructure)?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| CliError::InputOrInfrastructure)?;
    Ok(())
}

fn require_output_directory(path: &Path) -> Result<(), CliError> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(CliError::InputOrInfrastructure)
    }
}

fn success(message: String) -> CommandOutcome {
    CommandOutcome {
        code: EXIT_SUCCESS,
        message,
    }
}

fn qualification(qualified: bool, message: String) -> CommandOutcome {
    CommandOutcome {
        code: if qualified {
            EXIT_SUCCESS
        } else {
            EXIT_QUALIFICATION_FAILED
        },
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::BaselineError;

    #[test]
    fn qualification_errors_map_infrastructure_separately_from_internal_failures() {
        assert_eq!(
            qualification_error_exit_code(QualificationError::Baseline(
                BaselineError::Infrastructure
            )),
            EXIT_INPUT_OR_INFRASTRUCTURE
        );
        assert_eq!(
            qualification_error_exit_code(QualificationError::Composition),
            EXIT_INTERNAL
        );
        assert_eq!(
            qualification_error_exit_code(QualificationError::InvalidCorpus),
            EXIT_INTERNAL
        );
    }
}
