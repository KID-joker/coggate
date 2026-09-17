use std::{collections::BTreeMap, io::Write, path::PathBuf};

use crate::{
    BundleError, Target, assemble_bundle, create_phase5d_receipt, create_phase6a_receipt,
    create_sanitizer_receipt, receipt::write_receipt, verify_bundle,
};

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_BLOCKED: u8 = 2;
pub const EXIT_AUTHORIZATION_BLOCKED: u8 = EXIT_BLOCKED;
pub const EXIT_INPUT_OR_INFRASTRUCTURE: u8 = 3;
pub const EXIT_INTERNAL: u8 = 4;

const HELP: &str = "AgentGate Phase 6B release gate\n\ncommands:\n  receipt phase5d --commit SHA --target TRIPLE --artifact DIR --output FILE\n  receipt sanitizer --commit SHA --rust-version VERSION --clang-version VERSION --output FILE\n  receipt phase6a --commit SHA --report JSON --summary MARKDOWN --output FILE\n  assemble --commit SHA --evidence DIR --output DIR\n  verify --bundle DIR\n";

pub fn run_with_io<I, S>(args: I, stdout: &mut impl Write, stderr: &mut impl Write) -> u8
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect::<Vec<_>>();
    match parse(&args).and_then(execute) {
        Ok(outcome) => write_outcome(outcome, stdout, stderr),
        Err(CliError::InputOrInfrastructure) => write_input_error(stderr),
        Err(CliError::Internal) => write_internal(stderr),
    }
}

fn write_outcome(outcome: Outcome, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    if stdout.write_all(outcome.message.as_bytes()).is_ok() {
        outcome.code
    } else {
        let _ = stderr.write_all(b"phase6b: internal\n");
        EXIT_INTERNAL
    }
}

fn write_input_error(stderr: &mut impl Write) -> u8 {
    if stderr
        .write_all(b"phase6b: input_or_infrastructure\n")
        .is_ok()
    {
        EXIT_INPUT_OR_INFRASTRUCTURE
    } else {
        let _ = stderr.write_all(b"phase6b: internal\n");
        EXIT_INTERNAL
    }
}

fn write_internal(stderr: &mut impl Write) -> u8 {
    let _ = stderr.write_all(b"phase6b: internal\n");
    EXIT_INTERNAL
}

enum ParsedCommand {
    Help,
    ReceiptPhase5d {
        commit: String,
        target: Target,
        artifact: PathBuf,
        output: PathBuf,
    },
    ReceiptSanitizer {
        commit: String,
        rust_version: String,
        clang_version: String,
        output: PathBuf,
    },
    ReceiptPhase6a {
        commit: String,
        report: PathBuf,
        summary: PathBuf,
        output: PathBuf,
    },
    Assemble {
        commit: String,
        evidence: PathBuf,
        output: PathBuf,
    },
    Verify {
        bundle: PathBuf,
    },
}

struct Outcome {
    code: u8,
    message: String,
}

enum CliError {
    InputOrInfrastructure,
    Internal,
}

fn parse(args: &[String]) -> Result<ParsedCommand, CliError> {
    match args.first().map(String::as_str) {
        Some("--help") if args.len() == 1 => Ok(ParsedCommand::Help),
        Some("receipt") => parse_receipt(&args[1..]),
        Some("assemble") => {
            let flags = parse_flags(&args[1..], &["--commit", "--evidence", "--output"])?;
            Ok(ParsedCommand::Assemble {
                commit: parse_commit(flags["--commit"])?,
                evidence: PathBuf::from(flags["--evidence"]),
                output: PathBuf::from(flags["--output"]),
            })
        }
        Some("verify") => {
            let flags = parse_flags(&args[1..], &["--bundle"])?;
            Ok(ParsedCommand::Verify {
                bundle: PathBuf::from(flags["--bundle"]),
            })
        }
        _ => Err(CliError::InputOrInfrastructure),
    }
}

fn parse_receipt(args: &[String]) -> Result<ParsedCommand, CliError> {
    let Some(kind) = args.first().map(String::as_str) else {
        return Err(CliError::InputOrInfrastructure);
    };
    match kind {
        "phase5d" => {
            let flags = parse_flags(
                &args[1..],
                &["--commit", "--target", "--artifact", "--output"],
            )?;
            Ok(ParsedCommand::ReceiptPhase5d {
                commit: parse_commit(flags["--commit"])?,
                target: parse_target(flags["--target"])?,
                artifact: PathBuf::from(flags["--artifact"]),
                output: PathBuf::from(flags["--output"]),
            })
        }
        "sanitizer" => {
            let flags = parse_flags(
                &args[1..],
                &["--commit", "--rust-version", "--clang-version", "--output"],
            )?;
            Ok(ParsedCommand::ReceiptSanitizer {
                commit: parse_commit(flags["--commit"])?,
                rust_version: flags["--rust-version"].to_owned(),
                clang_version: flags["--clang-version"].to_owned(),
                output: PathBuf::from(flags["--output"]),
            })
        }
        "phase6a" => {
            let flags = parse_flags(
                &args[1..],
                &["--commit", "--report", "--summary", "--output"],
            )?;
            Ok(ParsedCommand::ReceiptPhase6a {
                commit: parse_commit(flags["--commit"])?,
                report: PathBuf::from(flags["--report"]),
                summary: PathBuf::from(flags["--summary"]),
                output: PathBuf::from(flags["--output"]),
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
        let value = pair[1].as_str();
        if !expected.contains(&name)
            || value.is_empty()
            || value.starts_with("--")
            || flags.insert(name, value).is_some()
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

fn parse_commit(value: &str) -> Result<String, CliError> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(value.to_owned())
    } else {
        Err(CliError::InputOrInfrastructure)
    }
}

fn parse_target(value: &str) -> Result<Target, CliError> {
    match value {
        "x86_64-unknown-linux-gnu" => Ok(Target::LinuxX86_64),
        "x86_64-apple-darwin" => Ok(Target::MacosX86_64),
        "x86_64-pc-windows-msvc" => Ok(Target::WindowsX86_64),
        _ => Err(CliError::InputOrInfrastructure),
    }
}

fn execute(command: ParsedCommand) -> Result<Outcome, CliError> {
    match command {
        ParsedCommand::Help => Ok(success(HELP)),
        ParsedCommand::ReceiptPhase5d {
            commit,
            target,
            artifact,
            output,
        } => {
            let receipt = create_phase5d_receipt(&commit, target, &artifact)
                .map_err(|_| CliError::InputOrInfrastructure)?;
            write_receipt(&output, &receipt).map_err(|_| CliError::InputOrInfrastructure)?;
            Ok(success(format!(
                "phase6b: receipt=OK kind=phase5d commit={commit}\n"
            )))
        }
        ParsedCommand::ReceiptSanitizer {
            commit,
            rust_version,
            clang_version,
            output,
        } => {
            let receipt = create_sanitizer_receipt(&commit, &rust_version, &clang_version)
                .map_err(|_| CliError::InputOrInfrastructure)?;
            write_receipt(&output, &receipt).map_err(|_| CliError::InputOrInfrastructure)?;
            Ok(success(format!(
                "phase6b: receipt=OK kind=sanitizer commit={commit}\n"
            )))
        }
        ParsedCommand::ReceiptPhase6a {
            commit,
            report,
            summary,
            output,
        } => {
            let receipt = create_phase6a_receipt(&commit, &report, &summary)
                .map_err(|_| CliError::InputOrInfrastructure)?;
            write_receipt(&output, &receipt).map_err(|_| CliError::InputOrInfrastructure)?;
            Ok(success(format!(
                "phase6b: receipt=OK kind=phase6a commit={commit}\n"
            )))
        }
        ParsedCommand::Assemble {
            commit,
            evidence,
            output,
        } => match assemble_bundle(&evidence, &output, &commit) {
            Ok(_) => Ok(success(format!(
                "phase6b: release=AUTHORIZED commit={commit}\n"
            ))),
            Err(BundleError::Blocked) => Ok(Outcome {
                code: EXIT_AUTHORIZATION_BLOCKED,
                message: "phase6b: release=BLOCKED\n".to_owned(),
            }),
            Err(error) => Err(bundle_error(error)),
        },
        ParsedCommand::Verify { bundle } => match verify_bundle(&bundle) {
            Ok(verified) => Ok(success(format!(
                "phase6b: bundle=VALID authorized=true commit={}\n",
                verified.commit()
            ))),
            Err(error) => Err(bundle_error(error)),
        },
    }
}

fn bundle_error(error: BundleError) -> CliError {
    match error {
        BundleError::Internal => CliError::Internal,
        BundleError::Blocked
        | BundleError::InvalidInput
        | BundleError::DestinationExists
        | BundleError::Infrastructure => CliError::InputOrInfrastructure,
    }
}

fn success(message: impl Into<String>) -> Outcome {
    Outcome {
        code: EXIT_SUCCESS,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_bundle_failures_use_the_internal_cli_category() {
        assert!(matches!(
            bundle_error(BundleError::Internal),
            CliError::Internal
        ));
        assert!(matches!(
            bundle_error(BundleError::Infrastructure),
            CliError::InputOrInfrastructure
        ));
        let mut stderr = Vec::new();
        assert_eq!(write_internal(&mut stderr), EXIT_INTERNAL);
        assert_eq!(stderr, b"phase6b: internal\n");
    }
}
