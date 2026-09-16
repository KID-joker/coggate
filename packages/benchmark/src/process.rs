use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_TOOL_ID_BYTES: usize = 32;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 4_096;
const MAX_OUTPUT_LIMIT: usize = 1_048_576;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ToolId(String);

impl ToolId {
    pub fn new(value: &str) -> Result<Self, ProcessError> {
        if value.is_empty()
            || value.len() > MAX_TOOL_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(ProcessError::InvalidConfiguration);
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Program {
    Tool(ToolId),
    Local(String),
}

#[derive(Clone, Eq, PartialEq)]
pub struct CommandSpec {
    program: Program,
    arguments: Vec<OsString>,
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("arguments", &"[REDACTED]")
            .field("argument_count", &self.arguments.len())
            .finish()
    }
}

impl CommandSpec {
    pub fn new<I, S>(tool: ToolId, arguments: I) -> Result<Self, ProcessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self::build(Program::Tool(tool), arguments)
    }

    pub fn local<I, S>(name: &str, arguments: I) -> Result<Self, ProcessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        validate_file_name(name)?;
        Self::build(Program::Local(name.to_owned()), arguments)
    }

    fn build<I, S>(program: Program, arguments: I) -> Result<Self, ProcessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        if arguments.len() > MAX_ARGUMENTS
            || arguments
                .iter()
                .any(|value| value.to_string_lossy().len() > MAX_ARGUMENT_BYTES)
        {
            return Err(ProcessError::InvalidCommand);
        }
        Ok(Self { program, arguments })
    }
}

pub struct ProcessRunner {
    root: PathBuf,
    timeout: Duration,
    output_limit: usize,
    programs: BTreeMap<ToolId, PathBuf>,
}

impl ProcessRunner {
    pub fn new(
        root: PathBuf,
        timeout: Duration,
        output_limit: usize,
        programs: BTreeMap<ToolId, PathBuf>,
    ) -> Result<Self, ProcessError> {
        if !root.is_dir()
            || timeout.is_zero()
            || output_limit == 0
            || output_limit > MAX_OUTPUT_LIMIT
            || programs.is_empty()
            || programs.values().any(|path| path.as_os_str().is_empty())
        {
            return Err(ProcessError::InvalidConfiguration);
        }
        Ok(Self {
            root,
            timeout,
            output_limit,
            programs,
        })
    }

    pub fn workspace(&self) -> Result<ProcessWorkspace<'_>, ProcessError> {
        let directory = tempfile::Builder::new()
            .prefix("agentgate-benchmark-")
            .tempdir_in(&self.root)
            .map_err(|_| ProcessError::Workspace)?;
        Ok(ProcessWorkspace {
            runner: self,
            directory: Some(directory),
            sequence: 0,
        })
    }
}

impl fmt::Debug for ProcessRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessRunner")
            .field("root", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .field("programs", &self.programs.keys().collect::<Vec<_>>())
            .finish()
    }
}

pub struct ProcessWorkspace<'a> {
    runner: &'a ProcessRunner,
    directory: Option<tempfile::TempDir>,
    sequence: usize,
}

impl ProcessWorkspace<'_> {
    pub fn path(&self) -> &Path {
        self.directory
            .as_ref()
            .expect("workspace directory exists until close")
            .path()
    }

    pub fn write_file(&mut self, name: &str, contents: &[u8]) -> Result<(), ProcessError> {
        validate_file_name(name)?;
        if contents.len() > agentgate_core::generation::MAX_QUESTION_BYTES {
            return Err(ProcessError::InvalidCommand);
        }
        fs::write(self.path().join(name), contents).map_err(|_| ProcessError::Workspace)
    }

    pub fn run(&mut self, spec: &CommandSpec) -> Result<ProcessResult, ProcessError> {
        let program = match &spec.program {
            Program::Tool(tool) => self
                .runner
                .programs
                .get(tool)
                .ok_or(ProcessError::ToolUnavailable)?,
            Program::Local(name) => {
                let path = self.path().join(name);
                if !path.is_file() {
                    return Err(ProcessError::ToolUnavailable);
                }
                return self.run_program(&path, spec);
            }
        };
        self.run_program(program, spec)
    }

    fn run_program(
        &mut self,
        program: &Path,
        spec: &CommandSpec,
    ) -> Result<ProcessResult, ProcessError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ProcessError::InvalidCommand)?;
        let stdout_path = self.path().join(format!("stdout-{}", self.sequence));
        let stderr_path = self.path().join(format!("stderr-{}", self.sequence));
        let stdout = File::create(&stdout_path).map_err(|_| ProcessError::Workspace)?;
        let stderr = File::create(&stderr_path).map_err(|_| ProcessError::Workspace)?;

        let mut child = Command::new(program)
            .args(&spec.arguments)
            .current_dir(self.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|_| ProcessError::Spawn)?;

        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| ProcessError::Wait)? {
                break Some(status);
            }
            if started.elapsed() >= self.runner.timeout {
                child.kill().map_err(|_| ProcessError::Kill)?;
                child.wait().map_err(|_| ProcessError::Wait)?;
                break None;
            }
            thread::sleep(Duration::from_millis(5));
        };

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let Some(status) = status else {
            return Ok(ProcessResult {
                outcome: ProcessOutcome::TimedOut,
                stdout: Vec::new(),
                stderr: Vec::new(),
                duration_ms,
            });
        };

        let stdout_length = file_length(&stdout_path)?;
        let stderr_length = file_length(&stderr_path)?;
        let combined = stdout_length
            .checked_add(stderr_length)
            .ok_or(ProcessError::Output)?;
        if combined > self.runner.output_limit {
            return Ok(ProcessResult {
                outcome: ProcessOutcome::OutputLimit,
                stdout: Vec::new(),
                stderr: Vec::new(),
                duration_ms,
            });
        }

        Ok(ProcessResult {
            outcome: ProcessOutcome::Exited(status.code().unwrap_or(-1)),
            stdout: fs::read(stdout_path).map_err(|_| ProcessError::Output)?,
            stderr: fs::read(stderr_path).map_err(|_| ProcessError::Output)?,
            duration_ms,
        })
    }

    pub fn close(mut self) -> Result<(), ProcessError> {
        self.directory
            .take()
            .ok_or(ProcessError::Workspace)?
            .close()
            .map_err(|_| ProcessError::Cleanup)
    }
}

impl fmt::Debug for ProcessWorkspace<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessWorkspace")
            .field("path", &"[REDACTED]")
            .field("sequence", &self.sequence)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutcome {
    Exited(i32),
    TimedOut,
    OutputLimit,
}

pub struct ProcessResult {
    outcome: ProcessOutcome,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_ms: u64,
}

impl ProcessResult {
    pub const fn outcome(&self) -> ProcessOutcome {
        self.outcome
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
}

impl fmt::Debug for ProcessResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessResult")
            .field("outcome", &self.outcome)
            .field("stdout", &"[REDACTED]")
            .field("stderr", &"[REDACTED]")
            .field("duration_ms", &self.duration_ms)
            .finish()
    }
}

fn validate_file_name(name: &str) -> Result<(), ProcessError> {
    let mut components = Path::new(name).components();
    let valid = matches!(components.next(), Some(Component::Normal(value)) if value == OsStr::new(name))
        && components.next().is_none()
        && !name.is_empty()
        && name.len() <= 64;
    if valid {
        Ok(())
    } else {
        Err(ProcessError::InvalidCommand)
    }
}

fn file_length(path: &Path) -> Result<usize, ProcessError> {
    let length = fs::metadata(path).map_err(|_| ProcessError::Output)?.len();
    usize::try_from(length).map_err(|_| ProcessError::Output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProcessError {
    #[error("invalid process runner configuration")]
    InvalidConfiguration,
    #[error("invalid process command")]
    InvalidCommand,
    #[error("benchmark process workspace failed")]
    Workspace,
    #[error("required benchmark tool is unavailable")]
    ToolUnavailable,
    #[error("benchmark process failed to start")]
    Spawn,
    #[error("benchmark process wait failed")]
    Wait,
    #[error("benchmark process termination failed")]
    Kill,
    #[error("benchmark process output failed")]
    Output,
    #[error("benchmark process cleanup failed")]
    Cleanup,
}
