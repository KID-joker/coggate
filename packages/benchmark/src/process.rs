use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use command_group::{CommandGroup, GroupChild};

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
            .prefix("coggate-benchmark-")
            .tempdir_in(&self.root)
            .map_err(|_| ProcessError::Workspace)?;
        Ok(ProcessWorkspace {
            runner: self,
            directory: Some(directory),
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
        if contents.len() > coggate_core::generation::MAX_QUESTION_BYTES {
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
        let mut command = Command::new(program);
        command
            .args(&spec.arguments)
            .current_dir(self.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.group_spawn().map_err(|_| ProcessError::Spawn)?;

        let Some(stdout) = child.inner().stdout.take() else {
            let _ = kill_and_wait(&mut child);
            return Err(ProcessError::Output);
        };
        let Some(stderr) = child.inner().stderr.take() else {
            let _ = kill_and_wait(&mut child);
            return Err(ProcessError::Output);
        };
        let budget = Arc::new(CaptureBudget::new(self.runner.output_limit));
        let stdout_reader = match spawn_reader(stdout, Arc::clone(&budget)) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = kill_and_wait(&mut child);
                return Err(error);
            }
        };
        let stderr_reader = match spawn_reader(stderr, Arc::clone(&budget)) {
            Ok(reader) => reader,
            Err(error) => {
                return match kill_and_wait(&mut child) {
                    Ok(_) => match stdout_reader.join() {
                        Ok(Ok(_)) => Err(error),
                        _ => Err(ProcessError::Output),
                    },
                    Err(cleanup) => Err(cleanup),
                };
            }
        };

        let started = Instant::now();
        let completion = loop {
            if budget.overflowed() {
                break Ok(Completion::OutputLimit);
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(Completion::Exited(status)),
                Ok(None) => {}
                Err(_) => break Err(ProcessError::Wait),
            }
            if budget.overflowed() {
                break Ok(Completion::OutputLimit);
            }
            if started.elapsed() >= self.runner.timeout {
                break Ok(Completion::TimedOut);
            }
            thread::sleep(Duration::from_millis(5));
        };

        let completion = match completion {
            Ok(Completion::Exited(status)) => {
                terminate_group(&mut child, &stdout_reader, &stderr_reader)
                    .map(|()| Completion::Exited(status))
            }
            Ok(Completion::OutputLimit) => {
                kill_and_wait(&mut child).map(|_| Completion::OutputLimit)
            }
            Ok(Completion::TimedOut) => kill_and_wait(&mut child).map(|status| match status {
                Termination::Killed => Completion::TimedOut,
                Termination::AlreadyExited(status) => Completion::Exited(status),
            }),
            Err(error) => {
                return match kill_and_wait(&mut child) {
                    Ok(_) => match join_readers(stdout_reader, stderr_reader) {
                        Ok(_) => Err(error),
                        Err(output) => Err(output),
                    },
                    Err(cleanup) => Err(cleanup),
                };
            }
        };
        let completion = completion?;
        let captured = join_readers(stdout_reader, stderr_reader);
        let (stdout, stderr) = captured?;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if budget.overflowed() || completion == Completion::OutputLimit {
            return Err(ProcessError::OutputLimit);
        }

        Ok(ProcessResult {
            outcome: match completion {
                Completion::Exited(status) => ProcessOutcome::Exited(status.code().unwrap_or(-1)),
                Completion::TimedOut => ProcessOutcome::TimedOut,
                Completion::OutputLimit => unreachable!("output overflow returned above"),
            },
            stdout,
            stderr,
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
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutcome {
    Exited(i32),
    TimedOut,
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum Completion {
    Exited(ExitStatus),
    TimedOut,
    OutputLimit,
}

enum Termination {
    Killed,
    AlreadyExited(ExitStatus),
}

fn terminate_group(
    child: &mut GroupChild,
    stdout: &Reader,
    stderr: &Reader,
) -> Result<(), ProcessError> {
    match child.kill() {
        Ok(()) => {
            child.wait().map_err(|_| ProcessError::Wait)?;
            Ok(())
        }
        Err(_) => {
            child.wait().map_err(|_| ProcessError::Wait)?;
            let deadline = Instant::now() + Duration::from_millis(100);
            while !(stdout.is_finished() && stderr.is_finished()) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            if stdout.is_finished() && stderr.is_finished() {
                // Empty process groups can disappear between `try_wait` and
                // `kill`. Closed pipes prove no descendant can block capture.
                Ok(())
            } else {
                Err(ProcessError::Kill)
            }
        }
    }
}

fn kill_and_wait(child: &mut GroupChild) -> Result<Termination, ProcessError> {
    match child.kill() {
        Ok(()) => {
            child.wait().map_err(|_| ProcessError::Wait)?;
            Ok(Termination::Killed)
        }
        Err(_) => match child.try_wait().map_err(|_| ProcessError::Wait)? {
            Some(status) => Ok(Termination::AlreadyExited(status)),
            None => Err(ProcessError::Kill),
        },
    }
}

struct CaptureBudget {
    remaining: AtomicUsize,
    overflowed: AtomicBool,
}

impl CaptureBudget {
    fn new(limit: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(limit),
            overflowed: AtomicBool::new(false),
        }
    }

    fn claim(&self, requested: usize) -> usize {
        let mut remaining = self.remaining.load(Ordering::Acquire);
        loop {
            let claimed = requested.min(remaining);
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - claimed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return claimed,
                Err(current) => remaining = current,
            }
        }
    }

    fn overflow(&self) {
        self.overflowed.store(true, Ordering::Release);
    }

    fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }
}

type Reader = JoinHandle<Result<Vec<u8>, ProcessError>>;

fn spawn_reader<R>(reader: R, budget: Arc<CaptureBudget>) -> Result<Reader, ProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .spawn(move || capture(reader, &budget))
        .map_err(|_| ProcessError::Output)
}

fn capture<R>(mut reader: R, budget: &CaptureBudget) -> Result<Vec<u8>, ProcessError>
where
    R: Read,
{
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8_192];
    loop {
        let read_limit = budget
            .remaining
            .load(Ordering::Acquire)
            .saturating_add(1)
            .min(buffer.len());
        let count = match reader.read(&mut buffer[..read_limit]) {
            Ok(0) => return Ok(output),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ProcessError::Output),
        };
        let claimed = budget.claim(count);
        output
            .try_reserve_exact(claimed)
            .map_err(|_| ProcessError::Output)?;
        output.extend_from_slice(&buffer[..claimed]);
        if claimed < count {
            budget.overflow();
            return Ok(output);
        }
    }
}

fn join_readers(stdout: Reader, stderr: Reader) -> Result<(Vec<u8>, Vec<u8>), ProcessError> {
    let stdout = stdout.join();
    let stderr = stderr.join();
    match (stdout, stderr) {
        (Ok(Ok(stdout)), Ok(Ok(stderr))) => Ok((stdout, stderr)),
        _ => Err(ProcessError::Output),
    }
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
    #[error("benchmark process output limit exceeded")]
    OutputLimit,
    #[error("benchmark process cleanup failed")]
    Cleanup,
}
