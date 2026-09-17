use std::{
    collections::BTreeMap,
    io::Write,
    time::{Duration, Instant},
};

use agentgate_benchmark::process::{
    CommandSpec, ProcessError, ProcessOutcome, ProcessRunner, ToolId,
};
use tempfile::TempDir;

fn runner(root: &TempDir, output_limit: usize, timeout: Duration) -> ProcessRunner {
    ProcessRunner::new(
        root.path().to_path_buf(),
        timeout,
        output_limit,
        BTreeMap::from([(
            ToolId::new("fixture").unwrap(),
            std::env::current_exe().unwrap(),
        )]),
    )
    .unwrap()
}

fn fixture(name: &str) -> CommandSpec {
    CommandSpec::new(
        ToolId::new("fixture").unwrap(),
        ["--ignored", "--exact", name, "--nocapture"],
    )
    .unwrap()
}

#[test]
fn executes_exact_argv_without_a_shell_and_cleans_workspace() {
    let root = tempfile::tempdir().unwrap();
    let runner = runner(&root, 65_536, Duration::from_secs(2));
    let mut workspace = runner.workspace().unwrap();
    let workspace_path = workspace.path().to_path_buf();
    let marker = root.path().join("shell-marker");
    let literal = format!("$(touch {})", marker.display());
    let spec = CommandSpec::new(ToolId::new("fixture").unwrap(), [literal]).unwrap();

    let result = workspace.run(&spec).unwrap();
    assert!(matches!(result.outcome(), ProcessOutcome::Exited(0)));
    assert!(!marker.exists());
    workspace.close().unwrap();
    assert!(!workspace_path.exists());
}

#[test]
fn kills_and_reaps_a_timed_out_child() {
    let root = tempfile::tempdir().unwrap();
    let runner = runner(&root, 65_536, Duration::from_millis(50));
    let mut workspace = runner.workspace().unwrap();

    let result = workspace.run(&fixture("process_child_sleeps")).unwrap();
    assert_eq!(result.outcome(), ProcessOutcome::TimedOut);
    assert!(result.stdout().len() + result.stderr().len() <= 65_536);
    workspace.close().unwrap();
}

#[test]
fn kills_and_reaps_a_child_that_floods_both_output_streams() {
    let root = tempfile::tempdir().unwrap();
    let runner = runner(&root, 1_024, Duration::from_secs(4));
    let mut workspace = runner.workspace().unwrap();
    let workspace_path = workspace.path().to_path_buf();

    let started = Instant::now();
    let error = workspace
        .run(&fixture("process_child_floods_both_streams"))
        .unwrap_err();

    assert_eq!(error, ProcessError::OutputLimit);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "output overflow should terminate well before the four-second timeout"
    );
    #[cfg(unix)]
    {
        let child_pid = std::fs::read_to_string(workspace.path().join("child.pid")).unwrap();
        let child_exists = std::process::Command::new("/bin/kill")
            .args(["-0", child_pid.trim()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(!child_exists, "overflowing child was not reaped");
    }
    workspace.close().unwrap();
    assert!(!workspace_path.exists());
}

#[test]
fn writes_only_safe_relative_input_names() {
    let root = tempfile::tempdir().unwrap();
    let runner = runner(&root, 65_536, Duration::from_secs(2));
    let mut workspace = runner.workspace().unwrap();

    workspace
        .write_file("fragment.rs", b"fn main() {}")
        .unwrap();
    for unsafe_name in ["../escape", "/absolute", "nested/file"] {
        assert!(workspace.write_file(unsafe_name, b"x").is_err());
    }
    assert!(workspace.path().join("fragment.rs").is_file());
    workspace.close().unwrap();
}

#[test]
#[ignore = "child process fixture"]
fn process_child_sleeps() {
    std::thread::sleep(Duration::from_secs(5));
}

#[test]
#[ignore = "child process fixture"]
fn process_child_floods_both_streams() {
    std::fs::write("child.pid", std::process::id().to_string()).unwrap();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let chunk = [b'x'; 64];
    loop {
        stdout.write_all(&chunk).unwrap();
        stdout.flush().unwrap();
        stderr.write_all(&chunk).unwrap();
        stderr.flush().unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn runner_is_send_and_sync() {
    fn assert_type<T: Send + Sync>() {}
    assert_type::<ProcessRunner>();
}

#[test]
fn command_debug_redacts_arguments() {
    let sentinel = "PRIVATE_PROCESS_ARGUMENT";
    let spec = CommandSpec::new(ToolId::new("fixture").unwrap(), [sentinel]).unwrap();
    let debug = format!("{spec:?}");

    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(sentinel));
}
