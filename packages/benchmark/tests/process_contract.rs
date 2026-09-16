use std::{collections::BTreeMap, time::Duration};

use agentgate_benchmark::process::{CommandSpec, ProcessOutcome, ProcessRunner, ToolId};
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
    workspace.close().unwrap();
}

#[test]
fn rejects_output_over_the_fixed_limit() {
    let root = tempfile::tempdir().unwrap();
    let runner = runner(&root, 1_024, Duration::from_secs(2));
    let mut workspace = runner.workspace().unwrap();

    let result = workspace.run(&fixture("process_child_floods")).unwrap();
    assert_eq!(result.outcome(), ProcessOutcome::OutputLimit);
    assert!(result.stdout().is_empty());
    workspace.close().unwrap();
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
fn process_child_floods() {
    print!("{}", "x".repeat(70_000));
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
