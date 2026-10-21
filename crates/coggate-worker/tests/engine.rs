//! Engine compatibility tests. These exercise a deliberately UNSANDBOXED
//! binary, and make no claim about OS isolation.
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn request(source: &str, inputs: &[&str]) -> Vec<u8> {
    let mut bytes = b"CGW1".to_vec();
    bytes.extend_from_slice(&(source.len() as u32).to_be_bytes());
    bytes.extend_from_slice(source.as_bytes());
    bytes.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
    for input in inputs {
        bytes.extend_from_slice(&(input.len() as u32).to_be_bytes());
        bytes.extend_from_slice(input.as_bytes());
    }
    bytes
}

fn invoke(binary: &str, source: &str, inputs: &[&str]) -> Output {
    invoke_bytes(binary, &request(source, inputs))
}

fn invoke_bytes(binary: &str, bytes: &[u8]) -> Output {
    let mut child = Command::new(binary)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A fail-closed worker can exit before the request is written.
    let _ = stdin.write_all(bytes);
    drop(stdin);
    child.wait_with_output().unwrap()
}

fn items(bytes: &[u8]) -> Vec<(u8, String)> {
    parse_items(bytes, b"CGE1")
}

fn production_items(bytes: &[u8]) -> Vec<(u8, String)> {
    parse_items(bytes, b"CGR1")
}

fn parse_items(bytes: &[u8], magic: &[u8; 4]) -> Vec<(u8, String)> {
    assert_eq!(&bytes[..4], magic);
    let count = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    let mut cursor = 8;
    let mut items = Vec::new();
    for _ in 0..count {
        let status = bytes[cursor];
        let len = u32::from_be_bytes(bytes[cursor + 1..cursor + 5].try_into().unwrap());
        cursor += 5;
        let end = cursor + len as usize;
        items.push((
            status,
            String::from_utf8(bytes[cursor..end].to_vec()).unwrap(),
        ));
        cursor = end;
    }
    assert_eq!(cursor, bytes.len());
    items
}

#[test]
fn engine_executes_source_and_resets_context_between_cases() {
    let result = invoke(
        coggate_worker::ENGINE_TEST_PATH,
        "var seen = 0; function solve(input) { seen++; return [input.x * 2, seen]; }",
        &[r#"{"x":7}"#, r#"{"x":9}"#],
    );
    assert!(result.status.success());
    assert_eq!(
        items(&result.stdout),
        vec![(0, "[14,1]".into()), (0, "[18,1]".into())]
    );
}

#[test]
fn submitted_code_cannot_replace_host_serializer() {
    let result = invoke(
        coggate_worker::ENGINE_TEST_PATH,
        r#"JSON.stringify = function() { return "12345"; };
           function solve(input) { return input; }"#,
        &[r#"{"x":"quotes: \" and \\"}"#],
    );
    assert!(result.status.success());
    assert_eq!(
        items(&result.stdout),
        vec![(0, r#"{"x":"quotes: \" and \\"}"#.into())]
    );
}

#[test]
fn submitted_code_has_no_host_io() {
    let result = invoke(
        coggate_worker::ENGINE_TEST_PATH,
        "function solve(input) { return [typeof load, typeof print, typeof console, typeof setTimeout, typeof process]; }",
        &["null"],
    );
    assert!(result.status.success());
    assert_eq!(
        items(&result.stdout),
        vec![(
            0,
            r#"["undefined","undefined","undefined","undefined","undefined"]"#.into()
        )]
    );
}

#[test]
fn exceptions_and_non_json_results_are_failures() {
    for source in [
        "function solve(input) { throw input; }",
        "function solve(input) { return undefined; }",
        "function solve(input) { return solve; }",
        "function solve( {",
    ] {
        let result = invoke(coggate_worker::ENGINE_TEST_PATH, source, &["null"]);
        assert!(result.status.success());
        assert_ne!(items(&result.stdout)[0].0, 0);
    }
}

#[test]
fn runaway_code_is_terminated() {
    let result = invoke(
        coggate_worker::ENGINE_TEST_PATH,
        "function solve(input) { while (true) {} }",
        &["null"],
    );
    assert!(
        !result.status.success() || items(&result.stdout).iter().all(|(status, _)| *status != 0)
    );
}

#[test]
fn oversized_output_is_rejected() {
    let result = invoke(
        coggate_worker::ENGINE_TEST_PATH,
        "function solve(input) { return 'x'.repeat(65537); }",
        &["null"],
    );
    assert!(result.status.success());
    assert_eq!(
        items(&result.stdout),
        vec![(2, "output limit exceeded".into())]
    );
}

#[test]
fn invalid_framing_cannot_produce_a_successful_response() {
    let source = "function solve(input) { return input; }";
    let mut trailing = request(source, &["1"]);
    trailing.push(0);
    let mut oversized = b"CGW1".to_vec();
    oversized.extend_from_slice(&65537_u32.to_be_bytes());
    for bytes in [
        Vec::new(),
        b"BAD!".to_vec(),
        oversized,
        request(source, &[]),
        request(source, &["null"; 33]),
        trailing,
    ] {
        let result = invoke_bytes(coggate_worker::ENGINE_TEST_PATH, &bytes);
        assert!(!result.status.success());
    }
}

#[test]
fn invalid_json_input_is_an_internal_failure() {
    let result = invoke(
        coggate_worker::ENGINE_TEST_PATH,
        "function solve(input) { return 1; }",
        &["[}"],
    );
    assert!(result.status.success());
    assert_eq!(
        items(&result.stdout),
        vec![(3, "invalid input JSON".into())]
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn production_worker_fails_closed_on_unsupported_operating_systems() {
    let result = invoke(
        coggate_worker::WORKER_PATH,
        "function solve(input) { return input; }",
        &["1"],
    );
    assert!(!result.status.success());
    assert_eq!(
        production_items(&result.stdout),
        vec![(3, "sandbox requires Linux".into())]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn production_worker_executes_under_isolation() {
    let result = invoke(
        coggate_worker::WORKER_PATH,
        "function solve(input) { return input + 1; }",
        &["6", "9"],
    );
    assert!(result.status.success());
    assert_eq!(
        production_items(&result.stdout),
        vec![(0, "7".into()), (0, "10".into())]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_rejects_files_network_processes_and_extra_descriptors() {
    let result = Command::new(coggate_worker::WORKER_PATH)
        .arg("--isolation-self-test")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(
        production_items(&result.stdout),
        vec![(0, "isolated".into())]
    );
}
