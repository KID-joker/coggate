//! Development-only fixtures. Output contains private tests and reference code:
//! never send this output to a client or use it as the public challenge protocol.
use coggate::{Engine, Runtime, Verdict};
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("--run");
    let count: usize = args
        .get(2)
        .map(|s| s.parse().expect("integer count"))
        .unwrap_or(20);
    assert!(count <= 100_000, "fixture count limit");
    let mut key = [0; 32];
    getrandom::fill(&mut key).expect("OS random");
    let engine = Engine::new(key);
    let runtime = Runtime::new(
        std::env::var_os("COGGATE_WORKER").unwrap_or_else(|| coggate_worker::WORKER_PATH.into()),
        2,
    );
    let composition = matches!(mode, "--composition-dump" | "--composition-run");
    let dump = matches!(mode, "--dump" | "--composition-dump");
    let run = matches!(mode, "--run" | "--composition-run");
    assert!(
        dump || run,
        "usage: demo [--dump|--run|--composition-dump|--composition-run] [count]"
    );
    let mut passed = 0;
    for i in 0..count {
        let (public, private) = if composition {
            engine.issue_composition("development-only", &i.to_be_bytes(), 1000)
        } else {
            engine.issue("development-only", &i.to_be_bytes(), 1000)
        }
        .expect("issue");
        let source = private.reference_solution();
        if dump {
            let cases: Vec<_> = private
                .cases()
                .iter()
                .map(|c| json!({"input": c.input(), "expected": c.expected()}))
                .collect();
            println!(
                "{}",
                json!({"public": public, "cases": cases, "reference_source": source})
            );
        } else {
            let result = runtime.execute(&private, &source);
            println!("{result:?}");
            if result == Verdict::Passed {
                passed += 1;
            }
        }
    }
    if run && passed != count {
        std::process::exit(1);
    }
}
