//! Development-only fixtures. Output contains private tests and reference code:
//! never send this output to a client or use it as the public challenge protocol.
use coggate::{Engine, Runtime, Verdict};
use serde_json::json;
use std::time::Instant;

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
    let screened = matches!(mode, "--screened-dump" | "--screened-run");
    let order = matches!(mode, "--order-dump" | "--order-run");
    let dump = matches!(
        mode,
        "--dump" | "--composition-dump" | "--screened-dump" | "--order-dump"
    );
    let run = matches!(
        mode,
        "--run" | "--composition-run" | "--screened-run" | "--order-run"
    );
    assert!(
        dump || run,
        "usage: demo [--dump|--run|--composition-dump|--composition-run|--screened-dump|--screened-run|--order-dump|--order-run] [count]"
    );
    let mut passed = 0;
    let mut issued = 0;
    for i in 0..count {
        let started = Instant::now();
        let issued_challenge = if order {
            engine
                .issue_order_synthesis("development-only", &i.to_be_bytes(), 1000)
                .map(|(public, private, stats)| (public, private, Some(json!(stats))))
        } else if screened {
            engine
                .issue_screened_composition("development-only", &i.to_be_bytes(), 1000)
                .map(|(public, private, stats)| (public, private, Some(json!(stats))))
        } else if composition {
            engine
                .issue_composition("development-only", &i.to_be_bytes(), 1000)
                .map(|(public, private)| (public, private, None))
        } else {
            engine
                .issue("development-only", &i.to_be_bytes(), 1000)
                .map(|(public, private)| (public, private, None))
        };
        let (public, private, diagnostics) = match issued_challenge {
            Ok(result) => result,
            Err(coggate_core::Error::GenerationExhausted) if screened || order => {
                println!(
                    "{}",
                    json!({
                        "generation_error": "candidate_budget_exhausted",
                        "generation_ms": started.elapsed().as_secs_f64() * 1000.0,
                        "issuance_attempt": i
                    })
                );
                continue;
            }
            Err(error) => panic!("issuance failed: {error}"),
        };
        issued += 1;
        let generation_ms = started.elapsed().as_secs_f64() * 1000.0;
        let source = private.reference_solution();
        if dump {
            let cases: Vec<_> = private
                .cases()
                .iter()
                .map(|c| json!({"input": c.input(), "expected": c.expected()}))
                .collect();
            println!(
                "{}",
                json!({
                    "public": public, "cases": cases, "reference_source": source,
                    "screening": if screened { diagnostics.as_ref() } else { None },
                    "order_synthesis": if order { diagnostics.as_ref() } else { None },
                    "generation_ms": generation_ms
                })
            );
        } else {
            let result = runtime.execute(&private, &source);
            println!("{result:?}");
            if result == Verdict::Passed {
                passed += 1;
            }
        }
    }
    if run {
        eprintln!("issuance_attempts={count} issued={issued} reference_passed={passed}");
        if passed != issued || issued == 0 {
            std::process::exit(1);
        }
    }
}
