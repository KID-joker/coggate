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
    let dump = matches!(mode, "--dump" | "--composition-dump" | "--screened-dump");
    let run = matches!(mode, "--run" | "--composition-run" | "--screened-run");
    assert!(
        dump || run,
        "usage: demo [--dump|--run|--composition-dump|--composition-run|--screened-dump|--screened-run] [count]"
    );
    let mut passed = 0;
    let mut issued = 0;
    for i in 0..count {
        let started = Instant::now();
        let (public, private, screening) = if screened {
            let (public, private, stats) =
                match engine.issue_screened_composition("development-only", &i.to_be_bytes(), 1000)
                {
                    Ok(result) => result,
                    Err(coggate_core::Error::GenerationExhausted) => {
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
                    Err(error) => panic!("screened issuance failed: {error}"),
                };
            (public, private, Some(stats))
        } else if composition {
            let (public, private) = engine
                .issue_composition("development-only", &i.to_be_bytes(), 1000)
                .expect("issue");
            (public, private, None)
        } else {
            let (public, private) = engine
                .issue("development-only", &i.to_be_bytes(), 1000)
                .expect("issue");
            (public, private, None)
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
                    "screening": screening, "generation_ms": generation_ms
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
