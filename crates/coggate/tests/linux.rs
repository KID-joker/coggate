#![cfg(all(target_os = "linux", feature = "dev-tools"))]

use coggate::{Engine, Gate, InMemoryStore, Runtime, StoreError, Verdict};

#[test]
fn reference_programs_pass_all_private_cases_under_linux_isolation() {
    let engine = Engine::new([37; 32]);
    let runtime = Runtime::new(coggate_worker::WORKER_PATH, 1);
    for i in 0_u32..100 {
        let (_, private) = engine.issue("test", &i.to_be_bytes(), 1000).unwrap();
        assert_eq!(
            runtime.execute(&private, &private.reference_solution()),
            Verdict::Passed
        );
    }
}

#[test]
fn resource_exhaustion_spends_attempts_and_cannot_replay_forever() {
    let gate = Gate::new(
        Engine::new([37; 32]),
        InMemoryStore::new(8),
        Runtime::new(coggate_worker::WORKER_PATH, 1),
    );
    let challenge = gate.issue("test", b"").unwrap();
    for _ in 0..2 {
        assert_eq!(
            gate.verify(
                "test",
                &challenge.id,
                "function solve(x) { while (true) {} }"
            )
            .unwrap(),
            Verdict::ResourceLimit,
        );
    }
    assert!(matches!(
        gate.verify("test", &challenge.id, "function solve(x) { return x; }"),
        Err(coggate::Error::Store(StoreError::Exhausted))
    ));
}

#[test]
fn accidentally_packaged_development_worker_can_never_pass() {
    let (_, private) = Engine::new([37; 32]).issue("test", b"", 1000).unwrap();
    let runtime = Runtime::new(coggate_worker::ENGINE_TEST_PATH, 1);
    assert_eq!(
        runtime.execute(&private, &private.reference_solution()),
        Verdict::WorkerFailure
    );
}

#[test]
fn hostile_execution_and_parsing_cannot_pass_or_poison_the_next_request() {
    let (_, private) = Engine::new([73; 32])
        .issue("test", b"hostile-input-recovery", 1000)
        .unwrap();
    let runtime = Runtime::new(coggate_worker::WORKER_PATH, 1);
    let reference = private.reference_solution();
    let deeply_nested_source = format!(
        "function solve(input) {{ return {}0{}; }}",
        "(".repeat(8192),
        ")".repeat(8192)
    );
    let attacks = [
        (
            "recursive call stack",
            "function solve(input) { return 1 + solve(input); }",
        ),
        (
            "retained heap growth",
            "function solve(input) { var a = []; while (true) { a.push('x'.repeat(16384)); } }",
        ),
        (
            // solve returns first; the trusted serializer then invokes this
            // property getter. Its work must share the submission budget.
            "nonterminating serialization getter",
            "function solve(input) { var result = {}; Object.defineProperty(result, 'value', { enumerable: true, get: function() { while (true) {} } }); return result; }",
        ),
        // The payload is below MAX_SOURCE: rejection must occur inside the
        // worker's parser/resource boundary, not at the SDK's size check.
        ("deeply nested parser input", deeply_nested_source.as_str()),
    ];
    for (name, source) in attacks {
        assert!(source.len() < coggate::runtime::MAX_SOURCE);
        let verdict = runtime.execute(&private, source);
        assert!(
            matches!(
                verdict,
                Verdict::InvalidSubmission | Verdict::ResourceLimit | Verdict::WorkerFailure
            ),
            "{name} must fail inside the worker, got {verdict:?}",
        );
        assert_eq!(
            runtime.execute(&private, &reference),
            Verdict::Passed,
            "{name} must not poison the next request or retain the runtime permit",
        );
    }
}
