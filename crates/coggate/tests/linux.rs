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
