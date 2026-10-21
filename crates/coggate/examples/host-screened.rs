//! Size probe for the development-only screened generator and complete gateway.
use coggate::{Engine, Gate, InMemoryStore, Runtime, StateStore};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let source = std::env::args().nth(1).unwrap_or_default();
    let worker = std::env::var_os("COGGATE_WORKER").expect("set trusted COGGATE_WORKER path");
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).expect("OS random");
    let engine = Engine::new(secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let (challenge, private, _) = engine
        .issue_screened_composition("example", b"example-business-factor", now)
        .expect("issue screened challenge");
    let store = InMemoryStore::new(128);
    store
        .insert(Arc::new(private), now)
        .expect("store challenge");
    let gate = Gate::new(engine, store, Runtime::new(worker, 2));
    let verdict = gate
        .verify("example", &challenge.id, &source)
        .expect("verify");
    println!("{} bytes received; {:?}", source.len(), verdict);
}
