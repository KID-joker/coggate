use coggate::{Engine, Gate, InMemoryStore, Runtime};

fn main() {
    let source = std::env::args().nth(1).unwrap_or_default();
    let worker = std::env::var_os("COGGATE_WORKER").expect("set trusted COGGATE_WORKER path");
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).expect("OS random");
    let gate = Gate::new(
        Engine::new(secret),
        InMemoryStore::new(128),
        Runtime::new(worker, 2),
    );
    let challenge = gate
        .issue("example", b"example-business-factor")
        .expect("issue");
    let verdict = gate
        .verify("example", &challenge.id, &source)
        .expect("verify");
    println!("{} bytes received; {:?}", source.len(), verdict);
}
