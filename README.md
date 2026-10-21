# Coggate

An experimental Rust gateway SDK for issuing programming challenges and judging
submitted JavaScript in a bounded Linux worker.

The gateway generates and verifies challenges locally, without model inference,
model credentials or a model service. Visiting agents may use their own models
to solve them; the integrating application decides what access a pass grants.

**The current task generator is an intentionally measurable baseline, not a
production agent detector. An independent, non-model script solves its public
grammar. Passing a challenge does not prove a model was called.**

The first milestone tests two hypotheses before investing in five language
bindings: the complete runtime increment can fit in 512,000 bytes, and a public
generator can impose a meaningful cost on specialized offline-developed solvers.
The Rust/Linux x86_64 prototype measured **347,160 bytes** of complete increment.
The current generator has failed the second hypothesis: the included offline
solver passed **1,000/1,000** fresh challenges on the strict Linux worker.

## Implemented

- Rust challenge generation: ten integer-array task families, explicit semantics,
  varied wording and 32 private test inputs per challenge.
- Server secret, optional business factor and fresh OS randomness; HMAC-SHA-256
  separates problem selection, wording, tests and challenge IDs.
- A bounded atomic in-memory lifecycle: scope binding, 180-second expiry, two
  attempts, exclusive claims and one-time successful consumption.
- A vendored MicroQuickJS source compiler/interpreter with a 2 MiB arena.
- A separate Linux worker: seccomp syscall restrictions, cleared environment,
  closed extra descriptors, resource limits and independent CPU/wall timers.
- Expected results stay in Rust. Only source and individual test inputs enter
  the worker. Every test gets a new language context.
- An independent public-prompt-only Python solver and reproducible evaluation.

Access tokens, business authentication and challenge-request rate limiting
belong to the integrating application. The SDK bounds its own worker concurrency
and returns `Busy` instead of creating an unbounded queue.

## Build and test

Development requires Rust and a C compiler. Runtime deployment requires the
application, its packaged worker and the build target's compatible system C
runtime. Deployment compatibility is not yet qualified. No JavaScript
environment, compiler installation or runtime download is needed.

```sh
cargo test --workspace --features coggate/dev-tools --locked
cargo clippy --workspace --all-targets --features coggate/dev-tools --locked -- -D warnings
cargo run -p coggate --example demo --features dev-tools -- --run 100
```

Production execution requires Linux with the required seccomp facilities. The
prototype implements x86_64 and aarch64 syscall architectures. The first x86_64
Linux CI checks passed; aarch64 and broader deployment compatibility have not
been validated.

On macOS, production execution returns `Unsupported`. An explicit development
feature builds `coggate-engine-test-UNSANDBOXED` for language compatibility tests.
It uses a different response magic and cannot be accepted by the production
runtime. It does not validate OS isolation:

```sh
python3 scripts/evaluate_solver.py --engine-only --samples 200
```

On Linux, evaluate the strict worker without that flag:

```sh
python3 scripts/evaluate_solver.py --samples 1000
```

The evaluation freezes the solver source **before** generating a new secret key
and fresh challenges. Only public fields reach the solver. Reports distinguish
language compatibility, OS isolation and adversarial effectiveness.

## SDK boundary

```rust,no_run
use coggate::{Engine, Gate, InMemoryStore, Runtime};

// Load a stable CSPRNG-generated 32-byte secret from server configuration.
let server_secret = load_secret_from_host_configuration();
let gate = Gate::new(
    Engine::new(server_secret),
    InMemoryStore::new(1024),
    Runtime::new("/trusted/application/coggate-worker", 2),
);
let challenge = gate.issue("trusted-tenant-scope", b"optional-business-factor")?;
// Return challenge to the client. Later, submit only the source and challenge ID.
let result = gate.verify("trusted-tenant-scope", &challenge.id, submitted_source)?;
// Host application decides what authorization a Passed result grants.
```

The worker path is trusted installation configuration, never client input.
`StateStore` specifies atomic adapter semantics; the implemented store is
single-process only. Durable cross-process state transport/adapters, Go/Java/
Python/Node.js bindings, model evaluation and long fuzzing runs are not yet
implemented or validated.

## Complete size accounting

Use one toolchain and the release profile for both baseline and integrated host:

```sh
mkdir -p artifacts
cargo build -p coggate --release --example host-baseline --example host-integrated \
  --locked --message-format=json > artifacts/release-build.jsonl
python3 scripts/worker_path.py < artifacts/release-build.jsonl
# Pass that exact worker path to:
python3 scripts/measure_size.py \
  --baseline target/release/examples/host-baseline \
  --integrated target/release/examples/host-integrated \
  --worker /path/printed/by/worker_path.py
```

The increment is `integrated host - baseline host + mandatory worker`. New
libraries/assets must also be counted when introduced. Development binaries,
fixtures and symbols are excluded from production distribution; no required
component may be excluded. A macOS unsupported-worker stub is **not** a valid
Linux size measurement.

See [product and security boundaries](docs/design.md) and the
[unfulfilled acceptance gates](docs/acceptance.md). Dependencies are pinned and
their provenance is in [third_party/README.md](third_party/README.md).

The [first prototype experiment](docs/prototype-results.md) records the exact
Linux build, size and attack evidence, and the remaining acceptance gaps.
The [composition experiment](docs/composition-experiment.md) tests ordered
operations, conditional execution and fresh local term definitions against an
adaptive parser; that parser passed 1,000/1,000 challenges in both local
compatibility and strict Linux runs.

The [shortcut-hardening experiment](docs/shortcut-hardening.md) adds bounded
screening against constant answers, skipped stages and ignored conditions, plus
inclusive-boundary regressions for the default generator. Screening remains
development-only; correct adaptive solvers remain a separate acceptance barrier.

MIT licensed; upstream MicroQuickJS notices are retained.
