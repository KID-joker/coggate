# CogGate

[![Cross-platform qualification](https://github.com/KID-joker/coggate/actions/workflows/cross-platform-qualification.yml/badge.svg)](https://github.com/KID-joker/coggate/actions/workflows/cross-platform-qualification.yml)
[![Adversarial benchmark](https://github.com/KID-joker/coggate/actions/workflows/adversarial-benchmark.yml/badge.svg)](https://github.com/KID-joker/coggate/actions/workflows/adversarial-benchmark.yml)
[![Release gate](https://github.com/KID-joker/coggate/actions/workflows/release-gate.yml/badge.svg)](https://github.com/KID-joker/coggate/actions/workflows/release-gate.yml)

CogGate generates bounded, mixed-language semantic challenges designed to make
LLM-assisted solving the economical general approach. It is not a traditional
CAPTCHA, and successful solving is not cryptographic proof of agent identity.

Repository: [KID-joker/coggate][repository]

## What CogGate does

CogGate is a building block for server-side admission decisions that need a
short semantic task rather than a reusable secret or a visual CAPTCHA. It is a
reasonable fit when an application can issue a challenge, keep verification
material private, and bind the eventual answer to an application-owned context.

CogGate deliberately does not claim to distinguish an LLM from every script,
identify the model or operator that produced an answer, or prove a user's
identity. It also does not provide sessions, rate limiting, account recovery,
or the final business-level admission policy.

The application server is the trust boundary. Challenge generation,
verification, lifecycle storage, and key access belong on infrastructure the
client cannot modify. Sending private verification material or an answer
oracle to the client defeats that boundary.

## How it works

1. **Issue:** the trusted server generates a bounded challenge, stores its
   private verification material and lifecycle state, and returns only the
   public challenge to the client.
2. **Solve:** the client interprets the mixed-language semantic task and
   produces an answer. The client never needs the private material.
3. **Submit:** the client returns the submission for the issued challenge.
   Submissions contain only `challenge_id`, `nonce`, and `answer`.
4. **Verify and consume:** The server reconstructs the binding from trusted
   application context, never trusts a client-supplied binding, and requires
   that it exactly matches the stored binding. It then atomically reserves an
   attempt, verifies the context-bound answer, and consumes the one-shot
   challenge according to the lifecycle result. Concurrent or replayed
   submissions fail closed.

The public challenge is safe to present to the solver. Private material is the
server-only state needed to verify it and must not be logged, exported, or
returned through an SDK response.

## Quick start

The complete workspace gate requires Rust 1.85 or newer, Python 3, a C11
compiler, Unix `nm` (or the `NM` override), JDK 17 or newer, and Maven. The
first run may download Cargo and Maven dependencies unless they are already
cached. The C and Java tools are used by C ABI header and Java packaging
contract tests in that gate.

Go and C++ are not prerequisites for the workspace gate. The adversarial
benchmark's `run-baselines` command requires C, C++, Rust, Go, and Java
toolchains; Go and C++ are also needed for their corresponding SDK tests and
examples. Node.js is required only for the Node.js SDK tests, build, and example.

```sh
git clone https://github.com/KID-joker/coggate.git
cd coggate
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

CogGate packages are not published to public package registries. Start from a
source checkout and the complete examples below; do not assume that crates.io,
PyPI, npm, or Maven Central installation commands are available.

## SDKs

All SDKs expose the same protocol concepts and structured failure model. The C
ABI in `libcoggate_ffi` is the stable native boundary used directly or by the
higher-level bindings.

| Language | Implementation | Complete example |
| --- | --- | --- |
| C | [`bindings/c/`](bindings/c/) | [`bindings/c/examples/complete.c`](bindings/c/examples/complete.c) |
| C++ | [`bindings/cpp/`](bindings/cpp/) | [`bindings/cpp/examples/complete.cpp`](bindings/cpp/examples/complete.cpp) |
| Python | [`bindings/python/`](bindings/python/) | [`bindings/python/examples/complete.py`](bindings/python/examples/complete.py) |
| Go | [`bindings/go/`](bindings/go/) | [`bindings/go/examples/complete/main.go`](bindings/go/examples/complete/main.go) |
| Java | [`bindings/java/`](bindings/java/) | [`bindings/java/examples/Complete.java`](bindings/java/examples/Complete.java) |
| Node.js | [`bindings/node/`](bindings/node/) | [`bindings/node/examples/complete.js`](bindings/node/examples/complete.js) |

Native library discovery is binding-specific. Python and the Node.js build use
`COGGATE_LIBRARY_PATH`, and the Go binding accepts it on Windows. Java callers
explicitly load the `coggate_jni` library with `Service.loadNative(Path)`; the
complete example takes that library path as its first argument. The Node.js
addon is named `coggate.node`. Consult the selected binding's build files and
example rather than assuming one cross-language build command.

## Core concepts

- **Challenge:** the bounded public task and identifiers sent to a solver.
- **Private material:** server-only data required to verify one issued
  challenge. It is not part of the public challenge.
- **Submission:** the public `challenge_id`, `nonce`, and encoded `answer`.
  Trusted application context supplies the binding separately on the server.
- **Binding:** application-owned context covered by verification, such as a
  session or operation identifier. Exact bytes matter.
- **Attempt limit:** the maximum number of reserved verification attempts.
  Attempts remain spent when verification cannot safely finish.
- **Lifecycle store:** durable state for issuance, expiry, attempt reservation,
  and atomic one-shot consumption.
- **Key provider:** protected lookup for the exact key ID recorded at issuance,
  including retained old keys while issued challenges may still be valid.

## Architecture

| Area | Responsibility |
| --- | --- |
| [`packages/contracts/`](packages/contracts/) | Wire contracts, canonical encodings, schemas, and compatibility checks |
| [`packages/core/`](packages/core/) | Challenge planning and rendering, verification, lifecycle policies, and ports |
| [`packages/ffi/`](packages/ffi/) | Stable C ABI shared by native SDK integrations |
| [`packages/benchmark/`](packages/benchmark/) | Reproducible corpus generation, baselines, offline LLM exchange, and qualification reports |
| [`packages/release/`](packages/release/) | Offline evidence receipts, bundle assembly, and release authorization checks |
| [`bindings/`](bindings/) | C, C++, Python, Go, Java, and Node.js SDK implementations and tests |
| [`schemas/`](schemas/) | Tracked protocol schemas |
| [`fixtures/contracts/`](fixtures/contracts/) | Cross-language contract fixtures |

The core depends on application-provided lifecycle and key-management ports.
Production integrations should implement those ports against durable trusted
services; the SDKs do not move that server responsibility to clients.

## Benchmarking

The adversarial benchmark provides four CLI operations:

```sh
mkdir -p target/phase6a/quick
cargo run -p coggate-benchmark --bin coggate-bench -- run-baselines --profile quick --output target/phase6a/quick
cargo run -p coggate-benchmark --bin coggate-bench -- export-llm --profile quick --output target/phase6a/prompts.jsonl
cargo run -p coggate-benchmark --bin coggate-bench -- score-llm --profile quick --input results.jsonl --output target/phase6a/quick
cargo run -p coggate-benchmark --bin coggate-bench -- verify-report --input target/phase6a/quick/direct-quick.json
```

The `quick` profile contains 100 calibration and 100 scored cases. The
`release` profile contains 1,000 calibration and 1,000 scored cases.
Qualification requires at least 80% LLM success, at most 5% direct-execution
success, and at most 1% success for each fingerprint, regex, and simple-parser
baseline. Each threshold is enforced independently.

LLM evaluation is offline: `export-llm` writes public prompts and `score-llm`
imports a complete JSONL result set. CogGate does not call model providers,
handle provider credentials, or establish model identity or provenance.
Qualification reports contain outcomes and bindings, not submitted answers or
raw model responses.

## Release qualification

Release qualification combines three independent evidence layers:

- [Cross-platform qualification](.github/workflows/cross-platform-qualification.yml)
  exercises native and SDK qualification and produces target-bound evidence.
- [Adversarial benchmark](.github/workflows/adversarial-benchmark.yml) produces
  reproducible benchmark reports and receipts.
- [Release gate](.github/workflows/release-gate.yml) verifies same-commit
  external evidence offline before it can authorize a release bundle.

The release gate reads explicit local paths and makes no network, upload,
publication, or signing request. All native, sanitizer, baseline, and offline
LLM receipts must bind the same commit supplied to bundle assembly.

No complete external same-commit qualification set is provided in this
repository, so a real release remains blocked until that evidence is collected.
Synthetic CI proves the gate implementation; it does not authorize a release.

## Security considerations

- Keep challenge generation, private material, lifecycle state, and key access
  on a trusted server.
- Enforce expiry, exact binding and nonce matching, attempt limits, durable
  reservation, and atomic single consumption. Reject replay and concurrent
  attempts fail closed.
- Never restore a reserved attempt merely because verification crashed or its
  dependency became unavailable.
- Resolve the exact stored key ID without falling back to the current key, and
  retain old keys through challenge expiry and the storage-retention horizon.
- Never log plaintext or submitted answers, bindings, nonces, answer MACs, MAC
  keys or key IDs, private verification material, or complete challenge text.
- Keep the deterministic benchmark oracle isolated. Do not enable
  `coggate-core/insecure-benchmarking` in a production service, the C ABI, or an
  SDK, and do not make the release crate depend on the benchmark or core crate.
- Treat the release bundle's output parent as a trusted concurrency boundary.

Integrators remain responsible for sessions, rate limits, abuse recovery,
authorization, monitoring, and the final business admission decision.

## Project status

The protocol contracts, challenge engine, lifecycle interfaces, stable C ABI,
six SDKs, adversarial benchmark, and offline release gate are implemented.
Cross-platform qualification workflows exist for native artifacts and SDKs.

This status describes implemented code and automation, not certification.
External same-commit release evidence has not yet been supplied, and no real
release is authorized by the repository's synthetic checks alone.

## Contributing

Before opening a change, run the workspace checks used in the quick start:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Keep protocol changes covered by contract fixtures and exercise affected SDKs
with their own toolchains. Use the [repository issues][issues] to report a bug
or discuss a scoped change.

## License

CogGate is available under the [MIT License](LICENSE).

[issues]: https://github.com/KID-joker/coggate/issues
[repository]: https://github.com/KID-joker/coggate
