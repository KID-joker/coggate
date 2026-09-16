# AgentGate

AgentGate generates short, mixed-language semantic challenges intended to make LLM-assisted solving the most economical general solution. It does not prove cryptographic Agent identity.

## Workspace status

Phase 1 defines protocol contracts and context-bound answer verification. Phase 2 adds the validated semantic DAG, deterministic answer engine, fixed-policy secret generation and partitioning, and constrained challenge planning. Phase 3 adds bounded mixed-language rendering and complete V1 operation coverage. Phase 4 adds persisted one-shot challenge issuance, fail-closed lifecycle adapters, key rotation, structured errors, and secret-safe observer hooks.

Phase 5 implementation, including the stable C ABI and language bindings, is complete; remote cross-platform qualification evidence remains pending. Phase 6A now provides the reproducible adversarial benchmark and offline LLM result scorer. Phase 6B release qualification remains pending and is blocked until the required Phase 5D evidence, all four non-LLM reports, and a qualifying LLM report are available.

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Phase 6A benchmark

The benchmark exposes four commands:

```sh
mkdir -p target/phase6a/quick
cargo run -p agentgate-benchmark --bin agentgate-bench -- run-baselines --profile quick --output target/phase6a/quick
cargo run -p agentgate-benchmark --bin agentgate-bench -- export-llm --profile quick --output target/phase6a/prompts.jsonl
cargo run -p agentgate-benchmark --bin agentgate-bench -- score-llm --profile quick --input results.jsonl --output target/phase6a/quick
cargo run -p agentgate-benchmark --bin agentgate-bench -- verify-report --input target/phase6a/quick/direct-quick.json
```

Profiles are `quick` (100 calibration and 100 scored cases) and `release` (1,000 plus 1,000). Qualification requires at least 80% LLM success, at most 5% direct-execution success, and at most 1% success for each fingerprint, regex, and simple-parser baseline. Each threshold is enforced independently.

LLM evaluation is offline only: AgentGate exports public prompts and strictly imports complete JSONL result sets. It does not call model providers, handle provider credentials, or prove model identity or provenance. Reports contain outcomes and bindings, never submitted answers or raw model responses.

## Security boundary

The core validates answer encoding and context-bound HMAC. The lifecycle adapter must durably enforce expiry, exact binding and nonce matching, attempt limits, atomic single consumption, persistence, and concurrent/replayed-attempt rejection. Reserved attempts must remain consumed if verification cannot finish. The key provider must protect key material, look up the exact stored key ID without active-key fallback, and retain old keys through challenge expiry and the storage-retention horizon. The integrator remains responsible for sessions, rate limits, recovery, and business admission.

Never log the plaintext answer, submitted answer, binding, nonce, answer MAC, MAC key or key ID, private verification material, or complete challenge question. Use only the observer's fixed allowlisted metadata for ordinary logs.

The `agentgate-core/insecure-benchmarking` feature exposes deterministic benchmark oracle support. It is exclusively for the benchmark crate and must never be enabled in production services, the C ABI, or language bindings.

## Protocol artifacts

Tracked protocol schemas are in [`schemas/`](schemas/), with contract fixtures in [`fixtures/contracts/`](fixtures/contracts/).
