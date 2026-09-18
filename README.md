# CogGate

[![Phase 5D](https://github.com/KID-joker/coggate/actions/workflows/phase5d.yml/badge.svg)](https://github.com/KID-joker/coggate/actions/workflows/phase5d.yml)
[![Phase 6A](https://github.com/KID-joker/coggate/actions/workflows/phase6a.yml/badge.svg)](https://github.com/KID-joker/coggate/actions/workflows/phase6a.yml)
[![Phase 6B](https://github.com/KID-joker/coggate/actions/workflows/phase6b.yml/badge.svg)](https://github.com/KID-joker/coggate/actions/workflows/phase6b.yml)

CogGate generates short, mixed-language semantic challenges intended to make LLM-assisted solving the most economical general solution. It does not prove cryptographic agent identity.

Repository: [KID-joker/coggate][repository]

## Workspace status

Phase 1 defines protocol contracts and context-bound answer verification. Phase 2 adds the validated semantic DAG, deterministic answer engine, fixed-policy secret generation and partitioning, and constrained challenge planning. Phase 3 adds bounded mixed-language rendering and complete V1 operation coverage. Phase 4 adds persisted one-shot challenge issuance, fail-closed lifecycle adapters, key rotation, structured errors, and secret-safe observer hooks.

Phase 5 implementation, including the stable C ABI and language bindings, is complete; remote cross-platform qualification evidence remains pending. Phase 6A now provides the reproducible adversarial benchmark and offline LLM result scorer. Phase 6B implementation complete; release authorization BLOCKED pending same-commit external evidence.

## Verify

```sh
git clone https://github.com/KID-joker/coggate.git
cd coggate
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Phase 6A benchmark

The benchmark exposes four commands:

```sh
mkdir -p target/phase6a/quick
cargo run -p coggate-benchmark --bin coggate-bench -- run-baselines --profile quick --output target/phase6a/quick
cargo run -p coggate-benchmark --bin coggate-bench -- export-llm --profile quick --output target/phase6a/prompts.jsonl
cargo run -p coggate-benchmark --bin coggate-bench -- score-llm --profile quick --input results.jsonl --output target/phase6a/quick
cargo run -p coggate-benchmark --bin coggate-bench -- verify-report --input target/phase6a/quick/direct-quick.json
```

Profiles are `quick` (100 calibration and 100 scored cases) and `release` (1,000 plus 1,000). Qualification requires at least 80% LLM success, at most 5% direct-execution success, and at most 1% success for each fingerprint, regex, and simple-parser baseline. Each threshold is enforced independently.

LLM evaluation is offline only: CogGate exports public prompts and strictly imports complete JSONL result sets. It does not call model providers, handle provider credentials, or prove model identity or provenance. Reports contain outcomes and bindings, never submitted answers or raw model responses.

## Phase 6B release gate

The release gate is an offline, unsigned authorization check. It consumes explicit local paths, makes no network calls, and performs no GitHub download, release, upload, or signing operation. `assemble` creates a deterministic evidence package only after all supplied evidence authorizes the requested commit; it is not itself a release publication step. The output parent is a trusted concurrency boundary: it must not be concurrently modified by a same-user adversary.

The public CLI has exactly these five forms:

```text
receipt phase5d --commit SHA --target TRIPLE --artifact DIR --output FILE
receipt sanitizer --commit SHA --rust-version VERSION --clang-version VERSION --output FILE
receipt phase6a --commit SHA --report JSON --summary MARKDOWN --output FILE
assemble --commit SHA --evidence DIR --output DIR
verify --bundle DIR
```

Exit codes are `0` for success, `2` for valid-but-blocked authorization, `3` for input or infrastructure failure, and `4` for an internal failure.

Before calling `assemble`, collect the independently produced files into this exact local evidence tree (no extra files or links):

```text
evidence/
  receipts/
    linux.json
    macos.json
    windows.json
    sanitizer.json
    direct.json
    fingerprint.json
    regex.json
    simple_parser.json
    llm.json
  phase5d/
    x86_64-unknown-linux-gnu/artifact/
    x86_64-apple-darwin/artifact/
    x86_64-pc-windows-msvc/artifact/
  phase6a/
    direct/report.json
    direct/report.md
    fingerprint/report.json
    fingerprint/report.md
    regex/report.json
    regex/report.md
    simple_parser/report.json
    simple_parser/report.md
    llm/report.json
    llm/report.md
```

The Phase 5D and Phase 6A producer workflows emit their receipts with the evidence they verify. Collect that external evidence locally and place it in the fixed tree above; the gate does not fetch it. A valid real release requires all three Phase 5D target artifacts, a successful sanitizer receipt, four qualifying release-baseline reports (`direct`, `fingerprint`, `regex`, and `simple_parser`), and one qualifying offline LLM report. Every receipt and the `assemble --commit` value must bind the exact same commit. Synthetic CI tests prove the implementation only; they do not authorize a real release.

## Security boundary

The core validates answer encoding and context-bound HMAC. The lifecycle adapter must durably enforce expiry, exact binding and nonce matching, attempt limits, atomic single consumption, persistence, and concurrent/replayed-attempt rejection. Reserved attempts must remain consumed if verification cannot finish. The key provider must protect key material, look up the exact stored key ID without active-key fallback, and retain old keys through challenge expiry and the storage-retention horizon. The integrator remains responsible for sessions, rate limits, recovery, and business admission.

Never log the plaintext answer, submitted answer, binding, nonce, answer MAC, MAC key or key ID, private verification material, or complete challenge question. Use only the observer's fixed allowlisted metadata for ordinary logs.

The release crate must never depend on `coggate-benchmark` or `coggate-core`, and it must never enable `coggate-core/insecure-benchmarking` or expose its oracle. The deterministic benchmark oracle is only for benchmark-crate feature tests; it must never be enabled in production services, the C ABI, or language bindings.

## Protocol artifacts

Tracked protocol schemas are in [`schemas/`](schemas/), with contract fixtures in [`fixtures/contracts/`](fixtures/contracts/).

[repository]: https://github.com/KID-joker/coggate
