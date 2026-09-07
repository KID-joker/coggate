# AgentGate

AgentGate generates short, mixed-language semantic challenges intended to make LLM-assisted solving the most economical general solution. It does not prove cryptographic Agent identity.

## Workspace status

Phase 1 defines protocol contracts and context-bound answer verification. Phase 2 adds the validated semantic DAG, deterministic answer engine, fixed-policy secret generation and partitioning, and constrained challenge planning. Phase 3 adds bounded mixed-language rendering with deterministic presentation planning, dependency clues, name randomization, distractor isolation, ambiguity validation, and complete V1 operation coverage. Phase 4 adds persisted one-shot challenge issuance, bounded invalid-candidate retries, stored-version verification dispatch, fail-closed lifecycle adapters, exact key-rotation lookup, structured errors, and secret-safe observer hooks. Stable C ABI and language bindings are next in Phase 5; adversarial qualification remains Phase 6.

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Security boundary

The core validates answer encoding and context-bound HMAC. The lifecycle adapter must durably enforce expiry, exact binding and nonce matching, attempt limits, atomic single consumption, persistence, and concurrent/replayed-attempt rejection. Reserved attempts must remain consumed if verification cannot finish. The key provider must protect key material, look up the exact stored key ID without active-key fallback, and retain old keys through challenge expiry and the storage-retention horizon. The integrator remains responsible for sessions, rate limits, recovery, and business admission.

Never log the plaintext answer, submitted answer, binding, nonce, answer MAC, MAC key or key ID, private verification material, or complete challenge question. Use only the observer's fixed allowlisted metadata for ordinary logs.

## Protocol artifacts

Tracked protocol schemas are in [`schemas/`](schemas/), with contract fixtures in [`fixtures/contracts/`](fixtures/contracts/).
