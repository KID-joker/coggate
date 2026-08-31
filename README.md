# AgentGate

AgentGate generates short, mixed-language semantic challenges intended to make LLM-assisted solving the most economical general solution. It does not prove cryptographic Agent identity.

## Workspace status

Phase 1 defines protocol contracts and context-bound answer verification. Phase 2 adds the validated semantic DAG, deterministic answer engine, fixed-policy secret generation and partitioning, and constrained challenge planning. Mixed-language rendering, lifecycle integration, language bindings, and adversarial qualification remain subsequent roadmap phases.

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Security boundary

The core validates answer encoding and context-bound HMAC. The integrator must enforce expiry, session binding, nonce matching, attempt limits, atomic single consumption, rate limits, and key lookup/rotation.

Never log the plaintext answer, submitted answer, answer MAC, MAC key, or private verification material.

## Protocol artifacts

Tracked protocol schemas are in [`schemas/`](schemas/), with contract fixtures in [`fixtures/contracts/`](fixtures/contracts/).
