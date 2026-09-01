# AgentGate Phase 4 Challenge Generation and Lifecycle Integration Design

Date: 2026-09-02

Status: approved for specification review

## 1. Scope

Phase 4 exposes the first public, one-shot challenge issuance and submission
verification API in `agentgate-core`. It composes the Phase 2 semantic engine
and Answer Engine with the Phase 3 renderer, the existing context-bound HMAC
primitives, version dispatch, caller-provided lifecycle persistence, key
lookup, and secret-safe observability.

Phase 4 defines synchronous lifecycle and key-provider adapter interfaces. It
does not provide an in-memory or database-backed lifecycle implementation. It
also does not add language bindings, a C ABI, adversarial benchmarks, account
or session storage, distributed rate limiting, or caller-configurable V1
difficulty controls. Those responsibilities remain with integrators or later
roadmap phases.

The existing `PublicChallenge`, `PrivateChallengeMaterial`, and `Submission`
wire contracts remain unchanged. Lifecycle binding data is private adapter
input and never enters those protocol objects.

## 2. Architecture

Phase 4 adds a public orchestration layer while keeping the existing semantic
engine, renderer, MAC implementation, and low-level verifier authoritative:

```text
ChallengeService
  |
  +-- Version dispatcher
  |     +-- V1 candidate generator
  |           +-- secret generator
  |           +-- semantic planner and Answer Engine
  |           +-- renderer
  |
  +-- Runtime boundary
  |     +-- operating-system CSPRNG
  |     +-- system clock
  |
  +-- MacKeyProvider
  +-- LifecycleAdapter
  +-- Observer
```

`ChallengeService` owns operation ordering and public error mapping. The
adapters own external state and infrastructure behavior. The service does not
hold a database, session system, rate limiter, or persistent key store.

Production construction always selects the operating-system random source and
system clock. Crate-internal tests may inject deterministic random bytes and a
fixed clock. No production API accepts a seed, secret length, fragment count,
TTL, retry count, or question-size override.

## 3. Module boundaries

Phase 4 adds focused modules rather than placing orchestration into the
existing low-level verifier or renderer:

- `service/mod.rs` defines `ChallengeService` and its public issuance and
  verification entry points.
- `service/model.rs` defines issuance and verification requests, verification
  outcomes, lifecycle attempt handles, and safe public metadata.
- `service/lifecycle.rs` defines the synchronous `LifecycleAdapter` contract.
- `service/keys.rs` defines `MacKeyProvider` and redacted key material.
- `service/observer.rs` defines fixed secret-safe events and a default no-op
  observer.
- `service/error.rs` defines stable service errors and lifecycle rejection
  classifications.
- `service/version.rs` dispatches issuance and verification without fallback
  or downgrade.
- `service/runtime.rs` owns system time and CSPRNG access plus crate-internal
  deterministic test implementations.
- `generation/candidate.rs` atomically composes secret generation, semantic
  planning, answer evaluation, and rendering into a crate-private candidate.

The public service and adapter types are re-exported from `agentgate-core`.
The lower-level answer, MAC, and verification primitives remain public for
advanced integrations and contract-vector testing.

The adapter interfaces are synchronous in V1 so Phase 5 can map them through a
stable C ABI without choosing an async runtime. Async hosts place the service
call behind their own blocking or transaction boundary.

## 4. Public service model

`ChallengeService` is parameterized by lifecycle, key-provider, and observer
implementations. Production construction installs the system runtime. Its two
public operations are conceptually:

```text
issue_challenge(IssueRequest) -> Result<PublicChallenge, ServiceError>
verify_submission(VerifyRequest) -> Result<VerificationOutcome, ServiceError>
```

`IssueRequest` contains a generator version, an `AttemptLimit` of one or two,
and an opaque lifecycle binding. Its V1 convenience constructor selects one
attempt by default. `VerifyRequest` contains a `Submission` and the opaque
binding presented for this attempt. Binding values must contain 1 through 256
bytes. They are never copied into public or private challenge protocol
objects, passed to observers, or formatted by core errors. The lifecycle
adapter persists and compares them.

V1 keeps all generation policy fixed:

- secret length is selected uniformly from 8 through 16 ASCII alphanumeric
  bytes;
- fragment count follows the existing length mapping;
- challenge TTL is 15 seconds;
- answer encoding is unpadded canonical base64url;
- the renderer uses its fixed internal question-size bound;
- candidate retries are fixed at eight total attempts.

Attempt count is lifecycle policy rather than generation difficulty. The
closed `AttemptLimit` enum prevents an adapter from receiving an out-of-range
V1 value through the service API.

## 5. Candidate generation and retry policy

A candidate contains a rendered question, renderer metadata, the canonical
answer bytes, and safe semantic diagnostics required by observability. Its
`Debug` representation redacts the question and answer.

One candidate attempt performs this sequence with one cryptographic random
stream:

1. Generate a new secret.
2. Partition it and build a validated semantic graph.
3. Evaluate the graph to obtain the unique answer.
4. Build, validate, and emit the rendered question.
5. Confirm the answer encoding and all fixed V1 bounds.

The private candidate error model distinguishes a safe candidate rejection,
randomness unavailability, and an internal invariant failure. Only safe
semantic or rendering rejection discards the entire candidate and restarts
from a new secret. The service performs at most eight candidate attempts.
Randomness failure, an invariant failure, invalid service configuration, time
failure, key failure, and lifecycle failure are not retryable candidate
failures. Exhaustion maps to `generation_failed`; no partial plan, question,
answer, or private material escapes.

## 6. Challenge issuance flow

Issuance is ordered as follows:

1. Validate the request and dispatch the requested generator version.
2. Generate a complete candidate using the bounded retry policy.
3. Read system time once after candidate generation.
4. Set `issued_at` to Unix time in seconds and compute
   `expires_at = issued_at + 15` with checked arithmetic.
5. Independently generate 16 random bytes for the challenge ID and 16 random
   bytes for the nonce.
6. Encode each as a 22-character unpadded base64url string.
7. Ask `MacKeyProvider` for the active key ID and key material.
8. Validate that the key ID is nonempty and bounded and that the key is at
   least 32 bytes.
9. Encode the answer as canonical unpadded base64url and compute the existing
   context-bound HMAC.
10. Construct matching `PublicChallenge` and `PrivateChallengeMaterial`
    objects.
11. Call `LifecycleAdapter::store_issued` with the private material, binding,
    and validated `AttemptLimit`.
12. Return the public challenge only after storage reports definite success.

The service never retries a storage operation with an uncertain result. On a
storage failure it drops the public result and secret-bearing intermediates.
An orphaned private record is safe because its public question was never
released. A storage implementation must reject duplicate challenge IDs, even
though a collision in a 128-bit random identifier is operationally
negligible.

## 7. Key-provider contract

`MacKeyProvider` supports two operations:

- return the current active key ID and key for issuance;
- return key material for a stored key ID during verification.

The integrator keeps old keys available until every challenge using them has
expired and left the storage-retention window. The service never selects a
replacement key when lookup by stored key ID fails. Key lookup failure cannot
downgrade a version, recompute material, or fall back to the active key.

Key material has a redacted `Debug` implementation and is never included in
observer events or service errors. Provider-specific messages and error
objects stay inside the provider's own logging boundary.

## 8. Lifecycle adapter contract

The lifecycle adapter provides three conceptual operations:

```text
store_issued(private_material, binding, attempt_limit)
begin_attempt(submission_identity, binding, server_time)
finish_attempt(attempt_token, core_outcome)
```

`store_issued` durably creates the issued record, its binding, initial state,
and the supplied one- or two-attempt budget before the public question can be
returned.

`begin_attempt` performs one atomic operation that:

- locates the challenge ID;
- requires the current state to be `ISSUED`;
- compares server time with the stored issuance and expiry times;
- compares the opaque binding exactly;
- compares the nonce exactly;
- requires at least one remaining attempt;
- reserves or consumes one attempt; and
- returns the private material plus an opaque attempt token.

If server time is at or after `expires_at`, `begin_attempt` atomically records
the terminal `EXPIRED` state before returning its structured rejection.

The token is meaningful only to the adapter that created it. Dropping a token
or crashing after `begin_attempt` is fail-closed: the reserved attempt remains
used and cannot reopen the same verification attempt.

`finish_attempt` atomically persists a success or failure result. A successful
core verification moves the record to `CONSUMED_SUCCESS`. A failed core
verification either leaves an issued record with a reduced remaining count or
moves it to `CONSUMED_FAILURE`, according to adapter policy. V1 defaults to one
attempt; an integrator may configure two attempts as permitted by the approved
system design. No adapter may permit more than two attempts through this V1
interface.

Expired, successfully consumed, failure-consumed, and attempt-exhausted states
are terminal. The service returns `Accepted` only after the adapter durably
commits `CONSUMED_SUCCESS`.

## 9. Submission verification flow

Verification is ordered as follows:

1. Validate bounded request fields and read server time.
2. Call `begin_attempt`; lifecycle rejection stops before key lookup or MAC
   work.
3. Treat the returned private material as untrusted stored data and validate
   its bounded fields.
4. Dispatch strictly on the material's `generator_version`.
5. Look up the exact stored `mac_key_id` through `MacKeyProvider`.
6. For V1, call the existing canonical-answer and constant-time HMAC verifier.
7. Call `finish_attempt` with accepted, answer-rejected, or fail-closed system
   outcome.
8. Return `Accepted` only after successful durable finalization.

The adapter checks nonce before revealing private material. The low-level V1
verifier checks challenge ID and nonce again as defense in depth. Unsupported
versions never fall back to V1. Missing old keys never fall back to the active
key.

If version dispatch, key lookup, material validation, or finalization fails
after `begin_attempt`, the attempt remains consumed. These cases return a
system error rather than pretending the submitted answer was wrong.

## 10. Error and outcome model

Phase 4 preserves the approved stable error categories:

- `invalid_configuration`;
- `generation_failed`;
- `invalid_challenge_material`;
- `invalid_answer_encoding`;
- `answer_mismatch`;
- `unsupported_generator_version`;
- `internal_error`.

Lifecycle rejection is a verification outcome rather than an infrastructure
error. Its structured reasons cover not found, expired, already consumed,
binding mismatch, nonce mismatch, and attempts exhausted. Integrators may map
all rejection reasons and answer failures to one external response when
serving an untrusted caller.

Adapter and provider implementations return stable classifications to the
service, not arbitrary display text. `ServiceError`, `VerificationOutcome`,
and their `Debug` output never include a binding, submission answer, question,
private material, key ID, MAC, key, secret, or canonical answer.

## 11. Observability and privacy

The observer callback is synchronous and returns no value. A default no-op
implementation is supplied. Events use fixed fields rather than arbitrary
messages. Under unwind-capable Rust builds, the service catches an observer
panic and treats it as a discarded observation; panic-abort behavior remains
controlled by the host build. Observer calls occur only after the relevant
durable lifecycle decision, so observer behavior can never turn a failed or
uncommitted operation into authorization.

An issuance-success event may contain:

- challenge ID and generator version;
- secret-length bucket and fragment count;
- question byte length;
- selected renderer languages and distractor presence;
- candidate-attempt count; and
- generation duration.

An issuance-failure event contains only generator version, attempt count,
stage, and stable error category. A verification-completion event may contain
challenge ID, generator version, accepted or rejected category, elapsed server
time since issuance, and core verification duration. System-failure events
contain only a stage and stable category.

Observers never receive the raw secret, canonical answer, submitted answer,
answer MAC, MAC key, key ID, private material, binding, internal render plan,
adapter error text, or complete question. The service does not log on its own.

## 12. Security and failure semantics

Issuance and verification are fail-closed:

- no public challenge is returned without durable private state;
- no successful verification is returned without durable terminal state;
- ambiguous persistence results are never retried automatically;
- unfinished verification tokens consume their attempt;
- unsupported versions and missing keys do not fall back;
- observer failures cannot authorize access;
- errors and debug representations redact secret-bearing values.

The adapter remains responsible for durable atomicity, expiry, binding,
attempt limits, single consumption, concurrency control, rate limits, and
storage recovery. The key provider remains responsible for key protection and
rotation. Skipping these contracts makes replay or concurrent reuse possible;
the answer MAC alone does not implement a challenge lifecycle.

## 13. Testing strategy

Implementation follows test-driven development with deterministic
crate-internal runtime injection.

1. Public API contract tests compile against all service, request, outcome,
   adapter, key-provider, and observer types without exposing construction of
   invalid internal candidates.
2. Redaction tests place unique secret markers in keys, answers, bindings,
   questions, submissions, and adapter diagnostics and prove they do not occur
   in public `Debug`, `Display`, errors, or observer events.
3. Candidate tests prove atomic assembly, same-stream determinism,
   cross-stream variation, recovery after retryable candidate rejection,
   exact eight-attempt exhaustion, and immediate propagation of randomness
   failure.
4. Issuance tests prove fixed TTL, ID and nonce format, public/private field
   correspondence, canonical answer MAC verification, exactly one storage
   call, and no public result on storage failure.
5. Issuance property tests exercise every supported secret length and many
   deterministic streams while preserving renderer and Answer Engine
   invariants.
6. Verification orchestration tests prove the exact begin, version dispatch,
   key lookup, constant-time verifier, and finish ordering.
7. Lifecycle model tests prove only one concurrent attempt can commit success,
   dropped tokens remain consumed, finalization failure never returns
   `Accepted`, and a second configured attempt cannot exceed the V1 limit.
8. Version and key tests cover unsupported issuance, unsupported stored
   versions, old-key lookup, missing-key failure, and prohibition of active-key
   fallback.
9. Negative verification tests cover modified material, invalid answer
   encoding, answer mismatch, nonce mismatch, binding mismatch, expiry,
   consumption, and attempt exhaustion.
10. Observer tests enforce the event-field allowlist and verify success,
    rejection, retry, and system-failure events.
11. Existing schemas, fixtures, golden vectors, verifier tests, semantic tests,
    and renderer tests remain unchanged and pass.

Final verification runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 14. Acceptance criteria

Phase 4 is complete when:

- the public service issues a persisted V1 challenge through one stable call;
- candidate generation retries only bounded candidate-local failures and
  never returns partial output;
- IDs and nonces are independent 128-bit CSPRNG values encoded as unpadded
  base64url;
- the public challenge is returned only after durable private-state creation;
- verification dispatches by stored version and stored key ID without
  fallback;
- lifecycle begin and finish operations enforce fail-closed attempt and
  terminal-state behavior;
- `Accepted` is returned only after durable successful consumption;
- stable errors and observer events contain no secret-bearing data;
- the existing protocol schemas and fixtures remain compatible;
- formatting, linting, workspace tests, and documentation tests pass; and
- README reports Phase 4 complete and identifies Phase 5 stable C ABI and
  language bindings as the next roadmap phase.
