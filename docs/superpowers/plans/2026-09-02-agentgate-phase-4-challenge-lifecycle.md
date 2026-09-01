# AgentGate Phase 4 Challenge Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose a fail-closed V1 challenge issuance and submission verification service with bounded candidate retries, version dispatch, lifecycle and key adapters, and secret-safe observability.

**Architecture:** Add a synchronous generic `ChallengeService` above the existing generator, renderer, HMAC, and verifier. The service generates and persists private material before returning a public challenge, and uses a two-stage lifecycle attempt protocol before and after versioned answer verification. External state remains behind caller-implemented adapters; deterministic randomness and time remain crate-internal test seams.

**Tech Stack:** Rust 1.85+, Cargo workspace, existing `base64`, `getrandom`, HMAC-SHA-256, `thiserror`, deterministic unit tests, property-style seed sweeps, Clippy.

---

## File structure

- Create `packages/core/src/service/mod.rs`: service construction, issuance and verification orchestration.
- Create `packages/core/src/service/model.rs`: requests, attempt limits, pending attempts, outcomes, safe metadata.
- Create `packages/core/src/service/error.rs`: stable service, adapter, provider, and lifecycle-rejection categories.
- Create `packages/core/src/service/lifecycle.rs`: synchronous lifecycle adapter trait.
- Create `packages/core/src/service/keys.rs`: redacted MAC key types and provider trait.
- Create `packages/core/src/service/observer.rs`: fixed allowlisted events, observer trait, no-op observer, panic isolation.
- Create `packages/core/src/service/version.rs`: exact V1 issuance and stored-material verification dispatch.
- Create `packages/core/src/service/runtime.rs`: system time and identifier/nonce helpers with test seams.
- Create `packages/core/src/generation/candidate.rs`: atomic candidate assembly and bounded retry helper.
- Modify `packages/core/src/generation/mod.rs`: register the candidate module and remove Phase 4 dead-code expectations.
- Modify `packages/core/src/generation/secret.rs`: remove obsolete production wrapper once candidate assembly owns the random stream.
- Modify `packages/core/src/generation/planner.rs`: remove obsolete production wrapper and expose safe candidate diagnostics crate-internally.
- Modify `packages/core/src/lib.rs`: register and re-export the Phase 4 public API.
- Create `packages/core/tests/service_public_api.rs`: external-crate compile and redaction contract.
- Create `packages/core/tests/challenge_service_issue.rs`: public issuance behavior and persistence ordering.
- Create `packages/core/tests/challenge_service_verify.rs`: public verification and lifecycle ordering.
- Modify `README.md`: report Phase 4 completion and the Phase 5 handoff.

### Task 1: Define the stable public service and adapter contracts

**Files:**
- Create: `packages/core/tests/service_public_api.rs`
- Create: `packages/core/src/service/error.rs`
- Create: `packages/core/src/service/model.rs`
- Create: `packages/core/src/service/lifecycle.rs`
- Create: `packages/core/src/service/keys.rs`
- Create: `packages/core/src/service/observer.rs`
- Create: `packages/core/src/service/mod.rs`
- Modify: `packages/core/src/lib.rs`

- [ ] **Step 1: Write the failing external public-API contract test**

Create `packages/core/tests/service_public_api.rs`:

```rust
use agentgate_core::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, ChallengeService, IssueRequest,
    KeyProviderError, LifecycleAdapter, LifecycleAdapterError, LifecycleRejection,
    MacKey, MacKeyProvider, NoopObserver, PendingAttempt, ServiceError, SubmissionIdentity,
    VerifyRequest, VerificationOutcome,
    contracts::{PrivateChallengeMaterial, Submission},
};

struct Lifecycle;

impl LifecycleAdapter for Lifecycle {
    type AttemptToken = u64;

    fn store_issued(
        &mut self,
        _material: PrivateChallengeMaterial,
        _binding: &[u8],
        _attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError> {
        Ok(())
    }

    fn begin_attempt(
        &mut self,
        _identity: SubmissionIdentity<'_>,
        _binding: &[u8],
        _server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, agentgate_core::BeginAttemptError> {
        Err(LifecycleRejection::NotFound.into())
    }

    fn finish_attempt(
        &mut self,
        _token: Self::AttemptToken,
        _outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        Ok(())
    }
}

struct Keys;

impl MacKeyProvider for Keys {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        ActiveMacKey::new("key-1", vec![7; 32]).map_err(|_| KeyProviderError::InvalidMaterial)
    }

    fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
        MacKey::new(vec![7; 32]).map_err(|_| KeyProviderError::InvalidMaterial)
    }
}

#[test]
fn exposes_constructible_phase4_contracts() {
    let _service = ChallengeService::new(Lifecycle, Keys);
    let issue = IssueRequest::v1(b"session-42");
    let two_attempts = IssueRequest::new("1.0", b"session-42", AttemptLimit::Two);
    let submission = Submission {
        challenge_id: "challenge".to_owned(),
        nonce: "nonce".to_owned(),
        answer: "YQ".to_owned(),
    };
    let verify = VerifyRequest::new(&submission, b"session-42");

    assert_eq!(issue.attempt_limit(), AttemptLimit::One);
    assert_eq!(two_attempts.attempt_limit(), AttemptLimit::Two);
    assert_eq!(verify.submission().challenge_id, "challenge");
    assert_eq!(ServiceError::GenerationFailed.code(), "generation_failed");
    assert_eq!(
        VerificationOutcome::Rejected(LifecycleRejection::Expired),
        VerificationOutcome::Rejected(LifecycleRejection::Expired)
    );
    assert_eq!(std::mem::size_of::<NoopObserver>(), 0);
}

#[test]
fn request_and_key_debug_output_redacts_sensitive_bytes() {
    let binding = b"BINDING_SENTINEL_4d78";
    let submission = Submission {
        challenge_id: "challenge".to_owned(),
        nonce: "nonce".to_owned(),
        answer: "ANSWER_SENTINEL_972a".to_owned(),
    };
    let issue_debug = format!("{:?}", IssueRequest::v1(binding));
    let verify_debug = format!("{:?}", VerifyRequest::new(&submission, binding));
    let key_debug = format!("{:?}", MacKey::new(b"KEY_SENTINEL____________________".to_vec()).unwrap());

    assert!(!issue_debug.contains("BINDING_SENTINEL"));
    assert!(!verify_debug.contains("BINDING_SENTINEL"));
    assert!(!verify_debug.contains("ANSWER_SENTINEL"));
    assert!(!key_debug.contains("KEY_SENTINEL"));
    assert!(issue_debug.contains("[REDACTED]"));
    assert!(verify_debug.contains("[REDACTED]"));
    assert!(key_debug.contains("[REDACTED]"));
}
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```sh
cargo test -p agentgate-core --test service_public_api
```

Expected: compilation fails because the Phase 4 service types are not exported.

- [ ] **Step 3: Implement stable error and model types**

Create `service/error.rs` with the exact closed enums below:

```rust
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ServiceError {
    #[error("invalid configuration")]
    InvalidConfiguration,
    #[error("challenge generation failed")]
    GenerationFailed,
    #[error("challenge material is invalid")]
    InvalidChallengeMaterial,
    #[error("answer encoding is invalid")]
    InvalidAnswerEncoding,
    #[error("answer does not match")]
    AnswerMismatch,
    #[error("generator version is unsupported")]
    UnsupportedGeneratorVersion,
    #[error("internal service failure")]
    InternalError,
}

impl ServiceError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::GenerationFailed => "generation_failed",
            Self::InvalidChallengeMaterial => "invalid_challenge_material",
            Self::InvalidAnswerEncoding => "invalid_answer_encoding",
            Self::AnswerMismatch => "answer_mismatch",
            Self::UnsupportedGeneratorVersion => "unsupported_generator_version",
            Self::InternalError => "internal_error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRejection {
    NotFound,
    Expired,
    AlreadyConsumed,
    BindingMismatch,
    NonceMismatch,
    AttemptsExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAdapterError {
    Unavailable,
    Conflict,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginAttemptError {
    Rejected(LifecycleRejection),
    Adapter(LifecycleAdapterError),
}

impl From<LifecycleRejection> for BeginAttemptError {
    fn from(value: LifecycleRejection) -> Self { Self::Rejected(value) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderError {
    Unavailable,
    NotFound,
    InvalidMaterial,
}
```

Create `service/model.rs` with `MAX_BINDING_BYTES = 256`,
`AttemptLimit::{One, Two}`, redacted borrowed request types,
`SubmissionIdentity`, `PendingAttempt<T>` with a public constructor and
crate-private `into_parts`, `AttemptOutcome::{Accepted, Rejected,
SystemFailure}`, and `VerificationOutcome::{Accepted,
Rejected(LifecycleRejection)}`. `IssueRequest::new(version, binding,
attempt_limit)` preserves an explicit closed limit and `IssueRequest::v1`
selects version `1.0` plus `AttemptLimit::One`. Validate binding length in
`IssueRequest::validate` and `VerifyRequest::validate`; do not expose binding
getters publicly.

- [ ] **Step 4: Implement redacted key types and adapter traits**

Create `service/keys.rs`:

```rust
use std::fmt;
use super::KeyProviderError;

pub const MAX_MAC_KEY_ID_BYTES: usize = 128;
pub const MIN_MAC_KEY_BYTES: usize = 32;

pub struct MacKey(Vec<u8>);

impl MacKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyProviderError> {
        (bytes.len() >= MIN_MAC_KEY_BYTES)
            .then_some(Self(bytes))
            .ok_or(KeyProviderError::InvalidMaterial)
    }

    pub(crate) fn expose(&self) -> &[u8] { &self.0 }
}

impl fmt::Debug for MacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacKey([REDACTED])")
    }
}

pub struct ActiveMacKey {
    key_id: String,
    key: MacKey,
}

impl ActiveMacKey {
    pub fn new(key_id: impl Into<String>, bytes: Vec<u8>) -> Result<Self, KeyProviderError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > MAX_MAC_KEY_ID_BYTES {
            return Err(KeyProviderError::InvalidMaterial);
        }
        Ok(Self { key_id, key: MacKey::new(bytes)? })
    }

    pub(crate) fn into_parts(self) -> (String, MacKey) { (self.key_id, self.key) }
}

impl fmt::Debug for ActiveMacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveMacKey")
            .field("key_id", &"[REDACTED]")
            .field("key", &self.key)
            .finish()
    }
}

pub trait MacKeyProvider {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError>;
    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError>;
}
```

Create `service/lifecycle.rs` with the three synchronous methods used by the failing test. Do not add default implementations; every adapter must make persistence and terminal-state choices explicit.

- [ ] **Step 5: Add the service shell, no-op observer, and root re-exports**

Create a zero-sized `NoopObserver`, an `Observer` trait with
`fn observe(&mut self, event: &ServiceEvent)`, and the final closed event model
in `service/observer.rs`:

```rust
pub enum ServiceEvent {
    ChallengeIssued(ChallengeIssuedEvent),
    IssueFailed(ServiceFailureEvent),
    VerificationCompleted(VerificationEvent),
    ServiceFailed(ServiceFailureEvent),
}
```

Define `SecretLengthBucket::{EightToTen, ElevenToThirteen,
FourteenToSixteen}`, `ServiceStage::{Request, VersionDispatch, Candidate,
Clock, KeyProvider, LifecycleStore, LifecycleBegin, CoreVerification,
LifecycleFinish}`, and `VerificationDisposition::{Accepted,
LifecycleRejected(LifecycleRejection), InvalidAnswerEncoding, AnswerMismatch,
SystemFailure}`. The event structs use only owned challenge ID/version strings,
these closed enums, `Duration`, renderer languages, counts, and booleans. Do not
add arbitrary messages, bindings, nonces, key IDs, or secret-bearing fields.

Create `service/mod.rs` with private submodules, public re-exports, and:

```rust
pub struct ChallengeService<L, K, O = NoopObserver> {
    lifecycle: L,
    keys: K,
    observer: O,
}

impl<L, K> ChallengeService<L, K, NoopObserver> {
    pub fn new(lifecycle: L, keys: K) -> Self {
        Self { lifecycle, keys, observer: NoopObserver }
    }
}

impl<L, K, O> ChallengeService<L, K, O> {
    pub fn with_observer(lifecycle: L, keys: K, observer: O) -> Self {
        Self { lifecycle, keys, observer }
    }
}
```

Register `pub mod service;` and re-export every public Phase 4 type from `packages/core/src/lib.rs`.

- [ ] **Step 6: Run the focused contract tests and full existing tests**

Run:

```sh
cargo test -p agentgate-core --test service_public_api
cargo test --workspace
```

Expected: both commands pass; the existing protocol, verifier, semantic, and renderer tests remain green.

- [ ] **Step 7: Commit the public contract checkpoint**

```sh
git add packages/core/src/lib.rs packages/core/src/service packages/core/tests/service_public_api.rs
git commit -m "feat: define phase4 service contracts"
```

### Task 2: Assemble atomic candidates and bounded retries

**Files:**
- Create: `packages/core/src/generation/candidate.rs`
- Modify: `packages/core/src/generation/mod.rs`
- Modify: `packages/core/src/generation/secret.rs`
- Modify: `packages/core/src/generation/planner.rs`

- [ ] **Step 1: Write failing candidate retry tests**

In the new `candidate.rs`, start with tests for a generic private retry helper:

```rust
#[cfg(test)]
mod tests {
    use super::{CandidateError, MAX_CANDIDATE_ATTEMPTS, retry_candidates};

    #[test]
    fn retries_candidate_rejections_until_success() {
        let mut calls = 0;
        let result = retry_candidates(|| {
            calls += 1;
            if calls < 3 { Err(CandidateError::Rejected) } else { Ok(41) }
        });
        assert_eq!(result, Ok((41, 3)));
    }

    #[test]
    fn stops_after_exactly_eight_rejected_candidates() {
        let mut calls = 0;
        let result: Result<(u8, u8), _> = retry_candidates(|| {
            calls += 1;
            Err(CandidateError::Rejected)
        });
        assert_eq!(calls, usize::from(MAX_CANDIDATE_ATTEMPTS));
        assert_eq!(result, Err(CandidateError::Exhausted));
    }

    #[test]
    fn does_not_retry_randomness_or_invariant_failures() {
        for failure in [CandidateError::RandomnessUnavailable, CandidateError::Internal] {
            let mut calls = 0;
            let result: Result<(u8, u8), _> = retry_candidates(|| {
                calls += 1;
                Err(failure)
            });
            assert_eq!(calls, 1);
            assert_eq!(result, Err(failure));
        }
    }
}
```

- [ ] **Step 2: Run the candidate unit tests and verify RED**

Run:

```sh
cargo test -p agentgate-core generation::candidate::tests
```

Expected: compilation fails because the candidate module and retry helper do not exist.

- [ ] **Step 3: Implement the exact retry state machine**

Define:

```rust
pub(crate) const MAX_CANDIDATE_ATTEMPTS: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateError {
    Rejected,
    RandomnessUnavailable,
    Internal,
    Exhausted,
}

pub(crate) fn retry_candidates<T>(
    mut generate: impl FnMut() -> Result<T, CandidateError>,
) -> Result<(T, u8), CandidateError> {
    for attempt in 1..=MAX_CANDIDATE_ATTEMPTS {
        match generate() {
            Ok(candidate) => return Ok((candidate, attempt)),
            Err(CandidateError::Rejected) => {}
            Err(error) => return Err(error),
        }
    }
    Err(CandidateError::Exhausted)
}
```

Run the focused tests and confirm GREEN before adding candidate assembly.

- [ ] **Step 4: Write the failing atomic candidate assembly test**

Add a deterministic test using `DeterministicRandom::new([23; 32])`. Assert that the candidate answer is canonical base64url, question length matches renderer metadata, secret length is 8 through 16, fragment count matches `fragment_count_for_secret_length`, operation count is 4 through 8, and `Debug` contains `[REDACTED]` but neither question nor answer.

- [ ] **Step 5: Implement minimal candidate assembly**

`generate_candidate_with(random)` must call, in order, `secret::generate_with`, `planner::plan_with`, and `render::render_with` using the same `RandomSource`. Encode `PlannedSemantics::answer()` with `URL_SAFE_NO_PAD`. Store only:

```rust
pub(crate) struct ChallengeCandidate {
    question: RenderedQuestion,
    answer: String,
    secret_length: usize,
    fragment_count: usize,
    operation_count: usize,
}
```

Provide crate-private read-only accessors and a manual redacted `Debug`. Map
`GenerationError::RandomnessUnavailable` to
`CandidateError::RandomnessUnavailable`; map every other `GenerationError` and
every `RenderError` returned while building this candidate to
`CandidateError::Rejected`; reserve `CandidateError::Internal` for a failed
post-validation invariant in candidate assembly.

Register `mod candidate;` in `generation/mod.rs`. Remove the unused `generate_secret()` and `plan_semantics()` wrappers; candidate assembly now owns the single production random stream. Remove their obsolete Phase 4 dead-code expectations while keeping focused test helpers.

Add only crate-private orchestration re-exports from `generation/mod.rs`:

```rust
pub(crate) use candidate::{
    CandidateError, ChallengeCandidate, generate_candidate_with,
    retry_candidates,
};
pub(crate) use random::{OsRandom, RandomSource};
```

Do not make the random source, candidate, answer, or candidate constructor part
of the public API.

- [ ] **Step 6: Verify candidate tests and the generation suite**

Run:

```sh
cargo test -p agentgate-core generation::candidate
cargo test -p agentgate-core generation
```

Expected: all candidate, semantic, renderer, operation, and random-source tests pass.

- [ ] **Step 7: Commit candidate assembly**

```sh
git add packages/core/src/generation
git commit -m "feat: assemble bounded challenge candidates"
```

### Task 3: Implement versioned fail-closed challenge issuance

**Files:**
- Create: `packages/core/src/service/runtime.rs`
- Create: `packages/core/src/service/version.rs`
- Create: `packages/core/tests/challenge_service_issue.rs`
- Modify: `packages/core/src/service/mod.rs`
- Modify: `packages/core/src/service/observer.rs`

- [ ] **Step 1: Write the failing successful-issuance integration test**

Create a recording lifecycle adapter backed by `Rc<RefCell<Vec<PrivateChallengeMaterial>>>` and a fixed key provider. Call `ChallengeService::issue_challenge(IssueRequest::v1(b"session-42"))` and assert:

```rust
assert_eq!(public.generator_version, GENERATOR_VERSION_V1);
assert_eq!(public.expires_at - public.issued_at, i64::from(CHALLENGE_TTL_SECONDS));
assert_eq!(public.challenge_id.len(), 22);
assert_eq!(public.nonce.len(), 22);
assert!(public.challenge_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
assert!(public.nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
assert_ne!(public.challenge_id, public.nonce);
assert!(!public.question.is_empty());
assert_eq!(stored.len(), 1);
assert_eq!(stored[0].challenge_id, public.challenge_id);
assert_eq!(stored[0].nonce, public.nonce);
assert_eq!(stored[0].issued_at, public.issued_at);
assert_eq!(stored[0].expires_at, public.expires_at);
assert_eq!(stored[0].generator_version, public.generator_version);
```

- [ ] **Step 2: Run the issuance test and verify RED**

Run:

```sh
cargo test -p agentgate-core --test challenge_service_issue
```

Expected: compilation fails because `issue_challenge` is not implemented.

- [ ] **Step 3: Implement runtime helpers and exact V1 dispatch**

In `service/runtime.rs`, implement `unix_time_now()` with
`SystemTime::now().duration_since(UNIX_EPOCH)` and checked `u64` to `i64`
conversion. Implement
`fn random_token(random: &mut impl RandomSource) -> Result<String,
GenerationError>` by filling a local `[u8; 16]` and encoding it with
`URL_SAFE_NO_PAD`.

In `service/version.rs`, define exact string matching against `GENERATOR_VERSION_V1`; every other issuance version returns `ServiceError::UnsupportedGeneratorVersion`. Do not trim, case-fold, or accept aliases.

- [ ] **Step 4: Implement the minimal issuance orchestration**

Add `issue_challenge` for `L: LifecycleAdapter`, `K: MacKeyProvider`, `O: Observer`. It must:

1. validate binding;
2. dispatch V1;
3. create one `OsRandom` and call `retry_candidates(|| generate_candidate_with(&mut random))`;
4. read time only after candidate success;
5. checked-add the fixed TTL;
6. draw ID and nonce independently from the same CSPRNG boundary;
7. fetch the active key;
8. construct `MacContext` and hex-encode `compute_answer_mac`;
9. build matching public/private objects;
10. move private material into `store_issued` exactly once; and
11. return public material only after storage succeeds.

Map candidate exhaustion and randomness loss to `GenerationFailed`; version mismatch to `UnsupportedGeneratorVersion`; invalid binding or active-key construction to `InvalidConfiguration`; clock, adapter, and unexpected MAC failures to `InternalError`.

- [ ] **Step 5: Verify GREEN, then add storage-failure and invalid-request RED tests**

Add tests proving an empty or 257-byte binding returns
`InvalidConfiguration` before adapter or key calls, unsupported version
returns `UnsupportedGeneratorVersion`, storage failure returns `InternalError`,
and storage is called exactly once without an automatic retry. Issue one
challenge through `IssueRequest::new("1.0", binding, AttemptLimit::Two)` and
assert the adapter receives exactly `AttemptLimit::Two`; the convenience V1
request must deliver `AttemptLimit::One`.

Run the focused test after each test addition; each new test must fail for its intended missing branch before the minimal branch is implemented.

- [ ] **Step 6: Run issuance and workspace tests**

```sh
cargo test -p agentgate-core --test challenge_service_issue
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 7: Commit issuance**

```sh
git add packages/core/src/service packages/core/tests/challenge_service_issue.rs
git commit -m "feat: issue persisted v1 challenges"
```

### Task 4: Implement two-stage lifecycle verification and version dispatch

**Files:**
- Create: `packages/core/tests/challenge_service_verify.rs`
- Modify: `packages/core/src/service/mod.rs`
- Modify: `packages/core/src/service/version.rs`

- [ ] **Step 1: Write the failing accepted-submission test**

Build a stored fixture with `compute_answer_mac`, a lifecycle adapter that records `begin_attempt` and `finish_attempt`, and a provider whose `key_by_id` records the requested ID. Submit the correct answer and assert:

```rust
assert_eq!(result, Ok(VerificationOutcome::Accepted));
assert_eq!(calls, vec!["begin", "key:key-old", "finish:accepted"]);
```

The adapter's `begin_attempt` must receive only `SubmissionIdentity` plus binding and server time; assert its debug/captured data never includes the submitted answer.

- [ ] **Step 2: Run the verification test and verify RED**

```sh
cargo test -p agentgate-core --test challenge_service_verify
```

Expected: compilation fails because `verify_submission` is absent.

- [ ] **Step 3: Implement the minimal accepted path**

Add `verify_submission` with this exact order:

```text
validate request
read server time
begin_attempt
dispatch stored generator_version
key_by_id(stored mac_key_id)
verify_answer
finish_attempt(Accepted)
return Accepted
```

If `finish_attempt(Accepted)` fails, return `InternalError`; never return `Accepted` first.

- [ ] **Step 4: Add lifecycle rejection tests and implement direct outcome mapping**

For every `LifecycleRejection` variant, make `begin_attempt` return `BeginAttemptError::Rejected(reason)`. Assert the service returns `Ok(VerificationOutcome::Rejected(reason))`, does not call the key provider, and does not call `finish_attempt`.

Adapter infrastructure failure maps to `Err(ServiceError::InternalError)` with no key lookup.

- [ ] **Step 5: Add answer and system-failure tests one at a time**

Add and watch each test fail before implementing its branch:

- invalid canonical encoding calls `finish_attempt(Rejected)` then returns `InvalidAnswerEncoding`;
- wrong canonical answer calls `finish_attempt(Rejected)` then returns `AnswerMismatch`;
- malformed stored material calls `finish_attempt(SystemFailure)` then returns `InvalidChallengeMaterial`;
- unsupported stored version calls `finish_attempt(SystemFailure)` then returns `UnsupportedGeneratorVersion` without key lookup;
- missing or unavailable old key calls `finish_attempt(SystemFailure)` then returns `InternalError` without active-key fallback;
- any failure finalization error overrides the earlier client/system category with `InternalError`.

Use a single private helper that owns the attempt token and performs exactly one finalization call. Do not clone or expose tokens.

- [ ] **Step 6: Prove defense-in-depth identity checks**

Add tests in which a malicious adapter returns material whose challenge ID or nonce differs from the submission. Assert low-level verification rejects it as `InvalidChallengeMaterial`, records `SystemFailure`, and never returns `Accepted`.

- [ ] **Step 7: Run focused and full verification**

```sh
cargo test -p agentgate-core --test challenge_service_verify
cargo test -p agentgate-core --test verifier
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 8: Commit verification orchestration**

```sh
git add packages/core/src/service packages/core/tests/challenge_service_verify.rs
git commit -m "feat: verify lifecycle-bound submissions"
```

### Task 5: Add secret-safe operational observability

**Files:**
- Modify: `packages/core/src/service/observer.rs`
- Modify: `packages/core/src/service/mod.rs`
- Modify: `packages/core/src/generation/candidate.rs`
- Modify: `packages/core/tests/challenge_service_issue.rs`
- Modify: `packages/core/tests/challenge_service_verify.rs`
- Modify: `packages/core/tests/service_public_api.rs`

- [ ] **Step 1: Write failing observer allowlist tests**

Create a recording observer and assert issuance success produces exactly one `ChallengeIssued` event with challenge ID, version, secret-length bucket, fragment count, question byte length, renderer languages, distractor flag, candidate-attempt count, and duration. Assert it has no question, answer, MAC, key ID, key, binding, or arbitrary message field.

Add a verification event test asserting the event contains challenge ID, optional stored version, disposition, optional elapsed-since-issuance duration, and core duration, but not submission answer, nonce, binding, key ID, or private material.

- [ ] **Step 2: Run observer tests and verify RED**

```sh
cargo test -p agentgate-core --test challenge_service_issue observer
cargo test -p agentgate-core --test challenge_service_verify observer
```

Expected: tests fail because the service does not yet emit the final event
types.

- [ ] **Step 3: Wire the closed event model to safe candidate diagnostics**

Add safe candidate diagnostic accessors needed to construct the already
defined `ChallengeIssuedEvent`; do not expose the candidate or diagnostics
outside the crate. Populate every final event field from allowlisted values
only. Keep all event types `Clone`, `Debug`, `Eq`, and `PartialEq`.

- [ ] **Step 4: Isolate observer panics and emit only after durable decisions**

Add one helper:

```rust
fn emit(&mut self, event: ServiceEvent) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        self.observer.observe(&event);
    }));
}
```

Emit issuance success only after `store_issued` succeeds. Emit accepted verification only after successful `finish_attempt(Accepted)`. Failures emit their stable category and stage after the service has determined the fail-closed result.

- [ ] **Step 5: Add panic and sentinel tests**

Use an observer that panics on every event. Assert successful issuance still returns its public challenge after one stored record, and successful verification still returns `Accepted` after one durable finish.

Place unique markers in binding, key, key ID, submitted answer, MAC, adapter diagnostics, and question. Format every event and public error with `Debug` and `Display`; assert no marker occurs. Keep challenge ID and generator version as the only permitted identifiers.

- [ ] **Step 6: Run observability and redaction suites**

```sh
cargo test -p agentgate-core --test service_public_api
cargo test -p agentgate-core --test challenge_service_issue
cargo test -p agentgate-core --test challenge_service_verify
```

Expected: all tests pass with no panic output counted as a failure.

- [ ] **Step 7: Commit observability**

```sh
git add packages/core/src/service packages/core/src/generation/candidate.rs packages/core/tests
git commit -m "feat: observe challenge lifecycle safely"
```

### Task 6: Harden deterministic properties, retry boundaries, and fail-closed concurrency semantics

**Files:**
- Modify: `packages/core/src/generation/candidate.rs`
- Modify: `packages/core/src/service/mod.rs`
- Modify: `packages/core/tests/challenge_service_issue.rs`
- Modify: `packages/core/tests/challenge_service_verify.rs`

- [ ] **Step 1: Add deterministic issuance property tests through crate-internal seams**

In `service/mod.rs` unit tests, inject `DeterministicRandom` and a fixed Unix time into a crate-private `issue_with(random, now)` helper. For seeds `0_u8..=127`, assert:

- the same seed produces the same question, ID, nonce, private MAC, and safe metadata;
- different representative seeds vary at least one permitted output dimension;
- ID and nonce decode to exactly 16 bytes;
- expiry is exactly 15 seconds after issuance;
- stored material verifies against the candidate's canonical answer and fixed key;
- secret length, fragment count, operation count, renderer language count, and question bound remain within V1 policy.

To obtain the expected answer without exposing it from the service, create two
fresh `DeterministicRandom` values with the same seed. Generate one candidate
directly with the first value and retain its test-only answer accessor; pass
the second value to `issue_with`. Because candidate generation consumes the
same byte stream before ID and nonce generation, the stored MAC must verify
against the separately replayed candidate answer.

Run the new test first and confirm it fails because the internal helper does not yet expose deterministic time/randomness.

- [ ] **Step 2: Add the smallest test seam without exposing production seeds**

Refactor public `issue_challenge` to create `OsRandom` and call private `issue_with(request, &mut random, unix_time_now)`. Keep `issue_with` private to the service module and its child tests. Do not re-export a runtime, clock, seed, or candidate constructor.

- [ ] **Step 3: Add exact retry-boundary tests at the service mapping layer**

Inject a private candidate factory into a unit-only helper. Assert seven retryable rejections followed by success records `candidate_attempts == 8`; eight rejections return `GenerationFailed`; randomness failure on the first attempt calls the factory once; key and storage failures do not restart candidate generation.

- [ ] **Step 4: Add a model adapter concurrency test**

Implement a test-only adapter with shared state and two service instances. Its `begin_attempt` atomically changes `ISSUED` to `RESERVED`; a second begin returns `AlreadyConsumed`. Assert only the first service reaches key lookup and only one service can commit `Accepted`.

Add a dropped/reserved-token test: make verification fail after begin because the old key is unavailable, then assert a second attempt is rejected and the adapter recorded a fail-closed used attempt.

- [ ] **Step 5: Verify all properties and legacy compatibility**

```sh
cargo test -p agentgate-core generation::candidate
cargo test -p agentgate-core service
cargo test -p agentgate-core --test challenge_service_issue
cargo test -p agentgate-core --test challenge_service_verify
cargo test -p agentgate-contracts
cargo test --workspace
```

Expected: all tests pass; existing schemas, fixtures, MAC vectors, and renderer behavior remain unchanged.

- [ ] **Step 6: Commit lifecycle hardening**

```sh
git add packages/core/src packages/core/tests
git commit -m "test: harden phase4 lifecycle boundaries"
```

### Task 7: Freeze Phase 4 documentation and run release-level verification

**Files:**
- Modify: `README.md`
- Modify: `packages/core/src/service/lifecycle.rs`
- Modify: `packages/core/src/service/keys.rs`
- Modify: `packages/core/src/service/mod.rs`
- Test: entire workspace

- [ ] **Step 1: Add public Rust documentation with security obligations**

Document every public service, adapter, key, request, outcome, event, and error type. The `LifecycleAdapter` docs must state atomicity, expiry, exact binding and nonce comparison, attempt reservation, fail-closed dropped tokens, and durable finalization requirements. The key-provider docs must state old-key retention and no active-key fallback. `ChallengeService` docs must state that observer callbacks cannot authorize and that the SDK does not implement storage, sessions, rate limiting, or business admission.

- [ ] **Step 2: Run documentation tests and strict lint before changing status text**

```sh
cargo test --doc --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: both commands pass with no missing-doc or dead-code workaround introduced for Phase 4.

- [ ] **Step 3: Update README only after the implementation gates pass**

Replace the workspace-status paragraph with text stating that Phase 4 now adds persisted one-shot challenge issuance, bounded invalid-candidate retries, stored-version verification dispatch, fail-closed lifecycle adapters, key rotation lookup, structured errors, and secret-safe observer hooks. Identify stable C ABI and language bindings as Phase 5, with adversarial qualification still Phase 6.

Add a lifecycle integration paragraph that explicitly repeats: the adapter must enforce expiry, binding, nonce, attempts, atomic single consumption, persistence, and concurrency; the provider must retain old keys; no secret-bearing value may enter ordinary logs.

- [ ] **Step 4: Run final formatting and complete workspace verification**

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
git status --short
```

Expected: formatting, Clippy, and all workspace tests pass; `git diff --check` is silent; status lists only the intentional Phase 4 documentation changes.

- [ ] **Step 5: Commit Phase 4 completion documentation**

```sh
git add README.md packages/core/src/service
git commit -m "docs: mark challenge lifecycle phase complete"
```

- [ ] **Step 6: Re-run final verification against the committed tree**

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git status --short
```

Expected: all commands pass and the final status is empty.
