//! One-shot challenge issuance and verification orchestration.
//!
//! This module composes generation, MAC verification, caller-provided durable
//! lifecycle storage, key lookup, and secret-safe observations. It does not
//! implement storage, sessions, distributed rate limits, recovery, or business
//! admission policy; hosts must supply and enforce those controls.

mod error;
mod keys;
mod lifecycle;
mod model;
mod observer;
mod runtime;
mod version;

use std::time::{Duration, Instant};

use agentgate_contracts::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::generation::{
    CandidateError, OsRandom, RenderMetadata, generate_candidate_with,
    retry_candidates_with_attempts,
};
use crate::mac::validate_context_fields;
use crate::{CoreError, MacContext, compute_answer_mac, verify_answer};

pub use error::{
    BeginAttemptError, KeyProviderError, LifecycleAdapterError, LifecycleRejection, ServiceError,
};
pub use keys::{ActiveMacKey, MAX_MAC_KEY_ID_BYTES, MIN_MAC_KEY_BYTES, MacKey, MacKeyProvider};
pub use lifecycle::LifecycleAdapter;
pub use model::{
    AttemptLimit, AttemptOutcome, IssueRequest, MAX_BINDING_BYTES, PendingAttempt,
    SubmissionIdentity, VerificationOutcome, VerifyRequest,
};
pub use observer::{
    ChallengeIssuedEvent, NoopObserver, Observer, SecretLengthBucket, ServiceEvent,
    ServiceFailureEvent, ServiceStage, VerificationDisposition, VerificationEvent,
};

struct PreparedCandidate {
    question: String,
    answer: String,
    secret_length: usize,
    fragment_count: usize,
    render_metadata: RenderMetadata,
}

fn generate_issue_candidate(
    random: &mut impl crate::generation::RandomSource,
) -> Result<PreparedCandidate, CandidateError> {
    let candidate = generate_candidate_with(random)?;
    Ok(PreparedCandidate {
        question: candidate.question().to_owned(),
        answer: candidate.answer().to_owned(),
        secret_length: candidate.secret_length(),
        fragment_count: candidate.fragment_count(),
        render_metadata: candidate.render_metadata().clone(),
    })
}

/// Orchestrates persisted challenge issuance and one-shot verification.
///
/// `L` owns durable lifecycle and concurrency semantics, `K` owns protected key
/// storage and rotation, and `O` receives allowlisted diagnostics. Observer
/// callbacks are isolated from authorization: they cannot change a returned or
/// durable result, and an unwind from a callback is discarded in unwind-capable
/// builds.
///
/// This service does not provide storage, sessions, rate limiting, recovery, or
/// application-specific admission. See [`LifecycleAdapter`] and
/// [`MacKeyProvider`] for the host's security obligations.
pub struct ChallengeService<L, K, O = NoopObserver> {
    lifecycle: L,
    keys: K,
    observer: O,
}

impl<L, K> ChallengeService<L, K, NoopObserver> {
    /// Creates a service with the default no-op observer and system runtime.
    pub fn new(lifecycle: L, keys: K) -> Self {
        Self {
            lifecycle,
            keys,
            observer: NoopObserver,
        }
    }
}

impl<L, K, O> ChallengeService<L, K, O> {
    /// Creates a service with an explicit observer and the system runtime.
    pub fn with_observer(lifecycle: L, keys: K, observer: O) -> Self {
        Self {
            lifecycle,
            keys,
            observer,
        }
    }
}

impl<L, K, O> ChallengeService<L, K, O>
where
    L: LifecycleAdapter,
    K: MacKeyProvider,
    O: Observer,
{
    /// Generates, authenticates, and durably stores a public challenge.
    ///
    /// The public challenge is returned only after `store_issued` reports
    /// definite success. Candidate rejection is retried within the fixed V1
    /// bound, but storage and other infrastructure operations are never retried
    /// automatically. A failure returns only a stable [`ServiceError`].
    pub fn issue_challenge(
        &mut self,
        request: IssueRequest<'_>,
    ) -> Result<PublicChallenge, ServiceError> {
        let mut random = OsRandom;
        self.issue_with(request, &mut random, runtime::unix_time_now)
    }

    fn issue_with(
        &mut self,
        request: IssueRequest<'_>,
        random: &mut impl crate::generation::RandomSource,
        clock: impl FnOnce() -> Result<i64, ServiceError>,
    ) -> Result<PublicChallenge, ServiceError> {
        self.issue_with_timing(request, random, clock, Instant::now, |started, finished| {
            finished.saturating_duration_since(started)
        })
    }

    fn issue_with_timing<T: Copy>(
        &mut self,
        request: IssueRequest<'_>,
        random: &mut impl crate::generation::RandomSource,
        clock: impl FnOnce() -> Result<i64, ServiceError>,
        mut now: impl FnMut() -> T,
        duration_between: impl Fn(T, T) -> Duration,
    ) -> Result<PublicChallenge, ServiceError> {
        let operation_started = now();
        if let Err(error) = request.validate() {
            self.observe_issue_failure(
                duration_between(operation_started, now()),
                safe_generator_version(request.version()),
                ServiceStage::Request,
                error,
                0,
            );
            return Err(error);
        }
        if let Err(error) = version::dispatch_issue_version(request.version()) {
            self.observe_issue_failure(
                duration_between(operation_started, now()),
                safe_generator_version(request.version()),
                ServiceStage::VersionDispatch,
                error,
                0,
            );
            return Err(error);
        }

        let candidate_started = now();
        let (candidate, candidate_attempts) =
            match retry_candidates_with_attempts(|| generate_issue_candidate(random)) {
                Ok(success) => success,
                Err((candidate_error, attempts)) => {
                    let error = map_candidate_error(candidate_error);
                    self.observe_issue_failure(
                        duration_between(operation_started, now()),
                        safe_generator_version(request.version()),
                        ServiceStage::Candidate,
                        error,
                        usize::from(attempts),
                    );
                    return Err(error);
                }
            };
        let candidate_duration = duration_between(candidate_started, now());

        self.complete_issue(
            request,
            random,
            clock,
            (now, duration_between, operation_started),
            (candidate, candidate_attempts, candidate_duration),
        )
    }

    #[cfg(test)]
    fn issue_with_candidate_factory<R: crate::generation::RandomSource>(
        &mut self,
        request: IssueRequest<'_>,
        random: &mut R,
        clock: impl FnOnce() -> Result<i64, ServiceError>,
        mut candidate_factory: impl FnMut(&mut R) -> Result<PreparedCandidate, CandidateError>,
    ) -> Result<PublicChallenge, ServiceError> {
        let operation_started = Instant::now();
        if let Err(error) = request.validate() {
            self.observe_issue_failure(
                operation_started.elapsed(),
                safe_generator_version(request.version()),
                ServiceStage::Request,
                error,
                0,
            );
            return Err(error);
        }
        if let Err(error) = version::dispatch_issue_version(request.version()) {
            self.observe_issue_failure(
                operation_started.elapsed(),
                safe_generator_version(request.version()),
                ServiceStage::VersionDispatch,
                error,
                0,
            );
            return Err(error);
        }

        let candidate_started = Instant::now();
        let (candidate, candidate_attempts) =
            match retry_candidates_with_attempts(|| candidate_factory(random)) {
                Ok(success) => success,
                Err((candidate_error, attempts)) => {
                    let error = map_candidate_error(candidate_error);
                    self.observe_issue_failure(
                        operation_started.elapsed(),
                        safe_generator_version(request.version()),
                        ServiceStage::Candidate,
                        error,
                        usize::from(attempts),
                    );
                    return Err(error);
                }
            };
        let candidate_duration = candidate_started.elapsed();

        self.complete_issue(
            request,
            random,
            clock,
            (
                Instant::now,
                |started, finished| finished.saturating_duration_since(started),
                operation_started,
            ),
            (candidate, candidate_attempts, candidate_duration),
        )
    }

    fn complete_issue<
        T: Copy,
        R: crate::generation::RandomSource,
        N: FnMut() -> T,
        D: Fn(T, T) -> Duration,
    >(
        &mut self,
        request: IssueRequest<'_>,
        random: &mut R,
        clock: impl FnOnce() -> Result<i64, ServiceError>,
        timing: (N, D, T),
        candidate_result: (PreparedCandidate, u8, Duration),
    ) -> Result<PublicChallenge, ServiceError> {
        let (mut now, duration_between, operation_started) = timing;
        let (candidate, candidate_attempts, candidate_duration) = candidate_result;
        let issued_at = match clock() {
            Ok(issued_at) => issued_at,
            Err(error) => {
                self.observe_issue_failure(
                    duration_between(operation_started, now()),
                    safe_generator_version(request.version()),
                    ServiceStage::Clock,
                    error,
                    usize::from(candidate_attempts),
                );
                return Err(error);
            }
        };
        let expires_at =
            match issued_at.checked_add(i64::from(agentgate_contracts::CHALLENGE_TTL_SECONDS)) {
                Some(expires_at) => expires_at,
                None => {
                    let error = ServiceError::InternalError;
                    self.observe_issue_failure(
                        duration_between(operation_started, now()),
                        safe_generator_version(request.version()),
                        ServiceStage::Clock,
                        error,
                        usize::from(candidate_attempts),
                    );
                    return Err(error);
                }
            };
        let challenge_id = match runtime::random_token(random) {
            Ok(challenge_id) => challenge_id,
            Err(_) => {
                let error = ServiceError::GenerationFailed;
                self.observe_issue_failure(
                    duration_between(operation_started, now()),
                    safe_generator_version(request.version()),
                    ServiceStage::Candidate,
                    error,
                    usize::from(candidate_attempts),
                );
                return Err(error);
            }
        };
        let nonce = match runtime::random_token(random) {
            Ok(nonce) => nonce,
            Err(_) => {
                let error = ServiceError::GenerationFailed;
                self.observe_issue_failure(
                    duration_between(operation_started, now()),
                    safe_generator_version(request.version()),
                    ServiceStage::Candidate,
                    error,
                    usize::from(candidate_attempts),
                );
                return Err(error);
            }
        };

        let (mac_key_id, mac_key) = match self.keys.active_key() {
            Ok(active) => active.into_parts(),
            Err(key_error) => {
                let error = map_active_key_error(key_error);
                self.observe_issue_failure(
                    duration_between(operation_started, now()),
                    safe_generator_version(request.version()),
                    ServiceStage::KeyProvider,
                    error,
                    usize::from(candidate_attempts),
                );
                return Err(error);
            }
        };
        let answer_encoding = AnswerEncoding::Base64Url;
        let context = MacContext {
            challenge_id: challenge_id.clone(),
            generator_version: request.version().to_owned(),
            nonce: nonce.clone(),
            issued_at,
            expires_at,
            mac_key_id: mac_key_id.clone(),
            answer_encoding,
        };
        let answer_mac = match compute_answer_mac(mac_key.expose(), &context, &candidate.answer) {
            Ok(answer_mac) => answer_mac,
            Err(_) => {
                let error = ServiceError::InternalError;
                self.observe_issue_failure(
                    duration_between(operation_started, now()),
                    safe_generator_version(request.version()),
                    ServiceStage::CoreVerification,
                    error,
                    usize::from(candidate_attempts),
                );
                return Err(error);
            }
        };
        let answer_mac = hex::encode(answer_mac);
        let generator_version = request.version().to_owned();
        let public = PublicChallenge {
            challenge_id: challenge_id.clone(),
            generator_version: generator_version.clone(),
            nonce: nonce.clone(),
            issued_at,
            expires_at,
            question: candidate.question.clone(),
            answer_encoding,
        };
        let private = PrivateChallengeMaterial {
            challenge_id,
            generator_version,
            nonce,
            issued_at,
            expires_at,
            mac_key_id,
            answer_mac,
            answer_encoding,
        };

        if self
            .lifecycle
            .store_issued(private, request.binding(), request.attempt_limit())
            .is_err()
        {
            let error = ServiceError::InternalError;
            self.observe_issue_failure(
                duration_between(operation_started, now()),
                safe_generator_version(&public.generator_version),
                ServiceStage::LifecycleStore,
                error,
                usize::from(candidate_attempts),
            );
            return Err(error);
        }

        let metadata = &candidate.render_metadata;
        observer::observe_safely(
            &mut self.observer,
            &ServiceEvent::ChallengeIssued(ChallengeIssuedEvent {
                challenge_id: public.challenge_id.clone(),
                generator_version: public.generator_version.clone(),
                secret_length_bucket: secret_length_bucket(candidate.secret_length),
                fragment_count: candidate.fragment_count,
                question_byte_length: metadata.byte_length(),
                render_languages: metadata.languages().to_vec(),
                has_distractor: metadata.has_distractor(),
                candidate_attempts: usize::from(candidate_attempts),
                duration: candidate_duration,
            }),
        );

        Ok(public)
    }

    fn observe_issue_failure(
        &mut self,
        duration: Duration,
        generator_version: Option<String>,
        stage: ServiceStage,
        error: ServiceError,
        attempts: usize,
    ) {
        observer::observe_safely(
            &mut self.observer,
            &ServiceEvent::IssueFailed(ServiceFailureEvent {
                challenge_id: None,
                generator_version,
                stage,
                error,
                attempts,
                duration,
            }),
        );
    }

    /// Verifies a submission through an atomic, fail-closed lifecycle attempt.
    ///
    /// Dispatch uses the stored generator version and exact stored key ID; no
    /// active-key or version fallback occurs. Once `begin_attempt` succeeds, a
    /// later system failure still consumes the reserved attempt. `Accepted` is
    /// returned only after the lifecycle adapter durably commits acceptance.
    pub fn verify_submission(
        &mut self,
        request: VerifyRequest<'_>,
    ) -> Result<VerificationOutcome, ServiceError> {
        self.verify_with(request, runtime::unix_time_now)
    }

    fn verify_with(
        &mut self,
        request: VerifyRequest<'_>,
        clock: impl FnOnce() -> Result<i64, ServiceError>,
    ) -> Result<VerificationOutcome, ServiceError> {
        if let Err(error) = request.validate() {
            self.observe_service_failure(ServiceStage::Request, error, Duration::ZERO);
            return Err(error);
        }
        let server_time = match clock() {
            Ok(server_time) => server_time,
            Err(error) => {
                self.observe_service_failure(ServiceStage::Clock, error, Duration::ZERO);
                return Err(error);
            }
        };
        let pending = match self.lifecycle.begin_attempt(
            SubmissionIdentity::from_submission(request.submission()),
            request.binding(),
            server_time,
        ) {
            Ok(pending) => pending,
            Err(BeginAttemptError::Rejected(reason)) => {
                observer::observe_safely(
                    &mut self.observer,
                    &ServiceEvent::VerificationCompleted(VerificationEvent {
                        challenge_id: safe_challenge_id(&request.submission().challenge_id),
                        generator_version: None,
                        disposition: VerificationDisposition::LifecycleRejected(reason),
                        elapsed_since_issue: None,
                        duration: Duration::ZERO,
                    }),
                );
                return Ok(VerificationOutcome::Rejected(reason));
            }
            Err(BeginAttemptError::Adapter(_)) => {
                let error = ServiceError::InternalError;
                self.observe_service_failure(ServiceStage::LifecycleBegin, error, Duration::ZERO);
                return Err(error);
            }
        };
        let (token, material) = pending.into_parts();
        let challenge_id = safe_challenge_id(&material.challenge_id);
        let elapsed_since_issue = elapsed_since_issue(server_time, material.issued_at);

        if stored_material_is_invalid(&material) {
            return self.finish_failed_verification(
                token,
                ServiceStage::CoreVerification,
                ServiceError::InvalidChallengeMaterial,
                Duration::ZERO,
            );
        }
        if let Err(error) = version::dispatch_verify_version(&material.generator_version) {
            return self.finish_failed_verification(
                token,
                ServiceStage::VersionDispatch,
                error,
                Duration::ZERO,
            );
        }
        let generator_version = Some(material.generator_version.clone());

        let key = match self.keys.key_by_id(&material.mac_key_id) {
            Ok(key) => key,
            Err(_) => {
                return self.finish_failed_verification(
                    token,
                    ServiceStage::KeyProvider,
                    ServiceError::InternalError,
                    Duration::ZERO,
                );
            }
        };

        let core_started = Instant::now();
        let core_result = verify_answer(key.expose(), &material, request.submission());
        let core_duration = core_started.elapsed();
        match core_result {
            Ok(()) => self.finish_completed_verification(
                token,
                AttemptOutcome::Accepted,
                Ok(VerificationOutcome::Accepted),
                VerificationEvent {
                    challenge_id,
                    generator_version,
                    disposition: VerificationDisposition::Accepted,
                    elapsed_since_issue,
                    duration: core_duration,
                },
            ),
            Err(CoreError::InvalidAnswerEncoding) => self.finish_completed_verification(
                token,
                AttemptOutcome::Rejected,
                Err(ServiceError::InvalidAnswerEncoding),
                VerificationEvent {
                    challenge_id,
                    generator_version,
                    disposition: VerificationDisposition::InvalidAnswerEncoding,
                    elapsed_since_issue,
                    duration: core_duration,
                },
            ),
            Err(CoreError::AnswerMismatch) => self.finish_completed_verification(
                token,
                AttemptOutcome::Rejected,
                Err(ServiceError::AnswerMismatch),
                VerificationEvent {
                    challenge_id,
                    generator_version,
                    disposition: VerificationDisposition::AnswerMismatch,
                    elapsed_since_issue,
                    duration: core_duration,
                },
            ),
            Err(CoreError::InvalidChallengeMaterial) => self.finish_failed_verification(
                token,
                ServiceStage::CoreVerification,
                ServiceError::InvalidChallengeMaterial,
                core_duration,
            ),
        }
    }

    fn finish_completed_verification(
        &mut self,
        token: L::AttemptToken,
        outcome: AttemptOutcome,
        result: Result<VerificationOutcome, ServiceError>,
        event: VerificationEvent,
    ) -> Result<VerificationOutcome, ServiceError> {
        if self.lifecycle.finish_attempt(token, outcome).is_err() {
            let error = ServiceError::InternalError;
            self.observe_service_failure(ServiceStage::LifecycleFinish, error, event.duration);
            return Err(error);
        }
        observer::observe_safely(
            &mut self.observer,
            &ServiceEvent::VerificationCompleted(event),
        );
        result
    }

    fn finish_failed_verification(
        &mut self,
        token: L::AttemptToken,
        stage: ServiceStage,
        error: ServiceError,
        duration: Duration,
    ) -> Result<VerificationOutcome, ServiceError> {
        if self
            .lifecycle
            .finish_attempt(token, AttemptOutcome::SystemFailure)
            .is_err()
        {
            let finish_error = ServiceError::InternalError;
            self.observe_service_failure(ServiceStage::LifecycleFinish, finish_error, duration);
            return Err(finish_error);
        }
        self.observe_service_failure(stage, error, duration);
        Err(error)
    }

    fn observe_service_failure(
        &mut self,
        stage: ServiceStage,
        error: ServiceError,
        duration: Duration,
    ) {
        observer::observe_safely(
            &mut self.observer,
            &ServiceEvent::ServiceFailed(ServiceFailureEvent {
                challenge_id: None,
                generator_version: None,
                stage,
                error,
                attempts: 0,
                duration,
            }),
        );
    }
}

fn safe_challenge_id(value: &str) -> String {
    if !is_canonical_random_token_with(value, |value, decoded| {
        URL_SAFE_NO_PAD.decode_slice(value, decoded) == Ok(decoded.len())
    }) {
        return String::new();
    }

    value.to_owned()
}

fn is_canonical_random_token_with(
    value: &str,
    decode: impl FnOnce(&str, &mut [u8; 16]) -> bool,
) -> bool {
    if value.len() != 22 {
        return false;
    }

    let mut decoded = [0_u8; 16];
    if !decode(value, &mut decoded) {
        return false;
    }

    let mut canonical = [0_u8; 22];
    if URL_SAFE_NO_PAD.encode_slice(decoded, &mut canonical) != Ok(canonical.len())
        || canonical != value.as_bytes()
    {
        return false;
    }

    true
}

fn safe_generator_version(value: &str) -> Option<String> {
    version::dispatch_issue_version(value)
        .is_ok()
        .then(|| value.to_owned())
}

fn elapsed_since_issue(server_time: i64, issued_at: i64) -> Option<Duration> {
    server_time
        .checked_sub(issued_at)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map(Duration::from_secs)
}

fn secret_length_bucket(secret_length: usize) -> SecretLengthBucket {
    match secret_length {
        8..=10 => SecretLengthBucket::EightToTen,
        11..=13 => SecretLengthBucket::ElevenToThirteen,
        14..=16 => SecretLengthBucket::FourteenToSixteen,
        _ => unreachable!("validated candidate secret length"),
    }
}

fn stored_material_is_invalid(material: &PrivateChallengeMaterial) -> bool {
    validate_context_fields(
        &material.challenge_id,
        &material.generator_version,
        &material.nonce,
        &material.mac_key_id,
    )
    .is_err()
        || material.challenge_id.is_empty()
        || material.nonce.is_empty()
        || material.mac_key_id.is_empty()
        || !is_canonical_random_token_with(&material.challenge_id, |value, decoded| {
            URL_SAFE_NO_PAD.decode_slice(value, decoded) == Ok(decoded.len())
        })
        || !is_canonical_random_token_with(&material.nonce, |value, decoded| {
            URL_SAFE_NO_PAD.decode_slice(value, decoded) == Ok(decoded.len())
        })
        || material.answer_mac.len() != 64
        || !material
            .answer_mac
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || material.expires_at < material.issued_at
}

fn map_candidate_error(error: CandidateError) -> ServiceError {
    match error {
        CandidateError::Exhausted
        | CandidateError::RandomnessUnavailable
        | CandidateError::Rejected => ServiceError::GenerationFailed,
        CandidateError::Internal => ServiceError::InternalError,
    }
}

fn map_active_key_error(error: KeyProviderError) -> ServiceError {
    match error {
        KeyProviderError::InvalidMaterial => ServiceError::InvalidConfiguration,
        KeyProviderError::Unavailable | KeyProviderError::NotFound => ServiceError::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use crate::{
        Submission,
        generation::{DeterministicRandom, GenerationError, MAX_QUESTION_BYTES, RandomSource},
        verify_answer,
    };

    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Random(usize),
        Clock,
        ActiveKey,
        Store,
    }

    struct TrackingRandom {
        calls: Rc<RefCell<Vec<Call>>>,
    }

    impl RandomSource for TrackingRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            self.calls
                .borrow_mut()
                .push(Call::Random(destination.len()));
            destination.fill(0);
            Ok(())
        }
    }

    struct TokenFailingRandom {
        calls: Rc<RefCell<Vec<Call>>>,
    }

    impl RandomSource for TokenFailingRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            self.calls
                .borrow_mut()
                .push(Call::Random(destination.len()));
            if self.calls.borrow().contains(&Call::Clock) {
                return Err(GenerationError::RandomnessUnavailable);
            }
            destination.fill(0);
            Ok(())
        }
    }

    struct TrackingLifecycle(Rc<RefCell<Vec<Call>>>);

    impl LifecycleAdapter for TrackingLifecycle {
        type AttemptToken = ();

        fn store_issued(
            &mut self,
            _material: PrivateChallengeMaterial,
            _binding: &[u8],
            _attempt_limit: AttemptLimit,
        ) -> Result<(), LifecycleAdapterError> {
            self.0.borrow_mut().push(Call::Store);
            Ok(())
        }

        fn begin_attempt(
            &mut self,
            _identity: SubmissionIdentity<'_>,
            _binding: &[u8],
            _server_time: i64,
        ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
            unreachable!("issuance does not begin attempts")
        }

        fn finish_attempt(
            &mut self,
            _token: Self::AttemptToken,
            _outcome: AttemptOutcome,
        ) -> Result<(), LifecycleAdapterError> {
            unreachable!("issuance does not finish attempts")
        }
    }

    struct CapturingLifecycle(Rc<RefCell<Option<PrivateChallengeMaterial>>>);

    impl LifecycleAdapter for CapturingLifecycle {
        type AttemptToken = ();

        fn store_issued(
            &mut self,
            material: PrivateChallengeMaterial,
            _binding: &[u8],
            _attempt_limit: AttemptLimit,
        ) -> Result<(), LifecycleAdapterError> {
            *self.0.borrow_mut() = Some(material);
            Ok(())
        }

        fn begin_attempt(
            &mut self,
            _identity: SubmissionIdentity<'_>,
            _binding: &[u8],
            _server_time: i64,
        ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
            unreachable!("issuance does not begin attempts")
        }

        fn finish_attempt(
            &mut self,
            _token: Self::AttemptToken,
            _outcome: AttemptOutcome,
        ) -> Result<(), LifecycleAdapterError> {
            unreachable!("issuance does not finish attempts")
        }
    }

    struct TrackingKeys(Rc<RefCell<Vec<Call>>>);

    impl MacKeyProvider for TrackingKeys {
        fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
            self.0.borrow_mut().push(Call::ActiveKey);
            ActiveMacKey::new("active", MacKey::new(vec![0x42; 32])?)
        }

        fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
            unreachable!("issuance only reads the active key")
        }
    }

    struct CollectObserver(Rc<RefCell<Vec<ServiceEvent>>>);

    impl Observer for CollectObserver {
        fn observe(&mut self, event: &ServiceEvent) {
            self.0.borrow_mut().push(event.clone());
        }
    }

    struct TimingLifecycle {
        now: Rc<Cell<Duration>>,
        store_error: Option<LifecycleAdapterError>,
    }

    struct TimingRandom {
        now: Rc<Cell<Duration>>,
    }

    impl RandomSource for TimingRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            self.now.set(self.now.get() + Duration::from_millis(1));
            destination.fill(0);
            Ok(())
        }
    }

    impl LifecycleAdapter for TimingLifecycle {
        type AttemptToken = ();

        fn store_issued(
            &mut self,
            _material: PrivateChallengeMaterial,
            _binding: &[u8],
            _attempt_limit: AttemptLimit,
        ) -> Result<(), LifecycleAdapterError> {
            self.now.set(self.now.get() + Duration::from_secs(200));
            self.store_error.map_or(Ok(()), Err)
        }

        fn begin_attempt(
            &mut self,
            _identity: SubmissionIdentity<'_>,
            _binding: &[u8],
            _server_time: i64,
        ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
            unreachable!("issuance does not begin attempts")
        }

        fn finish_attempt(
            &mut self,
            _token: Self::AttemptToken,
            _outcome: AttemptOutcome,
        ) -> Result<(), LifecycleAdapterError> {
            unreachable!("issuance does not finish attempts")
        }
    }

    #[test]
    fn issued_duration_freezes_before_clock_key_and_store_work() {
        let now = Rc::new(Cell::new(Duration::from_millis(10)));
        let expected_candidate_duration = Rc::new(Cell::new(Duration::ZERO));
        let events = Rc::new(RefCell::new(Vec::new()));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::with_observer(
            TimingLifecycle {
                now: Rc::clone(&now),
                store_error: None,
            },
            TrackingKeys(calls),
            CollectObserver(Rc::clone(&events)),
        );
        let mut random = TimingRandom {
            now: Rc::clone(&now),
        };

        service
            .issue_with_timing(
                IssueRequest::v1(b"binding").unwrap(),
                &mut random,
                || {
                    expected_candidate_duration.set(now.get() - Duration::from_millis(10));
                    now.set(now.get() + Duration::from_secs(100));
                    Ok(1_000)
                },
                || now.get(),
                |started, finished| finished.saturating_sub(started),
            )
            .unwrap();

        assert!(expected_candidate_duration.get() > Duration::ZERO);
        let ServiceEvent::ChallengeIssued(event) = &events.borrow()[0] else {
            panic!("unexpected event")
        };
        assert_eq!(event.duration, expected_candidate_duration.get());
        assert!(now.get() >= event.duration + Duration::from_secs(300));
    }

    #[test]
    fn issue_failure_duration_keeps_full_operation_timing() {
        let now = Rc::new(Cell::new(Duration::from_millis(10)));
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::with_observer(
            TimingLifecycle {
                now: Rc::clone(&now),
                store_error: Some(LifecycleAdapterError::Unavailable),
            },
            TrackingKeys(Rc::new(RefCell::new(Vec::new()))),
            CollectObserver(Rc::clone(&events)),
        );
        let mut random = TimingRandom {
            now: Rc::clone(&now),
        };

        assert_eq!(
            service.issue_with_timing(
                IssueRequest::v1(b"binding").unwrap(),
                &mut random,
                || {
                    now.set(now.get() + Duration::from_secs(100));
                    Ok(1_000)
                },
                || now.get(),
                |started, finished| finished.saturating_sub(started),
            ),
            Err(ServiceError::InternalError)
        );

        let ServiceEvent::IssueFailed(event) = &events.borrow()[0] else {
            panic!("unexpected event")
        };
        assert_eq!(event.stage, ServiceStage::LifecycleStore);
        assert_eq!(event.duration, now.get() - Duration::from_millis(10));
    }

    #[test]
    fn candidate_precedes_clock_and_tokens_key_and_single_store_follow_in_order() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::new(
            TrackingLifecycle(Rc::clone(&calls)),
            TrackingKeys(Rc::clone(&calls)),
        );
        let mut random = TrackingRandom {
            calls: Rc::clone(&calls),
        };

        service
            .issue_with(IssueRequest::v1(b"binding").unwrap(), &mut random, || {
                calls.borrow_mut().push(Call::Clock);
                Ok(1_000)
            })
            .unwrap();

        let calls = calls.borrow();
        let clock_index = calls.iter().position(|call| *call == Call::Clock).unwrap();
        assert!(
            calls[..clock_index]
                .iter()
                .all(|call| matches!(call, Call::Random(_)))
        );
        assert_eq!(
            &calls[clock_index..],
            &[
                Call::Clock,
                Call::Random(16),
                Call::Random(16),
                Call::ActiveKey,
                Call::Store,
            ]
        );
    }

    #[test]
    fn version_dispatch_precedes_random_clock_key_and_store_dependencies() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::new(
            TrackingLifecycle(Rc::clone(&calls)),
            TrackingKeys(Rc::clone(&calls)),
        );
        let mut random = TrackingRandom {
            calls: Rc::clone(&calls),
        };

        assert_eq!(
            service.issue_with(
                IssueRequest::new("1.00", b"binding", AttemptLimit::One).unwrap(),
                &mut random,
                || {
                    calls.borrow_mut().push(Call::Clock);
                    Ok(1_000)
                },
            ),
            Err(ServiceError::UnsupportedGeneratorVersion)
        );
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn ttl_overflow_stops_before_token_key_and_store_dependencies() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::new(
            TrackingLifecycle(Rc::clone(&calls)),
            TrackingKeys(Rc::clone(&calls)),
        );
        let mut random = TrackingRandom {
            calls: Rc::clone(&calls),
        };

        assert_eq!(
            service.issue_with(IssueRequest::v1(b"binding").unwrap(), &mut random, || {
                calls.borrow_mut().push(Call::Clock);
                Ok(i64::MAX)
            },),
            Err(ServiceError::InternalError)
        );
        let calls = calls.borrow();
        let clock_index = calls.iter().position(|call| *call == Call::Clock).unwrap();
        assert!(
            calls[..clock_index]
                .iter()
                .all(|call| matches!(call, Call::Random(_)))
        );
        assert_eq!(&calls[clock_index..], &[Call::Clock]);
    }

    #[test]
    fn token_randomness_failure_is_generation_failure_before_key_and_store() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::new(
            TrackingLifecycle(Rc::clone(&calls)),
            TrackingKeys(Rc::clone(&calls)),
        );
        let mut random = TokenFailingRandom {
            calls: Rc::clone(&calls),
        };

        assert_eq!(
            service.issue_with(IssueRequest::v1(b"binding").unwrap(), &mut random, || {
                calls.borrow_mut().push(Call::Clock);
                Ok(1_000)
            },),
            Err(ServiceError::GenerationFailed)
        );
        let calls = calls.borrow();
        let clock_index = calls.iter().position(|call| *call == Call::Clock).unwrap();
        assert_eq!(&calls[clock_index..], &[Call::Clock, Call::Random(16)]);
    }

    #[test]
    fn token_and_clock_failures_emit_exact_stages_and_candidate_attempts() {
        for clock_fails in [false, true] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let events = Rc::new(RefCell::new(Vec::new()));
            let mut service = ChallengeService::with_observer(
                TrackingLifecycle(Rc::clone(&calls)),
                TrackingKeys(Rc::clone(&calls)),
                CollectObserver(Rc::clone(&events)),
            );
            let mut random = TokenFailingRandom {
                calls: Rc::clone(&calls),
            };

            let result =
                service.issue_with(IssueRequest::v1(b"binding").unwrap(), &mut random, || {
                    calls.borrow_mut().push(Call::Clock);
                    if clock_fails {
                        Err(ServiceError::InternalError)
                    } else {
                        Ok(1_000)
                    }
                });
            assert_eq!(
                result,
                Err(if clock_fails {
                    ServiceError::InternalError
                } else {
                    ServiceError::GenerationFailed
                })
            );
            let events = events.borrow();
            assert_eq!(events.len(), 1);
            assert!(matches!(
                &events[0],
                ServiceEvent::IssueFailed(event)
                    if event.stage == (if clock_fails {
                        ServiceStage::Clock
                    } else {
                        ServiceStage::Candidate
                    }) && event.attempts == 1
            ));
        }
    }

    #[test]
    fn candidate_errors_map_to_stable_service_categories() {
        for error in [
            CandidateError::Exhausted,
            CandidateError::RandomnessUnavailable,
            CandidateError::Rejected,
        ] {
            assert_eq!(map_candidate_error(error), ServiceError::GenerationFailed);
        }
        assert_eq!(
            map_candidate_error(CandidateError::Internal),
            ServiceError::InternalError
        );
    }

    #[test]
    fn secret_length_buckets_cover_every_supported_boundary() {
        for (length, expected) in [
            (8, SecretLengthBucket::EightToTen),
            (10, SecretLengthBucket::EightToTen),
            (11, SecretLengthBucket::ElevenToThirteen),
            (13, SecretLengthBucket::ElevenToThirteen),
            (14, SecretLengthBucket::FourteenToSixteen),
            (16, SecretLengthBucket::FourteenToSixteen),
        ] {
            assert_eq!(secret_length_bucket(length), expected);
        }
    }

    #[test]
    fn oversized_observer_token_is_rejected_in_constant_bounded_time() {
        let oversized = "A".repeat(1024 * 1024);
        assert!(!is_canonical_random_token_with(
            &oversized,
            |_value, _decoded| panic!("oversized IDs must be rejected before decoding")
        ));
        assert!(safe_challenge_id(&oversized).is_empty());
    }

    #[test]
    fn verification_clock_failure_stops_before_lifecycle_and_keys() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::new(
            TrackingLifecycle(Rc::clone(&calls)),
            TrackingKeys(Rc::clone(&calls)),
        );
        let submission = Submission {
            challenge_id: "challenge-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            answer: "YUI5MmtM".to_owned(),
        };

        assert_eq!(
            service.verify_with(
                VerifyRequest::new(&submission, b"binding").unwrap(),
                || Err(ServiceError::InternalError),
            ),
            Err(ServiceError::InternalError)
        );
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn persisted_mac_authenticates_the_generated_answer_and_context() {
        let material = Rc::new(RefCell::new(None));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::new(
            CapturingLifecycle(Rc::clone(&material)),
            TrackingKeys(calls),
        );
        let mut issuance_random = TrackingRandom {
            calls: Rc::new(RefCell::new(Vec::new())),
        };

        service
            .issue_with(
                IssueRequest::v1(b"binding").unwrap(),
                &mut issuance_random,
                || Ok(1_000),
            )
            .unwrap();

        let mut replay_random = TrackingRandom {
            calls: Rc::new(RefCell::new(Vec::new())),
        };
        let candidate = generate_candidate_with(&mut replay_random).unwrap();
        let material = material.borrow();
        let material = material.as_ref().unwrap();
        let submission = Submission {
            challenge_id: material.challenge_id.clone(),
            nonce: material.nonce.clone(),
            answer: candidate.answer().to_owned(),
        };

        assert_eq!(verify_answer(&[0x42; 32], material, &submission), Ok(()));
    }

    #[test]
    fn deterministic_issuance_preserves_all_v1_properties_across_seed_sweep() {
        let mut representative_outputs = Vec::new();
        let mut covered_secret_lengths = std::collections::BTreeSet::new();

        for seed in 0_u8..=127 {
            let seed = [seed; 32];
            let mut replay_random = DeterministicRandom::new(seed);
            let replay = generate_candidate_with(&mut replay_random).unwrap();
            let expected_challenge_id = runtime::random_token(&mut replay_random).unwrap();
            let expected_nonce = runtime::random_token(&mut replay_random).unwrap();

            let issue_once = || {
                let material = Rc::new(RefCell::new(None));
                let events = Rc::new(RefCell::new(Vec::new()));
                let mut service = ChallengeService::with_observer(
                    CapturingLifecycle(Rc::clone(&material)),
                    TrackingKeys(Rc::new(RefCell::new(Vec::new()))),
                    CollectObserver(Rc::clone(&events)),
                );
                let mut random = DeterministicRandom::new(seed);
                let public = service
                    .issue_with_timing(
                        IssueRequest::v1(b"binding").unwrap(),
                        &mut random,
                        || Ok(10_000),
                        || (),
                        |(), ()| Duration::ZERO,
                    )
                    .unwrap();
                let material = material.borrow_mut().take().unwrap();
                let event = events.borrow_mut().pop().unwrap();
                (public, material, event)
            };

            let first = issue_once();
            let second = issue_once();
            assert_eq!(first, second, "seed {seed:?}");
            let (public, material, event) = first;

            assert_eq!(public.expires_at - public.issued_at, 15);
            assert_eq!(public.challenge_id, expected_challenge_id);
            assert_eq!(public.nonce, expected_nonce);
            for token in [&public.challenge_id, &public.nonce] {
                assert_eq!(URL_SAFE_NO_PAD.decode(token).unwrap().len(), 16);
            }
            assert_eq!(public.question, replay.question());
            assert_eq!(material.challenge_id, public.challenge_id);
            assert_eq!(material.nonce, public.nonce);
            assert_eq!(material.expires_at, public.expires_at);
            assert_eq!(
                verify_answer(
                    &[0x42; 32],
                    &material,
                    &Submission {
                        challenge_id: material.challenge_id.clone(),
                        nonce: material.nonce.clone(),
                        answer: replay.answer().to_owned(),
                    },
                ),
                Ok(())
            );
            assert!((8..=16).contains(&replay.secret_length()));
            covered_secret_lengths.insert(replay.secret_length());
            assert_eq!(
                replay.fragment_count(),
                usize::from(
                    agentgate_contracts::fragment_count_for_secret_length(
                        replay.secret_length() as u8,
                    )
                    .unwrap(),
                )
            );
            assert!((4..=8).contains(&replay.operation_count()));
            assert!((2..=3).contains(&replay.render_metadata().languages().len()));
            assert!(public.question.len() <= MAX_QUESTION_BYTES);
            let ServiceEvent::ChallengeIssued(metadata) = event else {
                panic!("expected issued event")
            };
            assert_eq!(metadata.question_byte_length, public.question.len());
            assert_eq!(metadata.fragment_count, replay.fragment_count());
            assert_eq!(
                metadata.secret_length_bucket,
                secret_length_bucket(replay.secret_length())
            );
            assert_eq!(
                metadata.render_languages,
                replay.render_metadata().languages()
            );
            assert_eq!(
                metadata.has_distractor,
                replay.render_metadata().has_distractor()
            );
            assert_eq!(metadata.candidate_attempts, 1);

            if matches!(seed[0], 0 | 23 | 64 | 127) {
                representative_outputs.push((
                    public.question,
                    public.challenge_id,
                    public.nonce,
                    material.answer_mac,
                    metadata,
                ));
            }
        }

        assert_eq!(covered_secret_lengths, (8_usize..=16).collect());
        assert!(
            representative_outputs
                .windows(2)
                .any(|pair| pair[0].0 != pair[1].0),
            "representative seeds must vary rendered questions"
        );
        assert!(
            representative_outputs
                .windows(2)
                .any(|pair| pair[0].1 != pair[1].1),
            "representative seeds must vary challenge IDs"
        );
        assert!(
            representative_outputs
                .windows(2)
                .any(|pair| pair[0].2 != pair[1].2),
            "representative seeds must vary nonces"
        );
    }

    #[test]
    fn service_retry_mapping_reports_success_on_exactly_eighth_attempt() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut service = ChallengeService::with_observer(
            TrackingLifecycle(Rc::new(RefCell::new(Vec::new()))),
            TrackingKeys(Rc::new(RefCell::new(Vec::new()))),
            CollectObserver(Rc::clone(&events)),
        );
        let mut random = DeterministicRandom::new([31; 32]);
        let mut calls = 0;

        service
            .issue_with_candidate_factory(
                IssueRequest::v1(b"binding").unwrap(),
                &mut random,
                || Ok(10_000),
                |random| {
                    calls += 1;
                    if calls < 8 {
                        Err(CandidateError::Rejected)
                    } else {
                        generate_issue_candidate(random)
                    }
                },
            )
            .unwrap();

        assert_eq!(calls, 8);
        assert!(matches!(
            &events.borrow()[0],
            ServiceEvent::ChallengeIssued(event) if event.candidate_attempts == 8
        ));
    }

    #[test]
    fn service_retry_mapping_exhausts_or_stops_terminal_failures_exactly() {
        for (candidate_error, expected_calls, expected_attempts) in [
            (CandidateError::Rejected, 8, 8),
            (CandidateError::RandomnessUnavailable, 1, 1),
        ] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let mut service = ChallengeService::with_observer(
                TrackingLifecycle(Rc::new(RefCell::new(Vec::new()))),
                TrackingKeys(Rc::new(RefCell::new(Vec::new()))),
                CollectObserver(Rc::clone(&events)),
            );
            let mut random = DeterministicRandom::new([41; 32]);
            let mut calls = 0;

            let result = service.issue_with_candidate_factory(
                IssueRequest::v1(b"binding").unwrap(),
                &mut random,
                || Ok(10_000),
                |_random| {
                    calls += 1;
                    Err(candidate_error)
                },
            );

            assert_eq!(result, Err(ServiceError::GenerationFailed));
            assert_eq!(calls, expected_calls);
            assert!(matches!(
                &events.borrow()[0],
                ServiceEvent::IssueFailed(event)
                    if event.stage == ServiceStage::Candidate
                        && event.attempts == expected_attempts
            ));
        }
    }

    struct FailingActiveKeys;

    impl MacKeyProvider for FailingActiveKeys {
        fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
            Err(KeyProviderError::Unavailable)
        }

        fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
            unreachable!("issuance only reads active keys")
        }
    }

    #[test]
    fn key_and_storage_failures_do_not_restart_candidate_generation() {
        let mut key_failure_candidate_calls = 0;
        let mut key_failing_service = ChallengeService::new(
            TrackingLifecycle(Rc::new(RefCell::new(Vec::new()))),
            FailingActiveKeys,
        );
        let mut random = DeterministicRandom::new([51; 32]);
        assert_eq!(
            key_failing_service.issue_with_candidate_factory(
                IssueRequest::v1(b"binding").unwrap(),
                &mut random,
                || Ok(10_000),
                |random| {
                    key_failure_candidate_calls += 1;
                    generate_issue_candidate(random)
                },
            ),
            Err(ServiceError::InternalError)
        );
        assert_eq!(key_failure_candidate_calls, 1);

        let mut store_failure_candidate_calls = 0;
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut store_failing_service = ChallengeService::new(
            TimingLifecycle {
                now: Rc::clone(&now),
                store_error: Some(LifecycleAdapterError::Unavailable),
            },
            TrackingKeys(Rc::new(RefCell::new(Vec::new()))),
        );
        let mut random = DeterministicRandom::new([52; 32]);
        assert_eq!(
            store_failing_service.issue_with_candidate_factory(
                IssueRequest::v1(b"binding").unwrap(),
                &mut random,
                || Ok(10_000),
                |random| {
                    store_failure_candidate_calls += 1;
                    generate_issue_candidate(random)
                },
            ),
            Err(ServiceError::InternalError)
        );
        assert_eq!(store_failure_candidate_calls, 1);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SharedAttemptState {
        Issued,
        Reserved,
        Used,
    }

    struct SharedLifecycleState {
        state: SharedAttemptState,
        material: PrivateChallengeMaterial,
        finishes: Vec<AttemptOutcome>,
    }

    struct SharedLifecycle(std::sync::Arc<std::sync::Mutex<SharedLifecycleState>>);

    impl LifecycleAdapter for SharedLifecycle {
        type AttemptToken = ();

        fn store_issued(
            &mut self,
            _material: PrivateChallengeMaterial,
            _binding: &[u8],
            _attempt_limit: AttemptLimit,
        ) -> Result<(), LifecycleAdapterError> {
            unreachable!("verification-only model")
        }

        fn begin_attempt(
            &mut self,
            _identity: SubmissionIdentity<'_>,
            _binding: &[u8],
            _server_time: i64,
        ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
            let mut shared = self.0.lock().unwrap();
            if shared.state != SharedAttemptState::Issued {
                return Err(LifecycleRejection::AlreadyConsumed.into());
            }
            shared.state = SharedAttemptState::Reserved;
            Ok(PendingAttempt::new((), shared.material.clone()))
        }

        fn finish_attempt(
            &mut self,
            _token: Self::AttemptToken,
            outcome: AttemptOutcome,
        ) -> Result<(), LifecycleAdapterError> {
            let mut shared = self.0.lock().unwrap();
            assert_eq!(shared.state, SharedAttemptState::Reserved);
            shared.state = SharedAttemptState::Used;
            shared.finishes.push(outcome);
            Ok(())
        }
    }

    struct SharedLookupKeys {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        available: bool,
    }

    struct BlockingLookupKeys {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl MacKeyProvider for SharedLookupKeys {
        fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
            unreachable!("verification only reads stored key IDs")
        }

        fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.available {
                MacKey::new(vec![0x42; 32])
            } else {
                Err(KeyProviderError::Unavailable)
            }
        }
    }

    impl MacKeyProvider for BlockingLookupKeys {
        fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
            unreachable!("verification only reads stored key IDs")
        }

        fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.entered
                .send(())
                .map_err(|_| KeyProviderError::Unavailable)?;
            self.release
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| KeyProviderError::Unavailable)?;
            MacKey::new(vec![0x42; 32])
        }
    }

    fn deterministic_material_and_submission() -> (PrivateChallengeMaterial, Submission) {
        let captured = Rc::new(RefCell::new(None));
        let mut issuer = ChallengeService::new(
            CapturingLifecycle(Rc::clone(&captured)),
            TrackingKeys(Rc::new(RefCell::new(Vec::new()))),
        );
        let mut issuance_random = DeterministicRandom::new([61; 32]);
        issuer
            .issue_with(
                IssueRequest::v1(b"binding").unwrap(),
                &mut issuance_random,
                || Ok(10_000),
            )
            .unwrap();
        let material = captured.borrow_mut().take().unwrap();
        let mut replay_random = DeterministicRandom::new([61; 32]);
        let candidate = generate_candidate_with(&mut replay_random).unwrap();
        let submission = Submission {
            challenge_id: material.challenge_id.clone(),
            nonce: material.nonce.clone(),
            answer: candidate.answer().to_owned(),
        };
        (material, submission)
    }

    #[test]
    fn second_service_is_rejected_during_the_first_services_reserved_window() {
        let (material, submission) = deterministic_material_and_submission();
        let state = std::sync::Arc::new(std::sync::Mutex::new(SharedLifecycleState {
            state: SharedAttemptState::Issued,
            material,
            finishes: Vec::new(),
        }));
        let first_key_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let second_key_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let mut first = ChallengeService::new(
            SharedLifecycle(std::sync::Arc::clone(&state)),
            BlockingLookupKeys {
                calls: std::sync::Arc::clone(&first_key_calls),
                entered: entered_sender,
                release: release_receiver,
            },
        );
        let mut second = ChallengeService::new(
            SharedLifecycle(std::sync::Arc::clone(&state)),
            SharedLookupKeys {
                calls: std::sync::Arc::clone(&second_key_calls),
                available: true,
            },
        );

        std::thread::scope(|scope| {
            let first_submission = &submission;
            let first_handle = scope.spawn(move || {
                first.verify_with(
                    VerifyRequest::new(first_submission, b"binding").unwrap(),
                    || Ok(10_001),
                )
            });

            entered_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("first service must reach key lookup");
            {
                let shared = state.lock().unwrap();
                assert_eq!(shared.state, SharedAttemptState::Reserved);
                assert!(shared.finishes.is_empty());
            }
            assert_eq!(
                second.verify_with(VerifyRequest::new(&submission, b"binding").unwrap(), || Ok(
                    10_001
                ),),
                Ok(VerificationOutcome::Rejected(
                    LifecycleRejection::AlreadyConsumed
                ))
            );
            assert_eq!(
                second_key_calls.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
            {
                let shared = state.lock().unwrap();
                assert_eq!(shared.state, SharedAttemptState::Reserved);
                assert!(shared.finishes.is_empty());
            }

            release_sender
                .send(())
                .expect("release first service key lookup");
            assert_eq!(
                first_handle.join().unwrap(),
                Ok(VerificationOutcome::Accepted)
            );
        });

        assert_eq!(first_key_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            second_key_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let shared = state.lock().unwrap();
        assert_eq!(shared.state, SharedAttemptState::Used);
        assert_eq!(shared.finishes, [AttemptOutcome::Accepted]);
    }

    #[test]
    fn reserved_attempt_stays_fail_closed_when_old_key_is_unavailable() {
        let (material, submission) = deterministic_material_and_submission();
        let state = std::sync::Arc::new(std::sync::Mutex::new(SharedLifecycleState {
            state: SharedAttemptState::Issued,
            material,
            finishes: Vec::new(),
        }));
        let key_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut first = ChallengeService::new(
            SharedLifecycle(std::sync::Arc::clone(&state)),
            SharedLookupKeys {
                calls: std::sync::Arc::clone(&key_calls),
                available: false,
            },
        );
        let mut second = ChallengeService::new(
            SharedLifecycle(std::sync::Arc::clone(&state)),
            SharedLookupKeys {
                calls: std::sync::Arc::clone(&key_calls),
                available: true,
            },
        );

        assert_eq!(
            first.verify_with(VerifyRequest::new(&submission, b"binding").unwrap(), || Ok(
                10_001
            ),),
            Err(ServiceError::InternalError)
        );
        assert_eq!(
            second.verify_with(VerifyRequest::new(&submission, b"binding").unwrap(), || Ok(
                10_001
            ),),
            Ok(VerificationOutcome::Rejected(
                LifecycleRejection::AlreadyConsumed
            ))
        );
        assert_eq!(key_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let shared = state.lock().unwrap();
        assert_eq!(shared.state, SharedAttemptState::Used);
        assert_eq!(shared.finishes, [AttemptOutcome::SystemFailure]);
    }
}
