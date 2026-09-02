mod error;
mod keys;
mod lifecycle;
mod model;
mod observer;
mod runtime;
mod version;

use agentgate_contracts::{AnswerEncoding, PrivateChallengeMaterial, PublicChallenge};

use crate::generation::{CandidateError, OsRandom, generate_candidate_with, retry_candidates};
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

#[expect(dead_code, reason = "consumed by Phase 4 orchestration")]
pub struct ChallengeService<L, K, O = NoopObserver> {
    lifecycle: L,
    keys: K,
    observer: O,
}

impl<L, K> ChallengeService<L, K, NoopObserver> {
    pub fn new(lifecycle: L, keys: K) -> Self {
        Self {
            lifecycle,
            keys,
            observer: NoopObserver,
        }
    }
}

impl<L, K, O> ChallengeService<L, K, O> {
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
        request.validate()?;
        version::dispatch_issue_version(request.version())?;

        let (candidate, _) =
            retry_candidates(|| generate_candidate_with(random)).map_err(map_candidate_error)?;

        let issued_at = clock()?;
        let expires_at = issued_at
            .checked_add(i64::from(agentgate_contracts::CHALLENGE_TTL_SECONDS))
            .ok_or(ServiceError::InternalError)?;
        let challenge_id =
            runtime::random_token(random).map_err(|_| ServiceError::GenerationFailed)?;
        let nonce = runtime::random_token(random).map_err(|_| ServiceError::GenerationFailed)?;

        let (mac_key_id, mac_key) = self
            .keys
            .active_key()
            .map_err(map_active_key_error)?
            .into_parts();
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
        let answer_mac = compute_answer_mac(mac_key.expose(), &context, candidate.answer())
            .map_err(|_| ServiceError::InternalError)?;
        let answer_mac = hex::encode(answer_mac);
        let generator_version = request.version().to_owned();
        let public = PublicChallenge {
            challenge_id: challenge_id.clone(),
            generator_version: generator_version.clone(),
            nonce: nonce.clone(),
            issued_at,
            expires_at,
            question: candidate.question().to_owned(),
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

        self.lifecycle
            .store_issued(private, request.binding(), request.attempt_limit())
            .map_err(|_| ServiceError::InternalError)?;

        Ok(public)
    }

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
        request.validate()?;
        let server_time = clock()?;
        let pending = match self.lifecycle.begin_attempt(
            SubmissionIdentity::from_submission(request.submission()),
            request.binding(),
            server_time,
        ) {
            Ok(pending) => pending,
            Err(BeginAttemptError::Rejected(reason)) => {
                return Ok(VerificationOutcome::Rejected(reason));
            }
            Err(BeginAttemptError::Adapter(_)) => return Err(ServiceError::InternalError),
        };
        let (token, material) = pending.into_parts();

        if let Err(error) = version::dispatch_verify_version(&material.generator_version) {
            return self.finish_verification(token, AttemptOutcome::SystemFailure, Err(error));
        }
        if !stored_material_has_valid_bounds(&material) {
            return self.finish_verification(
                token,
                AttemptOutcome::SystemFailure,
                Err(ServiceError::InvalidChallengeMaterial),
            );
        }

        let key = match self.keys.key_by_id(&material.mac_key_id) {
            Ok(key) => key,
            Err(_) => {
                return self.finish_verification(
                    token,
                    AttemptOutcome::SystemFailure,
                    Err(ServiceError::InternalError),
                );
            }
        };

        match verify_answer(key.expose(), &material, request.submission()) {
            Ok(()) => self.finish_verification(
                token,
                AttemptOutcome::Accepted,
                Ok(VerificationOutcome::Accepted),
            ),
            Err(CoreError::InvalidAnswerEncoding) => self.finish_verification(
                token,
                AttemptOutcome::Rejected,
                Err(ServiceError::InvalidAnswerEncoding),
            ),
            Err(CoreError::AnswerMismatch) => self.finish_verification(
                token,
                AttemptOutcome::Rejected,
                Err(ServiceError::AnswerMismatch),
            ),
            Err(CoreError::InvalidChallengeMaterial) => self.finish_verification(
                token,
                AttemptOutcome::SystemFailure,
                Err(ServiceError::InvalidChallengeMaterial),
            ),
        }
    }

    fn finish_verification(
        &mut self,
        token: L::AttemptToken,
        outcome: AttemptOutcome,
        result: Result<VerificationOutcome, ServiceError>,
    ) -> Result<VerificationOutcome, ServiceError> {
        self.lifecycle
            .finish_attempt(token, outcome)
            .map_err(|_| ServiceError::InternalError)?;
        result
    }
}

fn stored_material_has_valid_bounds(material: &PrivateChallengeMaterial) -> bool {
    const MAX_CHALLENGE_ID_BYTES: usize = 128;
    const MAX_NONCE_BYTES: usize = 256;

    !material.challenge_id.is_empty()
        && material.challenge_id.len() <= MAX_CHALLENGE_ID_BYTES
        && !material.nonce.is_empty()
        && material.nonce.len() <= MAX_NONCE_BYTES
        && !material.mac_key_id.is_empty()
        && material.mac_key_id.len() <= MAX_MAC_KEY_ID_BYTES
        && material.expires_at >= material.issued_at
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
    use std::{cell::RefCell, rc::Rc};

    use crate::{
        Submission,
        generation::{GenerationError, RandomSource},
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
}
