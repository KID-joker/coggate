use std::{cell::RefCell, rc::Rc};

use agentgate_core::{
    ActiveMacKey, AttemptLimit, BeginAttemptError, ChallengeService, IssueRequest,
    KeyProviderError, LifecycleAdapter, LifecycleAdapterError, MacKey, MacKeyProvider, Observer,
    PendingAttempt, PrivateChallengeMaterial, SecretLengthBucket, ServiceEvent, ServiceStage,
    SubmissionIdentity,
};
use agentgate_core::{
    contracts::{AnswerEncoding, CHALLENGE_TTL_SECONDS, GENERATOR_VERSION_V1},
    generation::MAX_QUESTION_BYTES,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[derive(Debug, Default)]
struct LifecycleRecords {
    issued: Vec<(PrivateChallengeMaterial, Vec<u8>, AttemptLimit)>,
    store_error: Option<LifecycleAdapterError>,
}

struct RecordingLifecycle(Rc<RefCell<LifecycleRecords>>);

impl LifecycleAdapter for RecordingLifecycle {
    type AttemptToken = ();

    fn store_issued(
        &mut self,
        material: PrivateChallengeMaterial,
        binding: &[u8],
        attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError> {
        self.0
            .borrow_mut()
            .issued
            .push((material, binding.to_vec(), attempt_limit));
        self.0.borrow().store_error.map_or(Ok(()), Err)
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
        _outcome: agentgate_core::AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        unreachable!("issuance does not finish attempts")
    }
}

struct RecordingObserver {
    events: Rc<RefCell<Vec<ServiceEvent>>>,
    records: Rc<RefCell<LifecycleRecords>>,
    expect_stored: bool,
    panic: bool,
}

impl Observer for RecordingObserver {
    fn observe(&mut self, event: &ServiceEvent) {
        assert_eq!(
            self.records.borrow().issued.len(),
            usize::from(self.expect_stored),
            "event emitted at the wrong durable boundary"
        );
        self.events.borrow_mut().push(event.clone());
        assert!(!self.panic, "observer sentinel panic");
    }
}

struct FixedMacKeyProvider;

impl MacKeyProvider for FixedMacKeyProvider {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        ActiveMacKey::new("active-v1", MacKey::new(vec![0x42; 32]).unwrap())
    }

    fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
        unreachable!("issuance only reads the active key")
    }
}

#[derive(Clone, Copy)]
enum KeyBehavior {
    Available,
    Unavailable,
    NotFound,
    InvalidMaterial,
}

struct CountingMacKeyProvider {
    calls: Rc<RefCell<usize>>,
    behavior: KeyBehavior,
}

impl MacKeyProvider for CountingMacKeyProvider {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        *self.calls.borrow_mut() += 1;
        match self.behavior {
            KeyBehavior::Available => {
                ActiveMacKey::new("key-id-sentinel", MacKey::new(vec![0xa5; 32]).unwrap())
            }
            KeyBehavior::Unavailable => Err(KeyProviderError::Unavailable),
            KeyBehavior::NotFound => Err(KeyProviderError::NotFound),
            KeyBehavior::InvalidMaterial => Err(KeyProviderError::InvalidMaterial),
        }
    }

    fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
        unreachable!("issuance only reads the active key")
    }
}

fn recording_service(
    records: Rc<RefCell<LifecycleRecords>>,
    calls: Rc<RefCell<usize>>,
    behavior: KeyBehavior,
) -> ChallengeService<RecordingLifecycle, CountingMacKeyProvider> {
    ChallengeService::new(
        RecordingLifecycle(records),
        CountingMacKeyProvider { calls, behavior },
    )
}

#[test]
fn issues_and_persists_a_versioned_v1_challenge() {
    let records = Rc::new(RefCell::new(LifecycleRecords::default()));
    let lifecycle = RecordingLifecycle(Rc::clone(&records));
    let mut service = ChallengeService::new(lifecycle, FixedMacKeyProvider);

    let public = service
        .issue_challenge(IssueRequest::v1(b"session-42").unwrap())
        .unwrap();

    assert_eq!(public.generator_version, GENERATOR_VERSION_V1);
    assert_eq!(
        public.expires_at - public.issued_at,
        i64::from(CHALLENGE_TTL_SECONDS)
    );
    for token in [&public.challenge_id, &public.nonce] {
        assert_eq!(token.len(), 22);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(token).unwrap().len(), 16);
    }
    assert_ne!(public.challenge_id, public.nonce);
    assert!(!public.question.is_empty());
    assert!(public.question.len() <= MAX_QUESTION_BYTES);

    let records = records.borrow();
    assert_eq!(records.issued.len(), 1);
    let (private, binding, attempt_limit) = &records.issued[0];
    assert_eq!(binding, b"session-42");
    assert_eq!(*attempt_limit, AttemptLimit::One);
    assert_eq!(private.challenge_id, public.challenge_id);
    assert_eq!(private.generator_version, public.generator_version);
    assert_eq!(private.nonce, public.nonce);
    assert_eq!(private.issued_at, public.issued_at);
    assert_eq!(private.expires_at, public.expires_at);
    assert_eq!(private.answer_encoding, AnswerEncoding::Base64Url);
    assert_eq!(private.answer_encoding, public.answer_encoding);
    assert_eq!(private.mac_key_id, "active-v1");
    assert_eq!(private.answer_mac.len(), 64);
    assert!(
        private
            .answer_mac
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn rejects_noncanonical_generator_versions_before_key_or_storage_access() {
    for version in [" 1.0", "1.0 ", "1.0\n", "1.00", "V1"] {
        let records = Rc::new(RefCell::new(LifecycleRecords::default()));
        let key_calls = Rc::new(RefCell::new(0));
        let mut service = recording_service(
            Rc::clone(&records),
            Rc::clone(&key_calls),
            KeyBehavior::Available,
        );

        let result = service
            .issue_challenge(IssueRequest::new(version, b"session-42", AttemptLimit::One).unwrap());

        assert_eq!(
            result,
            Err(agentgate_core::ServiceError::UnsupportedGeneratorVersion)
        );
        assert_eq!(*key_calls.borrow(), 0);
        assert!(records.borrow().issued.is_empty());
    }
}

#[test]
fn request_rejects_invalid_binding_before_service_dependencies_are_reachable() {
    for binding in [&[][..], &[0; 257][..]] {
        let records = Rc::new(RefCell::new(LifecycleRecords::default()));
        let key_calls = Rc::new(RefCell::new(0));
        let _service = recording_service(
            Rc::clone(&records),
            Rc::clone(&key_calls),
            KeyBehavior::Available,
        );

        assert_eq!(
            IssueRequest::new("1.0", binding, AttemptLimit::One).map(|_| ()),
            Err(agentgate_core::ServiceError::InvalidConfiguration)
        );
        assert_eq!(*key_calls.borrow(), 0);
        assert!(records.borrow().issued.is_empty());
    }
}

#[test]
fn storage_failure_returns_internal_error_after_one_store_attempt() {
    let records = Rc::new(RefCell::new(LifecycleRecords {
        store_error: Some(LifecycleAdapterError::Unavailable),
        ..LifecycleRecords::default()
    }));
    let key_calls = Rc::new(RefCell::new(0));
    let mut service = recording_service(
        Rc::clone(&records),
        Rc::clone(&key_calls),
        KeyBehavior::Available,
    );

    assert_eq!(
        service.issue_challenge(IssueRequest::v1(b"session-42").unwrap()),
        Err(agentgate_core::ServiceError::InternalError)
    );
    assert_eq!(*key_calls.borrow(), 1);
    assert_eq!(records.borrow().issued.len(), 1);
}

#[test]
fn maps_active_key_failures_without_storing_a_challenge() {
    for (behavior, expected) in [
        (
            KeyBehavior::InvalidMaterial,
            agentgate_core::ServiceError::InvalidConfiguration,
        ),
        (
            KeyBehavior::Unavailable,
            agentgate_core::ServiceError::InternalError,
        ),
        (
            KeyBehavior::NotFound,
            agentgate_core::ServiceError::InternalError,
        ),
    ] {
        let records = Rc::new(RefCell::new(LifecycleRecords::default()));
        let key_calls = Rc::new(RefCell::new(0));
        let mut service = recording_service(Rc::clone(&records), Rc::clone(&key_calls), behavior);

        assert_eq!(
            service.issue_challenge(IssueRequest::v1(b"session-42").unwrap()),
            Err(expected)
        );
        assert_eq!(*key_calls.borrow(), 1);
        assert!(records.borrow().issued.is_empty());
    }
}

#[test]
fn forwards_the_request_attempt_limit_exactly() {
    for (request, expected) in [
        (IssueRequest::v1(b"session-42").unwrap(), AttemptLimit::One),
        (
            IssueRequest::new("1.0", b"session-42", AttemptLimit::Two).unwrap(),
            AttemptLimit::Two,
        ),
    ] {
        let records = Rc::new(RefCell::new(LifecycleRecords::default()));
        let key_calls = Rc::new(RefCell::new(0));
        let mut service = recording_service(records.clone(), key_calls, KeyBehavior::Available);

        service.issue_challenge(request).unwrap();
        assert_eq!(records.borrow().issued[0].2, expected);
    }
}

#[test]
fn persists_only_a_32_byte_answer_mac_and_redacts_sensitive_values() {
    let records = Rc::new(RefCell::new(LifecycleRecords::default()));
    let key_calls = Rc::new(RefCell::new(0));
    let mut service = recording_service(Rc::clone(&records), key_calls, KeyBehavior::Available);
    let request = IssueRequest::v1(b"binding-sentinel").unwrap();
    let request_debug = format!("{request:?}");

    let public = service.issue_challenge(request).unwrap();
    let records = records.borrow();
    let (private, binding, _) = &records.issued[0];
    assert_eq!(hex::decode(&private.answer_mac).unwrap().len(), 32);
    assert!(!format!("{private:?}").contains("answer:"));
    assert!(!format!("{private:?}").contains(&private.answer_mac));
    assert!(!format!("{public:?}").contains("key-id-sentinel"));
    assert_eq!(binding, b"binding-sentinel");
    assert!(!request_debug.contains("binding-sentinel"));
}

#[test]
fn successful_issue_observes_safe_generated_metadata_after_storage() {
    let records = Rc::new(RefCell::new(LifecycleRecords::default()));
    let events = Rc::new(RefCell::new(Vec::new()));
    let observer = RecordingObserver {
        events: Rc::clone(&events),
        records: Rc::clone(&records),
        expect_stored: true,
        panic: false,
    };
    let mut service = ChallengeService::with_observer(
        RecordingLifecycle(Rc::clone(&records)),
        FixedMacKeyProvider,
        observer,
    );

    let public = service
        .issue_challenge(IssueRequest::v1(b"binding-secret-sentinel").unwrap())
        .unwrap();
    let events = events.borrow();
    assert_eq!(events.len(), 1);
    let ServiceEvent::ChallengeIssued(event) = &events[0] else {
        panic!("unexpected event: {:?}", events[0]);
    };
    assert_eq!(event.challenge_id, public.challenge_id);
    assert_eq!(event.generator_version, public.generator_version);
    assert_eq!(event.question_byte_length, public.question.len());
    assert_eq!(event.candidate_attempts, 1);
    assert!((2..=3).contains(&event.render_languages.len()));
    assert!(event.duration <= std::time::Duration::from_secs(10));
    match event.secret_length_bucket {
        SecretLengthBucket::EightToTen => assert_eq!(event.fragment_count, 3),
        SecretLengthBucket::ElevenToThirteen => assert_eq!(event.fragment_count, 4),
        SecretLengthBucket::FourteenToSixteen => assert_eq!(event.fragment_count, 5),
    }
    let formatted = format!("{event:?}");
    for secret in [
        "binding-secret-sentinel",
        "active-v1",
        &public.nonce,
        &public.question,
    ] {
        assert!(!formatted.contains(secret));
    }
}

#[test]
fn failed_store_emits_one_safe_failure_and_observer_panic_does_not_change_results() {
    for (store_error, panic, expected) in [
        (
            Some(LifecycleAdapterError::Unavailable),
            false,
            Err(agentgate_core::ServiceError::InternalError),
        ),
        (
            Some(LifecycleAdapterError::Unavailable),
            true,
            Err(agentgate_core::ServiceError::InternalError),
        ),
        (None, true, Ok(())),
    ] {
        let records = Rc::new(RefCell::new(LifecycleRecords {
            store_error,
            ..LifecycleRecords::default()
        }));
        let events = Rc::new(RefCell::new(Vec::new()));
        let observer = RecordingObserver {
            events: Rc::clone(&events),
            records: Rc::clone(&records),
            expect_stored: true,
            panic,
        };
        let mut service = ChallengeService::with_observer(
            RecordingLifecycle(Rc::clone(&records)),
            FixedMacKeyProvider,
            observer,
        );
        let result = service
            .issue_challenge(IssueRequest::v1(b"binding-secret-sentinel").unwrap())
            .map(|_| ());
        assert_eq!(result, expected);
        assert_eq!(records.borrow().issued.len(), 1);
        assert_eq!(events.borrow().len(), 1);
        if store_error.is_some() {
            assert!(matches!(
                &events.borrow()[0],
                ServiceEvent::IssueFailed(event)
                    if event.stage == ServiceStage::LifecycleStore
                        && event.error == agentgate_core::ServiceError::InternalError
                        && event.challenge_id.is_none()
                        && event.generator_version.as_deref() == Some("1.0")
                        && event.attempts == 1
            ));
        }
    }
}

#[test]
fn issue_failures_report_bounded_identifiers_stable_stages_and_errors() {
    let oversized_version = "version-private-material-sentinel".repeat(4);
    for (version, behavior, expected_stage, expected_error, expected_version) in [
        (
            oversized_version.as_str(),
            KeyBehavior::Available,
            ServiceStage::VersionDispatch,
            agentgate_core::ServiceError::UnsupportedGeneratorVersion,
            None,
        ),
        (
            "V1",
            KeyBehavior::Available,
            ServiceStage::VersionDispatch,
            agentgate_core::ServiceError::UnsupportedGeneratorVersion,
            None,
        ),
        (
            "1.0",
            KeyBehavior::InvalidMaterial,
            ServiceStage::KeyProvider,
            agentgate_core::ServiceError::InvalidConfiguration,
            Some("1.0"),
        ),
    ] {
        let records = Rc::new(RefCell::new(LifecycleRecords::default()));
        let events = Rc::new(RefCell::new(Vec::new()));
        let observer = RecordingObserver {
            events: Rc::clone(&events),
            records: Rc::clone(&records),
            expect_stored: false,
            panic: false,
        };
        let mut service = ChallengeService::with_observer(
            RecordingLifecycle(records),
            CountingMacKeyProvider {
                calls: Rc::new(RefCell::new(0)),
                behavior,
            },
            observer,
        );

        assert_eq!(
            service.issue_challenge(
                IssueRequest::new(version, b"binding-secret-sentinel", AttemptLimit::One).unwrap()
            ),
            Err(expected_error)
        );
        let events = events.borrow();
        assert_eq!(events.len(), 1);
        let ServiceEvent::IssueFailed(event) = &events[0] else {
            panic!("unexpected event: {:?}", events[0]);
        };
        assert_eq!(event.stage, expected_stage);
        assert_eq!(event.error, expected_error);
        assert!(event.challenge_id.is_none());
        assert_eq!(event.generator_version.as_deref(), expected_version);
        assert_eq!(
            event.attempts,
            usize::from(expected_stage == ServiceStage::KeyProvider)
        );
        assert!(!format!("{event:?}").contains(&oversized_version));
    }
}
