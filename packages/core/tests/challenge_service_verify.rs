use std::{cell::RefCell, rc::Rc};

use agentgate_core::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, BeginAttemptError, ChallengeService,
    KeyProviderError, LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MacContext,
    MacKey, MacKeyProvider, Observer, PendingAttempt, PrivateChallengeMaterial, ServiceError,
    ServiceEvent, ServiceStage, Submission, SubmissionIdentity, VerificationDisposition,
    VerificationOutcome, VerifyRequest, compute_answer_mac, contracts::AnswerEncoding,
};

const OLD_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const ANSWER: &str = "YUI5MmtM";
const CHALLENGE_ID: &str = "Y2hhbGxlbmdlLTEyMzQ1Ng";

fn material() -> PrivateChallengeMaterial {
    let context = MacContext {
        challenge_id: CHALLENGE_ID.to_owned(),
        generator_version: "1.0".to_owned(),
        nonce: "bm9uY2U".to_owned(),
        issued_at: 1_788_062_400,
        expires_at: 1_788_062_408,
        mac_key_id: "key-old".to_owned(),
        answer_encoding: AnswerEncoding::Base64Url,
    };
    PrivateChallengeMaterial {
        challenge_id: context.challenge_id.clone(),
        generator_version: context.generator_version.clone(),
        nonce: context.nonce.clone(),
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        mac_key_id: context.mac_key_id.clone(),
        answer_mac: hex::encode(compute_answer_mac(OLD_KEY, &context, ANSWER).unwrap()),
        answer_encoding: context.answer_encoding,
    }
}

fn submission() -> Submission {
    Submission {
        challenge_id: CHALLENGE_ID.to_owned(),
        nonce: "bm9uY2U".to_owned(),
        answer: ANSWER.to_owned(),
    }
}

struct RecordingLifecycle {
    calls: Rc<RefCell<Vec<String>>>,
    pending: Option<PendingAttempt<&'static str>>,
}

impl LifecycleAdapter for RecordingLifecycle {
    type AttemptToken = &'static str;

    fn store_issued(
        &mut self,
        _material: PrivateChallengeMaterial,
        _binding: &[u8],
        _attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError> {
        unreachable!("verification does not store challenges")
    }

    fn begin_attempt(
        &mut self,
        identity: SubmissionIdentity<'_>,
        binding: &[u8],
        _server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
        assert_eq!(identity.challenge_id(), CHALLENGE_ID);
        assert_eq!(identity.nonce(), "bm9uY2U");
        assert_eq!(binding, b"tenant-binding");
        self.calls.borrow_mut().push("begin".to_owned());
        Ok(self.pending.take().unwrap())
    }

    fn finish_attempt(
        &mut self,
        token: Self::AttemptToken,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        assert_eq!(token, "attempt-token");
        self.calls
            .borrow_mut()
            .push(format!("finish:{outcome:?}").to_ascii_lowercase());
        Ok(())
    }
}

struct RecordingKeys {
    calls: Rc<RefCell<Vec<String>>>,
}

impl MacKeyProvider for RecordingKeys {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        unreachable!("verification must never request the active key")
    }

    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError> {
        self.calls.borrow_mut().push(format!("key:{key_id}"));
        assert_eq!(key_id, "key-old");
        MacKey::new(OLD_KEY.to_vec())
    }
}

#[test]
fn accepts_with_the_exact_stored_key_after_begin_and_before_finish() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let lifecycle = RecordingLifecycle {
        calls: Rc::clone(&calls),
        pending: Some(PendingAttempt::new("attempt-token", material())),
    };
    let keys = RecordingKeys {
        calls: Rc::clone(&calls),
    };
    let mut service = ChallengeService::new(lifecycle, keys);
    let submission = submission();
    let request = VerifyRequest::new(&submission, b"tenant-binding").unwrap();

    assert_eq!(
        service.verify_submission(request),
        Ok(VerificationOutcome::Accepted)
    );
    assert_eq!(
        calls.borrow().as_slice(),
        ["begin", "key:key-old", "finish:accepted"]
    );
}

#[test]
fn rejects_an_empty_stored_key_id_as_system_failure_before_key_lookup() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut stored = material();
    stored.mac_key_id.clear();
    let lifecycle = RecordingLifecycle {
        calls: Rc::clone(&calls),
        pending: Some(PendingAttempt::new("attempt-token", stored)),
    };
    let keys = RecordingKeys {
        calls: Rc::clone(&calls),
    };
    let mut service = ChallengeService::new(lifecycle, keys);
    let submission = submission();

    assert_eq!(
        service.verify_submission(VerifyRequest::new(&submission, b"tenant-binding").unwrap()),
        Err(ServiceError::InvalidChallengeMaterial)
    );
    assert_eq!(calls.borrow().as_slice(), ["begin", "finish:systemfailure"]);
}

enum BeginBehavior {
    Pending(PrivateChallengeMaterial),
    Rejected(LifecycleRejection),
    Adapter(LifecycleAdapterError),
}

struct ScenarioLifecycle {
    calls: Rc<RefCell<Vec<String>>>,
    begin: Option<BeginBehavior>,
    finish_error: Option<LifecycleAdapterError>,
}

impl LifecycleAdapter for ScenarioLifecycle {
    type AttemptToken = &'static str;

    fn store_issued(
        &mut self,
        _material: PrivateChallengeMaterial,
        _binding: &[u8],
        _attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError> {
        unreachable!()
    }

    fn begin_attempt(
        &mut self,
        identity: SubmissionIdentity<'_>,
        binding: &[u8],
        server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
        self.calls.borrow_mut().push(format!(
            "begin:{}:{}:{}:{}",
            identity.challenge_id(),
            identity.nonce(),
            String::from_utf8_lossy(binding),
            server_time
        ));
        match self.begin.take().unwrap() {
            BeginBehavior::Pending(material) => Ok(PendingAttempt::new("attempt-token", material)),
            BeginBehavior::Rejected(reason) => Err(BeginAttemptError::Rejected(reason)),
            BeginBehavior::Adapter(error) => Err(BeginAttemptError::Adapter(error)),
        }
    }

    fn finish_attempt(
        &mut self,
        token: Self::AttemptToken,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        assert_eq!(token, "attempt-token");
        self.calls
            .borrow_mut()
            .push(format!("finish:{outcome:?}").to_ascii_lowercase());
        match self.finish_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

enum KeyBehavior {
    Key(Vec<u8>),
    Error(KeyProviderError),
}

struct ScenarioKeys {
    calls: Rc<RefCell<Vec<String>>>,
    active_calls: Rc<RefCell<usize>>,
    behavior: KeyBehavior,
}

struct RecordingObserver {
    events: Rc<RefCell<Vec<ServiceEvent>>>,
    calls: Rc<RefCell<Vec<String>>>,
    panic: bool,
}

impl Observer for RecordingObserver {
    fn observe(&mut self, event: &ServiceEvent) {
        if matches!(
            event,
            ServiceEvent::VerificationCompleted(completed)
                if !matches!(completed.disposition, VerificationDisposition::LifecycleRejected(_))
        ) {
            assert!(
                self.calls
                    .borrow()
                    .iter()
                    .any(|call| call.starts_with("finish:"))
            );
        }
        self.events.borrow_mut().push(event.clone());
        assert!(!self.panic, "observer sentinel panic");
    }
}

impl MacKeyProvider for ScenarioKeys {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        *self.active_calls.borrow_mut() += 1;
        ActiveMacKey::new(
            "key-active",
            MacKey::new(b"abcdef0123456789abcdef0123456789".to_vec()).unwrap(),
        )
    }

    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError> {
        self.calls.borrow_mut().push(format!("key:{key_id}"));
        match &self.behavior {
            KeyBehavior::Key(key) => MacKey::new(key.clone()),
            KeyBehavior::Error(error) => Err(*error),
        }
    }
}

fn run_scenario(
    begin: BeginBehavior,
    key_behavior: KeyBehavior,
    finish_error: Option<LifecycleAdapterError>,
    submitted: &Submission,
) -> (
    Result<VerificationOutcome, ServiceError>,
    Vec<String>,
    usize,
) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let active_calls = Rc::new(RefCell::new(0));
    let lifecycle = ScenarioLifecycle {
        calls: Rc::clone(&calls),
        begin: Some(begin),
        finish_error,
    };
    let keys = ScenarioKeys {
        calls: Rc::clone(&calls),
        active_calls: Rc::clone(&active_calls),
        behavior: key_behavior,
    };
    let mut service = ChallengeService::new(lifecycle, keys);
    let result =
        service.verify_submission(VerifyRequest::new(submitted, b"tenant-binding").unwrap());
    let recorded_calls = calls.borrow().clone();
    let active_call_count = *active_calls.borrow();
    (result, recorded_calls, active_call_count)
}

fn run_observed_scenario(
    begin: BeginBehavior,
    key_behavior: KeyBehavior,
    finish_error: Option<LifecycleAdapterError>,
    submitted: &Submission,
    panic: bool,
) -> (
    Result<VerificationOutcome, ServiceError>,
    Vec<String>,
    Vec<ServiceEvent>,
) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let events = Rc::new(RefCell::new(Vec::new()));
    let lifecycle = ScenarioLifecycle {
        calls: Rc::clone(&calls),
        begin: Some(begin),
        finish_error,
    };
    let keys = ScenarioKeys {
        calls: Rc::clone(&calls),
        active_calls: Rc::new(RefCell::new(0)),
        behavior: key_behavior,
    };
    let observer = RecordingObserver {
        events: Rc::clone(&events),
        calls: Rc::clone(&calls),
        panic,
    };
    let mut service = ChallengeService::with_observer(lifecycle, keys, observer);
    let result = service
        .verify_submission(VerifyRequest::new(submitted, b"binding-secret-sentinel").unwrap());
    let calls = calls.borrow().clone();
    let events = events.borrow().clone();
    (result, calls, events)
}

#[test]
fn verification_observes_lifecycle_rejections_and_durable_core_outcomes() {
    let scenarios = [
        (
            BeginBehavior::Rejected(LifecycleRejection::Expired),
            submission(),
            Ok(VerificationOutcome::Rejected(LifecycleRejection::Expired)),
            VerificationDisposition::LifecycleRejected(LifecycleRejection::Expired),
            false,
        ),
        (
            BeginBehavior::Pending(material()),
            submission(),
            Ok(VerificationOutcome::Accepted),
            VerificationDisposition::Accepted,
            true,
        ),
        (
            BeginBehavior::Pending(material()),
            Submission {
                answer: "not base64url!".to_owned(),
                ..submission()
            },
            Err(ServiceError::InvalidAnswerEncoding),
            VerificationDisposition::InvalidAnswerEncoding,
            true,
        ),
        (
            BeginBehavior::Pending(material()),
            Submission {
                answer: "YUI5MmtN".to_owned(),
                ..submission()
            },
            Err(ServiceError::AnswerMismatch),
            VerificationDisposition::AnswerMismatch,
            true,
        ),
    ];

    for (begin, submitted, expected, disposition, expects_finish) in scenarios {
        let (result, calls, events) = run_observed_scenario(
            begin,
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
            false,
        );
        assert_eq!(result, expected);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            ServiceEvent::VerificationCompleted(event)
                if event.challenge_id == CHALLENGE_ID
                    && event.disposition == disposition
                    && event.generator_version.as_deref() == if expects_finish {
                        Some("1.0")
                    } else {
                        None
                    }
                    && (event.elapsed_since_issue.is_some() || !expects_finish)
        ));
        if expects_finish {
            let server_time = calls[0].rsplit(':').next().unwrap().parse::<i64>().unwrap();
            let ServiceEvent::VerificationCompleted(event) = &events[0] else {
                unreachable!()
            };
            assert_eq!(
                event.elapsed_since_issue,
                Some(std::time::Duration::from_secs(
                    u64::try_from(server_time - material().issued_at).unwrap()
                ))
            );
        }
        assert_eq!(
            calls.iter().any(|call| call.starts_with("finish:")),
            expects_finish
        );
    }
}

#[test]
fn verification_system_and_finish_failures_emit_only_safe_service_failures() {
    let oversized_version = "version-secret-sentinel".repeat(4);
    let mut invalid = material();
    invalid.generator_version = oversized_version.clone();
    let mut unsupported = material();
    unsupported.generator_version = "1.1".to_owned();
    let mut malformed_mac = material();
    malformed_mac.answer_mac = "not-hex".to_owned();
    let scenarios = [
        (
            BeginBehavior::Adapter(LifecycleAdapterError::Internal),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            ServiceStage::LifecycleBegin,
            ServiceError::InternalError,
            Some(std::time::Duration::ZERO),
        ),
        (
            BeginBehavior::Pending(invalid),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            ServiceStage::CoreVerification,
            ServiceError::InvalidChallengeMaterial,
            Some(std::time::Duration::ZERO),
        ),
        (
            BeginBehavior::Pending(unsupported),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            ServiceStage::VersionDispatch,
            ServiceError::UnsupportedGeneratorVersion,
            Some(std::time::Duration::ZERO),
        ),
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Error(KeyProviderError::Unavailable),
            None,
            ServiceStage::KeyProvider,
            ServiceError::InternalError,
            Some(std::time::Duration::ZERO),
        ),
        (
            BeginBehavior::Pending(malformed_mac),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            ServiceStage::CoreVerification,
            ServiceError::InvalidChallengeMaterial,
            None,
        ),
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            Some(LifecycleAdapterError::Unavailable),
            ServiceStage::LifecycleFinish,
            ServiceError::InternalError,
            None,
        ),
    ];

    for (begin, key_behavior, finish_error, stage, expected_error, expected_duration) in scenarios {
        let submitted = submission();
        let (result, _calls, events) =
            run_observed_scenario(begin, key_behavior, finish_error, &submitted, false);
        assert_eq!(result, Err(expected_error));
        assert_eq!(events.len(), 1);
        let ServiceEvent::ServiceFailed(event) = &events[0] else {
            panic!("unexpected event: {:?}", events[0]);
        };
        assert_eq!(event.stage, stage);
        assert_eq!(event.error, expected_error);
        assert_eq!(event.attempts, 0);
        if let Some(expected_duration) = expected_duration {
            assert_eq!(event.duration, expected_duration);
        }
        assert!(event.challenge_id.is_none());
        assert!(event.generator_version.is_none());
        assert!(!format!("{event:?}").contains(&oversized_version));
        assert_ne!(
            event.generator_version.as_deref(),
            Some(oversized_version.as_str())
        );
    }
}

#[test]
fn observer_panic_does_not_change_system_failure_or_finished_state() {
    let submitted = submission();
    let (result, calls, events) = run_observed_scenario(
        BeginBehavior::Pending(material()),
        KeyBehavior::Error(KeyProviderError::Unavailable),
        None,
        &submitted,
        true,
    );
    assert_eq!(result, Err(ServiceError::InternalError));
    assert_eq!(
        calls.last().map(String::as_str),
        Some("finish:systemfailure")
    );
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], ServiceEvent::ServiceFailed(_)));
}

#[test]
fn observer_panics_do_not_change_verification_result_or_durable_finish() {
    let submitted = submission();
    let (result, calls, events) = run_observed_scenario(
        BeginBehavior::Pending(material()),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
        true,
    );
    assert_eq!(result, Ok(VerificationOutcome::Accepted));
    assert_eq!(calls.last().map(String::as_str), Some("finish:accepted"));
    assert_eq!(events.len(), 1);
}

#[test]
fn verification_events_exclude_every_secret_and_omit_oversized_caller_identity() {
    let stored = material();
    let answer_mac = stored.answer_mac.clone();
    let submitted = submission();
    let (_result, _calls, events) = run_observed_scenario(
        BeginBehavior::Pending(stored),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
        false,
    );
    let formatted = format!("{:?}", events[0]);
    for secret in [
        "binding-secret-sentinel",
        ANSWER,
        "bm9uY2U",
        "key-old",
        std::str::from_utf8(OLD_KEY).unwrap(),
        answer_mac.as_str(),
    ] {
        assert!(!formatted.contains(secret), "leaked {secret}");
    }

    let oversized_id = "challenge-private-material-sentinel".repeat(5);
    let oversized = Submission {
        challenge_id: oversized_id.clone(),
        ..submission()
    };
    let (_result, _calls, events) = run_observed_scenario(
        BeginBehavior::Rejected(LifecycleRejection::NotFound),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &oversized,
        false,
    );
    let ServiceEvent::VerificationCompleted(event) = &events[0] else {
        panic!("unexpected event")
    };
    assert!(event.challenge_id.is_empty());
    assert!(!format!("{event:?}").contains(&oversized_id));
}

#[test]
fn lifecycle_rejection_omits_noncanonical_and_log_injection_challenge_ids() {
    for challenge_id in [
        "short",
        "control\u{0007}token",
        "line-one\nforged-log-entry",
        "Y2hhbGxlbmdlLTEyMzQ1Ng==",
        "!!!!!!!!!!!!!!!!!!!!!!",
    ] {
        let submitted = Submission {
            challenge_id: challenge_id.to_owned(),
            ..submission()
        };
        let (result, _calls, events) = run_observed_scenario(
            BeginBehavior::Rejected(LifecycleRejection::NotFound),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
            false,
        );
        assert_eq!(
            result,
            Ok(VerificationOutcome::Rejected(LifecycleRejection::NotFound))
        );
        let ServiceEvent::VerificationCompleted(event) = &events[0] else {
            panic!("unexpected event")
        };
        assert!(event.challenge_id.is_empty());
        assert!(!format!("{event:?}").contains(challenge_id));

        let (_result, _calls, events) = run_observed_scenario(
            BeginBehavior::Adapter(LifecycleAdapterError::Internal),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
            false,
        );
        let ServiceEvent::ServiceFailed(event) = &events[0] else {
            panic!("unexpected event")
        };
        assert!(event.challenge_id.is_none());
        assert!(event.generator_version.is_none());
        assert!(!format!("{event:?}").contains(challenge_id));
    }
}

#[test]
fn accepted_completion_omits_a_noncanonical_stored_challenge_id() {
    let mut stored = material();
    stored.challenge_id = "short".to_owned();
    let context = MacContext {
        challenge_id: stored.challenge_id.clone(),
        generator_version: stored.generator_version.clone(),
        nonce: stored.nonce.clone(),
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
        mac_key_id: stored.mac_key_id.clone(),
        answer_encoding: stored.answer_encoding,
    };
    stored.answer_mac = hex::encode(compute_answer_mac(OLD_KEY, &context, ANSWER).unwrap());
    let submitted = Submission {
        challenge_id: "short".to_owned(),
        ..submission()
    };

    let (result, _calls, events) = run_observed_scenario(
        BeginBehavior::Pending(stored),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
        false,
    );

    assert_eq!(result, Ok(VerificationOutcome::Accepted));
    assert!(matches!(
        &events[0],
        ServiceEvent::VerificationCompleted(event)
            if event.challenge_id.is_empty()
                && event.generator_version.as_deref() == Some("1.0")
    ));
}

#[test]
fn elapsed_since_issue_is_omitted_when_stored_time_is_in_the_future() {
    let mut stored = material();
    stored.issued_at = i64::MAX - 1;
    stored.expires_at = i64::MAX;
    let context = MacContext {
        challenge_id: stored.challenge_id.clone(),
        generator_version: stored.generator_version.clone(),
        nonce: stored.nonce.clone(),
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
        mac_key_id: stored.mac_key_id.clone(),
        answer_encoding: stored.answer_encoding,
    };
    stored.answer_mac = hex::encode(compute_answer_mac(OLD_KEY, &context, ANSWER).unwrap());
    let submitted = submission();
    let (result, _calls, events) = run_observed_scenario(
        BeginBehavior::Pending(stored),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
        false,
    );
    assert_eq!(result, Ok(VerificationOutcome::Accepted));
    assert!(matches!(
        &events[0],
        ServiceEvent::VerificationCompleted(event) if event.elapsed_since_issue.is_none()
    ));
}

#[test]
fn maps_every_lifecycle_rejection_without_key_lookup_or_finish() {
    for reason in [
        LifecycleRejection::NotFound,
        LifecycleRejection::Expired,
        LifecycleRejection::AlreadyConsumed,
        LifecycleRejection::BindingMismatch,
        LifecycleRejection::NonceMismatch,
        LifecycleRejection::AttemptsExhausted,
    ] {
        let submitted = submission();
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Rejected(reason),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
        );

        assert_eq!(result, Ok(VerificationOutcome::Rejected(reason)));
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with(&format!("begin:{CHALLENGE_ID}:bm9uY2U:tenant-binding:")));
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn maps_every_begin_adapter_error_to_internal_without_key_or_finish() {
    for error in [
        LifecycleAdapterError::Unavailable,
        LifecycleAdapterError::Conflict,
        LifecycleAdapterError::Internal,
    ] {
        let submitted = submission();
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Adapter(error),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
        );

        assert_eq!(result, Err(ServiceError::InternalError));
        assert_eq!(calls.len(), 1);
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn invalid_answer_encoding_and_mismatch_finish_as_rejected() {
    for (answer, expected) in [
        ("not base64url!", ServiceError::InvalidAnswerEncoding),
        ("YUI5MmtN", ServiceError::AnswerMismatch),
    ] {
        let mut submitted = submission();
        submitted.answer = answer.to_owned();
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Pending(material()),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
        );

        assert_eq!(result, Err(expected));
        assert_eq!(calls[1..], ["key:key-old", "finish:rejected"]);
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn malformed_mac_and_oversized_material_finish_as_system_failures() {
    let mut malformed_mac = material();
    malformed_mac.answer_mac = "not-hex".to_owned();
    let mut oversized_nonce = material();
    oversized_nonce.nonce = "n".repeat(257);
    let mut oversized_submission = submission();
    oversized_submission.nonce = oversized_nonce.nonce.clone();

    for (stored, submitted, expected_suffix) in [
        (
            malformed_mac,
            submission(),
            vec!["key:key-old", "finish:systemfailure"],
        ),
        (
            oversized_nonce,
            oversized_submission,
            vec!["finish:systemfailure"],
        ),
    ] {
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Pending(stored),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
        );
        assert_eq!(result, Err(ServiceError::InvalidChallengeMaterial));
        assert_eq!(calls[1..], expected_suffix);
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn unsupported_stored_versions_are_exact_and_fail_before_key_lookup() {
    for version in ["1.0 ", " 1.0", "V1", "1.1", ""] {
        let mut stored = material();
        stored.generator_version = version.to_owned();
        let submitted = submission();
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Pending(stored),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
        );
        assert_eq!(result, Err(ServiceError::UnsupportedGeneratorVersion));
        assert_eq!(calls[1..], ["finish:systemfailure"]);
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn oversized_stored_generator_version_is_invalid_before_dispatch_or_key_lookup() {
    let mut stored = material();
    stored.generator_version = "v".repeat(33);
    let submitted = submission();

    let (result, calls, active_calls) = run_scenario(
        BeginBehavior::Pending(stored),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
    );

    assert_eq!(result, Err(ServiceError::InvalidChallengeMaterial));
    assert_eq!(calls[1..], ["finish:systemfailure"]);
    assert_eq!(active_calls, 0);
}

#[test]
fn old_key_lookup_failures_never_fall_back_to_the_active_key() {
    for error in [
        KeyProviderError::Unavailable,
        KeyProviderError::NotFound,
        KeyProviderError::InvalidMaterial,
    ] {
        let submitted = submission();
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Pending(material()),
            KeyBehavior::Error(error),
            None,
            &submitted,
        );
        assert_eq!(result, Err(ServiceError::InternalError));
        assert_eq!(calls[1..], ["key:key-old", "finish:systemfailure"]);
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn finish_failure_overrides_accepted_rejected_and_system_results() {
    let mut wrong = submission();
    wrong.answer = "YUI5MmtN".to_owned();
    let submitted = submission();
    let scenarios = [
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            submitted,
            "finish:accepted",
        ),
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            wrong,
            "finish:rejected",
        ),
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Error(KeyProviderError::Unavailable),
            submission(),
            "finish:systemfailure",
        ),
    ];

    for (begin, keys, submitted, expected_finish) in scenarios {
        let (result, calls, active_calls) = run_scenario(
            begin,
            keys,
            Some(LifecycleAdapterError::Unavailable),
            &submitted,
        );
        assert_eq!(result, Err(ServiceError::InternalError));
        assert_eq!(calls.last().map(String::as_str), Some(expected_finish));
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn mismatched_adapter_identity_material_is_never_accepted() {
    for mutate in ["challenge_id", "nonce"] {
        let mut stored = material();
        match mutate {
            "challenge_id" => stored.challenge_id = "other-challenge".to_owned(),
            "nonce" => stored.nonce = "other-nonce".to_owned(),
            _ => unreachable!(),
        }
        let submitted = submission();
        let (result, calls, active_calls) = run_scenario(
            BeginBehavior::Pending(stored),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            None,
            &submitted,
        );
        assert_eq!(result, Err(ServiceError::InvalidChallengeMaterial));
        assert_eq!(calls[1..], ["key:key-old", "finish:systemfailure"]);
        assert_eq!(active_calls, 0);
    }
}

#[test]
fn verify_request_rejects_invalid_binding_boundaries() {
    let submitted = submission();
    assert_eq!(
        VerifyRequest::new(&submitted, b"").map(|_| ()),
        Err(ServiceError::InvalidConfiguration)
    );
    assert_eq!(
        VerifyRequest::new(&submitted, &[1; 257]).map(|_| ()),
        Err(ServiceError::InvalidConfiguration)
    );
}

#[test]
fn key_rotation_uses_the_stored_old_key_and_never_the_different_active_key() {
    let submitted = submission();
    let (result, calls, active_calls) = run_scenario(
        BeginBehavior::Pending(material()),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
    );
    assert_eq!(result, Ok(VerificationOutcome::Accepted));
    assert_eq!(calls[1..], ["key:key-old", "finish:accepted"]);
    assert_eq!(active_calls, 0);
}

#[test]
fn begin_attempt_receives_identity_and_binding_but_not_the_submitted_answer() {
    let mut submitted = submission();
    submitted.answer = "answer-sentinel-never-shared-with-lifecycle".to_owned();
    let (result, calls, active_calls) = run_scenario(
        BeginBehavior::Rejected(LifecycleRejection::Expired),
        KeyBehavior::Key(OLD_KEY.to_vec()),
        None,
        &submitted,
    );

    assert_eq!(
        result,
        Ok(VerificationOutcome::Rejected(LifecycleRejection::Expired))
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with(&format!("begin:{CHALLENGE_ID}:bm9uY2U:tenant-binding:")));
    assert!(!calls[0].contains("answer-sentinel"));
    assert_eq!(active_calls, 0);
}
