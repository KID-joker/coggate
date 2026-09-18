use coggate_core::{
    ActiveMacKey, AttemptLimit, BeginAttemptError, ChallengeIssuedEvent, ChallengeService,
    IssueRequest, KeyProviderError, LifecycleAdapter, LifecycleAdapterError, LifecycleRejection,
    MacKey, MacKeyProvider, NoopObserver, Observer, PendingAttempt, PrivateChallengeMaterial,
    SecretLengthBucket, ServiceError, ServiceEvent, ServiceFailureEvent, ServiceStage, Submission,
    SubmissionIdentity, VerificationDisposition, VerificationEvent, VerifyRequest,
};
use coggate_core::{contracts::AnswerEncoding, generation::RenderLanguage};
use std::time::Duration;

struct MemoryLifecycle;

impl LifecycleAdapter for MemoryLifecycle {
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
    ) -> Result<coggate_core::PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
        Err(LifecycleRejection::NotFound.into())
    }

    fn finish_attempt(
        &mut self,
        _token: Self::AttemptToken,
        _outcome: coggate_core::AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        Ok(())
    }
}

struct StaticKeys;

impl MacKeyProvider for StaticKeys {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        ActiveMacKey::new("primary", MacKey::new(vec![7; 32]).unwrap())
    }

    fn key_by_id(&mut self, _key_id: &str) -> Result<MacKey, KeyProviderError> {
        MacKey::new(vec![7; 32])
    }
}

#[derive(Default)]
struct RecordingObserver {
    event_count: usize,
}

impl Observer for RecordingObserver {
    fn observe(&mut self, _event: &ServiceEvent) {
        self.event_count += 1;
    }
}

fn submission() -> Submission {
    Submission {
        challenge_id: "challenge-1".to_owned(),
        nonce: "nonce-sentinel".to_owned(),
        answer: "answer-sentinel".to_owned(),
    }
}

fn private_material() -> PrivateChallengeMaterial {
    PrivateChallengeMaterial {
        challenge_id: "challenge-1".to_owned(),
        generator_version: "1.0".to_owned(),
        nonce: "nonce-sentinel".to_owned(),
        issued_at: 1,
        expires_at: 2,
        mac_key_id: "key-id-sentinel".to_owned(),
        answer_mac: "mac-sentinel".to_owned(),
        answer_encoding: AnswerEncoding::Base64Url,
    }
}

#[test]
fn public_service_contract_is_constructible_and_redacts_sensitive_values() {
    let mut service = ChallengeService::new(MemoryLifecycle, StaticKeys);
    let issue = IssueRequest::v1(b"tenant-binding").unwrap();
    let two_attempts = IssueRequest::new("1.0", b"tenant-binding", AttemptLimit::Two).unwrap();
    let submission = submission();
    let verify = VerifyRequest::new(&submission, b"tenant-binding").unwrap();

    assert_eq!(issue.version(), "1.0");
    assert_eq!(issue.attempt_limit(), AttemptLimit::One);
    assert_eq!(two_attempts.attempt_limit(), AttemptLimit::Two);
    assert_eq!(verify.submission().challenge_id, "challenge-1");
    assert_eq!(
        SubmissionIdentity::new("challenge-1", "nonce-1").challenge_id(),
        "challenge-1"
    );
    assert_eq!(LifecycleRejection::NotFound, LifecycleRejection::NotFound);
    let issue_debug = format!("{issue:?}");
    assert!(issue_debug.contains("[REDACTED]"));
    assert!(!issue_debug.contains("tenant-binding"));
    let verify_debug = format!("{verify:?}");
    assert!(verify_debug.contains("[REDACTED]"));
    assert!(!verify_debug.contains("tenant-binding"));
    assert!(!verify_debug.contains("answer-sentinel"));
    assert!(!verify_debug.contains("nonce-sentinel"));
    assert_eq!(
        format!("{:?}", MacKey::new(vec![9; 32]).unwrap()),
        "MacKey([REDACTED])"
    );
    assert_eq!(
        coggate_core::ServiceError::AnswerMismatch.code(),
        "answer_mismatch"
    );
    assert_eq!(
        coggate_core::ServiceError::InvalidConfiguration.code(),
        "invalid_configuration"
    );

    let _ = &mut service;
}

#[test]
fn request_constructors_enforce_exact_binding_boundaries() {
    let submission = submission();

    for binding in [&[][..], &[1][..], &[1; 256][..], &[1; 257][..]] {
        let expected = if binding.is_empty() || binding.len() == 257 {
            Err(ServiceError::InvalidConfiguration)
        } else {
            Ok(())
        };
        assert_eq!(
            IssueRequest::new("1.0", binding, AttemptLimit::One).map(|_| ()),
            expected
        );
        assert_eq!(
            VerifyRequest::new(&submission, binding).map(|_| ()),
            expected
        );
    }
}

#[test]
fn verify_request_rejects_oversized_submission_identity_fields() {
    let oversized_id = Submission {
        challenge_id: "c".repeat(129),
        ..submission()
    };
    assert_eq!(
        VerifyRequest::new(&oversized_id, b"tenant-binding").map(|_| ()),
        Err(ServiceError::InvalidChallengeMaterial)
    );

    let oversized_nonce = Submission {
        nonce: "n".repeat(257),
        ..submission()
    };
    assert_eq!(
        VerifyRequest::new(&oversized_nonce, b"tenant-binding").map(|_| ()),
        Err(ServiceError::InvalidChallengeMaterial)
    );

    let bounded = Submission {
        challenge_id: "c".repeat(128),
        nonce: "n".repeat(256),
        ..submission()
    };
    assert!(VerifyRequest::new(&bounded, b"tenant-binding").is_ok());
}

#[test]
fn public_key_constructors_enforce_exact_boundaries_and_redact_values() {
    assert_eq!(
        MacKey::new(vec![1; 31]).map(|_| ()),
        Err(KeyProviderError::InvalidMaterial)
    );
    assert!(MacKey::new(vec![1; 32]).is_ok());

    for key_id in ["", "a", &"k".repeat(128), &"k".repeat(129)] {
        let actual = ActiveMacKey::new(key_id, MacKey::new(vec![3; 32]).unwrap()).map(|_| ());
        let expected = if key_id.is_empty() || key_id.len() == 129 {
            Err(KeyProviderError::InvalidMaterial)
        } else {
            Ok(())
        };
        assert_eq!(actual, expected);
    }

    let key_bytes = vec![0xa5; 32];
    let active_debug = format!(
        "{:?}",
        ActiveMacKey::new("key-id-sentinel", MacKey::new(key_bytes).unwrap()).unwrap()
    );
    assert!(active_debug.contains("[REDACTED]"));
    assert!(!active_debug.contains("key-id-sentinel"));
    assert!(!active_debug.contains("165"));
}

#[test]
fn public_debug_contracts_redact_identity_and_pending_attempt_secrets() {
    let submission = submission();
    let identity = SubmissionIdentity::from_submission(&submission);
    let identity_debug = format!("{identity:?}");
    assert!(identity_debug.contains("challenge-1"));
    assert!(identity_debug.contains("[REDACTED]"));
    assert!(!identity_debug.contains("nonce-sentinel"));
    assert!(!identity_debug.contains("answer-sentinel"));

    let pending = PendingAttempt::new("token-sentinel", private_material());
    let pending_debug = format!("{pending:?}");
    assert!(pending_debug.contains("[REDACTED]"));
    for secret in [
        "token-sentinel",
        "nonce-sentinel",
        "key-id-sentinel",
        "mac-sentinel",
    ] {
        assert!(!pending_debug.contains(secret));
    }
}

#[test]
fn public_observer_and_event_surfaces_are_usable() {
    let canonical_challenge_id = "Y2hhbGxlbmdlLTEyMzQ1Ng";
    let issued = ChallengeIssuedEvent {
        challenge_id: canonical_challenge_id.to_owned(),
        generator_version: "1.0".to_owned(),
        secret_length_bucket: SecretLengthBucket::EightToTen,
        fragment_count: 2,
        question_byte_length: 64,
        render_languages: vec![RenderLanguage::Rust],
        has_distractor: false,
        candidate_attempts: 1,
        duration: Duration::from_millis(5),
    };
    let failure = ServiceFailureEvent {
        challenge_id: None,
        generator_version: None,
        stage: ServiceStage::LifecycleStore,
        error: ServiceError::InternalError,
        attempts: 2,
        duration: Duration::from_millis(6),
    };
    let verified = VerificationEvent {
        challenge_id: canonical_challenge_id.to_owned(),
        generator_version: None,
        disposition: VerificationDisposition::LifecycleRejected(LifecycleRejection::Expired),
        elapsed_since_issue: Some(Duration::from_secs(1)),
        duration: Duration::from_millis(7),
    };
    let events = [
        ServiceEvent::ChallengeIssued(issued),
        ServiceEvent::IssueFailed(failure.clone()),
        ServiceEvent::VerificationCompleted(verified),
        ServiceEvent::ServiceFailed(failure),
    ];
    for event in &events {
        let formatted = format!("{event:?}");
        for secret in [
            "tenant-binding",
            "nonce-sentinel",
            "answer-sentinel",
            "key-id-sentinel",
            "mac-sentinel",
            "token-sentinel",
        ] {
            assert!(!formatted.contains(secret));
        }
    }
    for error in [
        ServiceError::InvalidConfiguration,
        ServiceError::GenerationFailed,
        ServiceError::InvalidChallengeMaterial,
        ServiceError::InvalidAnswerEncoding,
        ServiceError::AnswerMismatch,
        ServiceError::UnsupportedGeneratorVersion,
        ServiceError::InternalError,
    ] {
        let formatted = format!("{error:?} {error}");
        assert!(!formatted.contains("adapter-arbitrary-text-sentinel"));
        assert!(!formatted.contains("private-material-sentinel"));
    }
    let mut observer = RecordingObserver::default();
    for event in &events {
        observer.observe(event);
    }
    assert_eq!(observer.event_count, 4);
    let ServiceEvent::ChallengeIssued(ChallengeIssuedEvent {
        challenge_id,
        generator_version,
        secret_length_bucket,
        fragment_count,
        question_byte_length,
        render_languages,
        has_distractor,
        candidate_attempts,
        duration,
    }) = &events[0]
    else {
        panic!("expected issued event")
    };
    assert_eq!(challenge_id, canonical_challenge_id);
    assert_eq!(generator_version, "1.0");
    assert_eq!(*secret_length_bucket, SecretLengthBucket::EightToTen);
    assert_eq!(*fragment_count, 2);
    assert_eq!(*question_byte_length, 64);
    assert_eq!(render_languages, &[RenderLanguage::Rust]);
    assert!(!has_distractor);
    assert_eq!(*candidate_attempts, 1);
    assert_eq!(*duration, Duration::from_millis(5));

    let ServiceEvent::VerificationCompleted(VerificationEvent {
        challenge_id,
        generator_version,
        disposition,
        elapsed_since_issue,
        duration,
    }) = &events[2]
    else {
        panic!("expected verification event")
    };
    assert_eq!(challenge_id, canonical_challenge_id);
    assert!(generator_version.is_none());
    assert_eq!(
        *disposition,
        VerificationDisposition::LifecycleRejected(LifecycleRejection::Expired)
    );
    assert_eq!(*elapsed_since_issue, Some(Duration::from_secs(1)));
    assert_eq!(*duration, Duration::from_millis(7));

    for event in [&events[1], &events[3]] {
        let (ServiceEvent::IssueFailed(ServiceFailureEvent {
            challenge_id,
            generator_version,
            stage,
            error,
            attempts,
            duration,
        })
        | ServiceEvent::ServiceFailed(ServiceFailureEvent {
            challenge_id,
            generator_version,
            stage,
            error,
            attempts,
            duration,
        })) = event
        else {
            panic!("expected failure event")
        };
        assert!(challenge_id.is_none());
        assert!(generator_version.is_none());
        assert_eq!(*stage, ServiceStage::LifecycleStore);
        assert_eq!(*error, ServiceError::InternalError);
        assert_eq!(*attempts, 2);
        assert_eq!(*duration, Duration::from_millis(6));
    }

    let _with_observer = ChallengeService::with_observer(MemoryLifecycle, StaticKeys, observer);
    let _with_noop_observer =
        ChallengeService::with_observer(MemoryLifecycle, StaticKeys, NoopObserver);
}
