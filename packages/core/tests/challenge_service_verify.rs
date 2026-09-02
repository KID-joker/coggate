use std::{cell::RefCell, rc::Rc};

use agentgate_core::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, BeginAttemptError, ChallengeService,
    KeyProviderError, LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MacContext,
    MacKey, MacKeyProvider, PendingAttempt, PrivateChallengeMaterial, ServiceError, Submission,
    SubmissionIdentity, VerificationOutcome, VerifyRequest, compute_answer_mac,
    contracts::AnswerEncoding,
};

const OLD_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const ANSWER: &str = "YUI5MmtM";

fn material() -> PrivateChallengeMaterial {
    let context = MacContext {
        challenge_id: "challenge-1".to_owned(),
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
        challenge_id: "challenge-1".to_owned(),
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
        assert_eq!(identity.challenge_id(), "challenge-1");
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
        assert!(calls[0].starts_with("begin:challenge-1:bm9uY2U:tenant-binding:"));
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
        ),
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Key(OLD_KEY.to_vec()),
            wrong,
        ),
        (
            BeginBehavior::Pending(material()),
            KeyBehavior::Error(KeyProviderError::Unavailable),
            submission(),
        ),
    ];

    for (begin, keys, submitted) in scenarios {
        let (result, calls, active_calls) = run_scenario(
            begin,
            keys,
            Some(LifecycleAdapterError::Unavailable),
            &submitted,
        );
        assert_eq!(result, Err(ServiceError::InternalError));
        assert!(calls.last().unwrap().starts_with("finish:"));
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
    assert!(calls[0].starts_with("begin:challenge-1:bm9uY2U:tenant-binding:"));
    assert!(!calls[0].contains("answer-sentinel"));
    assert_eq!(active_calls, 0);
}
