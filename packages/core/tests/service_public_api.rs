use agentgate_core::{
    ActiveMacKey, AttemptLimit, BeginAttemptError, ChallengeService, IssueRequest,
    KeyProviderError, LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MacKey,
    MacKeyProvider, PrivateChallengeMaterial, Submission, SubmissionIdentity, VerifyRequest,
};

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
    ) -> Result<agentgate_core::PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
        Err(LifecycleRejection::NotFound.into())
    }

    fn finish_attempt(
        &mut self,
        _token: Self::AttemptToken,
        _outcome: agentgate_core::AttemptOutcome,
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

#[test]
fn public_service_contract_is_constructible_and_redacts_sensitive_values() {
    let mut service = ChallengeService::new(MemoryLifecycle, StaticKeys);
    let issue = IssueRequest::v1(b"tenant-binding").unwrap();
    let two_attempts = IssueRequest::new("1.0", b"tenant-binding", AttemptLimit::Two).unwrap();
    let submission = Submission {
        challenge_id: "challenge-1".to_owned(),
        nonce: "nonce-1".to_owned(),
        answer: "sensitive-answer".to_owned(),
    };
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
    assert!(format!("{issue:?}").contains("REDACTED"));
    assert!(!format!("{verify:?}").contains("sensitive-answer"));
    assert_eq!(
        format!("{:?}", MacKey::new(vec![9; 32]).unwrap()),
        "MacKey([REDACTED])"
    );
    assert_eq!(
        agentgate_core::ServiceError::AnswerMismatch.code(),
        "answer_mismatch"
    );
    assert_eq!(
        agentgate_core::ServiceError::InvalidConfiguration.code(),
        "invalid_configuration"
    );

    let _ = &mut service;
}
