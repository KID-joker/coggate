use std::fmt;

use agentgate_contracts::{PrivateChallengeMaterial, Submission};

use super::{LifecycleRejection, ServiceError};

pub const MAX_BINDING_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptLimit {
    One,
    Two,
}

pub struct IssueRequest<'a> {
    version: &'a str,
    binding: &'a [u8],
    attempt_limit: AttemptLimit,
}

impl<'a> IssueRequest<'a> {
    pub fn new(
        version: &'a str,
        binding: &'a [u8],
        attempt_limit: AttemptLimit,
    ) -> Result<Self, ServiceError> {
        let request = Self {
            version,
            binding,
            attempt_limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn v1(binding: &'a [u8]) -> Result<Self, ServiceError> {
        Self::new(
            agentgate_contracts::GENERATOR_VERSION_V1,
            binding,
            AttemptLimit::One,
        )
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub const fn attempt_limit(&self) -> AttemptLimit {
        self.attempt_limit
    }

    #[allow(dead_code)]
    pub(crate) fn binding(&self) -> &[u8] {
        self.binding
    }

    pub(crate) fn validate(&self) -> Result<(), ServiceError> {
        if self.binding.is_empty() || self.binding.len() > MAX_BINDING_BYTES {
            return Err(ServiceError::InvalidConfiguration);
        }
        Ok(())
    }
}

impl fmt::Debug for IssueRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssueRequest")
            .field("version", &self.version)
            .field("binding", &"[REDACTED]")
            .field("attempt_limit", &self.attempt_limit)
            .finish()
    }
}

pub struct VerifyRequest<'a> {
    submission: &'a Submission,
    binding: &'a [u8],
}

impl<'a> VerifyRequest<'a> {
    pub fn new(submission: &'a Submission, binding: &'a [u8]) -> Result<Self, ServiceError> {
        let request = Self {
            submission,
            binding,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn submission(&self) -> &Submission {
        self.submission
    }

    #[allow(dead_code)]
    pub(crate) fn binding(&self) -> &[u8] {
        self.binding
    }

    pub(crate) fn validate(&self) -> Result<(), ServiceError> {
        if self.binding.is_empty() || self.binding.len() > MAX_BINDING_BYTES {
            return Err(ServiceError::InvalidConfiguration);
        }
        Ok(())
    }
}

impl fmt::Debug for VerifyRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyRequest")
            .field(
                "submission",
                &SubmissionIdentity::from_submission(self.submission),
            )
            .field("binding", &"[REDACTED]")
            .finish()
    }
}

pub struct SubmissionIdentity<'a> {
    challenge_id: &'a str,
    nonce: &'a str,
}

impl<'a> SubmissionIdentity<'a> {
    pub const fn new(challenge_id: &'a str, nonce: &'a str) -> Self {
        Self {
            challenge_id,
            nonce,
        }
    }

    pub fn from_submission(submission: &'a Submission) -> Self {
        Self::new(&submission.challenge_id, &submission.nonce)
    }

    pub const fn challenge_id(&self) -> &str {
        self.challenge_id
    }

    pub const fn nonce(&self) -> &str {
        self.nonce
    }
}

impl fmt::Debug for SubmissionIdentity<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmissionIdentity")
            .field("challenge_id", &self.challenge_id)
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

#[allow(dead_code)]
pub struct PendingAttempt<T> {
    token: T,
    material: PrivateChallengeMaterial,
}

impl<T> PendingAttempt<T> {
    pub fn new(token: T, material: PrivateChallengeMaterial) -> Self {
        Self { token, material }
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts(self) -> (T, PrivateChallengeMaterial) {
        (self.token, self.material)
    }
}

impl<T> fmt::Debug for PendingAttempt<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAttempt")
            .field("token", &"[REDACTED]")
            .field("material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    Accepted,
    Rejected,
    SystemFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    Accepted,
    Rejected(LifecycleRejection),
}
