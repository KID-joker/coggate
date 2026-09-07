use std::fmt;

use agentgate_contracts::{PrivateChallengeMaterial, Submission};

use super::{LifecycleRejection, ServiceError};

/// Maximum byte length of an opaque lifecycle binding.
pub const MAX_BINDING_BYTES: usize = 256;

/// Closed V1 verification-attempt budget supplied to lifecycle storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptLimit {
    /// Permit one reserved verification attempt.
    One,
    /// Permit at most two reserved verification attempts.
    Two,
}

/// Borrowed parameters for issuing a challenge.
///
/// The binding is opaque, must contain 1 through [`MAX_BINDING_BYTES`] bytes,
/// is passed only to the lifecycle adapter, and is redacted from `Debug`.
pub struct IssueRequest<'a> {
    version: &'a str,
    binding: &'a [u8],
    attempt_limit: AttemptLimit,
}

impl<'a> IssueRequest<'a> {
    /// Creates a request for an explicit generator version after validating
    /// the binding. Version support is checked by the service during dispatch.
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

    /// Creates a V1 request with a one-attempt budget.
    pub fn v1(binding: &'a [u8]) -> Result<Self, ServiceError> {
        Self::new(
            agentgate_contracts::GENERATOR_VERSION_V1,
            binding,
            AttemptLimit::One,
        )
    }

    /// Returns the requested generator version.
    pub fn version(&self) -> &str {
        self.version
    }

    /// Returns the lifecycle attempt budget.
    pub const fn attempt_limit(&self) -> AttemptLimit {
        self.attempt_limit
    }

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

/// Borrowed parameters for verifying a submission.
///
/// The binding must contain 1 through [`MAX_BINDING_BYTES`] bytes and must
/// exactly match the value stored during issuance. Challenge IDs are bounded to
/// 128 bytes and nonces to 256 bytes before the lifecycle adapter is called. The
/// binding is redacted from `Debug`.
pub struct VerifyRequest<'a> {
    submission: &'a Submission,
    binding: &'a [u8],
}

impl<'a> VerifyRequest<'a> {
    /// Creates a verification request after validating binding and identity
    /// field bounds.
    pub fn new(submission: &'a Submission, binding: &'a [u8]) -> Result<Self, ServiceError> {
        let request = Self {
            submission,
            binding,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the submitted public protocol fields.
    pub fn submission(&self) -> &Submission {
        self.submission
    }

    pub(crate) fn binding(&self) -> &[u8] {
        self.binding
    }

    pub(crate) fn validate(&self) -> Result<(), ServiceError> {
        if self.binding.is_empty() || self.binding.len() > MAX_BINDING_BYTES {
            return Err(ServiceError::InvalidConfiguration);
        }
        if self.submission.challenge_id.len() > crate::mac::MAX_CHALLENGE_ID_BYTES
            || self.submission.nonce.len() > crate::mac::MAX_NONCE_BYTES
        {
            return Err(ServiceError::InvalidChallengeMaterial);
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

/// Borrowed public identity fields used for atomic lifecycle lookup.
///
/// The nonce is redacted from `Debug`; adapters must compare both fields
/// exactly before releasing private material.
pub struct SubmissionIdentity<'a> {
    challenge_id: &'a str,
    nonce: &'a str,
}

impl<'a> SubmissionIdentity<'a> {
    /// Creates an identity from an exact challenge ID and nonce pair.
    pub const fn new(challenge_id: &'a str, nonce: &'a str) -> Self {
        Self {
            challenge_id,
            nonce,
        }
    }

    /// Borrows identity fields from a submission.
    pub fn from_submission(submission: &'a Submission) -> Self {
        Self::new(&submission.challenge_id, &submission.nonce)
    }

    /// Returns the challenge identifier used for lifecycle lookup.
    pub const fn challenge_id(&self) -> &str {
        self.challenge_id
    }

    /// Returns the nonce that the adapter must compare exactly.
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

/// Private material and opaque token returned after atomically reserving an
/// attempt.
///
/// Both components are redacted from `Debug`. Dropping this value without
/// finalization must remain fail-closed according to [`crate::LifecycleAdapter`].
pub struct PendingAttempt<T> {
    token: T,
    material: PrivateChallengeMaterial,
}

impl<T> PendingAttempt<T> {
    /// Creates a pending attempt for adapter implementations.
    pub fn new(token: T, material: PrivateChallengeMaterial) -> Self {
        Self { token, material }
    }

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

/// Result that the service asks lifecycle storage to commit for a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    /// Core verification authenticated the submission.
    Accepted,
    /// Core verification rejected the submitted answer.
    Rejected,
    /// Verification could not complete after the attempt was reserved.
    SystemFailure,
}

/// Non-secret result of a completed service verification call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    /// Authentication succeeded and durable success consumption committed.
    Accepted,
    /// The lifecycle adapter rejected the attempt before core verification.
    Rejected(LifecycleRejection),
}
