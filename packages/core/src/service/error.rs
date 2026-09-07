use std::fmt;

/// Stable failures returned by [`crate::ChallengeService`].
///
/// The variants deliberately carry no provider, adapter, request, or secret
/// text. Integrators may safely classify them by [`ServiceError::code`], but
/// should avoid exposing distinctions such as answer mismatch to an untrusted
/// caller when doing so would create an oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// A caller-supplied option or provider-supplied active key is invalid.
    InvalidConfiguration,
    /// Challenge generation or its cryptographic randomness failed.
    GenerationFailed,
    /// Persisted private challenge material is malformed or inconsistent.
    InvalidChallengeMaterial,
    /// The submitted answer is not canonical unpadded base64url.
    InvalidAnswerEncoding,
    /// The submitted answer does not authenticate against the stored material.
    AnswerMismatch,
    /// The requested or persisted generator version is unsupported.
    UnsupportedGeneratorVersion,
    /// A clock, adapter, key lookup, finalization, or internal invariant failed.
    InternalError,
}

impl ServiceError {
    /// Returns the stable, lowercase identifier for this category.
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

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ServiceError {}

/// Stable reasons why a lifecycle adapter rejected an attempt before
/// verification began.
///
/// These values contain no adapter-provided text. Hosts may collapse all
/// variants into one external rejection response to avoid disclosing lifecycle
/// state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRejection {
    /// No record exists for the supplied challenge identifier.
    NotFound,
    /// The challenge has expired.
    Expired,
    /// The record is already consumed, or an attempt is currently reserved and
    /// the same challenge cannot be reused while that attempt is in flight.
    AlreadyConsumed,
    /// The presented opaque binding does not exactly match the stored binding.
    BindingMismatch,
    /// The presented nonce does not exactly match the stored nonce.
    NonceMismatch,
    /// No verification attempt remains.
    AttemptsExhausted,
}

/// Stable failure categories produced by a [`crate::LifecycleAdapter`].
///
/// Adapter-specific errors and messages remain inside the adapter's own
/// operational boundary and must not contain secrets when logged there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAdapterError {
    /// The backing lifecycle system is temporarily unavailable.
    Unavailable,
    /// The requested transition conflicts with stored state.
    Conflict,
    /// The adapter encountered an internal failure.
    Internal,
}

/// Result error from [`crate::LifecycleAdapter::begin_attempt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginAttemptError {
    /// A normal, structured lifecycle rejection.
    Rejected(LifecycleRejection),
    /// An infrastructure or persistence failure.
    Adapter(LifecycleAdapterError),
}

impl From<LifecycleRejection> for BeginAttemptError {
    fn from(value: LifecycleRejection) -> Self {
        Self::Rejected(value)
    }
}

/// Stable failure categories produced by a [`crate::MacKeyProvider`].
///
/// Provider-specific messages and key identifiers are intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderError {
    /// The key provider is temporarily unavailable.
    Unavailable,
    /// The exact requested key identifier is unavailable.
    NotFound,
    /// A key or active key identifier violates the public key contract.
    InvalidMaterial,
}
