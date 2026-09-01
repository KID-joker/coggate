use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    InvalidConfiguration,
    GenerationFailed,
    InvalidChallengeMaterial,
    InvalidAnswerEncoding,
    AnswerMismatch,
    UnsupportedGeneratorVersion,
    InternalError,
}

impl ServiceError {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRejection {
    NotFound,
    Expired,
    AlreadyConsumed,
    BindingMismatch,
    NonceMismatch,
    AttemptsExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAdapterError {
    Unavailable,
    Conflict,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginAttemptError {
    Rejected(LifecycleRejection),
    Adapter(LifecycleAdapterError),
}

impl From<LifecycleRejection> for BeginAttemptError {
    fn from(value: LifecycleRejection) -> Self {
        Self::Rejected(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderError {
    Unavailable,
    NotFound,
    InvalidMaterial,
}
