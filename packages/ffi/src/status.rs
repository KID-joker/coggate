#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgStatus {
    Ok = 0,
    InvalidConfiguration = 1,
    GenerationFailed = 2,
    InvalidChallengeMaterial = 3,
    InvalidAnswerEncoding = 4,
    AnswerMismatch = 5,
    UnsupportedGeneratorVersion = 6,
    InternalError = 7,
    InvalidArgument = 100,
    CallbackFailed = 101,
    PanicCaught = 102,
}

impl From<agentgate_core::ServiceError> for AgStatus {
    fn from(error: agentgate_core::ServiceError) -> Self {
        match error {
            agentgate_core::ServiceError::InvalidConfiguration => Self::InvalidConfiguration,
            agentgate_core::ServiceError::GenerationFailed => Self::GenerationFailed,
            agentgate_core::ServiceError::InvalidChallengeMaterial => {
                Self::InvalidChallengeMaterial
            }
            agentgate_core::ServiceError::InvalidAnswerEncoding => Self::InvalidAnswerEncoding,
            agentgate_core::ServiceError::AnswerMismatch => Self::AnswerMismatch,
            agentgate_core::ServiceError::UnsupportedGeneratorVersion => {
                Self::UnsupportedGeneratorVersion
            }
            agentgate_core::ServiceError::InternalError => Self::InternalError,
        }
    }
}
