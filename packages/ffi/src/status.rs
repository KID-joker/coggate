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

#[cfg(test)]
mod tests {
    use agentgate_core::ServiceError;

    use super::AgStatus;

    #[test]
    fn every_service_error_maps_to_its_exact_abi_status() {
        let cases = [
            (
                ServiceError::InvalidConfiguration,
                AgStatus::InvalidConfiguration,
            ),
            (ServiceError::GenerationFailed, AgStatus::GenerationFailed),
            (
                ServiceError::InvalidChallengeMaterial,
                AgStatus::InvalidChallengeMaterial,
            ),
            (
                ServiceError::InvalidAnswerEncoding,
                AgStatus::InvalidAnswerEncoding,
            ),
            (ServiceError::AnswerMismatch, AgStatus::AnswerMismatch),
            (
                ServiceError::UnsupportedGeneratorVersion,
                AgStatus::UnsupportedGeneratorVersion,
            ),
            (ServiceError::InternalError, AgStatus::InternalError),
        ];

        for (error, expected) in cases {
            assert_eq!(AgStatus::from(error), expected, "{}", error.code());
        }
    }
}
