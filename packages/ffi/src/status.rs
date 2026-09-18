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

impl From<coggate_core::ServiceError> for AgStatus {
    fn from(error: coggate_core::ServiceError) -> Self {
        match error {
            coggate_core::ServiceError::InvalidConfiguration => Self::InvalidConfiguration,
            coggate_core::ServiceError::GenerationFailed => Self::GenerationFailed,
            coggate_core::ServiceError::InvalidChallengeMaterial => Self::InvalidChallengeMaterial,
            coggate_core::ServiceError::InvalidAnswerEncoding => Self::InvalidAnswerEncoding,
            coggate_core::ServiceError::AnswerMismatch => Self::AnswerMismatch,
            coggate_core::ServiceError::UnsupportedGeneratorVersion => {
                Self::UnsupportedGeneratorVersion
            }
            coggate_core::ServiceError::InternalError => Self::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use coggate_core::ServiceError;

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
