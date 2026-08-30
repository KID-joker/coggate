#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CoreError {
    #[error("answer does not use the required canonical encoding")]
    InvalidAnswerEncoding,
    #[error("verification material is invalid")]
    InvalidChallengeMaterial,
    #[error("answer does not match")]
    AnswerMismatch,
}
