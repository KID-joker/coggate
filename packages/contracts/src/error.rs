use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("difficulty is reserved by this generator version")]
    UnsupportedDifficulty,
}
