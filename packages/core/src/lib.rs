#![forbid(unsafe_code)]

mod answer;
mod error;

pub use agentgate_contracts as contracts;
pub use answer::canonicalize_answer;
pub use error::CoreError;
