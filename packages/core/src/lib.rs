#![forbid(unsafe_code)]

mod answer;
mod error;
mod mac;
mod verifier;

pub use agentgate_contracts as contracts;
pub use answer::canonicalize_answer;
pub use error::CoreError;
pub use mac::{MacContext, compute_answer_mac};
pub use verifier::verify_answer;
