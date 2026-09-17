use thiserror::Error;

use crate::generation::{GenerationError, NodeId};

#[derive(Debug, Eq, Error, PartialEq)]
#[allow(dead_code)]
pub(crate) enum RenderError {
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    #[error("renderer identifier namespace exhausted")]
    NameExhausted,
    #[error("invalid render plan")]
    InvalidPlan,
    #[error("render plan references missing node {0:?}")]
    MissingReference(NodeId),
    #[error("render plan contains duplicate node reference {0:?}")]
    DuplicateReference(NodeId),
    #[error("render plan does not match semantic node {0:?}")]
    SemanticMismatch(NodeId),
    #[error("render plan output is ambiguous")]
    AmbiguousOutput,
    #[error("render template is unsupported")]
    UnsupportedTemplate,
    #[error("rendered question exceeds the length limit")]
    LengthLimit,
}

impl RenderError {
    pub(super) fn from_generation_error(error: GenerationError) -> Self {
        match error {
            GenerationError::RandomnessUnavailable => Self::RandomnessUnavailable,
            _ => Self::InvalidPlan,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RenderError;
    use crate::generation::NodeId;

    const SECRET_MARKER: &str = "SECRET_MARKER";

    #[test]
    fn every_error_has_safe_display_text() {
        let errors = [
            RenderError::RandomnessUnavailable,
            RenderError::NameExhausted,
            RenderError::InvalidPlan,
            RenderError::MissingReference(NodeId(1)),
            RenderError::DuplicateReference(NodeId(2)),
            RenderError::SemanticMismatch(NodeId(3)),
            RenderError::AmbiguousOutput,
            RenderError::UnsupportedTemplate,
            RenderError::LengthLimit,
        ];

        for error in errors {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(!display.is_empty());
            assert!(!display.contains(SECRET_MARKER));
            assert!(!debug.contains(SECRET_MARKER));
        }
    }
}
