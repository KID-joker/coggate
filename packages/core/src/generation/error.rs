#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum GenerationError {
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    #[error("operation parameters are invalid")]
    InvalidOperation,
    #[error("semantic graph contains duplicate node {0}")]
    DuplicateNode(u32),
    #[error("semantic graph references missing node {0}")]
    MissingNode(u32),
    #[error("semantic graph references invalid fragment {0}")]
    InvalidFragment(usize),
    #[error("semantic graph contains a cycle")]
    Cycle,
    #[error("semantic graph contains unreachable node {0}")]
    UnreachableNode(u32),
    #[error("semantic graph must declare exactly one output")]
    InvalidOutput,
    #[error("semantic graph has an invalid operation count")]
    InvalidOperationCount,
    #[error("semantic value length is invalid")]
    InvalidLength,
    #[error("semantic value encoding is invalid")]
    InvalidEncoding,
    #[error("semantic graph execution failed")]
    ExecutionFailed,
}
