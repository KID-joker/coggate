mod answer;
mod candidate;
mod error;
mod graph;
mod operation;
mod operation_kind;
mod partition;
mod planner;
#[allow(
    dead_code,
    reason = "OsRandom is constructed by the Phase 4 challenge service"
)]
mod random;
mod render;
mod secret;

#[cfg(any(test, feature = "insecure-benchmarking"))]
mod test_random;

#[cfg(any(test, feature = "insecure-benchmarking"))]
pub(crate) use test_random::DeterministicRandom;

#[cfg(feature = "insecure-benchmarking")]
mod benchmark;
#[cfg(feature = "insecure-benchmarking")]
pub use benchmark::{BenchmarkCase, BenchmarkError, BenchmarkOracle, generate_benchmark_case};

pub use answer::evaluate_semantic_graph;
pub(crate) use candidate::{
    CandidateError, generate_candidate_with, retry_candidates_with_attempts,
};
pub use error::GenerationError;
pub use graph::{NodeId, NodeKind, SemanticGraphBuilder, SemanticNode, ValidatedSemanticGraph};
pub use operation::{MAX_CONCAT_INPUTS, MAX_PERMUTATION_LENGTH, MAX_XOR_KEY_LENGTH, Operation};
#[allow(
    unused_imports,
    reason = "Operation taxonomy is consumed by diversity planning"
)]
pub(crate) use operation_kind::{OperationFamily, OperationKind};
pub(crate) use random::{OsRandom, RandomSource};
pub use render::{MAX_QUESTION_BYTES, RenderLanguage, RenderMetadata, RenderedQuestion};
