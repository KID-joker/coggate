mod answer;
mod candidate;
mod error;
mod graph;
mod operation;
mod partition;
mod planner;
#[allow(
    dead_code,
    reason = "OsRandom is constructed by the Phase 4 challenge service"
)]
mod random;
mod render;
mod secret;

#[cfg(test)]
mod test_random;

pub use answer::evaluate_semantic_graph;
pub(crate) use candidate::{
    CandidateError, generate_candidate_with, retry_candidates_with_attempts,
};
pub use error::GenerationError;
pub use graph::{NodeId, NodeKind, SemanticGraphBuilder, SemanticNode, ValidatedSemanticGraph};
pub use operation::{MAX_CONCAT_INPUTS, MAX_PERMUTATION_LENGTH, MAX_XOR_KEY_LENGTH, Operation};
pub(crate) use random::{OsRandom, RandomSource};
pub use render::{MAX_QUESTION_BYTES, RenderLanguage, RenderMetadata, RenderedQuestion};
