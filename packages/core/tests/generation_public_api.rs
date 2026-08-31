use agentgate_core::generation::{
    MAX_QUESTION_BYTES, MAX_XOR_KEY_LENGTH, NodeId, Operation, RenderLanguage, RenderMetadata,
    RenderedQuestion, SemanticGraphBuilder, ValidatedSemanticGraph, evaluate_semantic_graph,
};

fn graph() -> ValidatedSemanticGraph {
    let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
    let first = builder.fragment(0).expect("first fragment exists");
    let second = builder.fragment(1).expect("second fragment exists");
    let third = builder.fragment(2).expect("third fragment exists");
    let reversed = builder.operation(Operation::Reverse, vec![first]);
    let rotated = builder.operation(Operation::RotateLeft(1), vec![second]);
    let joined = builder.operation(Operation::Concat, vec![reversed, rotated]);
    let output = builder.operation(Operation::Concat, vec![joined, third]);
    builder.output(output);
    builder.validate().expect("graph is valid")
}

#[test]
fn builds_and_inspects_a_validated_semantic_graph() {
    let graph = graph();

    assert_eq!(graph.output(), NodeId(6));
    assert_eq!(graph.operation_count(), 4);
    assert!(graph.node(NodeId(999)).is_none());
}

#[test]
fn evaluates_a_validated_semantic_graph() {
    let graph = graph();

    let value = evaluate_semantic_graph(
        &graph,
        &[b"ab".as_slice(), b"cd".as_slice(), b"ef".as_slice()],
    )
    .expect("validated graph evaluates");

    assert_eq!(value, b"badcef");
}

#[test]
fn exposes_the_v1_xor_key_length_limit() {
    assert_eq!(MAX_XOR_KEY_LENGTH, 16);
}

#[test]
fn exposes_read_only_renderer_diagnostics() {
    assert_eq!(RenderLanguage::ALL.len(), 6);
    assert!(std::hint::black_box(MAX_QUESTION_BYTES) >= 8_192);
    assert!(std::mem::size_of::<RenderMetadata>() > 0);
    assert!(std::mem::size_of::<RenderedQuestion>() > 0);
}
