use agentgate_core::generation::{NodeId, Operation, SemanticGraphBuilder};

#[test]
fn builds_and_inspects_a_validated_semantic_graph() {
    let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
    let first = builder.fragment(0).expect("first fragment exists");
    let second = builder.fragment(1).expect("second fragment exists");
    let third = builder.fragment(2).expect("third fragment exists");
    let reversed = builder.operation(Operation::Reverse, vec![first]);
    let rotated = builder.operation(Operation::RotateLeft(1), vec![second]);
    let joined = builder.operation(Operation::Concat, vec![reversed, rotated]);
    let output = builder.operation(Operation::Concat, vec![joined, third]);
    builder.output(output);

    let graph = builder.validate().expect("graph is valid");

    assert_eq!(graph.output(), output);
    assert_eq!(graph.operation_count(), 4);
    assert!(graph.node(NodeId(999)).is_none());
}
