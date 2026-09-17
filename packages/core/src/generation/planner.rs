use std::collections::{BTreeMap, BTreeSet};

use super::{
    GenerationError, NodeId, NodeKind, OperationFamily, OperationKind, SemanticGraphBuilder,
    ValidatedSemanticGraph, evaluate_semantic_graph,
    motifs::{build_motif, sample_motif},
    partition::partition_with,
    random::RandomSource,
    secret::Secret,
};

pub(crate) struct PlannedSemantics {
    graph: ValidatedSemanticGraph,
    fragments: Vec<Vec<u8>>,
    answer: Vec<u8>,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "retained as a planning invariant diagnostic")
    )]
    cross_fragment_dependency_count: usize,
}

impl PlannedSemantics {
    pub(crate) fn graph(&self) -> &ValidatedSemanticGraph {
        &self.graph
    }

    pub(crate) fn fragments(&self) -> &[Vec<u8>] {
        &self.fragments
    }

    pub(crate) fn answer(&self) -> &[u8] {
        &self.answer
    }
}

pub(crate) fn plan_with(
    secret: &Secret,
    random: &mut impl RandomSource,
) -> Result<PlannedSemantics, GenerationError> {
    let fragments = partition_with(secret.expose(), random)?;
    let mut builder = SemanticGraphBuilder::new(fragments.iter().map(Vec::len).collect());
    let fragment_nodes = (0..fragments.len())
        .map(|index| builder.fragment(index))
        .collect::<Result<Vec<_>, _>>()?;
    let fragment_lengths = fragments.iter().map(Vec::len).collect::<Vec<_>>();
    let motif = sample_motif(random)?;
    let output = build_motif(
        &mut builder,
        &fragment_nodes,
        &fragment_lengths,
        motif,
        random,
    )?;
    builder.output(output);

    let graph = builder.validate()?;
    let shape = validate_v1_shape(&graph)?;
    let fragment_slices = fragments.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let answer = evaluate_semantic_graph(&graph, &fragment_slices)?;

    Ok(PlannedSemantics {
        graph,
        fragments,
        answer,
        cross_fragment_dependency_count: shape.cross_fragment_dependency_count,
    })
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct V1Shape {
    pub(super) operation_count: usize,
    pub(super) operation_families: BTreeSet<OperationFamily>,
    pub(super) cross_fragment_dependency_count: usize,
    pub(super) has_nonlegacy_operation: bool,
    pub(super) directly_transformed_fragments: BTreeSet<usize>,
}

pub(super) fn validate_v1_shape(
    graph: &ValidatedSemanticGraph,
) -> Result<V1Shape, GenerationError> {
    let shape = analyze_v1_shape(graph)?;
    let all_fragments = (0..graph.fragment_lengths().len()).collect::<BTreeSet<_>>();
    if !(4..=8).contains(&shape.operation_count)
        || shape.operation_families.len() < 3
        || shape.cross_fragment_dependency_count < 2
        || !shape.has_nonlegacy_operation
        || shape.directly_transformed_fragments != all_fragments
    {
        return Err(GenerationError::ExecutionFailed);
    }

    Ok(shape)
}

fn analyze_v1_shape(graph: &ValidatedSemanticGraph) -> Result<V1Shape, GenerationError> {
    let mut provenance = BTreeMap::<NodeId, BTreeSet<usize>>::new();
    let mut shape = V1Shape {
        operation_count: 0,
        operation_families: BTreeSet::new(),
        cross_fragment_dependency_count: 0,
        has_nonlegacy_operation: false,
        directly_transformed_fragments: BTreeSet::new(),
    };

    for node in graph.topological_nodes() {
        let origins = match node.kind() {
            NodeKind::Fragment { index } => BTreeSet::from([*index]),
            NodeKind::Operation { operation, inputs } => {
                shape.operation_count += 1;
                let kind = OperationKind::from(operation);
                shape.operation_families.insert(kind.family());
                shape.has_nonlegacy_operation |= !kind.is_legacy();

                if kind.family() != OperationFamily::Composition {
                    for input in inputs {
                        if let Some(NodeKind::Fragment { index }) =
                            graph.node(*input).map(|input_node| input_node.kind())
                        {
                            shape.directly_transformed_fragments.insert(*index);
                        }
                    }
                }

                let mut origins = BTreeSet::new();
                for input in inputs {
                    let input_origins = provenance
                        .get(input)
                        .ok_or(GenerationError::ExecutionFailed)?;
                    origins.extend(input_origins.iter().copied());
                }
                if origins.len() >= 2 {
                    shape.cross_fragment_dependency_count += 1;
                }
                origins
            }
        };
        provenance.insert(node.id(), origins);
    }

    Ok(shape)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentgate_contracts::fragment_count_for_secret_length;

    use super::{PlannedSemantics, analyze_v1_shape, plan_with, validate_v1_shape};
    use crate::generation::{
        GenerationError, NodeId, NodeKind, Operation, SemanticGraphBuilder, ValidatedSemanticGraph,
        evaluate_semantic_graph, secret::Secret, test_random::DeterministicRandom,
    };

    fn ascii_secret(length: usize) -> Secret {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Secret::from_test_bytes(
            (0..length)
                .map(|index| alphabet[index % alphabet.len()])
                .collect(),
        )
    }

    fn assert_plan_contracts(plan: &PlannedSemantics, secret: &Secret) {
        assert_eq!(plan.fragments.concat(), secret.expose());
        assert!(plan.fragments.iter().all(|fragment| !fragment.is_empty()));
        assert_eq!(
            plan.fragments.len(),
            usize::from(fragment_count_for_secret_length(secret.len() as u8).unwrap())
        );
        let shape = validate_v1_shape(&plan.graph).unwrap();
        assert!((4..=8).contains(&shape.operation_count));
        assert!(shape.operation_families.len() >= 3);
        assert!(shape.cross_fragment_dependency_count >= 2);
        assert_eq!(
            plan.cross_fragment_dependency_count,
            shape.cross_fragment_dependency_count
        );
        assert!(shape.has_nonlegacy_operation);
        assert_eq!(
            shape.directly_transformed_fragments,
            (0..plan.fragments.len()).collect()
        );

        let fragments: Vec<&[u8]> = plan.fragments.iter().map(Vec::as_slice).collect();
        assert_eq!(
            evaluate_semantic_graph(&plan.graph, &fragments).unwrap(),
            plan.answer
        );
        assert!(plan.graph.topological_nodes().iter().all(|node| {
            matches!(
                node.kind(),
                NodeKind::Fragment { .. } | NodeKind::Operation { .. }
            )
        }));
    }

    #[test]
    fn plans_every_supported_ascii_secret_for_many_random_streams() {
        for length in 8..=16 {
            let secret = ascii_secret(length);
            for seed in 0_u8..=u8::MAX {
                let mut random = DeterministicRandom::new([seed; 32]);
                let plan = plan_with(&secret, &mut random).unwrap();
                assert_plan_contracts(&plan, &secret);
            }
        }
    }

    #[test]
    fn planning_is_deterministic_for_the_same_secret_and_random_stream() {
        let secret = Secret::from_test_bytes(b"AbCdEf12Gh".to_vec());
        let mut first_random = DeterministicRandom::new([7; 32]);
        let mut second_random = DeterministicRandom::new([7; 32]);

        let first = plan_with(&secret, &mut first_random).unwrap();
        let second = plan_with(&secret, &mut second_random).unwrap();

        assert_eq!(first.graph, second.graph);
        assert_eq!(first.fragments, second.fragments);
        assert_eq!(first.answer, second.answer);
        assert_eq!(
            first.cross_fragment_dependency_count,
            second.cross_fragment_dependency_count
        );
    }

    fn three_fragment_builder() -> (SemanticGraphBuilder, [NodeId; 3]) {
        let builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
        let fragments = [
            builder.fragment(0).unwrap(),
            builder.fragment(1).unwrap(),
            builder.fragment(2).unwrap(),
        ];
        (builder, fragments)
    }

    fn graph_with_insufficient_families() -> ValidatedSemanticGraph {
        let (mut builder, [first, second, third]) = three_fragment_builder();
        let first = builder.operation(Operation::Slice { start: 0, end: 1 }, vec![first]);
        let second = builder.operation(Operation::Reverse, vec![second]);
        let third = builder.operation(Operation::Reverse, vec![third]);
        let joined = builder.operation(Operation::Concat, vec![first, second, third]);
        let output = builder.operation(Operation::RotateLeftDerived, vec![joined, first]);
        builder.output(output);
        builder.validate().unwrap()
    }

    fn graph_without_nonlegacy_kind() -> ValidatedSemanticGraph {
        let (mut builder, [first, second, third]) = three_fragment_builder();
        let first = builder.operation(Operation::Reverse, vec![first]);
        let second = builder.operation(Operation::Xor(vec![0xA5]), vec![second]);
        let third = builder.operation(Operation::Sha256Prefix(2), vec![third]);
        let joined = builder.operation(Operation::Concat, vec![first, second, third]);
        let output = builder.operation(Operation::RotateLeftDerived, vec![joined, first]);
        builder.output(output);
        builder.validate().unwrap()
    }

    fn graph_with_untransformed_fragment() -> ValidatedSemanticGraph {
        let (mut builder, [first, second, third]) = three_fragment_builder();
        let first = builder.operation(Operation::Slice { start: 0, end: 1 }, vec![first]);
        let second = builder.operation(Operation::Xor(vec![0xA5]), vec![second]);
        let joined = builder.operation(Operation::Concat, vec![first, second, third]);
        let digest = builder.operation(Operation::Sha256Prefix(2), vec![joined]);
        let output = builder.operation(Operation::RotateLeftDerived, vec![digest, first]);
        builder.output(output);
        builder.validate().unwrap()
    }

    fn graph_with_one_cross_fragment_node() -> ValidatedSemanticGraph {
        let (mut builder, [first, second, third]) = three_fragment_builder();
        let first = builder.operation(Operation::Slice { start: 0, end: 1 }, vec![first]);
        let second = builder.operation(Operation::Xor(vec![0xA5]), vec![second]);
        let third = builder.operation(Operation::Sha256Prefix(2), vec![third]);
        let output = builder.operation(Operation::Concat, vec![first, second, third]);
        builder.output(output);
        builder.validate().unwrap()
    }

    #[test]
    fn v1_shape_rejects_insufficient_operation_families() {
        let graph = graph_with_insufficient_families();
        let shape = analyze_v1_shape(&graph).unwrap();
        assert!((4..=8).contains(&shape.operation_count));
        assert!(shape.operation_families.len() < 3);
        assert!(shape.cross_fragment_dependency_count >= 2);
        assert!(shape.has_nonlegacy_operation);
        assert_eq!(
            shape.directly_transformed_fragments,
            BTreeSet::from([0, 1, 2])
        );
        assert_eq!(
            validate_v1_shape(&graph),
            Err(GenerationError::ExecutionFailed)
        );
    }

    #[test]
    fn v1_shape_rejects_missing_nonlegacy_operation() {
        let graph = graph_without_nonlegacy_kind();
        let shape = analyze_v1_shape(&graph).unwrap();
        assert!((4..=8).contains(&shape.operation_count));
        assert!(shape.operation_families.len() >= 3);
        assert!(shape.cross_fragment_dependency_count >= 2);
        assert!(!shape.has_nonlegacy_operation);
        assert_eq!(
            shape.directly_transformed_fragments,
            BTreeSet::from([0, 1, 2])
        );
        assert_eq!(
            validate_v1_shape(&graph),
            Err(GenerationError::ExecutionFailed)
        );
    }

    #[test]
    fn v1_shape_rejects_a_source_fragment_without_direct_transformation() {
        let graph = graph_with_untransformed_fragment();
        let shape = analyze_v1_shape(&graph).unwrap();
        assert!((4..=8).contains(&shape.operation_count));
        assert!(shape.operation_families.len() >= 3);
        assert!(shape.cross_fragment_dependency_count >= 2);
        assert!(shape.has_nonlegacy_operation);
        assert_eq!(shape.directly_transformed_fragments, BTreeSet::from([0, 1]));
        assert_eq!(
            validate_v1_shape(&graph),
            Err(GenerationError::ExecutionFailed)
        );
    }

    #[test]
    fn v1_shape_rejects_insufficient_cross_fragment_nodes() {
        let graph = graph_with_one_cross_fragment_node();
        let shape = analyze_v1_shape(&graph).unwrap();
        assert!((4..=8).contains(&shape.operation_count));
        assert!(shape.operation_families.len() >= 3);
        assert_eq!(shape.cross_fragment_dependency_count, 1);
        assert!(shape.has_nonlegacy_operation);
        assert_eq!(
            shape.directly_transformed_fragments,
            BTreeSet::from([0, 1, 2])
        );
        assert_eq!(
            validate_v1_shape(&graph),
            Err(GenerationError::ExecutionFailed)
        );
    }
}
