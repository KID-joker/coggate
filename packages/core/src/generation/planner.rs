use std::collections::{BTreeMap, BTreeSet};

use super::{
    GenerationError, NodeId, NodeKind, Operation, SemanticGraphBuilder, ValidatedSemanticGraph,
    evaluate_semantic_graph,
    partition::partition_with,
    random::{RandomSource, sample_below, shuffle},
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

    let transformed_nodes = fragment_nodes
        .into_iter()
        .map(|fragment| {
            let operation = match sample_below(random, 4)? {
                0 => Operation::Reverse,
                1 => Operation::RotateLeft(1),
                2 => Operation::RotateRight(1),
                3 => Operation::Xor(vec![sample_below(random, 256)? as u8]),
                _ => return Err(GenerationError::ExecutionFailed),
            };
            Ok(builder.operation(operation, vec![fragment]))
        })
        .collect::<Result<Vec<_>, GenerationError>>()?;

    let mut concat_inputs = transformed_nodes.clone();
    shuffle(random, &mut concat_inputs)?;
    let concat = builder.operation(Operation::Concat, concat_inputs);
    let first_transformed = *transformed_nodes
        .first()
        .ok_or(GenerationError::ExecutionFailed)?;
    let mut output = builder.operation(
        Operation::RotateLeftDerived,
        vec![concat, first_transformed],
    );

    if fragments.len() == 3 || fragments.len() == 4 {
        output = builder.operation(Operation::Sha256Prefix(secret.len()), vec![output]);
    }
    builder.output(output);

    let graph = builder.validate()?;
    let fragment_slices = fragments.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let answer = evaluate_semantic_graph(&graph, &fragment_slices)?;
    let cross_fragment_dependency_count = cross_fragment_dependency_count(&graph)?;
    if cross_fragment_dependency_count < 2 {
        return Err(GenerationError::ExecutionFailed);
    }

    Ok(PlannedSemantics {
        graph,
        fragments,
        answer,
        cross_fragment_dependency_count,
    })
}

fn cross_fragment_dependency_count(
    graph: &ValidatedSemanticGraph,
) -> Result<usize, GenerationError> {
    let mut provenance = BTreeMap::<NodeId, BTreeSet<usize>>::new();
    let mut cross_fragment_dependencies = 0;

    for node in graph.topological_nodes() {
        let origins = match node.kind() {
            NodeKind::Fragment { index } => BTreeSet::from([*index]),
            NodeKind::Operation { inputs, .. } => {
                let mut origins = BTreeSet::new();
                for input in inputs {
                    let input_origins = provenance
                        .get(input)
                        .ok_or(GenerationError::ExecutionFailed)?;
                    origins.extend(input_origins.iter().copied());
                }
                if origins.len() >= 2 {
                    cross_fragment_dependencies += 1;
                }
                origins
            }
        };
        provenance.insert(node.id(), origins);
    }

    Ok(cross_fragment_dependencies)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use agentgate_contracts::fragment_count_for_secret_length;

    use super::{PlannedSemantics, plan_with};
    use crate::generation::{
        NodeId, NodeKind, Operation, evaluate_semantic_graph, secret::Secret,
        test_random::DeterministicRandom,
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
        assert!((4..=8).contains(&plan.graph.operation_count()));
        let expected_operation_count = match plan.fragments.len() {
            3 => 6,
            4 => 7,
            5 => 7,
            _ => unreachable!(),
        };
        assert_eq!(plan.graph.operation_count(), expected_operation_count);
        let recomputed_cross_fragment_dependency_count =
            recompute_cross_fragment_dependencies(plan);
        assert!(recomputed_cross_fragment_dependency_count >= 2);
        assert_eq!(
            plan.cross_fragment_dependency_count,
            recomputed_cross_fragment_dependency_count
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

    fn recompute_cross_fragment_dependencies(plan: &PlannedSemantics) -> usize {
        let mut provenance = BTreeMap::<NodeId, BTreeSet<usize>>::new();
        let mut count = 0;

        for node in plan.graph.topological_nodes() {
            let origins = match node.kind() {
                NodeKind::Fragment { index } => BTreeSet::from([*index]),
                NodeKind::Operation { inputs, .. } => {
                    let origins = inputs
                        .iter()
                        .flat_map(|input| {
                            provenance
                                .get(input)
                                .expect("topological input provenance exists")
                                .iter()
                                .copied()
                        })
                        .collect::<BTreeSet<_>>();
                    if origins.len() >= 2 {
                        count += 1;
                    }
                    origins
                }
            };
            provenance.insert(node.id(), origins);
        }

        count
    }

    fn operation_pattern(plan: &PlannedSemantics) -> Vec<(Operation, Vec<NodeId>)> {
        plan.graph
            .topological_nodes()
            .iter()
            .filter_map(|node| match node.kind() {
                NodeKind::Fragment { .. } => None,
                NodeKind::Operation { operation, inputs } => {
                    Some((operation.clone(), inputs.clone()))
                }
            })
            .collect()
    }

    fn randomized_structure_pattern(plan: &PlannedSemantics) -> (Vec<&'static str>, Vec<NodeId>) {
        let mut unary_sequence = Vec::new();
        let mut concat_inputs = Vec::new();

        for node in plan.graph.topological_nodes() {
            let NodeKind::Operation { operation, inputs } = node.kind() else {
                continue;
            };
            match operation {
                Operation::Reverse => unary_sequence.push("reverse"),
                Operation::RotateLeft(1) => unary_sequence.push("rotate-left-one"),
                Operation::RotateRight(1) => unary_sequence.push("rotate-right-one"),
                Operation::Xor(_) => unary_sequence.push("xor"),
                Operation::Concat => concat_inputs.clone_from(inputs),
                _ => {}
            }
        }

        (unary_sequence, concat_inputs)
    }

    #[test]
    fn plans_every_supported_ascii_secret_for_many_random_streams() {
        for length in 8..=16 {
            let secret = ascii_secret(length);
            for seed in 0_u8..=127 {
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

    #[test]
    fn planning_varies_the_unary_operations_or_concat_order_across_streams() {
        let secret = Secret::from_test_bytes(b"AbCdEf12Gh".to_vec());
        let mut operation_patterns = Vec::new();
        let mut randomized_structure_patterns = BTreeSet::new();

        for seed in 0_u8..=127 {
            let mut random = DeterministicRandom::new([seed; 32]);
            let plan = plan_with(&secret, &mut random).unwrap();
            let operation_pattern = operation_pattern(&plan);
            if !operation_patterns.contains(&operation_pattern) {
                operation_patterns.push(operation_pattern);
            }
            randomized_structure_patterns.insert(randomized_structure_pattern(&plan));
        }

        assert!(operation_patterns.len() > 1);
        assert!(randomized_structure_patterns.len() > 1);
    }
}
