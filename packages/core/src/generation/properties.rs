#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentgate_contracts::{GENERATOR_VERSION_V1, fragment_count_for_secret_length};

    use crate::generation::{
        NodeKind, OperationKind, ValidatedSemanticGraph, evaluate_semantic_graph,
        planner::{plan_with, validate_v1_shape},
        secret::Secret,
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

    fn operation_kinds(graph: &ValidatedSemanticGraph) -> Vec<OperationKind> {
        graph
            .topological_nodes()
            .iter()
            .filter_map(|node| match node.kind() {
                NodeKind::Fragment { .. } => None,
                NodeKind::Operation { operation, .. } => Some(OperationKind::from(operation)),
            })
            .collect()
    }

    #[test]
    fn fixed_seed_matrix_preserves_v1_invariants_and_reaches_the_exact_operation_catalog() {
        let mut observed_kinds = BTreeSet::new();

        for length in 8..=16 {
            let secret = ascii_secret(length);
            for seed in 0_u8..=u8::MAX {
                let mut random = DeterministicRandom::new([seed; 32]);
                let plan = plan_with(&secret, &mut random).expect("matrix plan succeeds");
                let mut replay_random = DeterministicRandom::new([seed; 32]);
                let replay =
                    plan_with(&secret, &mut replay_random).expect("matrix replay succeeds");

                assert_eq!(plan.fragments().concat(), secret.expose());
                assert!(plan.fragments().iter().all(|fragment| !fragment.is_empty()));
                assert_eq!(
                    plan.fragments().len(),
                    usize::from(fragment_count_for_secret_length(length as u8).unwrap())
                );
                assert!((4..=8).contains(&plan.graph().operation_count()));

                let kinds = operation_kinds(plan.graph());
                observed_kinds.extend(kinds);
                let shape = validate_v1_shape(plan.graph()).unwrap();
                let replay_shape = validate_v1_shape(replay.graph()).unwrap();
                assert!((4..=8).contains(&shape.operation_count));
                assert!(shape.operation_families.len() >= 3);
                assert!(shape.cross_fragment_dependency_count >= 2);
                assert!(shape.has_nonlegacy_operation);
                assert_eq!(
                    shape.directly_transformed_fragments,
                    (0..plan.fragments().len()).collect()
                );
                assert_eq!(plan.graph(), replay.graph());
                assert_eq!(plan.fragments(), replay.fragments());
                assert_eq!(plan.answer(), replay.answer());
                assert_eq!(shape, replay_shape);

                let fragments = plan
                    .fragments()
                    .iter()
                    .map(Vec::as_slice)
                    .collect::<Vec<_>>();
                assert_eq!(
                    evaluate_semantic_graph(plan.graph(), &fragments).unwrap(),
                    plan.answer()
                );
            }
        }

        assert_eq!(
            observed_kinds,
            OperationKind::ALL.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn operation_diversity_does_not_change_the_v1_generator_version() {
        assert_eq!(GENERATOR_VERSION_V1, "1.0");
    }
}
