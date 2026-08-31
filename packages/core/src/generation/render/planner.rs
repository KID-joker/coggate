use crate::generation::{
    NodeKind, ValidatedSemanticGraph,
    random::{RandomSource, sample_below, shuffle},
};

use super::{
    error::RenderError,
    model::{
        DisplayFragment, DisplayStep, DisplayStepKind, RenderLanguage, RenderPlan, TemplateFamily,
    },
    names::NameAllocator,
};

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the Phase 4 lifecycle API")
)]
pub(super) fn plan_rendering(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
    random: &mut impl RandomSource,
) -> Result<RenderPlan, RenderError> {
    validate_inputs(graph, fragments)?;

    let language_count = 2 + sample(random, 2)?;
    let mut languages = RenderLanguage::ALL;
    shuffle(random, &mut languages).map_err(|_| RenderError::InvalidPlan)?;
    let selected_languages = &languages[..language_count];

    let mut assigned_languages = (0..fragments.len())
        .map(|index| selected_languages[index % language_count])
        .collect::<Vec<_>>();
    shuffle(random, &mut assigned_languages).map_err(|_| RenderError::InvalidPlan)?;

    let has_distractor = sample(random, 2)? == 1;
    let templates = (0..graph.topological_nodes().len())
        .map(|_| {
            sample(random, 2).map(|choice| match choice {
                0 => TemplateFamily::Direct,
                _ => TemplateFamily::Helper,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let allocated_name_count =
        graph.topological_nodes().len() * 2 + fragments.len() + usize::from(has_distractor);
    let allocated_names = {
        let mut allocator = NameAllocator::new(random);
        (0..allocated_name_count)
            .map(|_| allocator.allocate_identifier())
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut names = allocated_names.into_iter();

    let steps = graph
        .topological_nodes()
        .iter()
        .zip(templates)
        .map(|(node, template)| {
            let output_label = names.next().ok_or(RenderError::InvalidPlan)?;
            let local_name = names.next().ok_or(RenderError::InvalidPlan)?;
            let kind = match node.kind() {
                NodeKind::Fragment { index } => DisplayStepKind::Fragment { index: *index },
                NodeKind::Operation { operation, inputs } => DisplayStepKind::Operation {
                    operation: operation.clone(),
                    inputs: inputs.clone(),
                },
            };
            Ok(DisplayStep {
                node: node.id(),
                output_label,
                local_name,
                template,
                kind,
            })
        })
        .collect::<Result<Vec<_>, RenderError>>()?;

    let step_count = steps.len();
    let fragment_count = fragments.len();
    let base_chunk_size = step_count / fragment_count;
    let larger_chunk_count = step_count % fragment_count;
    let mut steps = steps.into_iter();
    let mut display_fragments = Vec::with_capacity(fragment_count + usize::from(has_distractor));

    for (index, language) in assigned_languages.into_iter().enumerate() {
        let chunk_size = base_chunk_size + usize::from(index < larger_chunk_count);
        let chunk = steps.by_ref().take(chunk_size).collect::<Vec<_>>();
        if chunk.len() != chunk_size || chunk.is_empty() {
            return Err(RenderError::InvalidPlan);
        }
        display_fragments.push(DisplayFragment {
            heading: names.next().ok_or(RenderError::InvalidPlan)?,
            language,
            steps: chunk,
            distractor: false,
        });
    }
    if steps.next().is_some() {
        return Err(RenderError::InvalidPlan);
    }

    if has_distractor {
        display_fragments.push(DisplayFragment {
            heading: names.next().ok_or(RenderError::InvalidPlan)?,
            language: selected_languages[0],
            steps: Vec::new(),
            distractor: true,
        });
    }
    if names.next().is_some() {
        return Err(RenderError::InvalidPlan);
    }

    shuffle(random, &mut display_fragments).map_err(|_| RenderError::InvalidPlan)?;
    Ok(RenderPlan {
        fragments: display_fragments,
        output: graph.output(),
    })
}

fn validate_inputs(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
) -> Result<(), RenderError> {
    if fragments.len() != graph.fragment_lengths().len()
        || !(3..=5).contains(&fragments.len())
        || !(4..=8).contains(&graph.operation_count())
    {
        return Err(RenderError::InvalidPlan);
    }

    let valid_fragments =
        fragments
            .iter()
            .zip(graph.fragment_lengths())
            .all(|(fragment, declared_length)| {
                fragment.len() == *declared_length
                    && !fragment.is_empty()
                    && fragment.len() <= 16
                    && fragment.iter().all(u8::is_ascii_alphanumeric)
            });
    if !valid_fragments {
        return Err(RenderError::InvalidPlan);
    }

    Ok(())
}

fn sample(random: &mut impl RandomSource, upper: usize) -> Result<usize, RenderError> {
    sample_below(random, upper).map_err(|_| RenderError::InvalidPlan)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::plan_rendering;
    use crate::generation::{
        NodeId, NodeKind, Operation, SemanticGraphBuilder, ValidatedSemanticGraph,
        render::{
            error::RenderError,
            model::{DisplayStepKind, RenderPlan},
            names::MAX_IDENTIFIER_BYTES,
        },
        test_random::DeterministicRandom,
    };

    fn valid_graph() -> ValidatedSemanticGraph {
        let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
        let first = builder.fragment(0).unwrap();
        let second = builder.fragment(1).unwrap();
        let third = builder.fragment(2).unwrap();
        let reversed = builder.operation(Operation::Reverse, vec![first]);
        let rotated = builder.operation(Operation::RotateLeft(1), vec![second]);
        let xored = builder.operation(Operation::Xor(vec![7]), vec![third]);
        let first_join = builder.operation(Operation::Concat, vec![reversed, rotated]);
        let second_join = builder.operation(Operation::Concat, vec![first_join, xored]);
        let output = builder.operation(Operation::RotateRight(1), vec![second_join]);
        builder.output(output);
        builder.validate().unwrap()
    }

    fn fragments() -> Vec<Vec<u8>> {
        vec![b"Ab".to_vec(), b"C1".to_vec(), b"d2".to_vec()]
    }

    fn graph_for_fragment_lengths(fragment_lengths: Vec<usize>) -> ValidatedSemanticGraph {
        let mut builder = SemanticGraphBuilder::new(fragment_lengths.clone());
        let inputs = (0..fragment_lengths.len())
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();
        let mut output = builder.operation(Operation::Concat, inputs);
        for _ in 0..3 {
            output = builder.operation(Operation::Reverse, vec![output]);
        }
        builder.output(output);
        builder.validate().unwrap()
    }

    fn plan_for(seed: u8) -> RenderPlan {
        let mut random = DeterministicRandom::new([seed; 32]);
        plan_rendering(&valid_graph(), &fragments(), &mut random).unwrap()
    }

    #[test]
    fn plans_the_complete_graph_for_many_random_streams() {
        let graph = valid_graph();

        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            let effective = plan
                .fragments
                .iter()
                .filter(|fragment| !fragment.distractor)
                .collect::<Vec<_>>();
            let languages = effective
                .iter()
                .map(|fragment| fragment.language)
                .collect::<BTreeSet<_>>();
            let distractors = plan
                .fragments
                .iter()
                .filter(|fragment| fragment.distractor)
                .collect::<Vec<_>>();
            let steps = effective
                .iter()
                .flat_map(|fragment| fragment.steps.iter())
                .collect::<Vec<_>>();

            assert_eq!(effective.len(), graph.fragment_lengths().len());
            assert!((3..=5).contains(&effective.len()));
            assert!((2..=3).contains(&languages.len()));
            assert_eq!(steps.len(), graph.topological_nodes().len());
            assert!(distractors.len() <= 1);
            assert!(distractors.iter().all(|fragment| fragment.steps.is_empty()));
            assert_eq!(plan.output, graph.output());

            let planned_nodes = steps.iter().map(|step| step.node).collect::<BTreeSet<_>>();
            let graph_nodes = graph
                .topological_nodes()
                .iter()
                .map(|node| node.id())
                .collect::<BTreeSet<_>>();
            assert_eq!(planned_nodes, graph_nodes);
            assert_eq!(planned_nodes.len(), steps.len());

            for step in steps {
                let semantic = graph.node(step.node).unwrap();
                match (&step.kind, semantic.kind()) {
                    (
                        DisplayStepKind::Fragment { index: actual },
                        NodeKind::Fragment { index: expected },
                    ) => assert_eq!(actual, expected),
                    (
                        DisplayStepKind::Operation {
                            operation: actual_operation,
                            inputs: actual_inputs,
                        },
                        NodeKind::Operation {
                            operation: expected_operation,
                            inputs: expected_inputs,
                        },
                    ) => {
                        assert_eq!(actual_operation, expected_operation);
                        assert_eq!(actual_inputs, expected_inputs);
                    }
                    _ => panic!("planned step must match its semantic node"),
                }
            }
        }
    }

    #[test]
    fn planning_is_deterministic_and_allows_surface_variation() {
        assert_eq!(plan_for(23), plan_for(23));

        let mut distinct = Vec::new();
        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            if !distinct.contains(&plan) {
                distinct.push(plan);
            }
        }
        assert!(distinct.len() > 1);
    }

    #[test]
    fn allocates_unique_bounded_names_and_contiguous_balanced_chunks() {
        let graph = valid_graph();

        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            let effective = plan
                .fragments
                .iter()
                .filter(|fragment| !fragment.distractor)
                .collect::<Vec<_>>();
            let mut allocated = BTreeSet::new();
            let topological_positions = graph
                .topological_order()
                .iter()
                .enumerate()
                .map(|(index, node)| (*node, index))
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut chunk_sizes = Vec::new();

            for fragment in effective {
                assert_allocated_name(&fragment.heading, &mut allocated);
                assert!(!fragment.steps.is_empty());
                chunk_sizes.push(fragment.steps.len());
                let positions = fragment
                    .steps
                    .iter()
                    .map(|step| topological_positions[&step.node])
                    .collect::<Vec<_>>();
                assert!(positions.windows(2).all(|pair| pair[1] == pair[0] + 1));

                for step in &fragment.steps {
                    assert_allocated_name(&step.output_label, &mut allocated);
                    assert_allocated_name(&step.local_name, &mut allocated);
                }
            }
            for distractor in plan.fragments.iter().filter(|fragment| fragment.distractor) {
                assert_allocated_name(&distractor.heading, &mut allocated);
            }

            let smallest = *chunk_sizes.iter().min().unwrap();
            let largest = *chunk_sizes.iter().max().unwrap();
            assert!(largest - smallest <= 1);
        }
    }

    fn assert_allocated_name(name: &str, allocated: &mut BTreeSet<String>) {
        assert!(!name.is_empty());
        assert!(name.len() <= MAX_IDENTIFIER_BYTES);
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        assert!(allocated.insert(name.to_owned()));
    }

    #[test]
    fn rejects_invalid_fragment_inputs() {
        let graph = valid_graph();
        let invalid_cases = [
            vec![b"Ab".to_vec(), b"C1".to_vec()],
            vec![b"Ab".to_vec(), b"C1".to_vec(), b"d23".to_vec()],
            vec![b"Ab".to_vec(), b"C!".to_vec(), b"d2".to_vec()],
            vec![b"Ab".to_vec(), Vec::new(), b"d2".to_vec()],
        ];

        for invalid in invalid_cases {
            let mut random = DeterministicRandom::new([31; 32]);
            assert_eq!(
                plan_rendering(&graph, &invalid, &mut random),
                Err(RenderError::InvalidPlan)
            );
        }
    }

    #[test]
    fn rejects_unsupported_fragment_counts_and_oversized_fragments() {
        let cases = [
            (
                graph_for_fragment_lengths(vec![2, 2]),
                vec![b"Ab".to_vec(), b"C1".to_vec()],
            ),
            (
                graph_for_fragment_lengths(vec![2, 2, 2, 2, 2, 2]),
                vec![b"Ab".to_vec(); 6],
            ),
            (
                graph_for_fragment_lengths(vec![17, 2, 2]),
                vec![vec![b'A'; 17], b"C1".to_vec(), b"d2".to_vec()],
            ),
        ];

        for (graph, fragments) in cases {
            let mut random = DeterministicRandom::new([37; 32]);
            assert_eq!(
                plan_rendering(&graph, &fragments, &mut random),
                Err(RenderError::InvalidPlan)
            );
        }
    }

    #[test]
    fn distractors_never_carry_semantic_steps() {
        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            for fragment in plan.fragments {
                if fragment.distractor {
                    assert!(fragment.steps.is_empty());
                } else {
                    assert!(
                        fragment
                            .steps
                            .iter()
                            .all(|step| step.node != NodeId(u32::MAX))
                    );
                }
            }
        }
    }
}
