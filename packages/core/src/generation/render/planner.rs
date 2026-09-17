use std::collections::{BTreeMap, BTreeSet};

use crate::generation::{
    NodeKind, ValidatedSemanticGraph,
    random::{RandomSource, sample_below, shuffle},
};

use super::{
    emitter::emit_distractor,
    error::RenderError,
    model::{
        DisplayDistractor, DisplayDistractorStep, DisplayFragment, DisplayStep, DisplayStepKind,
        DistractorOperation, HelperSemantic, MAX_DISTRACTOR_SEED_BYTES, MIN_DISTRACTOR_SEED_BYTES,
        ObfuscationProfile, RenderLanguage, RenderPlan, TemplateFamily,
    },
    names::{NameAllocator, ascii_identifier_tokens},
    obfuscation::{
        plan_fragment_literal, sample_guard_value, sample_numeric_style, sample_template_family,
        used_helper_semantics,
    },
};

pub(super) fn plan_rendering(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
    random: &mut impl RandomSource,
) -> Result<RenderPlan, RenderError> {
    validate_inputs(graph, fragments)?;

    let language_count = 2 + sample(random, 2)?;
    let mut languages = RenderLanguage::ALL;
    shuffle(random, &mut languages).map_err(RenderError::from_generation_error)?;
    let selected_languages = &languages[..language_count];

    let mut assigned_languages = (0..fragments.len())
        .map(|index| selected_languages[index % language_count])
        .collect::<Vec<_>>();
    shuffle(random, &mut assigned_languages).map_err(RenderError::from_generation_error)?;

    let distractor = (sample(random, 2)? == 1)
        .then(|| plan_distractor(random))
        .transpose()?;
    let obfuscation = graph
        .topological_nodes()
        .iter()
        .map(|node| {
            let template = sample_template_family(random)?;
            let numeric_style = sample_numeric_style(random)?;
            let literal_plan = match node.kind() {
                NodeKind::Fragment { index } => Some(plan_fragment_literal(
                    fragments.get(*index).ok_or(RenderError::InvalidPlan)?.len(),
                    random,
                )?),
                NodeKind::Operation { .. } => None,
            };
            let guard_value = (template == TemplateFamily::Guarded)
                .then(|| sample_guard_value(random))
                .transpose()?;
            Ok((template, numeric_style, literal_plan, guard_value))
        })
        .collect::<Result<Vec<_>, RenderError>>()?;

    let mut used_semantics = used_helper_semantics(
        graph,
        obfuscation
            .iter()
            .filter_map(|(_, _, literal_plan, _)| literal_plan.as_ref()),
    );
    if let Some(draft) = &distractor {
        if !matches!(draft.literal_plan, super::model::FragmentLiteralPlan::Whole) {
            used_semantics.insert(HelperSemantic::Operation(
                crate::generation::OperationKind::Concat,
            ));
        }
        used_semantics.extend(
            draft
                .steps
                .iter()
                .map(|step| HelperSemantic::Operation(step.operation.operation_kind())),
        );
    }
    let forbidden_effective_names = distractor
        .as_ref()
        .map(|draft| distractor_fixed_identifier_tokens(draft, &used_semantics))
        .transpose()?
        .unwrap_or_default();
    let effective_name_count = graph.topological_nodes().len() * 2 + fragments.len();
    let distractor_name_count = distractor
        .as_ref()
        .map_or(0, |draft| 1 + draft.steps.len() * 2);
    let mut allocator = NameAllocator::new(random)?;
    let allocated_names = (0..effective_name_count)
        .map(|_| allocator.allocate_identifier_avoiding(&forbidden_effective_names))
        .collect::<Result<Vec<_>, _>>()?;
    let allocated_distractor_names = (0..distractor_name_count)
        .map(|_| allocator.allocate_identifier())
        .collect::<Result<Vec<_>, _>>()?;
    let aliases = used_semantics
        .into_iter()
        .map(|semantic| {
            allocator
                .allocate_identifier()
                .map(|alias| (semantic, alias))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let profile = ObfuscationProfile::new(aliases);
    let mut names = allocated_names.into_iter();
    let mut distractor_names = allocated_distractor_names.into_iter();

    let steps = graph
        .topological_nodes()
        .iter()
        .zip(obfuscation)
        .map(
            |(node, (template, numeric_style, literal_plan, guard_value))| {
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
                    numeric_style,
                    literal_plan,
                    guard_value,
                    kind,
                })
            },
        )
        .collect::<Result<Vec<_>, RenderError>>()?;

    let step_count = steps.len();
    let fragment_count = fragments.len();
    let base_chunk_size = step_count / fragment_count;
    let larger_chunk_count = step_count % fragment_count;
    let mut chunk_sizes = (0..fragment_count)
        .map(|index| base_chunk_size + usize::from(index < larger_chunk_count))
        .collect::<Vec<_>>();
    shuffle(random, &mut chunk_sizes).map_err(RenderError::from_generation_error)?;
    let mut steps = steps.into_iter();
    let mut display_fragments = Vec::with_capacity(fragment_count);

    for (language, chunk_size) in assigned_languages.into_iter().zip(chunk_sizes) {
        let chunk = steps.by_ref().take(chunk_size).collect::<Vec<_>>();
        if chunk.len() != chunk_size || chunk.is_empty() {
            return Err(RenderError::InvalidPlan);
        }
        display_fragments.push(DisplayFragment {
            heading: names.next().ok_or(RenderError::InvalidPlan)?,
            language,
            steps: chunk,
        });
    }
    if steps.next().is_some() {
        return Err(RenderError::InvalidPlan);
    }

    let distractor = distractor
        .map(|draft| {
            let heading = distractor_names.next().ok_or(RenderError::InvalidPlan)?;
            let steps = draft
                .steps
                .into_iter()
                .map(|step| {
                    Ok(DisplayDistractorStep {
                        output_label: distractor_names.next().ok_or(RenderError::InvalidPlan)?,
                        local_name: distractor_names.next().ok_or(RenderError::InvalidPlan)?,
                        template: step.template,
                        numeric_style: step.numeric_style,
                        guard_value: step.guard_value,
                        operation: step.operation,
                    })
                })
                .collect::<Result<Vec<_>, RenderError>>()?;
            Ok(DisplayDistractor {
                heading,
                language: draft.language,
                seed_value: draft.seed_value,
                literal_plan: draft.literal_plan,
                steps,
            })
        })
        .transpose()?;
    if names.next().is_some() || distractor_names.next().is_some() {
        return Err(RenderError::InvalidPlan);
    }

    shuffle(random, &mut display_fragments).map_err(RenderError::from_generation_error)?;
    Ok(RenderPlan {
        fragments: display_fragments,
        output: graph.output(),
        profile,
        distractor,
    })
}

struct DistractorDraft {
    language: RenderLanguage,
    seed_value: Vec<u8>,
    literal_plan: super::model::FragmentLiteralPlan,
    steps: Vec<DistractorStepDraft>,
}

struct DistractorStepDraft {
    template: TemplateFamily,
    numeric_style: super::model::NumericStyle,
    guard_value: Option<u8>,
    operation: DistractorOperation,
}

fn distractor_fixed_identifier_tokens(
    draft: &DistractorDraft,
    used_semantics: &BTreeSet<HelperSemantic>,
) -> Result<BTreeSet<String>, RenderError> {
    // Double underscores make probe-only names impossible allocator outputs, so every real token
    // can stay in the forbidden set without maintaining a separate allowlist.
    let aliases = used_semantics
        .iter()
        .copied()
        .enumerate()
        .map(|(index, semantic)| (semantic, format!("__ProbeAlias{index}")))
        .collect::<BTreeMap<_, _>>();
    let steps = draft
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| DisplayDistractorStep {
            output_label: format!("__ProbeOutput{index}"),
            local_name: format!("__ProbeLocal{index}"),
            template: step.template,
            numeric_style: step.numeric_style,
            guard_value: step.guard_value,
            operation: step.operation.clone(),
        })
        .collect();
    let probe = DisplayDistractor {
        heading: "__ProbeHeading".to_owned(),
        language: draft.language,
        seed_value: draft.seed_value.clone(),
        literal_plan: draft.literal_plan.clone(),
        steps,
    };
    let profile = ObfuscationProfile::new(aliases);
    let rendered = emit_distractor(&probe, &profile)?;
    Ok(ascii_identifier_tokens(&rendered)
        .map(str::to_owned)
        .collect())
}

fn plan_distractor(random: &mut impl RandomSource) -> Result<DistractorDraft, RenderError> {
    const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let language = RenderLanguage::ALL[sample(random, RenderLanguage::ALL.len())?];
    let seed_length = MIN_DISTRACTOR_SEED_BYTES
        + sample(
            random,
            MAX_DISTRACTOR_SEED_BYTES - MIN_DISTRACTOR_SEED_BYTES + 1,
        )?;
    let seed_value = (0..seed_length)
        .map(|_| sample(random, ALPHANUMERIC.len()).map(|index| ALPHANUMERIC[index]))
        .collect::<Result<Vec<_>, _>>()?;
    let literal_plan = plan_fragment_literal(seed_length, random)?;
    let step_count = 1 + sample(random, 2)?;
    let mut steps = Vec::with_capacity(step_count);
    let previous_length = seed_length;
    for _ in 0..step_count {
        let operation = match sample(random, 3)? {
            0 => DistractorOperation::Reverse,
            1 => DistractorOperation::Xor(vec![sample(random, 256)? as u8]),
            _ => DistractorOperation::RotateLeft(1 + sample(random, previous_length)?),
        };
        let template = sample_template_family(random)?;
        let numeric_style = sample_numeric_style(random)?;
        let guard_value = (template == TemplateFamily::Guarded)
            .then(|| sample_guard_value(random))
            .transpose()?;
        steps.push(DistractorStepDraft {
            template,
            numeric_style,
            guard_value,
            operation,
        });
    }
    Ok(DistractorDraft {
        language,
        seed_value,
        literal_plan,
        steps,
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
    sample_below(random, upper).map_err(RenderError::from_generation_error)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::plan_rendering;
    use crate::generation::{
        GenerationError, NodeKind, Operation, OperationKind, SemanticGraphBuilder,
        ValidatedSemanticGraph,
        random::RandomSource,
        render::{
            error::RenderError,
            model::{
                DisplayStepKind, DistractorOperation, FragmentLiteralPlan, HelperSemantic,
                NumericStyle, RenderLanguage, RenderPlan, TemplateFamily,
            },
            names::{MAX_ALLOCATED_NAMES, MAX_IDENTIFIER_BYTES},
            validate::validate_plan,
        },
        test_random::DeterministicRandom,
    };

    struct FiniteRandom {
        remaining: usize,
    }

    impl RandomSource for FiniteRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            if destination.len() > self.remaining {
                return Err(GenerationError::RandomnessUnavailable);
            }
            destination.fill(0);
            self.remaining -= destination.len();
            Ok(())
        }
    }

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

    fn boundary_graph(fragment_count: usize, operation_count: usize) -> ValidatedSemanticGraph {
        let mut builder = SemanticGraphBuilder::new(vec![2; fragment_count]);
        let inputs = (0..fragment_count)
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();
        let mut output = builder.operation(Operation::Concat, inputs);
        for _ in 1..operation_count {
            output = builder.operation(Operation::Reverse, vec![output]);
        }
        builder.output(output);
        builder.validate().unwrap()
    }

    fn boundary_fragments(fragment_count: usize) -> Vec<Vec<u8>> {
        (0..fragment_count)
            .map(|index| vec![b'A' + index as u8, b'0' + index as u8])
            .collect()
    }

    fn four_fragment_graph() -> ValidatedSemanticGraph {
        boundary_graph(4, 4)
    }

    fn five_fragment_max_graph() -> ValidatedSemanticGraph {
        boundary_graph(5, 8)
    }

    fn five_fragment_eight_kind_graph() -> ValidatedSemanticGraph {
        let mut builder = SemanticGraphBuilder::new(vec![2; 5]);
        let fragments = (0..5)
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();
        let reversed = builder.operation(Operation::Reverse, vec![fragments[0]]);
        let left = builder.operation(Operation::RotateLeft(1), vec![fragments[1]]);
        let right = builder.operation(Operation::RotateRight(1), vec![fragments[2]]);
        let xored = builder.operation(Operation::Xor(vec![7]), vec![fragments[3]]);
        let evens = builder.operation(Operation::EvenBytes, vec![fragments[4]]);
        let concatenated =
            builder.operation(Operation::Concat, vec![reversed, left, right, xored, evens]);
        let odds = builder.operation(Operation::OddBytes, vec![concatenated]);
        let output = builder.operation(Operation::Sha256Prefix(8), vec![odds]);
        builder.output(output);
        builder.validate().unwrap()
    }

    fn plan_for(seed: u8) -> RenderPlan {
        let mut random = DeterministicRandom::new([seed; 32]);
        plan_rendering(&valid_graph(), &fragments(), &mut random).unwrap()
    }

    fn plan_boundary(fragment_count: usize, operation_count: usize, seed: u8) -> RenderPlan {
        let graph = boundary_graph(fragment_count, operation_count);
        let fragments = boundary_fragments(fragment_count);
        let mut random = DeterministicRandom::new([seed; 32]);
        plan_rendering(&graph, &fragments, &mut random).unwrap()
    }

    #[test]
    fn plans_the_complete_graph_for_many_random_streams() {
        let graph = valid_graph();

        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            let effective = plan.fragments.iter().collect::<Vec<_>>();
            let languages = effective
                .iter()
                .map(|fragment| fragment.language)
                .collect::<BTreeSet<_>>();
            let steps = effective
                .iter()
                .flat_map(|fragment| fragment.steps.iter())
                .collect::<Vec<_>>();

            assert_eq!(effective.len(), graph.fragment_lengths().len());
            assert!((3..=5).contains(&effective.len()));
            assert!((2..=3).contains(&languages.len()));
            assert_eq!(steps.len(), graph.topological_nodes().len());
            assert!(
                plan.distractor
                    .as_ref()
                    .is_none_or(|distractor| (1..=2).contains(&distractor.steps.len()))
            );
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
    fn planning_is_deterministic_and_exercises_all_surface_choices() {
        let mut distinct = Vec::new();
        let mut language_counts = BTreeSet::new();
        let mut distractor_choices = BTreeSet::new();
        let mut templates = BTreeSet::new();
        let mut numeric_styles = BTreeSet::new();
        let mut literal_kinds = BTreeSet::new();

        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            assert_eq!(plan, plan_for(seed));
            if !distinct.contains(&plan) {
                distinct.push(plan.clone());
            }

            let effective = plan.fragments.iter().collect::<Vec<_>>();
            language_counts.insert(
                effective
                    .iter()
                    .map(|fragment| fragment.language)
                    .collect::<BTreeSet<_>>()
                    .len(),
            );
            let has_distractor = plan.distractor.is_some();
            distractor_choices.insert(has_distractor);
            for fragment in &plan.fragments {
                for step in &fragment.steps {
                    templates.insert(step.template);
                    numeric_styles.insert(step.numeric_style);
                    if let Some(literal_plan) = &step.literal_plan {
                        literal_kinds.insert(match literal_plan {
                            FragmentLiteralPlan::Whole => 0,
                            FragmentLiteralPlan::OrderedChunks(_) => 1,
                            FragmentLiteralPlan::ShuffledChunks { .. } => 2,
                        });
                    }
                }
            }
            if let Some(distractor) = &plan.distractor {
                templates.extend(distractor.steps.iter().map(|step| step.template));
                numeric_styles.extend(distractor.steps.iter().map(|step| step.numeric_style));
                literal_kinds.insert(match distractor.literal_plan {
                    FragmentLiteralPlan::Whole => 0,
                    FragmentLiteralPlan::OrderedChunks(_) => 1,
                    FragmentLiteralPlan::ShuffledChunks { .. } => 2,
                });
            }
        }

        assert!(distinct.len() > 1);
        assert_eq!(language_counts, BTreeSet::from([2, 3]));
        assert_eq!(distractor_choices, BTreeSet::from([false, true]));
        assert_eq!(
            templates,
            BTreeSet::from([
                TemplateFamily::Direct,
                TemplateFamily::Helper,
                TemplateFamily::AliasChain,
                TemplateFamily::Guarded,
            ])
        );
        assert!(numeric_styles.contains(&NumericStyle::Decimal));
        assert!(numeric_styles.contains(&NumericStyle::LowerHex));
        assert!(
            numeric_styles
                .iter()
                .any(|style| matches!(style, NumericStyle::IdentityOffset { delta: 1..=15 }))
        );
        assert_eq!(literal_kinds, BTreeSet::from([0, 1, 2]));
    }

    #[test]
    fn step_obfuscation_fields_match_step_and_template_shapes() {
        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            for step in plan.fragments.iter().flat_map(|fragment| &fragment.steps) {
                assert_eq!(
                    step.guard_value.is_some(),
                    step.template == TemplateFamily::Guarded
                );
                assert_eq!(
                    step.literal_plan.is_some(),
                    matches!(step.kind, DisplayStepKind::Fragment { .. })
                );
                if let NumericStyle::IdentityOffset { delta } = step.numeric_style {
                    assert!((1..=15).contains(&delta));
                }
            }
        }
    }

    #[test]
    fn aliases_are_exact_sorted_deterministic_and_share_the_identifier_domain() {
        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            assert_eq!(plan, plan_for(seed));
            let expected_semantics = expected_semantics(&valid_graph(), &plan);
            assert_eq!(
                plan.profile
                    .aliases()
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                expected_semantics
            );
            assert!(plan.profile.aliases().keys().copied().is_sorted());

            let mut allocated = BTreeSet::new();
            for fragment in &plan.fragments {
                assert_allocated_name(&fragment.heading, &mut allocated);
                for step in &fragment.steps {
                    assert_allocated_name(&step.output_label, &mut allocated);
                    assert_allocated_name(&step.local_name, &mut allocated);
                }
            }
            if let Some(distractor) = &plan.distractor {
                assert_allocated_name(&distractor.heading, &mut allocated);
                for step in &distractor.steps {
                    assert_allocated_name(&step.output_label, &mut allocated);
                    assert_allocated_name(&step.local_name, &mut allocated);
                }
            }
            for alias in plan.profile.aliases().values() {
                assert_allocated_name(alias, &mut allocated);
            }
        }
    }

    #[test]
    fn maximum_used_semantics_with_a_distractor_stays_within_the_name_limit() {
        let graph = five_fragment_eight_kind_graph();
        let fragments = boundary_fragments(5);
        let plan = (0_u8..=127)
            .find_map(|seed| {
                let mut random = DeterministicRandom::new([seed; 32]);
                let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
                plan.distractor.is_some().then_some(plan)
            })
            .expect("a deterministic stream selects a distractor");
        let expected_semantics = expected_semantics(&graph, &plan);
        let aliases = plan.profile.aliases();
        let allocation_count = plan
            .fragments
            .iter()
            .map(|fragment| 1 + fragment.steps.len() * 2)
            .sum::<usize>()
            + plan
                .distractor
                .as_ref()
                .map_or(0, |distractor| 1 + distractor.steps.len() * 2)
            + aliases.len();

        assert_eq!(graph.topological_nodes().len(), 13);
        assert!((9..=12).contains(&expected_semantics.len()));
        assert_eq!(
            aliases.keys().copied().collect::<BTreeSet<_>>(),
            expected_semantics
        );
        assert!(allocation_count <= MAX_ALLOCATED_NAMES);
    }

    #[test]
    fn plans_valid_four_and_five_fragment_boundary_graphs() {
        let four_graph = four_fragment_graph();
        let five_graph = five_fragment_max_graph();

        assert_eq!(four_graph.fragment_lengths().len(), 4);
        assert_eq!(four_graph.operation_count(), 4);
        assert_eq!(five_graph.fragment_lengths().len(), 5);
        assert_eq!(five_graph.operation_count(), 8);
        assert_eq!(five_graph.topological_nodes().len(), 13);

        for seed in 0_u8..=127 {
            let four = plan_boundary(4, 4, seed);
            let five = plan_boundary(5, 8, seed);
            assert_eq!(four.fragments.len(), 4);
            assert_eq!(five.fragments.len(), 5);
        }
    }

    #[test]
    fn every_boundary_plan_passes_distractor_text_isolation_validation() {
        for (fragment_count, operation_count) in [(3, 4), (4, 4), (5, 8)] {
            let graph = boundary_graph(fragment_count, operation_count);
            let fragments = boundary_fragments(fragment_count);
            for seed in 0_u8..=127 {
                let mut random = DeterministicRandom::new([seed; 32]);
                let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
                assert_eq!(
                    validate_plan(&graph, &fragments, &plan),
                    Ok(()),
                    "fragment count {fragment_count}, operation count {operation_count}, seed {seed}"
                );
            }
        }
    }

    #[test]
    fn seed_120_avoids_the_known_distractor_prose_collision() {
        let graph = boundary_graph(3, 4);
        let fragments = boundary_fragments(3);
        let mut random = DeterministicRandom::new([120; 32]);

        let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();

        assert!(plan.distractor.is_some());
        assert!(
            !plan
                .fragments
                .iter()
                .flat_map(|fragment| std::iter::once(fragment.heading.as_str()).chain(
                    fragment
                        .steps
                        .iter()
                        .flat_map(|step| [step.output_label.as_str(), step.local_name.as_str()]),
                ))
                .any(|name| name == "It")
        );
        assert_eq!(validate_plan(&graph, &fragments, &plan), Ok(()));
    }

    #[test]
    fn allocates_unique_bounded_names_and_contiguous_balanced_chunks() {
        let graph = valid_graph();

        for seed in 0_u8..=127 {
            let plan = plan_for(seed);
            let effective = plan.fragments.iter().collect::<Vec<_>>();
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
            if let Some(distractor) = &plan.distractor {
                assert_allocated_name(&distractor.heading, &mut allocated);
                for step in &distractor.steps {
                    assert_allocated_name(&step.output_label, &mut allocated);
                    assert_allocated_name(&step.local_name, &mut allocated);
                }
            }

            let smallest = *chunk_sizes.iter().min().unwrap();
            let largest = *chunk_sizes.iter().max().unwrap();
            assert!(largest - smallest <= 1);
        }
    }

    #[test]
    fn randomizes_balanced_chunk_boundaries_for_the_maximum_graph() {
        let graph = five_fragment_max_graph();
        let fragments = boundary_fragments(5);
        let topological_positions = graph
            .topological_order()
            .iter()
            .enumerate()
            .map(|(index, node)| (*node, index))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut observed_arrangements = BTreeSet::new();

        for seed in 0_u8..=127 {
            let mut random = DeterministicRandom::new([seed; 32]);
            let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
            let mut chunks = plan
                .fragments
                .iter()
                .map(|fragment| {
                    (
                        topological_positions[&fragment.steps[0].node],
                        fragment.steps.len(),
                    )
                })
                .collect::<Vec<_>>();
            chunks.sort_unstable_by_key(|(start, _)| *start);
            let arrangement = chunks.into_iter().map(|(_, size)| size).collect::<Vec<_>>();
            let mut multiset = arrangement.clone();
            multiset.sort_unstable();
            assert_eq!(multiset, vec![2, 2, 3, 3, 3]);
            observed_arrangements.insert(arrangement);
        }

        assert!(observed_arrangements.len() > 1);
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
    fn maximum_graph_with_a_distractor_stays_within_the_name_limit() {
        let plan = (0_u8..=127)
            .map(|seed| plan_boundary(5, 8, seed))
            .find(|plan| plan.distractor.is_some())
            .expect("a deterministic stream selects a distractor");
        let mut allocated = BTreeSet::new();

        for fragment in &plan.fragments {
            assert_allocated_name(&fragment.heading, &mut allocated);
            for step in &fragment.steps {
                assert_allocated_name(&step.output_label, &mut allocated);
                assert_allocated_name(&step.local_name, &mut allocated);
            }
        }
        let distractor = plan.distractor.as_ref().unwrap();
        assert_allocated_name(&distractor.heading, &mut allocated);
        for step in &distractor.steps {
            assert_allocated_name(&step.output_label, &mut allocated);
            assert_allocated_name(&step.local_name, &mut allocated);
        }

        assert_eq!(MAX_ALLOCATED_NAMES, 48);
        assert!(allocated.len() <= MAX_ALLOCATED_NAMES);
        assert_eq!(
            plan.fragments
                .iter()
                .flat_map(|fragment| fragment.steps.iter())
                .count(),
            13
        );
        assert!((1..=2).contains(&distractor.steps.len()));
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
    fn deterministic_streams_produce_absent_and_isolated_present_distractors() {
        let mut choices = BTreeSet::new();
        let mut step_counts = BTreeSet::new();
        let mut languages = BTreeSet::new();
        let mut operations = BTreeSet::new();
        let mut templates = BTreeSet::new();
        let mut numeric_kinds = BTreeSet::new();
        let mut literal_kinds = BTreeSet::new();

        for seed in 0_u8..=u8::MAX {
            let plan = plan_for(seed);
            if let Some(distractor) = &plan.distractor {
                assert!((1..=2).contains(&distractor.steps.len()));
                assert!((3..=8).contains(&distractor.seed_value.len()));
                step_counts.insert(distractor.steps.len());
                languages.insert(distractor.language);
                literal_kinds.insert(match distractor.literal_plan {
                    FragmentLiteralPlan::Whole => 0,
                    FragmentLiteralPlan::OrderedChunks(_) => 1,
                    FragmentLiteralPlan::ShuffledChunks { .. } => 2,
                });
                for step in &distractor.steps {
                    operations.insert(match step.operation {
                        DistractorOperation::Reverse => 0,
                        DistractorOperation::Xor(_) => 1,
                        DistractorOperation::RotateLeft(_) => 2,
                    });
                    templates.insert(step.template);
                    numeric_kinds.insert(match step.numeric_style {
                        NumericStyle::Decimal => 0,
                        NumericStyle::LowerHex => 1,
                        NumericStyle::IdentityOffset { .. } => 2,
                    });
                }
            }
            choices.insert(plan.distractor.is_some());
        }

        assert_eq!(choices, BTreeSet::from([false, true]));
        assert_eq!(step_counts, BTreeSet::from([1, 2]));
        assert_eq!(languages, RenderLanguage::ALL.into_iter().collect());
        assert_eq!(operations, BTreeSet::from([0, 1, 2]));
        assert_eq!(
            templates,
            BTreeSet::from([
                TemplateFamily::Direct,
                TemplateFamily::Helper,
                TemplateFamily::AliasChain,
                TemplateFamily::Guarded,
            ])
        );
        assert_eq!(numeric_kinds, BTreeSet::from([0, 1, 2]));
        assert_eq!(literal_kinds, BTreeSet::from([0, 1, 2]));
    }

    fn expected_semantics(
        graph: &ValidatedSemanticGraph,
        plan: &RenderPlan,
    ) -> BTreeSet<HelperSemantic> {
        let mut expected = graph
            .topological_nodes()
            .iter()
            .filter_map(|node| match node.kind() {
                NodeKind::Operation { operation, .. } => {
                    Some(HelperSemantic::Operation(OperationKind::from(operation)))
                }
                NodeKind::Fragment { .. } => None,
            })
            .chain([HelperSemantic::BytesAscii])
            .collect::<BTreeSet<_>>();
        let has_chunks = plan
            .fragments
            .iter()
            .flat_map(|fragment| &fragment.steps)
            .filter_map(|step| step.literal_plan.as_ref())
            .any(|literal| !matches!(literal, FragmentLiteralPlan::Whole))
            || plan.distractor.as_ref().is_some_and(|distractor| {
                !matches!(distractor.literal_plan, FragmentLiteralPlan::Whole)
            });
        if has_chunks {
            expected.insert(HelperSemantic::Operation(OperationKind::Concat));
        }
        if let Some(distractor) = &plan.distractor {
            expected.extend(
                distractor
                    .steps
                    .iter()
                    .map(|step| HelperSemantic::Operation(step.operation.operation_kind())),
            );
        }
        expected
    }

    #[test]
    fn preserves_early_random_exhaustion_as_a_terminal_renderer_error() {
        let graph = valid_graph();
        let fragments = fragments();
        let error =
            plan_rendering(&graph, &fragments, &mut FiniteRandom { remaining: 0 }).unwrap_err();

        assert_eq!(error, RenderError::RandomnessUnavailable);
        let display = error.to_string();
        let debug = format!("{error:?}");
        for fragment in fragments {
            let fragment = String::from_utf8(fragment).unwrap();
            assert!(!display.contains(&fragment));
            assert!(!debug.contains(&fragment));
        }
    }
}
