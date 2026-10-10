use std::collections::{BTreeMap, BTreeSet};

use super::{
    emitter::{self, common_question_bytes, declared_template_max_bytes},
    error::RenderError,
    model::{
        DisplayDistractor, DisplayDistractorStep, DisplayFragment, DisplayStep, DisplayStepKind,
        DistractorOperation, FragmentLiteralPlan, HelperSemantic, MAX_FRAGMENT_BYTES,
        MAX_QUESTION_BYTES, NumericStyle, ObfuscationProfile, RenderLanguage, RenderPlan,
        TemplateFamily,
    },
    planner::plan_rendering,
    render_with,
    validate::{self, COMMON_QUESTION_BUDGET, FRAGMENT_WRAPPER_BUDGET},
};
use crate::generation::{
    MAX_CONCAT_INPUTS, NodeId, NodeKind, Operation, OperationKind, SemanticGraphBuilder,
    ValidatedSemanticGraph, evaluate_semantic_graph, planner::plan_with, secret::Secret,
    test_random::DeterministicRandom,
};

fn ascii_secret(length: usize) -> Secret {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    Secret::from_test_bytes(
        (0..length)
            .map(|index| alphabet[(index * 7 + length) % alphabet.len()])
            .collect(),
    )
}

fn fragment_slices(fragments: &[Vec<u8>]) -> Vec<&[u8]> {
    fragments.iter().map(Vec::as_slice).collect()
}

fn test_operation(
    family: TemplateFamily,
    operation: Operation,
) -> (DisplayStep, ObfuscationProfile) {
    let kind = OperationKind::from(&operation);
    let alias = match kind {
        OperationKind::Reverse => "reverse",
        OperationKind::Slice => "slice",
        _ => "operation_alias",
    };
    (
        DisplayStep {
            node: NodeId(0),
            output_label: "output_000000000".to_owned(),
            local_name: "helper_000000000".to_owned(),
            template: family,
            numeric_style: NumericStyle::Decimal,
            literal_plan: None,
            guard_value: (family == TemplateFamily::Guarded).then_some(255),
            kind: DisplayStepKind::Operation {
                operation,
                inputs: Vec::new(),
            },
        },
        ObfuscationProfile::new(BTreeMap::from([
            (HelperSemantic::BytesAscii, "bytes_ascii".to_owned()),
            (HelperSemantic::Operation(kind), alias.to_owned()),
        ])),
    )
}

fn boundary_fixture(
    fragment_count: usize,
    operation_count: usize,
) -> (ValidatedSemanticGraph, Vec<Vec<u8>>) {
    let fragments = (0..fragment_count)
        .map(|index| vec![b'A' + index as u8, b'0' + index as u8])
        .collect::<Vec<_>>();
    let mut builder = SemanticGraphBuilder::new(vec![2; fragment_count]);
    let inputs = (0..fragment_count)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    let mut output = builder.operation(Operation::Concat, inputs);
    for _ in 1..operation_count {
        output = builder.operation(Operation::Reverse, vec![output]);
    }
    builder.output(output);
    (builder.validate().unwrap(), fragments)
}

fn dense_dependency_fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>) {
    let fragments = [b"A0", b"B1", b"C2", b"D3", b"E4"]
        .into_iter()
        .map(|fragment| fragment.to_vec())
        .collect::<Vec<_>>();
    let mut builder = SemanticGraphBuilder::new(vec![2; 5]);
    let sources = (0..5)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    let mut prior = Vec::new();
    for operation_index in 0..8 {
        let mut inputs = sources.clone();
        inputs.extend(prior.clone());
        assert!(inputs.len() <= MAX_CONCAT_INPUTS);
        if operation_index == 7 {
            assert_eq!(inputs.len(), 12);
        }
        prior.push(builder.operation(Operation::Concat, inputs));
    }
    builder.output(*prior.last().unwrap());

    (builder.validate().unwrap(), fragments)
}

#[test]
fn dense_legal_dependencies_render_for_every_stream_within_fixed_bounds() {
    let (graph, fragments) = dense_dependency_fixture();
    let expected = evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap();
    assert_eq!(graph.operation_count(), 8);

    for seed in 0_u8..=127 {
        let mut random = DeterministicRandom::new([seed; 32]);
        let rendered = render_with(&graph, &fragments, &mut random).unwrap();
        let mut plan_random = DeterministicRandom::new([seed; 32]);
        let plan = plan_rendering(&graph, &fragments, &mut plan_random).unwrap();
        let mut locations = BTreeMap::<NodeId, (&str, usize)>::new();
        for (display_index, fragment) in plan.fragments.iter().enumerate() {
            for step in &fragment.steps {
                assert!(
                    locations
                        .insert(step.node, (&step.output_label, display_index))
                        .is_none()
                );
            }
        }

        let mut expected_clue_count = 0;
        for (display_index, fragment) in plan.fragments.iter().enumerate() {
            for step in &fragment.steps {
                let DisplayStepKind::Operation { inputs, .. } = &step.kind else {
                    continue;
                };
                let mut seen_producers = BTreeSet::new();
                let mut producers = Vec::new();
                for input in inputs {
                    let (producer_label, producer_display_index) = locations[input];
                    if producer_display_index != display_index && seen_producers.insert(*input) {
                        producers.push((producer_label, producer_display_index));
                    }
                }
                if producers.is_empty() {
                    continue;
                }

                let clue =
                    emitter::format_dependency_clue(&producers, &step.output_label, display_index)
                        .unwrap();
                assert_eq!(
                    rendered.question().matches(&clue).count(),
                    1,
                    "seed {seed}: {clue}"
                );
                expected_clue_count += 1;
            }
        }
        let actual_clue_count = rendered
            .question()
            .lines()
            .filter(|line| line.starts_with("Dependency: "))
            .count();
        assert_eq!(actual_clue_count, expected_clue_count, "seed {seed}");
        assert!(rendered.question().len() <= MAX_QUESTION_BYTES);
        assert_eq!(
            evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap(),
            expected
        );
    }
}

#[test]
fn deterministic_surface_matrix_emits_all_four_visibly_distinct_template_families() {
    let (graph, fragments) = boundary_fixture(5, 8);
    let mut reached = BTreeSet::new();

    for seed in 0_u8..=127 {
        let mut first_random = DeterministicRandom::new([seed; 32]);
        let first = plan_rendering(&graph, &fragments, &mut first_random).unwrap();
        let mut repeated_random = DeterministicRandom::new([seed; 32]);
        let repeated = plan_rendering(&graph, &fragments, &mut repeated_random).unwrap();
        assert_eq!(first, repeated, "seed {seed}");
        assert_eq!(
            emitter::emit_question(&first, &fragments).unwrap(),
            emitter::emit_question(&repeated, &fragments).unwrap(),
            "seed {seed}"
        );

        let labels = first
            .fragments
            .iter()
            .flat_map(|fragment| &fragment.steps)
            .map(|step| (step.node, step.output_label.clone()))
            .collect::<BTreeMap<_, _>>();
        for fragment in &first.fragments {
            for step in &fragment.steps {
                reached.insert(step.template);
                let emitted = match &step.kind {
                    DisplayStepKind::Fragment { index } => emitter::emit_fragment(
                        fragment.language,
                        step,
                        &first.profile,
                        &fragments[*index],
                    )
                    .unwrap(),
                    DisplayStepKind::Operation { inputs, .. } => {
                        let inputs = inputs
                            .iter()
                            .map(|input| labels[input].clone())
                            .collect::<Vec<_>>();
                        emitter::emit_operation(fragment.language, step, &first.profile, &inputs)
                            .unwrap()
                    }
                };
                let local_count = emitted
                    .split(|character: char| {
                        !(character.is_ascii_alphanumeric() || character == '_')
                    })
                    .filter(|token| *token == step.local_name)
                    .count();
                match step.template {
                    TemplateFamily::Direct => {
                        assert_eq!(local_count, 0, "seed {seed}: {emitted}");
                        assert!(!emitted.contains("if "), "seed {seed}: {emitted}");
                    }
                    TemplateFamily::Helper => {
                        assert_eq!(local_count, 2, "seed {seed}: {emitted}");
                        assert!(
                            emitted.contains(&format!("{}()", step.local_name)),
                            "seed {seed}: {emitted}"
                        );
                        assert!(!emitted.contains("if "), "seed {seed}: {emitted}");
                    }
                    TemplateFamily::AliasChain => {
                        assert_eq!(local_count, 2, "seed {seed}: {emitted}");
                        assert!(
                            !emitted.contains(&format!("{}()", step.local_name)),
                            "seed {seed}: {emitted}"
                        );
                        assert!(!emitted.contains("if "), "seed {seed}: {emitted}");
                    }
                    TemplateFamily::Guarded => {
                        assert_eq!(local_count, 1, "seed {seed}: {emitted}");
                        assert!(emitted.contains("if "), "seed {seed}: {emitted}");
                        assert!(emitted.contains("else"), "seed {seed}: {emitted}");
                    }
                }
            }
        }
    }

    assert_eq!(
        reached,
        BTreeSet::from([
            TemplateFamily::Direct,
            TemplateFamily::Helper,
            TemplateFamily::AliasChain,
            TemplateFamily::Guarded,
        ])
    );
}

#[test]
fn every_secret_length_and_planner_stream_preserves_renderer_properties() {
    let mut cases = 0;

    for length in 8..=16 {
        let secret = ascii_secret(length);
        for seed in 0_u8..=127 {
            let planner_seed = [seed; 32];
            let mut first_planner = DeterministicRandom::new(planner_seed);
            let first = plan_with(&secret, &mut first_planner).unwrap();
            let mut second_planner = DeterministicRandom::new(planner_seed);
            let second = plan_with(&secret, &mut second_planner).unwrap();

            assert_eq!(
                first.graph(),
                second.graph(),
                "length {length}, seed {seed}"
            );
            assert_eq!(first.fragments(), second.fragments());
            assert_eq!(first.answer(), second.answer());
            assert!((3..=5).contains(&first.fragments().len()));
            assert_eq!(
                evaluate_semantic_graph(first.graph(), &fragment_slices(first.fragments()))
                    .unwrap(),
                first.answer()
            );

            let render_seed = [seed ^ 0xa5; 32];
            let mut first_renderer = DeterministicRandom::new(render_seed);
            let rendered =
                render_with(first.graph(), first.fragments(), &mut first_renderer).unwrap();
            let mut repeated_renderer = DeterministicRandom::new(render_seed);
            let repeated =
                render_with(first.graph(), first.fragments(), &mut repeated_renderer).unwrap();

            assert_eq!(rendered.question(), repeated.question());
            assert_eq!(rendered.metadata(), repeated.metadata());
            assert_eq!(
                rendered.metadata().effective_fragment_count(),
                first.fragments().len()
            );
            assert!((2..=3).contains(&rendered.metadata().languages().len()));
            assert_eq!(rendered.metadata().byte_length(), rendered.question().len());
            assert!(rendered.question().len() <= MAX_QUESTION_BYTES);
            cases += 1;
        }
    }

    assert_eq!(cases, 9 * 128);
}

#[test]
fn representative_fragment_counts_cover_all_render_stream_outcomes() {
    let mut cases = 0;
    let mut largest_question = 0;

    for (fragment_count, operation_count) in [(3, 4), (4, 4), (5, 8)] {
        let (graph, fragments) = boundary_fixture(fragment_count, operation_count);
        let mut distractor_outcomes = BTreeSet::new();
        for seed in 0_u8..=127 {
            let mut random = DeterministicRandom::new([seed; 32]);
            let rendered = render_with(&graph, &fragments, &mut random).unwrap();
            assert_eq!(
                rendered.metadata().effective_fragment_count(),
                fragment_count
            );
            assert!((2..=3).contains(&rendered.metadata().languages().len()));
            assert_eq!(rendered.metadata().byte_length(), rendered.question().len());
            assert!(rendered.question().len() <= MAX_QUESTION_BYTES);
            distractor_outcomes.insert(rendered.metadata().has_distractor());
            largest_question = largest_question.max(rendered.question().len());
            cases += 1;
        }
        assert_eq!(distractor_outcomes, BTreeSet::from([false, true]));
    }

    assert_eq!(cases, 3 * 128);
    assert!(largest_question > 0);
    assert!(largest_question <= MAX_QUESTION_BYTES);
}

#[test]
fn removing_a_distractor_leaves_the_effective_graph_output_and_answer_unchanged() {
    let (graph, fragments) = boundary_fixture(5, 8);
    let plan = (0_u8..=u8::MAX)
        .find_map(|seed| {
            let mut random = DeterministicRandom::new([seed; 32]);
            let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
            plan.distractor.is_some().then_some(plan)
        })
        .expect("seed matrix includes a distractor");
    let mut without = plan.clone();
    without.distractor = None;

    assert_eq!(plan.fragments, without.fragments);
    assert_eq!(plan.output, without.output);
    assert_eq!(plan.output, graph.output());
    assert_eq!(
        evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap(),
        evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap()
    );

    let requested_prefix = "The requested result is output label ";
    let with_question = emitter::emit_question(&plan, &fragments).unwrap();
    let without_question = emitter::emit_question(&without, &fragments).unwrap();
    assert_eq!(
        with_question
            .lines()
            .find(|line| line.starts_with(requested_prefix)),
        without_question
            .lines()
            .find(|line| line.starts_with(requested_prefix))
    );
}

fn longest_identifier(prefix: char, index: usize) -> String {
    let identifier = format!("{prefix}{index:015}");
    assert_eq!(identifier.len(), 16);
    identifier
}

fn explicit_profile(graph: &ValidatedSemanticGraph) -> ObfuscationProfile {
    let semantics = graph
        .topological_nodes()
        .iter()
        .filter_map(|node| match node.kind() {
            NodeKind::Fragment { .. } => None,
            NodeKind::Operation { operation, .. } => {
                Some(HelperSemantic::Operation(OperationKind::from(operation)))
            }
        })
        .chain([HelperSemantic::BytesAscii])
        .collect::<BTreeSet<_>>();
    ObfuscationProfile::new(
        semantics
            .into_iter()
            .enumerate()
            .map(|(index, semantic)| (semantic, format!("a{index}")))
            .collect(),
    )
}

fn dense_exact_accounting_fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>, RenderPlan) {
    let fragments = (0..5)
        .map(|index| {
            (0..16)
                .map(|offset| b'A' + ((index * 16 + offset) % 26) as u8)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut builder = SemanticGraphBuilder::new(vec![16; 5]);
    let source = (0..5)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    let xored = builder.operation(Operation::Xor(vec![u8::MAX; 16]), vec![source[0]]);
    let permuted = builder.operation(Operation::Permute((0..16).rev().collect()), vec![source[1]]);
    let left = builder.operation(Operation::RotateLeft(usize::MAX), vec![source[2]]);
    // Keep the full maximum renderer-supported source range instead of an empty 16..16 slice.
    let sliced = builder.operation(Operation::Slice { start: 0, end: 16 }, vec![source[3]]);
    let hashed = builder.operation(Operation::Sha256Prefix(32), vec![source[4]]);
    let concatenated = builder.operation(
        Operation::Concat,
        vec![
            xored, permuted, left, sliced, hashed, xored, permuted, left, sliced, hashed, xored,
            permuted, left,
        ],
    );
    let right = builder.operation(Operation::RotateRight(usize::MAX), vec![concatenated]);
    let output = builder.operation(Operation::Reverse, vec![right]);
    builder.output(output);
    let graph = builder.validate().unwrap();

    let steps = graph
        .topological_nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| DisplayStep {
            node: node.id(),
            output_label: longest_identifier('o', index),
            local_name: longest_identifier('l', index),
            template: TemplateFamily::Helper,
            numeric_style: NumericStyle::Decimal,
            literal_plan: matches!(node.kind(), NodeKind::Fragment { .. })
                .then_some(FragmentLiteralPlan::Whole),
            guard_value: None,
            kind: match node.kind() {
                NodeKind::Fragment { index } => DisplayStepKind::Fragment { index: *index },
                NodeKind::Operation { operation, inputs } => DisplayStepKind::Operation {
                    operation: operation.clone(),
                    inputs: inputs.clone(),
                },
            },
        })
        .collect::<Vec<_>>();
    let languages = [
        RenderLanguage::Java,
        RenderLanguage::Java,
        RenderLanguage::Java,
        RenderLanguage::Java,
        RenderLanguage::Go,
    ];
    let mut steps = steps.into_iter();
    let display_fragments = [5, 5, 1, 1, 1]
        .into_iter()
        .enumerate()
        .map(|(index, size)| DisplayFragment {
            heading: longest_identifier('h', index),
            language: languages[index],
            steps: steps.by_ref().take(size).collect(),
        })
        .collect::<Vec<_>>();
    assert!(steps.next().is_none());
    let profile = explicit_profile(&graph);
    let plan = RenderPlan {
        fragments: display_fragments,
        output: graph.output(),
        profile,
        distractor: Some(DisplayDistractor {
            heading: longest_identifier('d', 0),
            language: RenderLanguage::Rust,
            seed_value: b"Ab3Z9x7Q".to_vec(),
            literal_plan: FragmentLiteralPlan::Whole,
            steps: vec![
                DisplayDistractorStep {
                    output_label: longest_identifier('q', 0),
                    local_name: longest_identifier('v', 0),
                    template: TemplateFamily::Direct,
                    numeric_style: NumericStyle::IdentityOffset { delta: 15 },
                    guard_value: None,
                    operation: DistractorOperation::Xor(vec![u8::MAX]),
                },
                DisplayDistractorStep {
                    output_label: longest_identifier('q', 1),
                    local_name: longest_identifier('v', 1),
                    template: TemplateFamily::Guarded,
                    numeric_style: NumericStyle::IdentityOffset { delta: 15 },
                    guard_value: Some(255),
                    operation: DistractorOperation::RotateLeft(8),
                },
            ],
        }),
    };

    (graph, fragments, plan)
}

fn maximum_surface_question_fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>, RenderPlan) {
    let fragments = vec![
        b"A0a".to_vec(),
        b"B1b".to_vec(),
        b"C2c".to_vec(),
        b"D3d".to_vec(),
        b"E4eF".to_vec(),
    ];
    let mut builder = SemanticGraphBuilder::new(vec![3, 3, 3, 3, 4]);
    let source = (0..5)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    let reversed = builder.operation(Operation::Reverse, vec![source[0]]);
    let left = builder.operation(Operation::RotateLeft(usize::MAX), vec![source[1]]);
    let xored = builder.operation(Operation::Xor(vec![u8::MAX; 16]), vec![source[2]]);
    let permuted = builder.operation(Operation::Permute(vec![2, 0, 1]), vec![source[3]]);
    let sliced = builder.operation(Operation::Slice { start: 0, end: 4 }, vec![source[4]]);
    let concatenated = builder.operation(
        Operation::Concat,
        vec![
            reversed, left, xored, permuted, sliced, reversed, left, xored, permuted, sliced,
            reversed, left, xored,
        ],
    );
    let hashed = builder.operation(Operation::Sha256Prefix(16), vec![concatenated]);
    let output = builder.operation(Operation::RotateRight(usize::MAX), vec![hashed]);
    builder.output(output);
    let graph = builder.validate().unwrap();

    let steps = graph
        .topological_nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| DisplayStep {
            node: node.id(),
            output_label: longest_identifier('o', index),
            local_name: longest_identifier('l', index),
            template: TemplateFamily::Helper,
            numeric_style: NumericStyle::IdentityOffset { delta: 15 },
            literal_plan: match node.kind() {
                NodeKind::Fragment { index } => {
                    let length = fragments[*index].len();
                    Some(FragmentLiteralPlan::ShuffledChunks {
                        chunks: vec![1..2, 2..length, 0..1],
                        restore_order: vec![2, 0, 1],
                    })
                }
                NodeKind::Operation { .. } => None,
            },
            guard_value: None,
            kind: match node.kind() {
                NodeKind::Fragment { index } => DisplayStepKind::Fragment { index: *index },
                NodeKind::Operation { operation, inputs } => DisplayStepKind::Operation {
                    operation: operation.clone(),
                    inputs: inputs.clone(),
                },
            },
        })
        .collect::<Vec<_>>();
    let mut steps = steps.into_iter();
    let languages = [
        RenderLanguage::Java,
        RenderLanguage::Java,
        RenderLanguage::Java,
        RenderLanguage::Java,
        RenderLanguage::Go,
    ];
    let display_fragments = [3, 3, 3, 2, 2]
        .into_iter()
        .enumerate()
        .map(|(index, size)| DisplayFragment {
            heading: longest_identifier('h', index),
            language: languages[index],
            steps: steps.by_ref().take(size).collect(),
        })
        .collect::<Vec<_>>();
    assert!(steps.next().is_none());

    let semantics = graph
        .topological_nodes()
        .iter()
        .filter_map(|node| match node.kind() {
            NodeKind::Fragment { .. } => None,
            NodeKind::Operation { operation, .. } => {
                Some(HelperSemantic::Operation(OperationKind::from(operation)))
            }
        })
        .chain([HelperSemantic::BytesAscii])
        .collect::<BTreeSet<_>>();
    let profile = ObfuscationProfile::new(
        semantics
            .into_iter()
            .enumerate()
            .map(|(index, semantic)| (semantic, longest_identifier('a', index)))
            .collect(),
    );
    let plan = RenderPlan {
        fragments: display_fragments,
        output: graph.output(),
        profile,
        distractor: Some(DisplayDistractor {
            heading: longest_identifier('d', 0),
            language: RenderLanguage::Java,
            seed_value: b"Ab3Z9x7Q".to_vec(),
            literal_plan: FragmentLiteralPlan::ShuffledChunks {
                chunks: vec![3..8, 1..3, 0..1],
                restore_order: vec![2, 1, 0],
            },
            steps: vec![
                DisplayDistractorStep {
                    output_label: longest_identifier('q', 0),
                    local_name: longest_identifier('v', 0),
                    template: TemplateFamily::Direct,
                    numeric_style: NumericStyle::IdentityOffset { delta: 15 },
                    guard_value: None,
                    operation: DistractorOperation::Xor(vec![u8::MAX]),
                },
                DisplayDistractorStep {
                    output_label: longest_identifier('q', 1),
                    local_name: longest_identifier('v', 1),
                    template: TemplateFamily::Guarded,
                    numeric_style: NumericStyle::IdentityOffset { delta: 15 },
                    guard_value: Some(255),
                    operation: DistractorOperation::RotateLeft(8),
                },
            ],
        }),
    };

    (graph, fragments, plan)
}

#[test]
fn maximum_surface_fixture_exercises_every_global_bound_factor() {
    let (graph, fragments, plan) = maximum_surface_question_fixture();
    let steps = plan
        .fragments
        .iter()
        .flat_map(|fragment| &fragment.steps)
        .collect::<Vec<_>>();

    assert_eq!(fragments.iter().map(Vec::len).sum::<usize>(), 16);
    assert_eq!(fragments.len(), 5);
    assert_eq!(graph.operation_count(), 8);
    assert_eq!(graph.topological_nodes().len(), 13);
    assert_eq!(plan.fragments.len(), 5);
    assert_eq!(plan.distractor.as_ref().unwrap().steps.len(), 2);
    assert_eq!(plan.profile.aliases().len(), 9);
    assert!(
        plan.profile
            .aliases()
            .values()
            .all(|alias| alias.len() == 16)
    );
    assert!(
        plan.fragments
            .iter()
            .all(|fragment| fragment.heading.len() == 16)
    );
    assert!(steps.iter().all(|step| {
        step.output_label.len() == 16
            && step.local_name.len() == 16
            && step.template == TemplateFamily::Helper
    }));
    assert!(
        steps
            .iter()
            .all(|step| { step.numeric_style == NumericStyle::IdentityOffset { delta: 15 } })
    );
    let literal_plans = steps
        .iter()
        .filter_map(|step| step.literal_plan.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(literal_plans.len(), 5);
    assert!(literal_plans.iter().all(
        |literal| matches!(literal, FragmentLiteralPlan::ShuffledChunks { chunks, .. } if chunks.len() == 3)
    ));
    let operation_kinds = steps
        .iter()
        .filter_map(|step| match &step.kind {
            DisplayStepKind::Fragment { .. } => None,
            DisplayStepKind::Operation { operation, .. } => Some(OperationKind::from(operation)),
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(operation_kinds.len(), 8);
    let concat_inputs = steps
        .iter()
        .find_map(|step| match &step.kind {
            DisplayStepKind::Operation {
                operation: Operation::Concat,
                inputs,
            } => Some(inputs),
            _ => None,
        })
        .unwrap();
    assert_eq!(concat_inputs.len(), MAX_CONCAT_INPUTS);
    assert_eq!(
        concat_inputs.iter().copied().collect::<BTreeSet<_>>().len(),
        5
    );

    validate::validate_plan(&graph, &fragments, &plan).unwrap();
    let question = emitter::emit_question(&plan, &fragments).unwrap();
    assert!(question.len() <= MAX_QUESTION_BYTES);
    assert!(question.contains("(new byte[][]{"));
    assert!(question.contains(" + 15) - 15)"));
    assert!(question.contains("return "));
    assert!(question.contains("unrelated scratch calculation"));
    assert!(question.contains("not part of the requested result"));
    assert_eq!(
        question
            .lines()
            .filter(|line| line.starts_with("Dependency: "))
            .count(),
        7
    );
}

#[test]
fn dense_exact_accounting_question_fits_actual_fragment_and_question_limits() {
    let (graph, fragments, plan) = dense_exact_accounting_fixture();
    assert_eq!(graph.operation_count(), 8);
    assert_eq!(plan.fragments.len(), 5);
    let effective_languages = plan
        .fragments
        .iter()
        .map(|fragment| fragment.language)
        .collect::<Vec<_>>();
    assert_eq!(
        effective_languages,
        vec![
            RenderLanguage::Java,
            RenderLanguage::Java,
            RenderLanguage::Java,
            RenderLanguage::Java,
            RenderLanguage::Go,
        ]
    );
    let (reverse_step, reverse_profile) =
        test_operation(TemplateFamily::Helper, Operation::Reverse);
    let reverse_helper_lengths = RenderLanguage::ALL.map(|language| {
        emitter::emit_operation(
            language,
            &reverse_step,
            &reverse_profile,
            &["source_000000000".to_owned()],
        )
        .unwrap()
        .len()
    });
    assert_eq!(reverse_helper_lengths, [136, 134, 131, 136, 137, 126]);
    let best_non_java = reverse_helper_lengths
        .iter()
        .enumerate()
        .filter_map(|(index, length)| (index != 4).then_some(*length))
        .max()
        .unwrap();
    assert_eq!(reverse_helper_lengths[3], best_non_java);
    assert_eq!(best_non_java + 1, reverse_helper_lengths[4]);
    let effective_steps = plan
        .fragments
        .iter()
        .flat_map(|fragment| &fragment.steps)
        .collect::<Vec<_>>();
    assert!(
        effective_steps
            .iter()
            .all(|step| step.template == TemplateFamily::Helper)
    );
    assert!(
        plan.fragments
            .iter()
            .all(|fragment| fragment.heading.len() == 16)
    );
    assert!(
        effective_steps
            .iter()
            .all(|step| { step.output_label.len() == 16 && step.local_name.len() == 16 })
    );
    let concat_inputs = effective_steps
        .iter()
        .find_map(|step| match &step.kind {
            DisplayStepKind::Operation {
                operation: Operation::Concat,
                inputs,
            } => Some(inputs),
            _ => None,
        })
        .unwrap();
    assert_eq!(concat_inputs.len(), 13);
    assert_eq!(
        concat_inputs.iter().copied().collect::<BTreeSet<_>>().len(),
        5
    );
    assert!(effective_steps.iter().any(|step| {
        matches!(
            &step.kind,
            DisplayStepKind::Operation {
                operation: Operation::Permute(permutation),
                ..
            } if permutation.len() == 16
        )
    }));
    assert!(effective_steps.iter().any(|step| {
        matches!(
            &step.kind,
            DisplayStepKind::Operation {
                operation: Operation::Slice { start: 0, end: 16 },
                ..
            }
        )
    }));
    let fragment_by_node = plan
        .fragments
        .iter()
        .enumerate()
        .flat_map(|(fragment_index, fragment)| {
            fragment
                .steps
                .iter()
                .map(move |step| (step.node, fragment_index))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let unique_edges = effective_steps
        .iter()
        .flat_map(|step| match &step.kind {
            DisplayStepKind::Operation { inputs, .. } => inputs
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|input| (input, step.node))
                .collect::<Vec<_>>(),
            DisplayStepKind::Fragment { .. } => Vec::new(),
        })
        .collect::<Vec<_>>();
    assert_eq!(unique_edges.len(), 12);
    assert!(
        unique_edges
            .iter()
            .all(|(input, output)| { fragment_by_node[input] < fragment_by_node[output] })
    );
    validate::validate_plan(&graph, &fragments, &plan).unwrap();

    let question = emitter::emit_question(&plan, &fragments).unwrap();
    let expected_question_bytes = match usize::BITS {
        64 => 5_307,
        32 => 5_287,
        width => panic!("unsupported usize width {width}"),
    };
    assert_eq!(question.len(), expected_question_bytes);
    assert_eq!(
        MAX_QUESTION_BYTES - question.len(),
        12_288 - expected_question_bytes
    );
    assert!(question.contains("unrelated scratch calculation"));
    assert!(question.contains("not part of the requested result"));

    let sections = question
        .match_indices("[Fragment ")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let clues = question
        .lines()
        .filter(|line| line.starts_with("Dependency: "))
        .collect::<Vec<_>>();
    assert_eq!(clues.len(), 8);
    assert_eq!(
        clues.iter().map(|clue| clue.len() + 1).collect::<Vec<_>>(),
        vec![115, 115, 115, 115, 115, 239, 115, 115]
    );
    let target_clue_counts = (1..=5)
        .map(|target| {
            let suffix = format!("in Fragment {target}.");
            clues.iter().filter(|clue| clue.ends_with(&suffix)).count()
        })
        .collect::<Vec<_>>();
    assert_eq!(target_clue_counts, vec![0, 5, 1, 1, 1]);
    let dependency_start = question.find("Dependency clues:\n").unwrap();
    let dependency_end = question
        .find("Display order is not evaluation order.\n")
        .unwrap();
    assert_eq!(dependency_end - dependency_start, 1_063);

    assert_eq!(sections.len(), 5);
    let distractor_start = question.find("[Unrelated scratch calculation").unwrap();
    let section_lengths = sections
        .iter()
        .enumerate()
        .map(|(index, start)| sections.get(index + 1).copied().unwrap_or(distractor_start) - start)
        .collect::<Vec<_>>();
    let expected_sections = match usize::BITS {
        64 => vec![735, 896, 409, 215, 190],
        32 => vec![735, 886, 409, 205, 190],
        _ => unreachable!(),
    };
    assert_eq!(section_lengths, expected_sections);
    let accounted_effective = section_lengths
        .iter()
        .zip([0, 575, 239, 115, 115])
        .map(|(section, clue_bytes)| section + clue_bytes)
        .collect::<Vec<_>>();
    let expected_accounted = match usize::BITS {
        64 => vec![735, 1_471, 648, 330, 305],
        32 => vec![735, 1_461, 648, 320, 305],
        _ => unreachable!(),
    };
    assert_eq!(accounted_effective, expected_accounted);
    assert!(
        accounted_effective
            .iter()
            .all(|bytes| *bytes <= MAX_FRAGMENT_BYTES)
    );
    let fragment_margins = accounted_effective
        .iter()
        .map(|bytes| MAX_FRAGMENT_BYTES - bytes)
        .collect::<Vec<_>>();
    let expected_margins = match usize::BITS {
        64 => vec![1_313, 577, 1_400, 1_718, 1_743],
        32 => vec![1_313, 587, 1_400, 1_728, 1_743],
        _ => unreachable!(),
    };
    assert_eq!(fragment_margins, expected_margins);
    assert_eq!(dependency_start - distractor_start, 444);
    assert!(dependency_start - distractor_start <= MAX_FRAGMENT_BYTES);
}

#[test]
fn maximum_dynamic_common_question_text_fits_the_validator_reservation() {
    let mut maximum = 0;
    for mask in 0_u32..(1_u32 << OperationKind::ALL.len()) {
        if mask.count_ones() != 11 {
            continue;
        }
        let semantics = OperationKind::ALL
            .into_iter()
            .enumerate()
            .filter_map(|(index, kind)| {
                (mask & (1 << index) != 0).then_some(HelperSemantic::Operation(kind))
            })
            .chain([HelperSemantic::BytesAscii])
            .collect::<BTreeSet<_>>();
        assert_eq!(semantics.len(), 12);
        let profile = ObfuscationProfile::new(
            semantics
                .into_iter()
                .enumerate()
                .map(|(index, semantic)| (semantic, format!("a{index:015}")))
                .collect(),
        );
        maximum = maximum.max(common_question_bytes(&profile));
    }

    assert_eq!(maximum, 1_805);
    assert_eq!(COMMON_QUESTION_BUDGET - maximum, 243);
    assert!(maximum <= COMMON_QUESTION_BUDGET);
}

fn maximum_source_step_bytes() -> usize {
    let profile = ObfuscationProfile::new(BTreeMap::from([
        (HelperSemantic::BytesAscii, longest_identifier('a', 0)),
        (
            HelperSemantic::Operation(OperationKind::Concat),
            longest_identifier('a', 1),
        ),
    ]));
    let value = b"ABCDEFGHIJKLMNOP";
    let literals = [
        FragmentLiteralPlan::Whole,
        FragmentLiteralPlan::OrderedChunks(vec![0..1, 1..2, 2..16]),
        FragmentLiteralPlan::ShuffledChunks {
            chunks: vec![2..16, 1..2, 0..1],
            restore_order: vec![2, 1, 0],
        },
    ];
    let numeric_styles = [
        NumericStyle::Decimal,
        NumericStyle::LowerHex,
        NumericStyle::IdentityOffset { delta: 15 },
    ];
    let mut maximum = 0;
    for language in RenderLanguage::ALL {
        for template in [
            TemplateFamily::Direct,
            TemplateFamily::Helper,
            TemplateFamily::AliasChain,
            TemplateFamily::Guarded,
        ] {
            for numeric_style in numeric_styles {
                for literal_plan in &literals {
                    let step = DisplayStep {
                        node: NodeId(0),
                        output_label: longest_identifier('o', 0),
                        local_name: longest_identifier('l', 0),
                        template,
                        numeric_style,
                        literal_plan: Some(literal_plan.clone()),
                        guard_value: (template == TemplateFamily::Guarded).then_some(255),
                        kind: DisplayStepKind::Fragment { index: 0 },
                    };
                    maximum = maximum.max(
                        emitter::emit_fragment(language, &step, &profile, value)
                            .unwrap()
                            .len(),
                    );
                }
            }
        }
    }
    maximum
}

fn maximum_distractor_bytes() -> usize {
    let profile = ObfuscationProfile::new(BTreeMap::from([
        (HelperSemantic::BytesAscii, longest_identifier('a', 0)),
        (
            HelperSemantic::Operation(OperationKind::Concat),
            longest_identifier('a', 1),
        ),
        (
            HelperSemantic::Operation(OperationKind::Reverse),
            longest_identifier('a', 2),
        ),
        (
            HelperSemantic::Operation(OperationKind::RotateLeft),
            longest_identifier('a', 3),
        ),
        (
            HelperSemantic::Operation(OperationKind::Xor),
            longest_identifier('a', 4),
        ),
    ]));
    let literals = [
        FragmentLiteralPlan::Whole,
        FragmentLiteralPlan::OrderedChunks(vec![0..1, 1..2, 2..8]),
        FragmentLiteralPlan::ShuffledChunks {
            chunks: vec![2..8, 1..2, 0..1],
            restore_order: vec![2, 1, 0],
        },
    ];
    let operations = [
        DistractorOperation::Reverse,
        DistractorOperation::Xor(vec![u8::MAX]),
        DistractorOperation::RotateLeft(8),
    ];
    let numeric_styles = [
        NumericStyle::Decimal,
        NumericStyle::LowerHex,
        NumericStyle::IdentityOffset { delta: 15 },
    ];
    let templates = [
        TemplateFamily::Direct,
        TemplateFamily::Helper,
        TemplateFamily::AliasChain,
        TemplateFamily::Guarded,
    ];
    let mut maximum = 0;
    for language in RenderLanguage::ALL {
        for literal_plan in &literals {
            for first_operation in &operations {
                for first_numeric in numeric_styles {
                    for first_template in templates {
                        for second_operation in &operations {
                            for second_numeric in numeric_styles {
                                for second_template in templates {
                                    let distractor = DisplayDistractor {
                                        heading: longest_identifier('d', 0),
                                        language,
                                        seed_value: b"Ab3Z9x7Q".to_vec(),
                                        literal_plan: literal_plan.clone(),
                                        steps: vec![
                                            DisplayDistractorStep {
                                                output_label: longest_identifier('q', 0),
                                                local_name: longest_identifier('v', 0),
                                                template: first_template,
                                                numeric_style: first_numeric,
                                                guard_value: (first_template
                                                    == TemplateFamily::Guarded)
                                                    .then_some(255),
                                                operation: first_operation.clone(),
                                            },
                                            DisplayDistractorStep {
                                                output_label: longest_identifier('q', 1),
                                                local_name: longest_identifier('v', 1),
                                                template: second_template,
                                                numeric_style: second_numeric,
                                                guard_value: (second_template
                                                    == TemplateFamily::Guarded)
                                                    .then_some(255),
                                                operation: second_operation.clone(),
                                            },
                                        ],
                                    };
                                    maximum = maximum.max(
                                        emitter::emit_distractor(&distractor, &profile)
                                            .unwrap()
                                            .len(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    maximum
}

fn checked_compositional_question_bound(
    common_bytes: usize,
    max_source_step_budget: usize,
    max_operation_step_budget: usize,
    distractor_bytes: usize,
) -> Option<usize> {
    const MAX_SOURCE_FRAGMENTS: usize = 5;
    const MAX_OPERATIONS: usize = 8;
    const MAX_IDENTIFIER: usize = 16;

    let clue_bytes = maximum_dependency_clue_bytes()?;
    let fragment_wrapper = FRAGMENT_WRAPPER_BUDGET.checked_add(MAX_IDENTIFIER)?;
    common_bytes
        .checked_add(MAX_IDENTIFIER)?
        .checked_add(MAX_SOURCE_FRAGMENTS.checked_mul(fragment_wrapper)?)?
        .checked_add(MAX_SOURCE_FRAGMENTS.checked_mul(max_source_step_budget)?)?
        .checked_add(MAX_OPERATIONS.checked_mul(max_operation_step_budget)?)?
        .checked_add(clue_bytes)?
        .checked_add(distractor_bytes)
}

fn maximum_dependency_clue_bytes() -> Option<usize> {
    const MAX_SOURCE_FRAGMENTS: usize = 5;
    const MAX_OPERATIONS: usize = 8;
    const MAX_IDENTIFIER: usize = 16;

    let longest_label = "x".repeat(MAX_IDENTIFIER);
    let mut chunk_sizes = [2, 2, 3, 3, 3];
    let mut maximum = 0;
    loop {
        let mut starts = [0_usize; 5];
        for index in 1..starts.len() {
            starts[index] = starts[index - 1].checked_add(chunk_sizes[index - 1])?;
        }
        let total = (MAX_SOURCE_FRAGMENTS..MAX_SOURCE_FRAGMENTS + MAX_OPERATIONS).try_fold(
            0_usize,
            |total, position| {
                let chunk_start = starts.iter().zip(chunk_sizes).find_map(|(start, size)| {
                    (*start..start.checked_add(size)?)
                        .contains(&position)
                        .then_some(*start)
                })?;
                let producer_count = chunk_start.min(MAX_CONCAT_INPUTS);
                let producers =
                    vec![(longest_label.as_str(), MAX_SOURCE_FRAGMENTS - 1); producer_count];
                let clue = emitter::format_dependency_clue(
                    &producers,
                    &longest_label,
                    MAX_SOURCE_FRAGMENTS - 1,
                )
                .ok()?;
                total.checked_add(clue.len())
            },
        )?;
        maximum = maximum.max(total);
        if !next_permutation(&mut chunk_sizes) {
            break;
        }
    }
    Some(maximum)
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(pivot) = (0..values.len().saturating_sub(1))
        .rev()
        .find(|index| values[*index] < values[*index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..values.len())
        .rev()
        .find(|index| values[pivot] < values[*index])
        .unwrap();
    values.swap(pivot, successor);
    values[pivot + 1..].reverse();
    true
}

#[test]
fn declared_budgets_compositionally_bound_every_legal_question() {
    let declared_step_max = RenderLanguage::ALL
        .into_iter()
        .flat_map(|language| {
            [
                TemplateFamily::Direct,
                TemplateFamily::Helper,
                TemplateFamily::AliasChain,
                TemplateFamily::Guarded,
            ]
            .map(move |family| declared_template_max_bytes(language, family))
        })
        .max()
        .unwrap();
    assert_eq!(declared_step_max, 512);

    let source_step_max = maximum_source_step_bytes();
    let distractor_max = maximum_distractor_bytes();
    assert_eq!(source_step_max, 501);
    assert_eq!(distractor_max, 848);
    assert_eq!(maximum_dependency_clue_bytes(), Some(2_563));
    assert!(source_step_max <= declared_step_max);
    assert!(distractor_max <= MAX_FRAGMENT_BYTES);

    let legal_bound = checked_compositional_question_bound(
        1_805,
        source_step_max,
        declared_step_max,
        distractor_max,
    )
    .unwrap();
    assert_eq!(legal_bound, 12_233);
    assert!(legal_bound <= MAX_QUESTION_BYTES);

    let inflated_step_budget = declared_step_max.checked_add(64).unwrap();
    let inflated_bound = checked_compositional_question_bound(
        1_805,
        source_step_max,
        inflated_step_budget,
        distractor_max,
    )
    .unwrap();
    assert!(inflated_bound > MAX_QUESTION_BYTES);
}

#[test]
fn maximum_legal_v1_slice_index_fits_every_template_declaration() {
    const MAX_LEGAL_SLICE_INDEX: usize = 1_003_976_272;

    let mut builder = SemanticGraphBuilder::new(vec![16; 5]);
    let sources = (0..5)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    let mut first_inputs = sources.clone();
    first_inputs.extend(std::iter::repeat(sources[0]).take(MAX_CONCAT_INPUTS - sources.len()));
    let mut current = builder.operation(Operation::Concat, first_inputs);
    let mut current_length = 16 * MAX_CONCAT_INPUTS;
    for _ in 0..6 {
        current = builder.operation(Operation::Concat, vec![current; MAX_CONCAT_INPUTS]);
        current_length *= MAX_CONCAT_INPUTS;
    }
    assert_eq!(current_length, MAX_LEGAL_SLICE_INDEX);
    let output = builder.operation(
        Operation::Slice {
            start: MAX_LEGAL_SLICE_INDEX,
            end: MAX_LEGAL_SLICE_INDEX,
        },
        vec![current],
    );
    builder.output(output);
    let graph = builder.validate().unwrap();
    assert_eq!(graph.operation_count(), 8);
    assert_eq!(graph.output_length(), 0);

    let input = ["source_000000000".to_owned()];
    let operation = Operation::Slice {
        start: MAX_LEGAL_SLICE_INDEX,
        end: MAX_LEGAL_SLICE_INDEX,
    };
    for language in RenderLanguage::ALL {
        for family in [
            TemplateFamily::Direct,
            TemplateFamily::Helper,
            TemplateFamily::AliasChain,
            TemplateFamily::Guarded,
        ] {
            let (step, profile) = test_operation(family, operation.clone());
            let emitted = emitter::emit_operation(language, &step, &profile, &input).unwrap();
            assert!(emitted.contains("1003976272, 1003976272"));
            assert!(emitted.len() <= declared_template_max_bytes(language, family));
        }
    }
}

#[test]
fn grouped_dependency_clue_names_every_ordered_unique_producer() {
    assert_eq!(
        emitter::format_dependency_clue(&[], "result_x", 3),
        Err(RenderError::InvalidPlan)
    );
    let clue = emitter::format_dependency_clue(&[("source_a", 0), ("source_b", 2)], "result_x", 3)
        .unwrap();

    assert_eq!(
        clue,
        "Dependency: output labels source_a (Fragment 1), source_b (Fragment 3) are inputs to output label result_x in Fragment 4.\n"
    );
}
