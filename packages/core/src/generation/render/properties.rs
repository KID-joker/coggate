use std::collections::BTreeSet;

use super::{
    emitter::{
        self, common_question_bytes, declared_template_max_bytes,
        emitted_dependency_clue_fixed_bytes,
    },
    model::{
        DisplayFragment, DisplayStep, DisplayStepKind, MAX_FRAGMENT_BYTES, MAX_QUESTION_BYTES,
        RenderLanguage, RenderPlan, TemplateFamily,
    },
    render_with,
    validate::{self, COMMON_QUESTION_BUDGET},
};
use crate::generation::{
    NodeKind, Operation, SemanticGraphBuilder, ValidatedSemanticGraph, evaluate_semantic_graph,
    planner::plan_with, secret::Secret, test_random::DeterministicRandom,
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

fn longest_identifier(prefix: char, index: usize) -> String {
    let identifier = format!("{prefix}{index:015}");
    assert_eq!(identifier.len(), 16);
    identifier
}

fn worst_case_question_fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>, RenderPlan) {
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
    let mut display_fragments = [5, 5, 1, 1, 1]
        .into_iter()
        .enumerate()
        .map(|(index, size)| DisplayFragment {
            heading: longest_identifier('h', index),
            language: languages[index],
            steps: steps.by_ref().take(size).collect(),
            distractor: false,
        })
        .collect::<Vec<_>>();
    assert!(steps.next().is_none());
    display_fragments.push(DisplayFragment {
        heading: longest_identifier('d', 0),
        language: RenderLanguage::Rust,
        steps: Vec::new(),
        distractor: true,
    });
    let plan = RenderPlan {
        fragments: display_fragments,
        output: graph.output(),
    };

    (graph, fragments, plan)
}

#[test]
fn worst_case_assembled_question_fits_actual_fragment_and_question_limits() {
    let (graph, fragments, plan) = worst_case_question_fixture();
    assert_eq!(graph.operation_count(), 8);
    assert_eq!(plan.fragments.len(), 6);
    let effective_languages = plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
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
    let reverse_helper_lengths = RenderLanguage::ALL.map(|language| {
        emitter::emit_operation(
            language,
            TemplateFamily::Helper,
            "output_000000000",
            "helper_000000000",
            &Operation::Reverse,
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
        .filter(|fragment| !fragment.distractor)
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
        .filter(|fragment| !fragment.distractor)
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
        64 => 5_954,
        32 => 5_934,
        width => panic!("unsupported usize width {width}"),
    };
    assert_eq!(question.len(), expected_question_bytes);
    assert_eq!(
        MAX_QUESTION_BYTES - question.len(),
        12_288 - expected_question_bytes
    );
    assert!(question.contains("audit/example branch"));

    let sections = question
        .match_indices("[Fragment ")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let clues = question
        .lines()
        .filter(|line| line.starts_with("Dependency: "))
        .collect::<Vec<_>>();
    assert_eq!(clues.len(), 12);
    assert!(clues.iter().all(|clue| clue.len() + 1 == 134));
    let target_clue_counts = (1..=5)
        .map(|target| {
            let suffix = format!("in display Fragment {target}.");
            clues.iter().filter(|clue| clue.ends_with(&suffix)).count()
        })
        .collect::<Vec<_>>();
    assert_eq!(target_clue_counts, vec![0, 5, 5, 1, 1]);
    let dependency_start = question.find("Dependency clues:\n").unwrap();
    let dependency_end = question
        .find("Display order is not evaluation order.\n")
        .unwrap();
    assert_eq!(dependency_end - dependency_start, 1_627);

    assert_eq!(sections.len(), 6);
    let section_lengths = sections
        .iter()
        .enumerate()
        .map(|(index, start)| sections.get(index + 1).copied().unwrap_or(dependency_start) - start)
        .collect::<Vec<_>>();
    let expected_sections = match usize::BITS {
        64 => vec![780, 932, 413, 225, 195, 94],
        32 => vec![780, 922, 413, 215, 195, 94],
        _ => unreachable!(),
    };
    assert_eq!(section_lengths, expected_sections);
    let accounted_effective = section_lengths[..5]
        .iter()
        .zip(&target_clue_counts)
        .map(|(section, clue_count)| section + clue_count * 134)
        .collect::<Vec<_>>();
    let expected_accounted = match usize::BITS {
        64 => vec![780, 1_602, 1_083, 359, 329],
        32 => vec![780, 1_592, 1_083, 349, 329],
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
        64 => vec![1_268, 446, 965, 1_689, 1_719],
        32 => vec![1_268, 456, 965, 1_699, 1_719],
        _ => unreachable!(),
    };
    assert_eq!(fragment_margins, expected_margins);
    assert_eq!(section_lengths[5], 94);
}

#[test]
fn fixed_common_question_text_fits_the_validator_reservation() {
    let actual = common_question_bytes();
    assert_eq!(actual, 1_691);
    assert_eq!(COMMON_QUESTION_BUDGET - actual, 357);
}

#[test]
fn maximum_legal_v1_slice_index_fits_every_template_declaration() {
    const MAX_LEGAL_SLICE_INDEX: usize = 1_003_976_272;

    let mut builder = SemanticGraphBuilder::new(vec![16; 5]);
    let sources = (0..5)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    let mut first_inputs = sources.clone();
    first_inputs.extend(std::iter::repeat(sources[0]).take(8));
    let mut current = builder.operation(Operation::Concat, first_inputs);
    let mut current_length = 16 * 13;
    for _ in 0..6 {
        current = builder.operation(Operation::Concat, vec![current; 13]);
        current_length *= 13;
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
        for family in [TemplateFamily::Direct, TemplateFamily::Helper] {
            let emitted = emitter::emit_operation(
                language,
                family,
                "output_000000000",
                "helper_000000000",
                &operation,
                &input,
            )
            .unwrap();
            assert!(emitted.contains("1003976272, 1003976272"));
            assert!(emitted.len() <= declared_template_max_bytes(language, family));
        }
    }
}

#[test]
fn dependency_clue_budget_matches_the_real_emitter_format() {
    assert_eq!(emitted_dependency_clue_fixed_bytes(), 102);
}
