mod emitter;
mod error;
mod languages;
mod model;
mod names;
mod obfuscation;
mod planner;
#[cfg(test)]
mod properties;
mod validate;

use crate::generation::{ValidatedSemanticGraph, random::RandomSource};

pub(crate) use error::RenderError;
pub use model::{MAX_QUESTION_BYTES, RenderLanguage, RenderMetadata, RenderedQuestion};

pub(crate) fn render_with(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
    random: &mut impl RandomSource,
) -> Result<RenderedQuestion, RenderError> {
    let plan = planner::plan_rendering(graph, fragments, random)?;
    validate::validate_plan(graph, fragments, &plan)?;
    let question = emitter::emit_question(&plan, fragments)?;
    let metadata = RenderMetadata::from_validated_plan(&plan, question.len());
    Ok(RenderedQuestion::new(question, metadata))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        RenderedQuestion, emitter,
        error::RenderError,
        model::{
            DisplayFragment, DisplayStep, DisplayStepKind, FragmentLiteralPlan, HelperSemantic,
            MAX_QUESTION_BYTES, NumericStyle, ObfuscationProfile, RenderLanguage, RenderPlan,
            TemplateFamily,
        },
        names::LEGACY_HELPER_IDENTIFIERS,
        planner::plan_rendering,
        render_with,
    };
    use crate::generation::{
        NodeId, Operation, OperationKind, SemanticGraphBuilder, ValidatedSemanticGraph,
        evaluate_semantic_graph,
        planner::{PlannedSemantics, plan_with},
        secret::Secret,
        test_random::DeterministicRandom,
    };

    fn planned_fixture() -> PlannedSemantics {
        let secret = Secret::from_test_bytes(b"AbCdEf12Gh".to_vec());
        let mut random = DeterministicRandom::new([11; 32]);
        plan_with(&secret, &mut random).unwrap()
    }

    fn fragment_slices(fragments: &[Vec<u8>]) -> Vec<&[u8]> {
        fragments.iter().map(Vec::as_slice).collect()
    }

    fn render_graph(
        graph: &ValidatedSemanticGraph,
        fragments: &[Vec<u8>],
        seed: u8,
    ) -> RenderedQuestion {
        let mut random = DeterministicRandom::new([seed; 32]);
        render_with(graph, fragments, &mut random).unwrap()
    }

    #[test]
    fn renders_an_atomic_bounded_question_without_changing_the_answer() {
        let semantics = planned_fixture();
        let before =
            evaluate_semantic_graph(semantics.graph(), &fragment_slices(semantics.fragments()))
                .unwrap();
        let mut random = DeterministicRandom::new([23; 32]);

        let rendered = render_with(semantics.graph(), semantics.fragments(), &mut random).unwrap();

        let after =
            evaluate_semantic_graph(semantics.graph(), &fragment_slices(semantics.fragments()))
                .unwrap();
        assert_eq!(before, after);
        assert_eq!(before, semantics.answer());
        assert!(rendered.question().contains("unpadded base64url"));
        assert!(
            rendered
                .question()
                .contains("Display order is not evaluation order.")
        );
        assert_eq!(rendered.question().len(), rendered.metadata().byte_length());
        assert!(rendered.question().len() <= MAX_QUESTION_BYTES);
    }

    #[test]
    fn rendering_is_exactly_deterministic_for_the_same_inputs_and_stream() {
        let semantics = planned_fixture();
        let mut first_random = DeterministicRandom::new([29; 32]);
        let mut second_random = DeterministicRandom::new([29; 32]);

        let first =
            render_with(semantics.graph(), semantics.fragments(), &mut first_random).unwrap();
        let second =
            render_with(semantics.graph(), semantics.fragments(), &mut second_random).unwrap();

        assert_eq!(first.question(), second.question());
        assert_eq!(first.metadata(), second.metadata());
    }

    #[test]
    fn rendering_varies_the_surface_across_random_streams() {
        let semantics = planned_fixture();
        let questions = (0_u8..=31)
            .map(|seed| {
                let mut random = DeterministicRandom::new([seed; 32]);
                render_with(semantics.graph(), semantics.fragments(), &mut random)
                    .unwrap()
                    .question()
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();

        assert!(questions.len() > 1);
    }

    #[test]
    fn generated_seed_matrix_never_leaks_fixed_helper_identifiers() {
        let fragments = vec![b"A0".to_vec(), b"B1".to_vec(), b"C2".to_vec()];
        let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
        let first = builder.fragment(0).unwrap();
        let second = builder.fragment(1).unwrap();
        let third = builder.fragment(2).unwrap();
        let reversed = builder.operation(Operation::Reverse, vec![first]);
        let rotated = builder.operation(Operation::RotateLeft(1), vec![second]);
        let xored = builder.operation(Operation::Xor(vec![7]), vec![third]);
        let output = builder.operation(Operation::Concat, vec![reversed, rotated, xored]);
        builder.output(output);
        let graph = builder.validate().unwrap();
        let mut observed_languages = BTreeSet::new();

        for seed in 0_u8..=127 {
            let rendered = render_graph(&graph, &fragments, seed);
            observed_languages.extend(rendered.metadata().languages().iter().copied());
            let tokens = rendered
                .question()
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .filter(|token| {
                    token
                        .as_bytes()
                        .first()
                        .is_some_and(|first| first.is_ascii_alphabetic() || *first == b'_')
                })
                .collect::<BTreeSet<_>>();
            for identifier in LEGACY_HELPER_IDENTIFIERS {
                assert!(
                    !tokens.contains(*identifier),
                    "seed {seed} leaked {identifier}"
                );
            }
        }
        assert_eq!(
            observed_languages,
            RenderLanguage::ALL.into_iter().collect()
        );
    }

    #[test]
    fn every_effective_output_label_and_metadata_language_is_visible() {
        let semantics = planned_fixture();
        let mut plan_random = DeterministicRandom::new([31; 32]);
        let plan =
            plan_rendering(semantics.graph(), semantics.fragments(), &mut plan_random).unwrap();
        let mut render_random = DeterministicRandom::new([31; 32]);
        let rendered =
            render_with(semantics.graph(), semantics.fragments(), &mut render_random).unwrap();

        for step in plan.fragments.iter().flat_map(|fragment| &fragment.steps) {
            assert!(rendered.question().contains(&step.output_label));
        }
        let expected_languages = plan
            .fragments
            .iter()
            .map(|fragment| fragment.language)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(rendered.metadata().languages(), expected_languages);
        assert_eq!(
            rendered.metadata().effective_fragment_count(),
            semantics.fragments().len()
        );
        assert_eq!(
            rendered.metadata().has_distractor(),
            plan.distractor.is_some()
        );
    }

    #[test]
    fn rendered_question_debug_redacts_the_complete_question() {
        let semantics = planned_fixture();
        let mut random = DeterministicRandom::new([37; 32]);
        let rendered = render_with(semantics.graph(), semantics.fragments(), &mut random).unwrap();

        let debug = format!("{rendered:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(rendered.question()));
    }

    #[test]
    fn oversized_final_assembly_rejects_without_partial_output() {
        const SECRET_MARKER: &str = "SECRET_OVERSIZED_FRAGMENT";
        let fragments = vec![b"Ab".to_vec()];
        let display_fragments = (0..128)
            .map(|index| DisplayFragment {
                heading: format!("{SECRET_MARKER}_{index}"),
                language: RenderLanguage::Rust,
                steps: vec![DisplayStep {
                    node: NodeId(index),
                    output_label: format!("result_{index}"),
                    local_name: format!("local_{index}"),
                    template: TemplateFamily::Direct,
                    numeric_style: NumericStyle::Decimal,
                    literal_plan: Some(FragmentLiteralPlan::Whole),
                    guard_value: None,
                    kind: DisplayStepKind::Fragment { index: 0 },
                }],
            })
            .collect();
        let plan = RenderPlan {
            fragments: display_fragments,
            output: NodeId(127),
            profile: ObfuscationProfile::new(BTreeMap::from([(
                HelperSemantic::BytesAscii,
                "make_bytes".to_owned(),
            )])),
            distractor: None,
        };

        let error = emitter::emit_question(&plan, &fragments).unwrap_err();

        assert_eq!(error, RenderError::LengthLimit);
        assert!(!error.to_string().contains(SECRET_MARKER));
        assert!(!format!("{error:?}").contains(SECRET_MARKER));
    }

    #[test]
    fn rendered_questions_define_only_allocated_helper_semantics_once() {
        let semantics = planned_fixture();
        let mut random = DeterministicRandom::new([41; 32]);
        let plan = plan_rendering(semantics.graph(), semantics.fragments(), &mut random).unwrap();
        let rendered = render_graph(semantics.graph(), semantics.fragments(), 41);

        for alias in plan.profile.aliases().values() {
            let definition = format!("{alias}(");
            assert_eq!(
                rendered
                    .question()
                    .lines()
                    .filter(|line| line.starts_with(&definition))
                    .count(),
                1,
                "exactly one definition expected for {alias}"
            );
            assert!(rendered.question().matches(&definition).count() >= 2);
        }
        assert!(!rendered.question().contains("bytes_ascii"));
        assert!(!rendered.question().contains("reverse("));
    }

    #[test]
    fn rotate_left_derived_has_an_independent_answer_oracle_and_definition() {
        let fragments = vec![b"abcd".to_vec(), b"5".to_vec(), b"Z".to_vec()];
        let mut builder = SemanticGraphBuilder::new(vec![4, 1, 1]);
        let value = builder.fragment(0).unwrap();
        let key = builder.fragment(1).unwrap();
        let suffix = builder.fragment(2).unwrap();
        let derived = builder.operation(Operation::RotateLeftDerived, vec![value, key]);
        let joined = builder.operation(Operation::Concat, vec![derived, suffix]);
        let reversed = builder.operation(Operation::Reverse, vec![joined]);
        let output = builder.operation(Operation::Reverse, vec![reversed]);
        builder.output(output);
        let graph = builder.validate().unwrap();

        let answer = evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap();
        let mut random = DeterministicRandom::new([43; 32]);
        let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
        let rendered = render_graph(&graph, &fragments, 43);
        let alias = plan
            .profile
            .alias(HelperSemantic::Operation(OperationKind::RotateLeftDerived))
            .unwrap();

        assert_eq!(answer, b"bcdaZ");
        assert!(
            rendered
                .question()
                .contains(&format!("{alias}(x, key): cyclically rotate x left"))
        );
    }

    #[test]
    fn conditional_order_has_an_independent_even_parity_oracle_and_definition() {
        let fragments = vec![b"2".to_vec(), b"ab".to_vec(), b"cd".to_vec()];
        let mut builder = SemanticGraphBuilder::new(vec![1, 2, 2]);
        let control = builder.fragment(0).unwrap();
        let first = builder.fragment(1).unwrap();
        let second = builder.fragment(2).unwrap();
        let conditional =
            builder.operation(Operation::ConditionalOrder, vec![control, first, second]);
        let reversed = builder.operation(Operation::Reverse, vec![conditional]);
        let restored = builder.operation(Operation::Reverse, vec![reversed]);
        let output = builder.operation(Operation::RotateLeft(4), vec![restored]);
        builder.output(output);
        let graph = builder.validate().unwrap();

        let answer = evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap();
        let mut random = DeterministicRandom::new([47; 32]);
        let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
        let rendered = render_graph(&graph, &fragments, 47);
        let alias = plan
            .profile
            .alias(HelperSemantic::Operation(OperationKind::ConditionalOrder))
            .unwrap();

        assert_eq!(answer, b"abcd");
        assert!(rendered.question().contains(&format!(
            "{alias}(control, a, b): a followed by b when unsigned control[0] is even"
        )));
    }

    #[test]
    fn repeated_ordered_inputs_emit_once_but_dependency_clues_are_deduplicated() {
        let fragments = vec![b"Ab".to_vec(), b"Cd".to_vec()];
        let source_x = NodeId(0);
        let source_y = NodeId(1);
        let combined = NodeId(2);
        let plan = RenderPlan {
            fragments: vec![
                DisplayFragment {
                    heading: "first".to_owned(),
                    language: RenderLanguage::Rust,
                    steps: vec![DisplayStep {
                        node: source_x,
                        output_label: "source_x".to_owned(),
                        local_name: "load_x".to_owned(),
                        template: TemplateFamily::Direct,
                        numeric_style: NumericStyle::Decimal,
                        literal_plan: Some(FragmentLiteralPlan::Whole),
                        guard_value: None,
                        kind: DisplayStepKind::Fragment { index: 0 },
                    }],
                },
                DisplayFragment {
                    heading: "second".to_owned(),
                    language: RenderLanguage::Go,
                    steps: vec![
                        DisplayStep {
                            node: source_y,
                            output_label: "source_y".to_owned(),
                            local_name: "load_y".to_owned(),
                            template: TemplateFamily::Direct,
                            numeric_style: NumericStyle::Decimal,
                            literal_plan: Some(FragmentLiteralPlan::Whole),
                            guard_value: None,
                            kind: DisplayStepKind::Fragment { index: 1 },
                        },
                        DisplayStep {
                            node: combined,
                            output_label: "combined".to_owned(),
                            local_name: "join_values".to_owned(),
                            template: TemplateFamily::Direct,
                            numeric_style: NumericStyle::Decimal,
                            literal_plan: None,
                            guard_value: None,
                            kind: DisplayStepKind::Operation {
                                operation: Operation::Concat,
                                inputs: vec![source_x, source_x, source_y],
                            },
                        },
                    ],
                },
            ],
            output: combined,
            profile: ObfuscationProfile::new(BTreeMap::from([
                (HelperSemantic::BytesAscii, "make_bytes".to_owned()),
                (
                    HelperSemantic::Operation(OperationKind::Concat),
                    "join_bytes".to_owned(),
                ),
            ])),
            distractor: None,
        };

        let question = emitter::emit_question(&plan, &fragments).unwrap();
        let clue = "Dependency: output labels source_x (Fragment 1) are inputs to output label combined in Fragment 2.\n";

        assert!(question.contains("join_bytes(source_x, source_x, source_y)"));
        assert_eq!(question.matches(clue).count(), 1);
    }
}
