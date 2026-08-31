mod emitter;
mod error;
mod languages;
mod model;
mod names;
#[allow(unfulfilled_lint_expectations)]
mod planner;
#[allow(unfulfilled_lint_expectations)]
mod validate;

use crate::generation::{ValidatedSemanticGraph, random::RandomSource};

use error::RenderError;
pub use model::{MAX_QUESTION_BYTES, RenderLanguage, RenderMetadata, RenderedQuestion};

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the Phase 4 lifecycle API")
)]
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
    use std::collections::BTreeSet;

    use super::{
        emitter,
        error::RenderError,
        model::{
            DisplayFragment, DisplayStep, DisplayStepKind, MAX_QUESTION_BYTES, RenderLanguage,
            RenderPlan, TemplateFamily,
        },
        planner::plan_rendering,
        render_with,
    };
    use crate::generation::{
        NodeId, evaluate_semantic_graph,
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
    fn every_effective_output_label_and_metadata_language_is_visible() {
        let semantics = planned_fixture();
        let mut plan_random = DeterministicRandom::new([31; 32]);
        let plan =
            plan_rendering(semantics.graph(), semantics.fragments(), &mut plan_random).unwrap();
        let mut render_random = DeterministicRandom::new([31; 32]);
        let rendered =
            render_with(semantics.graph(), semantics.fragments(), &mut render_random).unwrap();

        for step in plan
            .fragments
            .iter()
            .filter(|fragment| !fragment.distractor)
            .flat_map(|fragment| &fragment.steps)
        {
            assert!(rendered.question().contains(&step.output_label));
        }
        let expected_languages = plan
            .fragments
            .iter()
            .filter(|fragment| !fragment.distractor)
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
            plan.fragments.iter().any(|fragment| fragment.distractor)
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
                    kind: DisplayStepKind::Fragment { index: 0 },
                }],
                distractor: false,
            })
            .collect();
        let plan = RenderPlan {
            fragments: display_fragments,
            output: NodeId(127),
        };

        let error = emitter::emit_question(&plan, &fragments).unwrap_err();

        assert_eq!(error, RenderError::LengthLimit);
        assert!(!error.to_string().contains(SECRET_MARKER));
        assert!(!format!("{error:?}").contains(SECRET_MARKER));
    }
}
