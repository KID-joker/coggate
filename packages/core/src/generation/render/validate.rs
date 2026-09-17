use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::generation::{NodeId, NodeKind, OperationKind, ValidatedSemanticGraph};

use super::{
    emitter::{
        MAX_STEP_BYTES, declared_template_max_bytes, emit_fragment, emit_operation,
        format_dependency_clue,
    },
    error::RenderError,
    model::{
        DisplayStep, DisplayStepKind, FragmentLiteralPlan, HelperSemantic, MAX_FRAGMENT_BYTES,
        MAX_QUESTION_BYTES, NumericStyle, RenderLanguage, RenderPlan, TemplateFamily,
    },
    names::MAX_IDENTIFIER_BYTES,
};

pub(super) const COMMON_QUESTION_BUDGET: usize = 2_048;
const FRAGMENT_WRAPPER_BUDGET: usize = 64;
const DISTRACTOR_WRAPPER_BUDGET: usize = 256;

pub(super) fn validate_plan(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
    plan: &RenderPlan,
) -> Result<(), RenderError> {
    if plan.output != graph.output() {
        return Err(RenderError::AmbiguousOutput);
    }

    validate_source_fragments(graph, fragments)?;
    validate_shape(plan, graph.fragment_lengths().len())?;
    validate_obfuscation(graph, fragments, plan)?;
    validate_identifiers(plan)?;

    let steps = index_effective_steps(plan)?;
    for node in graph.topological_nodes() {
        if !steps.contains_key(&node.id()) {
            return Err(RenderError::MissingReference(node.id()));
        }
    }

    resolve_operation_inputs(&steps)?;
    validate_length_bounds(fragments, plan, &steps)?;
    validate_semantic_correspondence(graph, &steps)?;
    validate_fragment_dependencies(plan, &steps)
}

fn validate_source_fragments(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
) -> Result<(), RenderError> {
    if fragments.len() != graph.fragment_lengths().len() {
        return Err(RenderError::InvalidPlan);
    }
    for (fragment, expected_length) in fragments.iter().zip(graph.fragment_lengths()) {
        if fragment.len() != *expected_length
            || fragment.is_empty()
            || fragment.len() > MAX_IDENTIFIER_BYTES
            || !fragment.iter().all(u8::is_ascii_alphanumeric)
        {
            return Err(RenderError::InvalidPlan);
        }
    }
    Ok(())
}

fn validate_shape(plan: &RenderPlan, expected_fragment_count: usize) -> Result<(), RenderError> {
    let distractors = plan
        .fragments
        .iter()
        .filter(|fragment| fragment.distractor)
        .collect::<Vec<_>>();
    if distractors.len() > 1 {
        return Err(RenderError::InvalidPlan);
    }
    if distractors
        .iter()
        .any(|fragment| !fragment.steps.is_empty())
    {
        return Err(RenderError::DistractorReferenced);
    }

    let effective = plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
        .collect::<Vec<_>>();
    if effective.len() != expected_fragment_count
        || !(3..=5).contains(&effective.len())
        || effective.iter().any(|fragment| fragment.steps.is_empty())
    {
        return Err(RenderError::InvalidPlan);
    }

    let languages = effective
        .iter()
        .map(|fragment| fragment.language)
        .collect::<BTreeSet<_>>();
    if !(2..=3).contains(&languages.len()) || languages.iter().any(|language| !supported(*language))
    {
        return Err(RenderError::InvalidPlan);
    }
    Ok(())
}

fn supported(language: RenderLanguage) -> bool {
    match language {
        RenderLanguage::C
        | RenderLanguage::Cpp
        | RenderLanguage::Rust
        | RenderLanguage::Go
        | RenderLanguage::Java
        | RenderLanguage::Pseudocode => true,
    }
}

fn validate_identifiers(plan: &RenderPlan) -> Result<(), RenderError> {
    for fragment in &plan.fragments {
        validate_identifier(&fragment.heading)?;
        for step in &fragment.steps {
            validate_identifier(&step.output_label)?;
            validate_identifier(&step.local_name)?;
        }
    }
    for alias in plan.profile.aliases().values() {
        validate_identifier(alias)?;
    }

    let mut output_labels = BTreeSet::new();
    for step in plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
        .flat_map(|fragment| &fragment.steps)
    {
        if !output_labels.insert(step.output_label.as_str()) {
            return Err(RenderError::DuplicateReference(step.node));
        }
    }

    let mut all_names = BTreeSet::new();
    for heading in plan
        .fragments
        .iter()
        .map(|fragment| fragment.heading.as_str())
    {
        if !all_names.insert(heading) {
            return Err(RenderError::InvalidPlan);
        }
    }
    for output_label in plan
        .fragments
        .iter()
        .flat_map(|fragment| &fragment.steps)
        .map(|step| step.output_label.as_str())
    {
        if !all_names.insert(output_label) {
            return Err(RenderError::InvalidPlan);
        }
    }
    for local_name in plan
        .fragments
        .iter()
        .flat_map(|fragment| &fragment.steps)
        .map(|step| step.local_name.as_str())
    {
        if !all_names.insert(local_name) {
            return Err(RenderError::InvalidPlan);
        }
    }
    for alias in plan.profile.aliases().values() {
        if !all_names.insert(alias) {
            return Err(RenderError::InvalidPlan);
        }
    }
    Ok(())
}

fn validate_obfuscation(
    graph: &ValidatedSemanticGraph,
    fragments: &[Vec<u8>],
    plan: &RenderPlan,
) -> Result<(), RenderError> {
    let expected_semantics = expected_helper_semantics(graph);
    if plan
        .profile
        .aliases()
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != expected_semantics
    {
        return Err(RenderError::InvalidPlan);
    }

    for step in plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
        .flat_map(|fragment| &fragment.steps)
    {
        if step.guard_value.is_some() != (step.template == TemplateFamily::Guarded) {
            return Err(RenderError::InvalidPlan);
        }
        if let NumericStyle::IdentityOffset { delta } = step.numeric_style {
            if !(1..=15).contains(&delta) {
                return Err(RenderError::InvalidPlan);
            }
        }

        match (&step.kind, &step.literal_plan) {
            (DisplayStepKind::Fragment { index }, Some(literal_plan)) => {
                let length = fragments.get(*index).ok_or(RenderError::InvalidPlan)?.len();
                validate_literal_plan(literal_plan, length)?;
            }
            (DisplayStepKind::Operation { .. }, None) => {}
            _ => return Err(RenderError::InvalidPlan),
        }
    }
    Ok(())
}

fn expected_helper_semantics(graph: &ValidatedSemanticGraph) -> BTreeSet<HelperSemantic> {
    let mut expected = BTreeSet::from([HelperSemantic::BytesAscii]);
    for node in graph.topological_nodes() {
        if let NodeKind::Operation { operation, .. } = node.kind() {
            expected.insert(HelperSemantic::Operation(OperationKind::from(operation)));
        }
    }
    expected
}

fn validate_literal_plan(
    plan: &FragmentLiteralPlan,
    source_length: usize,
) -> Result<(), RenderError> {
    if source_length == 1 {
        return if *plan == FragmentLiteralPlan::Whole {
            Ok(())
        } else {
            Err(RenderError::InvalidPlan)
        };
    }

    match plan {
        FragmentLiteralPlan::Whole => Ok(()),
        FragmentLiteralPlan::OrderedChunks(chunks) => {
            validate_chunk_count(chunks.len(), source_length)?;
            validate_source_order(chunks, source_length)
        }
        FragmentLiteralPlan::ShuffledChunks {
            chunks,
            restore_order,
        } => {
            validate_chunk_count(chunks.len(), source_length)?;
            if restore_order.len() != chunks.len() {
                return Err(RenderError::InvalidPlan);
            }
            let permutation = restore_order.iter().copied().collect::<BTreeSet<_>>();
            if permutation != (0..chunks.len()).collect() {
                return Err(RenderError::InvalidPlan);
            }
            let restored = restore_order
                .iter()
                .map(|index| chunks[*index].clone())
                .collect::<Vec<_>>();
            validate_source_order(&restored, source_length)?;
            if chunks == &restored {
                return Err(RenderError::InvalidPlan);
            }
            Ok(())
        }
    }
}

fn validate_chunk_count(chunk_count: usize, source_length: usize) -> Result<(), RenderError> {
    if !(2..=3).contains(&chunk_count) || (chunk_count == 3 && source_length < 3) {
        return Err(RenderError::InvalidPlan);
    }
    Ok(())
}

fn validate_source_order(
    chunks: &[std::ops::Range<usize>],
    source_length: usize,
) -> Result<(), RenderError> {
    let mut expected_start = 0;
    for chunk in chunks {
        if chunk.start != expected_start || chunk.start >= chunk.end || chunk.end > source_length {
            return Err(RenderError::InvalidPlan);
        }
        expected_start = chunk.end;
    }
    if expected_start != source_length {
        return Err(RenderError::InvalidPlan);
    }
    Ok(())
}

fn validate_identifier(identifier: &str) -> Result<(), RenderError> {
    if identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err(RenderError::LengthLimit);
    }
    let Some((first, remaining)) = identifier.as_bytes().split_first() else {
        return Err(RenderError::InvalidPlan);
    };
    if identifier == "_"
        || !(first.is_ascii_alphabetic() || *first == b'_')
        || !remaining
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(RenderError::InvalidPlan);
    }
    Ok(())
}

fn index_effective_steps(
    plan: &RenderPlan,
) -> Result<BTreeMap<NodeId, (&DisplayStep, usize)>, RenderError> {
    let mut steps = BTreeMap::new();
    for (fragment_index, fragment) in plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
        .enumerate()
    {
        for step in &fragment.steps {
            if steps.insert(step.node, (step, fragment_index)).is_some() {
                return Err(RenderError::DuplicateReference(step.node));
            }
        }
    }
    Ok(steps)
}

fn resolve_operation_inputs(
    steps: &BTreeMap<NodeId, (&DisplayStep, usize)>,
) -> Result<(), RenderError> {
    for (step, _) in steps.values() {
        if let DisplayStepKind::Operation { inputs, .. } = &step.kind {
            for input in inputs {
                if !steps.contains_key(input) {
                    return Err(RenderError::MissingReference(*input));
                }
            }
        }
    }
    Ok(())
}

fn validate_semantic_correspondence(
    graph: &ValidatedSemanticGraph,
    steps: &BTreeMap<NodeId, (&DisplayStep, usize)>,
) -> Result<(), RenderError> {
    if steps.len() != graph.topological_nodes().len() {
        return Err(RenderError::InvalidPlan);
    }

    for node in graph.topological_nodes() {
        let (step, _) = steps
            .get(&node.id())
            .ok_or(RenderError::MissingReference(node.id()))?;
        let matches = match (node.kind(), &step.kind) {
            (
                NodeKind::Fragment { index: expected },
                DisplayStepKind::Fragment { index: actual },
            ) => expected == actual,
            (
                NodeKind::Operation {
                    operation: expected_operation,
                    inputs: expected_inputs,
                },
                DisplayStepKind::Operation {
                    operation: actual_operation,
                    inputs: actual_inputs,
                },
            ) => expected_operation == actual_operation && expected_inputs == actual_inputs,
            _ => false,
        };
        if !matches {
            return Err(RenderError::SemanticMismatch(node.id()));
        }
    }
    Ok(())
}

fn validate_fragment_dependencies(
    plan: &RenderPlan,
    steps: &BTreeMap<NodeId, (&DisplayStep, usize)>,
) -> Result<(), RenderError> {
    let fragment_count = plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
        .count();
    let mut edges = BTreeSet::new();
    for (step, target_fragment) in steps.values() {
        let DisplayStepKind::Operation { inputs, .. } = &step.kind else {
            continue;
        };
        for input in inputs {
            let (_, source_fragment) = steps
                .get(input)
                .ok_or(RenderError::MissingReference(*input))?;
            if source_fragment != target_fragment {
                edges.insert((*source_fragment, *target_fragment));
            }
        }
    }

    let mut outgoing = vec![Vec::new(); fragment_count];
    let mut indegree = vec![0_usize; fragment_count];
    for (source, target) in edges {
        outgoing[source].push(target);
        indegree[target] = indegree[target]
            .checked_add(1)
            .ok_or(RenderError::LengthLimit)?;
    }
    let mut ready = indegree
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(source) = ready.pop_front() {
        visited += 1;
        for target in &outgoing[source] {
            indegree[*target] -= 1;
            if indegree[*target] == 0 {
                ready.push_back(*target);
            }
        }
    }
    if visited != fragment_count {
        return Err(RenderError::InvalidPlan);
    }
    Ok(())
}

fn validate_length_bounds(
    fragments: &[Vec<u8>],
    plan: &RenderPlan,
    steps: &BTreeMap<NodeId, (&DisplayStep, usize)>,
) -> Result<(), RenderError> {
    let effective = plan
        .fragments
        .iter()
        .filter(|fragment| !fragment.distractor)
        .collect::<Vec<_>>();
    let mut fragment_budgets = effective
        .iter()
        .map(|fragment| checked_add(FRAGMENT_WRAPPER_BUDGET, fragment.heading.len()))
        .collect::<Result<Vec<_>, _>>()?;

    for (step, fragment_index) in steps.values() {
        let step_budget =
            emitted_step_bytes(effective[*fragment_index].language, step, fragments, steps)?;
        fragment_budgets[*fragment_index] =
            checked_add(fragment_budgets[*fragment_index], step_budget)?;

        if let DisplayStepKind::Operation { inputs, .. } = &step.kind {
            let mut seen_producers = BTreeSet::new();
            let mut producers = Vec::new();
            for input in inputs {
                let (producer, producer_fragment) = steps
                    .get(input)
                    .ok_or(RenderError::MissingReference(*input))?;
                if producer_fragment != fragment_index && seen_producers.insert(*input) {
                    producers.push((producer.output_label.as_str(), *producer_fragment));
                }
            }
            if !producers.is_empty() {
                let clue = format_dependency_clue(&producers, &step.output_label, *fragment_index)?;
                fragment_budgets[*fragment_index] =
                    checked_add(fragment_budgets[*fragment_index], clue.len())?;
            }
        }
    }

    if fragment_budgets
        .iter()
        .any(|budget| *budget > MAX_FRAGMENT_BYTES)
    {
        return Err(RenderError::LengthLimit);
    }

    let mut total = checked_add(COMMON_QUESTION_BUDGET, output_label(plan, steps)?.len())?;
    for budget in fragment_budgets {
        total = checked_add(total, budget)?;
    }
    if let Some(distractor) = plan.fragments.iter().find(|fragment| fragment.distractor) {
        total = checked_sum(&[total, DISTRACTOR_WRAPPER_BUDGET, distractor.heading.len()])?;
    }
    if total > MAX_QUESTION_BYTES {
        return Err(RenderError::LengthLimit);
    }
    Ok(())
}

fn output_label<'a>(
    plan: &RenderPlan,
    steps: &'a BTreeMap<NodeId, (&'a DisplayStep, usize)>,
) -> Result<&'a str, RenderError> {
    steps
        .get(&plan.output)
        .map(|(step, _)| step.output_label.as_str())
        .ok_or(RenderError::MissingReference(plan.output))
}

fn emitted_step_bytes(
    language: RenderLanguage,
    step: &DisplayStep,
    fragments: &[Vec<u8>],
    steps: &BTreeMap<NodeId, (&DisplayStep, usize)>,
) -> Result<usize, RenderError> {
    let emitted = match &step.kind {
        DisplayStepKind::Fragment { index } => emit_fragment(
            language,
            step.template,
            &step.output_label,
            &step.local_name,
            fragments.get(*index).ok_or(RenderError::InvalidPlan)?,
        )?,
        DisplayStepKind::Operation { operation, inputs } => {
            let input_labels = inputs
                .iter()
                .map(|input| {
                    steps
                        .get(input)
                        .map(|(producer, _)| producer.output_label.clone())
                        .ok_or(RenderError::MissingReference(*input))
                })
                .collect::<Result<Vec<_>, _>>()?;
            emit_operation(
                language,
                step.template,
                &step.output_label,
                &step.local_name,
                operation,
                &input_labels,
            )?
        }
    };
    let declared = declared_template_max_bytes(language, step.template);
    if emitted.len() > declared || emitted.len() > MAX_STEP_BYTES {
        return Err(RenderError::LengthLimit);
    }
    Ok(emitted.len())
}

fn checked_sum(values: &[usize]) -> Result<usize, RenderError> {
    values
        .iter()
        .try_fold(0_usize, |sum, value| checked_add(sum, *value))
}

fn checked_add(left: usize, right: usize) -> Result<usize, RenderError> {
    left.checked_add(right).ok_or(RenderError::LengthLimit)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::generation::{
        NodeId, Operation, OperationKind, SemanticGraphBuilder, ValidatedSemanticGraph,
        render::{
            error::RenderError,
            model::{
                DisplayFragment, DisplayStepKind, FragmentLiteralPlan, HelperSemantic,
                NumericStyle, ObfuscationProfile, RenderLanguage, RenderPlan, TemplateFamily,
            },
            planner::plan_rendering,
        },
        test_random::DeterministicRandom,
    };

    use super::{
        emitted_step_bytes, expected_helper_semantics, index_effective_steps, validate_plan,
    };

    fn fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>) {
        let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2, 2]);
        let inputs = (0..4)
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();
        let mut output = builder.operation(Operation::Concat, inputs);
        for _ in 0..4 {
            output = builder.operation(Operation::Reverse, vec![output]);
        }
        builder.output(output);

        (
            builder.validate().unwrap(),
            vec![
                b"A0".to_vec(),
                b"B1".to_vec(),
                b"C2".to_vec(),
                b"D3".to_vec(),
            ],
        )
    }

    fn fixture_plan() -> (ValidatedSemanticGraph, Vec<Vec<u8>>, RenderPlan) {
        let (graph, fragments) = fixture();
        let mut random = DeterministicRandom::new([37; 32]);
        let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
        (graph, fragments, plan)
    }

    fn diverse_alias_fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>, RenderPlan) {
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
        let mut random = DeterministicRandom::new([83; 32]);
        let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
        (graph, fragments, plan)
    }

    fn diverse_alias_oracle() -> std::collections::BTreeSet<HelperSemantic> {
        [
            HelperSemantic::BytesAscii,
            HelperSemantic::Operation(OperationKind::Reverse),
            HelperSemantic::Operation(OperationKind::RotateLeft),
            HelperSemantic::Operation(OperationKind::Xor),
            HelperSemantic::Operation(OperationKind::Concat),
        ]
        .into_iter()
        .collect()
    }

    fn effective_fragments(plan: &mut RenderPlan) -> Vec<&mut DisplayFragment> {
        plan.fragments
            .iter_mut()
            .filter(|fragment| !fragment.distractor)
            .collect()
    }

    #[test]
    fn accepts_an_unmodified_planner_plan() {
        let (graph, fragments, plan) = fixture_plan();

        assert_eq!(validate_plan(&graph, &fragments, &plan), Ok(()));
    }

    #[test]
    fn validator_alias_oracle_matches_a_hand_authored_diverse_graph() {
        let (graph, fragments, plan) = diverse_alias_fixture();

        assert_eq!(expected_helper_semantics(&graph), diverse_alias_oracle());
        assert_eq!(
            plan.profile
                .aliases()
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            diverse_alias_oracle()
        );
        assert_eq!(validate_plan(&graph, &fragments, &plan), Ok(()));
    }

    #[test]
    fn accepts_an_unmodified_diverse_planner_profile() {
        let (graph, fragments, plan) = diverse_alias_fixture();

        assert_eq!(validate_plan(&graph, &fragments, &plan), Ok(()));
    }

    #[test]
    fn diverse_graph_rejects_missing_and_extra_alias_semantics() {
        let (graph, fragments, mut plan) = diverse_alias_fixture();
        let mut aliases = plan.profile.aliases().clone();
        aliases.remove(&HelperSemantic::Operation(OperationKind::RotateLeft));
        plan.profile = ObfuscationProfile::new(aliases);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = diverse_alias_fixture();
        let mut aliases = plan.profile.aliases().clone();
        aliases.insert(
            HelperSemantic::Operation(OperationKind::ConditionalOrder),
            "unused_alias".to_owned(),
        );
        plan.profile = ObfuscationProfile::new(aliases);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn validator_step_bytes_match_actual_emission_for_every_language_and_template() {
        let (_, fragments, plan) = fixture_plan();
        let steps = index_effective_steps(&plan).unwrap();

        for fragment in plan
            .fragments
            .iter()
            .filter(|fragment| !fragment.distractor)
        {
            for step in &fragment.steps {
                let actual = match &step.kind {
                    DisplayStepKind::Fragment { index } => {
                        crate::generation::render::emitter::emit_fragment(
                            fragment.language,
                            step.template,
                            &step.output_label,
                            &step.local_name,
                            &fragments[*index],
                        )
                        .unwrap()
                    }
                    DisplayStepKind::Operation { operation, inputs } => {
                        let labels = inputs
                            .iter()
                            .map(|input| steps[input].0.output_label.clone())
                            .collect::<Vec<_>>();
                        crate::generation::render::emitter::emit_operation(
                            fragment.language,
                            step.template,
                            &step.output_label,
                            &step.local_name,
                            operation,
                            &labels,
                        )
                        .unwrap()
                    }
                };

                assert_eq!(
                    emitted_step_bytes(fragment.language, step, &fragments, &steps).unwrap(),
                    actual.len()
                );
            }
        }

        let representative_steps = [
            steps
                .values()
                .map(|(step, _)| *step)
                .find(|step| matches!(step.kind, DisplayStepKind::Fragment { .. }))
                .unwrap(),
            steps
                .values()
                .map(|(step, _)| *step)
                .find(|step| matches!(step.kind, DisplayStepKind::Operation { .. }))
                .unwrap(),
        ];
        for language in RenderLanguage::ALL {
            for family in [TemplateFamily::Direct, TemplateFamily::Helper] {
                for representative in representative_steps {
                    let mut step = representative.clone();
                    step.template = family;
                    let actual = match &step.kind {
                        DisplayStepKind::Fragment { index } => {
                            crate::generation::render::emitter::emit_fragment(
                                language,
                                family,
                                &step.output_label,
                                &step.local_name,
                                &fragments[*index],
                            )
                            .unwrap()
                        }
                        DisplayStepKind::Operation { operation, inputs } => {
                            let labels = inputs
                                .iter()
                                .map(|input| steps[input].0.output_label.clone())
                                .collect::<Vec<_>>();
                            crate::generation::render::emitter::emit_operation(
                                language,
                                family,
                                &step.output_label,
                                &step.local_name,
                                operation,
                                &labels,
                            )
                            .unwrap()
                        }
                    };
                    assert_eq!(
                        emitted_step_bytes(language, &step, &fragments, &steps).unwrap(),
                        actual.len()
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_a_missing_effective_step() {
        let (graph, fragments, mut plan) = fixture_plan();
        let removed = effective_fragments(&mut plan)[0].steps.pop().unwrap();

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::MissingReference(removed.node))
        );
    }

    #[test]
    fn rejects_a_duplicate_effective_node() {
        let (graph, fragments, mut plan) = fixture_plan();
        let duplicate = plan
            .fragments
            .iter()
            .filter(|fragment| !fragment.distractor)
            .flat_map(|fragment| &fragment.steps)
            .next()
            .unwrap()
            .clone();
        effective_fragments(&mut plan)[0]
            .steps
            .push(duplicate.clone());

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::DuplicateReference(duplicate.node))
        );
    }

    #[test]
    fn rejects_a_changed_operation() {
        let (graph, fragments, mut plan) = fixture_plan();
        let step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Operation { .. }))
            .unwrap();
        step.kind = DisplayStepKind::Operation {
            operation: Operation::RotateLeft(1),
            inputs: match &step.kind {
                DisplayStepKind::Operation { inputs, .. } => inputs.clone(),
                DisplayStepKind::Fragment { .. } => unreachable!(),
            },
        };
        let changed = step.node;

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::SemanticMismatch(changed))
        );
    }

    #[test]
    fn rejects_changed_ordered_inputs() {
        let (graph, fragments, mut plan) = fixture_plan();
        let step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| {
                matches!(
                    &step.kind,
                    DisplayStepKind::Operation { inputs, .. } if inputs.len() > 1
                )
            })
            .unwrap();
        let DisplayStepKind::Operation { inputs, .. } = &mut step.kind else {
            unreachable!();
        };
        inputs.swap(0, 1);
        let changed = step.node;

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::SemanticMismatch(changed))
        );
    }

    #[test]
    fn rejects_duplicate_output_labels_without_carrying_the_label() {
        let (graph, fragments, mut plan) = fixture_plan();
        let mut effective = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps);
        let label = effective.next().unwrap().output_label.clone();
        let duplicate = effective.next().unwrap();
        duplicate.output_label = label;
        let duplicate_node = duplicate.node;

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::DuplicateReference(duplicate_node))
        );
    }

    #[test]
    fn rejects_duplicate_local_names_and_headings_without_text_payloads() {
        let (graph, fragments, mut plan) = fixture_plan();
        let mut effective = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps);
        let local_name = effective.next().unwrap().local_name.clone();
        effective.next().unwrap().local_name = local_name;
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let mut effective = effective_fragments(&mut plan).into_iter();
        let heading = effective.next().unwrap().heading.clone();
        effective.next().unwrap().heading = heading;
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_identifier_collisions_across_categories() {
        let (graph, fragments, mut plan) = fixture_plan();
        let mut effective = effective_fragments(&mut plan).into_iter();
        let output_label = effective.next().unwrap().steps[0].output_label.clone();
        effective.next().unwrap().heading = output_label;

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_missing_or_unused_helper_alias_semantics() {
        let (graph, fragments, mut plan) = fixture_plan();
        let mut aliases = plan.profile.aliases().clone();
        aliases.remove(&HelperSemantic::BytesAscii);
        plan.profile = ObfuscationProfile::new(aliases);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let mut aliases = plan.profile.aliases().clone();
        aliases.insert(
            HelperSemantic::Operation(OperationKind::ConditionalOrder),
            "unused_alias".to_owned(),
        );
        plan.profile = ObfuscationProfile::new(aliases);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_alias_identifier_collisions_and_nonportable_aliases() {
        let (graph, fragments, mut plan) = fixture_plan();
        let collision = plan.fragments[0].heading.clone();
        let aliases = plan
            .profile
            .aliases()
            .keys()
            .copied()
            .enumerate()
            .map(|(index, semantic)| {
                (
                    semantic,
                    if index == 0 {
                        collision.clone()
                    } else {
                        format!("alias_{index}")
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        plan.profile = ObfuscationProfile::new(aliases);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let aliases = plan
            .profile
            .aliases()
            .keys()
            .copied()
            .enumerate()
            .map(|(index, semantic)| {
                (
                    semantic,
                    if index == 0 {
                        "not-portable".to_owned()
                    } else {
                        format!("alias_{index}")
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        plan.profile = ObfuscationProfile::new(aliases);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_literal_and_guard_field_shape_mismatches() {
        let (graph, fragments, mut plan) = fixture_plan();
        let fragment_step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Fragment { .. }))
            .unwrap();
        fragment_step.literal_plan = None;
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let operation_step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Operation { .. }))
            .unwrap();
        operation_step.literal_plan = Some(FragmentLiteralPlan::Whole);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let step = &mut effective_fragments(&mut plan)[0].steps[0];
        step.template = TemplateFamily::Guarded;
        step.guard_value = None;
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let step = &mut effective_fragments(&mut plan)[0].steps[0];
        step.template = TemplateFamily::Direct;
        step.guard_value = Some(7);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_malformed_literal_partitions_restore_orders_and_numeric_offsets() {
        let (graph, fragments, mut plan) = fixture_plan();
        let step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Fragment { .. }))
            .unwrap();
        step.literal_plan = Some(FragmentLiteralPlan::OrderedChunks(vec![0..1, 0..2]));
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        let step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Fragment { .. }))
            .unwrap();
        step.literal_plan = Some(FragmentLiteralPlan::ShuffledChunks {
            chunks: vec![1..2, 0..1],
            restore_order: vec![0, 0],
        });
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps[0].numeric_style =
            NumericStyle::IdentityOffset { delta: 0 };
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_an_operation_input_without_a_producer() {
        let (graph, fragments, mut plan) = fixture_plan();
        let missing = NodeId(u32::MAX);
        let step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Operation { .. }))
            .unwrap();
        let DisplayStepKind::Operation { inputs, .. } = &mut step.kind else {
            unreachable!();
        };
        inputs[0] = missing;

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::MissingReference(missing))
        );
    }

    #[test]
    fn rejects_a_declared_output_different_from_the_graph() {
        let (graph, fragments, mut plan) = fixture_plan();
        plan.output = graph.topological_nodes()[0].id();

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::AmbiguousOutput)
        );
    }

    #[test]
    fn rejects_fewer_than_two_or_more_than_three_effective_languages() {
        let (graph, fragments, mut plan) = fixture_plan();
        for fragment in effective_fragments(&mut plan) {
            fragment.language = RenderLanguage::Rust;
        }
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        for (fragment, language) in effective_fragments(&mut plan).into_iter().zip([
            RenderLanguage::C,
            RenderLanguage::Cpp,
            RenderLanguage::Rust,
            RenderLanguage::Go,
        ]) {
            fragment.language = language;
        }
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_an_empty_effective_fragment() {
        let (graph, fragments, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps.clear();

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_more_than_one_distractor() {
        let (graph, fragments, mut plan) = fixture_plan();
        let mut distractor = plan
            .fragments
            .iter()
            .find(|fragment| fragment.distractor)
            .cloned()
            .unwrap_or_else(|| DisplayFragment {
                heading: "audit_0".to_owned(),
                language: RenderLanguage::C,
                steps: Vec::new(),
                distractor: true,
            });
        distractor.heading = "audit_1".to_owned();
        plan.fragments.push(distractor.clone());
        distractor.heading = "audit_2".to_owned();
        plan.fragments.push(distractor);

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_a_distractor_containing_an_effective_step() {
        let (graph, fragments, mut plan) = fixture_plan();
        let step = effective_fragments(&mut plan)[0].steps.pop().unwrap();
        if let Some(distractor) = plan
            .fragments
            .iter_mut()
            .find(|fragment| fragment.distractor)
        {
            distractor.steps.push(step);
        } else {
            plan.fragments.push(DisplayFragment {
                heading: "audit_0".to_owned(),
                language: RenderLanguage::C,
                steps: vec![step],
                distractor: true,
            });
        }

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::DistractorReferenced)
        );
    }

    #[test]
    fn rejects_a_fragment_level_dependency_cycle_created_by_regrouping() {
        let (graph, fragments, mut plan) = fixture_plan();
        let mut steps = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| std::mem::take(&mut fragment.steps))
            .collect::<Vec<_>>();
        steps.sort_by_key(|step| step.node);
        let mut effective = effective_fragments(&mut plan);
        let fragment_count = effective.len();
        for (index, step) in steps.into_iter().enumerate() {
            effective[index % fragment_count].steps.push(step);
        }

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_oversized_or_nonportable_identifiers() {
        let (graph, fragments, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps[0].local_name = "x".repeat(17);
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::LengthLimit)
        );

        let (_, _, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].heading = "not-portable".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_digit_leading_names_in_every_identifier_category() {
        let (graph, fragments, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps[0].output_label = "1value".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps[0].local_name = "1value".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].heading = "1value".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_a_bare_underscore_in_every_identifier_category() {
        let (graph, fragments, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps[0].output_label = "_".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].steps[0].local_name = "_".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );

        let (_, _, mut plan) = fixture_plan();
        effective_fragments(&mut plan)[0].heading = "_".to_owned();
        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }

    #[test]
    fn rejects_an_operation_outside_the_authoritative_semantic_contract() {
        let (graph, fragments, mut plan) = fixture_plan();
        let step = effective_fragments(&mut plan)
            .into_iter()
            .flat_map(|fragment| &mut fragment.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Operation { .. }))
            .unwrap();
        let inputs = match &step.kind {
            DisplayStepKind::Operation { inputs, .. } => inputs.clone(),
            DisplayStepKind::Fragment { .. } => unreachable!(),
        };
        step.kind = DisplayStepKind::Operation {
            operation: Operation::Xor(vec![255; 3_000]),
            inputs,
        };

        assert_eq!(
            validate_plan(&graph, &fragments, &plan),
            Err(RenderError::InvalidPlan)
        );
    }
}
