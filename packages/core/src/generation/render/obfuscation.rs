use std::{collections::BTreeSet, ops::Range};

use crate::generation::{
    NodeKind, OperationKind, ValidatedSemanticGraph,
    random::{RandomSource, sample_below, shuffle},
};

use super::{
    error::RenderError,
    model::{FragmentLiteralPlan, HelperSemantic, NumericStyle, TemplateFamily},
};

pub(super) fn used_helper_semantics<'a>(
    graph: &ValidatedSemanticGraph,
    literal_plans: impl IntoIterator<Item = &'a FragmentLiteralPlan>,
) -> BTreeSet<HelperSemantic> {
    let mut semantics = graph
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
    if literal_plans
        .into_iter()
        .any(|plan| !matches!(plan, FragmentLiteralPlan::Whole))
    {
        semantics.insert(HelperSemantic::Operation(OperationKind::Concat));
    }
    semantics
}

pub(super) fn sample_template_family(
    random: &mut impl RandomSource,
) -> Result<TemplateFamily, RenderError> {
    match sample(random, 4)? {
        0 => Ok(TemplateFamily::Direct),
        1 => Ok(TemplateFamily::Helper),
        2 => Ok(TemplateFamily::AliasChain),
        _ => Ok(TemplateFamily::Guarded),
    }
}

pub(super) fn sample_numeric_style(
    random: &mut impl RandomSource,
) -> Result<NumericStyle, RenderError> {
    match sample(random, 3)? {
        0 => Ok(NumericStyle::Decimal),
        1 => Ok(NumericStyle::LowerHex),
        _ => Ok(NumericStyle::IdentityOffset {
            delta: (sample(random, 15)? + 1) as u8,
        }),
    }
}

pub(super) fn plan_fragment_literal(
    length: usize,
    random: &mut impl RandomSource,
) -> Result<FragmentLiteralPlan, RenderError> {
    if length == 0 {
        return Err(RenderError::InvalidPlan);
    }
    if length == 1 {
        return Ok(FragmentLiteralPlan::Whole);
    }

    match sample(random, 3)? {
        0 => Ok(FragmentLiteralPlan::Whole),
        1 => Ok(FragmentLiteralPlan::OrderedChunks(source_chunks(
            length, random,
        )?)),
        _ => shuffled_chunks(length, random),
    }
}

pub(super) fn sample_guard_value(random: &mut impl RandomSource) -> Result<u8, RenderError> {
    sample(random, 256).map(|value| value as u8)
}

fn source_chunks(
    length: usize,
    random: &mut impl RandomSource,
) -> Result<Vec<Range<usize>>, RenderError> {
    let chunk_count = if length >= 3 {
        2 + sample(random, 2)?
    } else {
        2
    };
    let mut cut_points = (1..length).collect::<Vec<_>>();
    shuffle(random, &mut cut_points).map_err(RenderError::from_generation_error)?;
    cut_points.truncate(chunk_count - 1);
    cut_points.sort_unstable();

    let mut boundaries = Vec::with_capacity(chunk_count + 1);
    boundaries.push(0);
    boundaries.extend(cut_points);
    boundaries.push(length);
    Ok(boundaries.windows(2).map(|pair| pair[0]..pair[1]).collect())
}

fn shuffled_chunks(
    length: usize,
    random: &mut impl RandomSource,
) -> Result<FragmentLiteralPlan, RenderError> {
    let source_order = source_chunks(length, random)?;
    let display_order = match source_order.len() {
        2 => vec![1, 0],
        3 => match sample(random, 5)? {
            0 => vec![0, 2, 1],
            1 => vec![1, 0, 2],
            2 => vec![1, 2, 0],
            3 => vec![2, 0, 1],
            _ => vec![2, 1, 0],
        },
        _ => return Err(RenderError::InvalidPlan),
    };
    let chunks = display_order
        .iter()
        .map(|source_index| source_order[*source_index].clone())
        .collect::<Vec<_>>();
    let mut restore_order = vec![0; display_order.len()];
    for (display_index, source_index) in display_order.into_iter().enumerate() {
        restore_order[source_index] = display_index;
    }

    Ok(FragmentLiteralPlan::ShuffledChunks {
        chunks,
        restore_order,
    })
}

fn sample(random: &mut impl RandomSource, upper: usize) -> Result<usize, RenderError> {
    sample_below(random, upper).map_err(RenderError::from_generation_error)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, ops::Range};

    use crate::generation::{
        GenerationError,
        random::RandomSource,
        render::error::RenderError,
        render::model::{FragmentLiteralPlan, NumericStyle, TemplateFamily},
        test_random::DeterministicRandom,
    };

    use super::{plan_fragment_literal, sample_numeric_style, sample_template_family};

    struct EmptyRandom;

    impl RandomSource for EmptyRandom {
        fn fill(&mut self, _destination: &mut [u8]) -> Result<(), GenerationError> {
            Err(GenerationError::RandomnessUnavailable)
        }
    }

    fn ranges(plan: &FragmentLiteralPlan) -> Vec<Range<usize>> {
        match plan {
            FragmentLiteralPlan::Whole => Vec::new(),
            FragmentLiteralPlan::OrderedChunks(ranges) => ranges.clone(),
            FragmentLiteralPlan::ShuffledChunks { chunks, .. } => chunks.clone(),
        }
    }

    #[test]
    fn deterministic_seed_matrix_reaches_every_obfuscation_choice() {
        let mut templates = BTreeSet::new();
        let mut numeric_styles = BTreeSet::new();
        let mut literal_kinds = BTreeSet::new();

        for seed in 0_u8..=127 {
            let mut random = DeterministicRandom::new([seed; 32]);
            templates.insert(sample_template_family(&mut random).unwrap());
            numeric_styles.insert(sample_numeric_style(&mut random).unwrap());
            literal_kinds.insert(match plan_fragment_literal(8, &mut random).unwrap() {
                FragmentLiteralPlan::Whole => 0,
                FragmentLiteralPlan::OrderedChunks(_) => 1,
                FragmentLiteralPlan::ShuffledChunks { .. } => 2,
            });
        }

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
    fn literal_plans_are_exact_nonempty_partitions_and_restore_source_bytes() {
        for length in 1..=16 {
            let source = (0..length).map(|value| value as u8).collect::<Vec<_>>();
            for seed in 0_u8..=127 {
                let mut random = DeterministicRandom::new([seed; 32]);
                let plan = plan_fragment_literal(length, &mut random).unwrap();
                if length == 1 {
                    assert_eq!(plan, FragmentLiteralPlan::Whole);
                    continue;
                }

                let chunks = ranges(&plan);
                if chunks.is_empty() {
                    assert_eq!(plan, FragmentLiteralPlan::Whole);
                    continue;
                }
                assert!((2..=3).contains(&chunks.len()));
                assert!(chunks.iter().all(|range| range.start < range.end));

                let mut source_ranges = chunks.clone();
                source_ranges.sort_unstable_by_key(|range| range.start);
                assert_eq!(source_ranges.first().unwrap().start, 0);
                assert_eq!(source_ranges.last().unwrap().end, length);
                assert!(
                    source_ranges
                        .windows(2)
                        .all(|pair| pair[0].end == pair[1].start)
                );

                let reconstructed = match &plan {
                    FragmentLiteralPlan::Whole => source.clone(),
                    FragmentLiteralPlan::OrderedChunks(ranges) => ranges
                        .iter()
                        .flat_map(|range| source[range.clone()].iter().copied())
                        .collect(),
                    FragmentLiteralPlan::ShuffledChunks {
                        chunks,
                        restore_order,
                    } => {
                        assert_eq!(restore_order.len(), chunks.len());
                        assert_eq!(
                            restore_order.iter().copied().collect::<BTreeSet<_>>(),
                            (0..chunks.len()).collect()
                        );
                        restore_order
                            .iter()
                            .flat_map(|index| source[chunks[*index].clone()].iter().copied())
                            .collect()
                    }
                };
                assert_eq!(reconstructed, source);
            }
        }
    }

    #[test]
    fn construction_randomness_exhaustion_is_terminal() {
        assert_eq!(
            sample_template_family(&mut EmptyRandom),
            Err(RenderError::RandomnessUnavailable)
        );
        assert_eq!(
            sample_numeric_style(&mut EmptyRandom),
            Err(RenderError::RandomnessUnavailable)
        );
        assert_eq!(
            plan_fragment_literal(8, &mut EmptyRandom),
            Err(RenderError::RandomnessUnavailable)
        );
    }
}
