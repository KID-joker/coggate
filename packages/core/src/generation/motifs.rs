use super::{
    GenerationError, MAX_PERMUTATION_LENGTH, MAX_XOR_KEY_LENGTH, NodeId, Operation,
    SemanticGraphBuilder,
    random::{RandomSource, sample_below, shuffle},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlanMotif {
    General,
    AddModulo,
    SubModulo,
    HexRoundTrip,
    Base64UrlRoundTrip,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the Task 3 planner integration")
)]
pub(crate) fn sample_motif(random: &mut impl RandomSource) -> Result<PlanMotif, GenerationError> {
    match sample_below(random, 5)? {
        0 => Ok(PlanMotif::General),
        1 => Ok(PlanMotif::AddModulo),
        2 => Ok(PlanMotif::SubModulo),
        3 => Ok(PlanMotif::HexRoundTrip),
        4 => Ok(PlanMotif::Base64UrlRoundTrip),
        _ => Err(GenerationError::ExecutionFailed),
    }
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the Task 3 planner integration")
)]
pub(crate) fn build_motif(
    builder: &mut SemanticGraphBuilder,
    fragment_nodes: &[NodeId],
    fragment_lengths: &[usize],
    motif: PlanMotif,
    random: &mut impl RandomSource,
) -> Result<NodeId, GenerationError> {
    validate_fragments(fragment_nodes, fragment_lengths)?;

    let mut roles = fragment_nodes
        .iter()
        .copied()
        .zip(fragment_lengths.iter().copied())
        .map(|(node, length)| FragmentRole { node, length })
        .collect::<Vec<_>>();
    shuffle(random, &mut roles)?;

    let transformed = match motif {
        PlanMotif::General => build_general(builder, &roles, random)?,
        PlanMotif::AddModulo => build_arithmetic(builder, &roles, Operation::AddModulo, random)?,
        PlanMotif::SubModulo => build_arithmetic(builder, &roles, Operation::SubModulo, random)?,
        PlanMotif::HexRoundTrip => build_codec_round_trip(
            builder,
            &roles,
            Operation::HexEncode,
            Operation::HexDecode,
            random,
        )?,
        PlanMotif::Base64UrlRoundTrip => build_codec_round_trip(
            builder,
            &roles,
            Operation::Base64UrlEncode,
            Operation::Base64UrlDecode,
            random,
        )?,
    };

    finalize(builder, &transformed, random)
}

#[derive(Clone, Copy)]
struct FragmentRole {
    node: NodeId,
    length: usize,
}

fn validate_fragments(
    fragment_nodes: &[NodeId],
    fragment_lengths: &[usize],
) -> Result<(), GenerationError> {
    if fragment_nodes.len() != fragment_lengths.len() {
        return Err(GenerationError::InvalidLength);
    }
    if !(3..=5).contains(&fragment_nodes.len()) {
        return Err(GenerationError::InvalidFragment(fragment_nodes.len()));
    }
    if fragment_lengths.contains(&0) {
        return Err(GenerationError::InvalidLength);
    }
    Ok(())
}

fn build_general(
    builder: &mut SemanticGraphBuilder,
    roles: &[FragmentRole],
    random: &mut impl RandomSource,
) -> Result<Vec<NodeId>, GenerationError> {
    let mut transformed = Vec::with_capacity(roles.len());
    let structural = nonlegacy_structural_operation(roles[0].length, random)?;
    transformed.push(builder.operation(structural, vec![roles[0].node]));

    let xor = xor_operation(roles[1].length, random)?;
    transformed.push(builder.operation(xor, vec![roles[1].node]));

    for role in &roles[2..] {
        let operation = safe_leaf_operation(role.length, random)?;
        transformed.push(builder.operation(operation, vec![role.node]));
    }

    Ok(transformed)
}

fn build_arithmetic(
    builder: &mut SemanticGraphBuilder,
    roles: &[FragmentRole],
    arithmetic: Operation,
    random: &mut impl RandomSource,
) -> Result<Vec<NodeId>, GenerationError> {
    let maximum_common_length = roles[0].length.min(roles[1].length);
    let common_length = 1 + sample_index(random, maximum_common_length)?;
    let first_slice = slice_with_length(roles[0].length, common_length, random)?;
    let second_slice = slice_with_length(roles[1].length, common_length, random)?;
    let first = builder.operation(first_slice, vec![roles[0].node]);
    let second = builder.operation(second_slice, vec![roles[1].node]);
    let combined = builder.operation(arithmetic, vec![first, second]);

    let mut transformed = Vec::with_capacity(roles.len() - 1);
    transformed.push(combined);
    for role in &roles[2..] {
        let operation = safe_leaf_operation(role.length, random)?;
        transformed.push(builder.operation(operation, vec![role.node]));
    }

    Ok(transformed)
}

fn build_codec_round_trip(
    builder: &mut SemanticGraphBuilder,
    roles: &[FragmentRole],
    encode: Operation,
    decode: Operation,
    random: &mut impl RandomSource,
) -> Result<Vec<NodeId>, GenerationError> {
    let encoded = builder.operation(encode, vec![roles[0].node]);
    let decoded = builder.operation(decode, vec![encoded]);
    let xor = xor_operation(roles[1].length, random)?;
    let xor = builder.operation(xor, vec![roles[1].node]);

    let mut transformed = Vec::with_capacity(roles.len());
    transformed.extend([decoded, xor]);
    for role in &roles[2..] {
        let operation = safe_leaf_operation(role.length, random)?;
        transformed.push(builder.operation(operation, vec![role.node]));
    }

    Ok(transformed)
}

fn finalize(
    builder: &mut SemanticGraphBuilder,
    values: &[NodeId],
    random: &mut impl RandomSource,
) -> Result<NodeId, GenerationError> {
    let control = values[sample_index(random, values.len())?];

    match sample_below(random, 2)? {
        0 => {
            let joined = builder.operation(Operation::Concat, values.to_vec());
            Ok(builder.operation(Operation::RotateLeftDerived, vec![joined, control]))
        }
        1 if values.len() >= 3 => {
            let joined_rest = builder.operation(Operation::Concat, values[1..].to_vec());
            Ok(builder.operation(
                Operation::ConditionalOrder,
                vec![control, values[0], joined_rest],
            ))
        }
        1 => {
            let ordered = builder.operation(
                Operation::ConditionalOrder,
                vec![control, values[0], values[1]],
            );
            Ok(builder.operation(Operation::RotateLeftDerived, vec![ordered, control]))
        }
        _ => Err(GenerationError::ExecutionFailed),
    }
}

fn nonlegacy_structural_operation(
    input_length: usize,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    let mut choices = vec![StructuralChoice::EvenBytes, StructuralChoice::Slice];
    if input_length >= 2 {
        choices.push(StructuralChoice::OddBytes);
    }
    if (2..=MAX_PERMUTATION_LENGTH).contains(&input_length) {
        choices.push(StructuralChoice::Permute);
    }

    match choices[sample_index(random, choices.len())?] {
        StructuralChoice::EvenBytes => Ok(Operation::EvenBytes),
        StructuralChoice::OddBytes => Ok(Operation::OddBytes),
        StructuralChoice::Permute => permutation_operation(input_length, random),
        StructuralChoice::Slice => slice_operation(input_length, random),
    }
}

#[derive(Clone, Copy)]
enum StructuralChoice {
    EvenBytes,
    OddBytes,
    Permute,
    Slice,
}

fn safe_leaf_operation(
    input_length: usize,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    match sample_below(random, 11)? {
        0 => Ok(Operation::Reverse),
        1 => rotate_operation(input_length, true, random),
        2 => rotate_operation(input_length, false, random),
        3 => Ok(Operation::EvenBytes),
        4 if input_length >= 2 => Ok(Operation::OddBytes),
        4 => Ok(Operation::Reverse),
        5 => permutation_operation(input_length, random),
        6 => slice_operation(input_length, random),
        7 => xor_operation(input_length, random),
        8 => Ok(Operation::Sha256Prefix(1 + sample_below(random, 16)?)),
        9 => Ok(Operation::HexEncode),
        10 => Ok(Operation::Base64UrlEncode),
        _ => Err(GenerationError::ExecutionFailed),
    }
}

fn rotate_operation(
    input_length: usize,
    left: bool,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    if input_length == 1 {
        return Ok(Operation::Reverse);
    }
    let amount = 1 + sample_index(random, input_length - 1)?;
    if left {
        Ok(Operation::RotateLeft(amount))
    } else {
        Ok(Operation::RotateRight(amount))
    }
}

fn permutation_operation(
    input_length: usize,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    if input_length == 1 || input_length > MAX_PERMUTATION_LENGTH {
        return Ok(Operation::Reverse);
    }

    let mut permutation = (0..input_length).collect::<Vec<_>>();
    shuffle(random, &mut permutation)?;
    if permutation.iter().copied().eq(0..input_length) {
        permutation.swap(0, 1);
    }
    Ok(Operation::Permute(permutation))
}

fn slice_operation(
    input_length: usize,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    let start = sample_index(random, input_length)?;
    let end = start + 1 + sample_index(random, input_length - start)?;
    Ok(Operation::Slice { start, end })
}

fn slice_with_length(
    input_length: usize,
    output_length: usize,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    let start = sample_index(random, input_length - output_length + 1)?;
    Ok(Operation::Slice {
        start,
        end: start + output_length,
    })
}

fn xor_operation(
    input_length: usize,
    random: &mut impl RandomSource,
) -> Result<Operation, GenerationError> {
    let maximum_key_length = input_length.min(MAX_XOR_KEY_LENGTH);
    let key_length = 1 + sample_index(random, maximum_key_length)?;
    let mut key = vec![0_u8; key_length];
    random.fill(&mut key)?;
    Ok(Operation::Xor(key))
}

fn sample_index(random: &mut impl RandomSource, upper: usize) -> Result<usize, GenerationError> {
    if upper == 0 {
        return Err(GenerationError::InvalidOperation);
    }
    if upper <= 256 {
        return sample_below(random, upper);
    }

    let threshold = upper.wrapping_neg() % upper;
    loop {
        let mut bytes = [0_u8; size_of::<usize>()];
        random.fill(&mut bytes)?;
        let value = usize::from_le_bytes(bytes);
        if value >= threshold {
            return Ok(value % upper);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{PlanMotif, build_motif, sample_motif};
    use crate::generation::{
        GenerationError, NodeId, NodeKind, Operation, OperationFamily, OperationKind, RandomSource,
        SemanticGraphBuilder, ValidatedSemanticGraph, evaluate_semantic_graph,
        test_random::DeterministicRandom,
    };

    const MOTIFS: [PlanMotif; 5] = [
        PlanMotif::General,
        PlanMotif::AddModulo,
        PlanMotif::SubModulo,
        PlanMotif::HexRoundTrip,
        PlanMotif::Base64UrlRoundTrip,
    ];

    struct PatternRandom(u8);

    impl RandomSource for PatternRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            destination.fill(self.0);
            Ok(())
        }
    }

    fn fragments(count: usize) -> Vec<Vec<u8>> {
        [
            b"a".to_vec(),
            b"bravo".to_vec(),
            b"charlie".to_vec(),
            b"delta-99".to_vec(),
            b"echo".to_vec(),
        ][..count]
            .to_vec()
    }

    fn build_graph(
        motif: PlanMotif,
        count: usize,
        seed: u8,
    ) -> (ValidatedSemanticGraph, Vec<Vec<u8>>) {
        let fragments = fragments(count);
        let lengths = fragments.iter().map(Vec::len).collect::<Vec<_>>();
        let mut builder = SemanticGraphBuilder::new(lengths.clone());
        let fragment_nodes = (0..count)
            .map(|index| builder.fragment(index).expect("fragment exists"))
            .collect::<Vec<_>>();
        let mut random = DeterministicRandom::new([seed; 32]);

        let output = build_motif(&mut builder, &fragment_nodes, &lengths, motif, &mut random)
            .expect("motif construction succeeds");
        builder.output(output);
        let graph = builder.validate().expect("motif graph validates");

        (graph, fragments)
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

    fn cross_fragment_operation_count(graph: &ValidatedSemanticGraph) -> usize {
        let mut provenance = BTreeMap::<NodeId, BTreeSet<usize>>::new();
        let mut count = 0;

        for node in graph.topological_nodes() {
            let origins = match node.kind() {
                NodeKind::Fragment { index } => BTreeSet::from([*index]),
                NodeKind::Operation { inputs, .. } => {
                    let origins = inputs
                        .iter()
                        .flat_map(|input| {
                            provenance
                                .get(input)
                                .expect("input provenance exists")
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

    fn directly_transformed_fragments(graph: &ValidatedSemanticGraph) -> BTreeSet<usize> {
        let mut transformed = BTreeSet::new();

        for node in graph.topological_nodes() {
            let NodeKind::Operation { operation, inputs } = node.kind() else {
                continue;
            };
            if OperationKind::from(operation).family() == OperationFamily::Composition {
                continue;
            }
            for input in inputs {
                if let Some(NodeKind::Fragment { index }) =
                    graph.node(*input).map(|input_node| input_node.kind())
                {
                    transformed.insert(*index);
                }
            }
        }

        transformed
    }

    fn is_nonlegacy(kind: OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::EvenBytes
                | OperationKind::OddBytes
                | OperationKind::Permute
                | OperationKind::Slice
                | OperationKind::AddModulo
                | OperationKind::SubModulo
                | OperationKind::HexEncode
                | OperationKind::HexDecode
                | OperationKind::Base64UrlEncode
                | OperationKind::Base64UrlDecode
        )
    }

    #[test]
    fn every_named_motif_satisfies_the_graph_contract_for_supported_fragment_counts() {
        for motif in MOTIFS {
            for count in 3..=5 {
                for seed in 0_u8..=31 {
                    let (graph, fragments) = build_graph(motif, count, seed);
                    let kinds = operation_kinds(&graph);
                    let families = kinds
                        .iter()
                        .map(|kind| kind.family())
                        .collect::<BTreeSet<_>>();
                    let expected_operations = match motif {
                        PlanMotif::General => count + 2,
                        PlanMotif::AddModulo
                        | PlanMotif::SubModulo
                        | PlanMotif::HexRoundTrip
                        | PlanMotif::Base64UrlRoundTrip => count + 3,
                    };

                    assert_eq!(graph.operation_count(), expected_operations);
                    assert!((4..=8).contains(&graph.operation_count()));
                    assert!(families.len() >= 3);
                    assert!(cross_fragment_operation_count(&graph) >= 2);
                    assert!(kinds.iter().copied().any(is_nonlegacy));
                    assert_eq!(directly_transformed_fragments(&graph).len(), count);

                    let fragment_slices = fragments.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    let answer = evaluate_semantic_graph(&graph, &fragment_slices)
                        .expect("validated motif evaluates");
                    assert!(!answer.is_empty());
                    assert_eq!(answer.len(), graph.output_length());
                }
            }
        }
    }

    #[test]
    fn arithmetic_motifs_include_the_requested_modular_operation() {
        for (motif, expected) in [
            (PlanMotif::AddModulo, OperationKind::AddModulo),
            (PlanMotif::SubModulo, OperationKind::SubModulo),
        ] {
            let (graph, _) = build_graph(motif, 5, 29);
            let kinds = operation_kinds(&graph);

            assert_eq!(kinds.iter().filter(|kind| **kind == expected).count(), 1);
        }
    }

    #[test]
    fn codec_motifs_connect_each_decoder_directly_to_its_matching_encoder() {
        for (motif, encode, decode) in [
            (
                PlanMotif::HexRoundTrip,
                OperationKind::HexEncode,
                OperationKind::HexDecode,
            ),
            (
                PlanMotif::Base64UrlRoundTrip,
                OperationKind::Base64UrlEncode,
                OperationKind::Base64UrlDecode,
            ),
        ] {
            let (graph, _) = build_graph(motif, 4, 91);
            let decoder_inputs = graph.topological_nodes().iter().find_map(|node| {
                let NodeKind::Operation { operation, inputs } = node.kind() else {
                    return None;
                };
                (OperationKind::from(operation) == decode).then_some(inputs)
            });
            let decoder_inputs = decoder_inputs.expect("matching decoder exists");
            let [encoded] = decoder_inputs.as_slice() else {
                panic!("decoder has unary input");
            };
            let encoded_node = graph.node(*encoded).expect("encoded input exists");
            let NodeKind::Operation { operation, .. } = encoded_node.kind() else {
                panic!("decoder input is an operation");
            };

            assert_eq!(OperationKind::from(operation), encode);
        }
    }

    #[test]
    fn operation_catalog_is_reachable_across_bounded_motifs_and_seeds() {
        let mut reached = BTreeSet::new();

        for motif in MOTIFS {
            for seed in 0_u8..=u8::MAX {
                let (graph, _) = build_graph(motif, 5, seed);
                reached.extend(operation_kinds(&graph));
            }
        }

        assert_eq!(reached, OperationKind::ALL.into_iter().collect());
    }

    #[test]
    fn sample_motif_reaches_all_variants_over_deterministic_seeds() {
        let mut seen = [false; MOTIFS.len()];

        for seed in 0_u8..=u8::MAX {
            let mut random = DeterministicRandom::new([seed; 32]);
            let index = match sample_motif(&mut random).expect("motif sample succeeds") {
                PlanMotif::General => 0,
                PlanMotif::AddModulo => 1,
                PlanMotif::SubModulo => 2,
                PlanMotif::HexRoundTrip => 3,
                PlanMotif::Base64UrlRoundTrip => 4,
            };
            seen[index] = true;
        }

        assert!(seen.into_iter().all(|was_seen| was_seen));
    }

    #[test]
    fn build_motif_rejects_invalid_input_shapes() {
        let mut random = DeterministicRandom::new([7; 32]);
        let mut builder = SemanticGraphBuilder::new(vec![1, 1, 1]);
        let nodes = (0..3)
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            build_motif(
                &mut builder,
                &nodes,
                &[1, 1],
                PlanMotif::General,
                &mut random,
            ),
            Err(GenerationError::InvalidLength)
        );

        for count in [2, 6] {
            let lengths = vec![1; count];
            let mut builder = SemanticGraphBuilder::new(lengths.clone());
            let nodes = (0..count)
                .map(|index| builder.fragment(index).unwrap())
                .collect::<Vec<_>>();

            assert_eq!(
                build_motif(
                    &mut builder,
                    &nodes,
                    &lengths,
                    PlanMotif::General,
                    &mut random,
                ),
                Err(GenerationError::InvalidFragment(count))
            );
        }

        let lengths = vec![1, 0, 1];
        let mut builder = SemanticGraphBuilder::new(lengths.clone());
        let nodes = (0..3)
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            build_motif(
                &mut builder,
                &nodes,
                &lengths,
                PlanMotif::General,
                &mut random,
            ),
            Err(GenerationError::InvalidLength)
        );
    }

    #[test]
    fn xor_keys_are_fully_filled_and_within_the_supported_bound() {
        for seed in 0_u8..=u8::MAX {
            let (graph, _) = build_graph(PlanMotif::HexRoundTrip, 5, seed);
            let key = graph
                .topological_nodes()
                .iter()
                .find_map(|node| match node.kind() {
                    NodeKind::Operation {
                        operation: Operation::Xor(key),
                        ..
                    } => Some(key),
                    _ => None,
                });
            let key = key.expect("codec motif includes XOR");

            assert!(!key.is_empty());
            assert!(key.len() <= crate::generation::MAX_XOR_KEY_LENGTH);
        }

        let fragments = fragments(5);
        let lengths = fragments.iter().map(Vec::len).collect::<Vec<_>>();
        let mut builder = SemanticGraphBuilder::new(lengths.clone());
        let nodes = (0..5)
            .map(|index| builder.fragment(index).unwrap())
            .collect::<Vec<_>>();
        let mut random = PatternRandom(0xA5);
        let output = build_motif(
            &mut builder,
            &nodes,
            &lengths,
            PlanMotif::HexRoundTrip,
            &mut random,
        )
        .unwrap();
        builder.output(output);
        let graph = builder.validate().unwrap();
        let key = graph
            .topological_nodes()
            .iter()
            .find_map(|node| match node.kind() {
                NodeKind::Operation {
                    operation: Operation::Xor(key),
                    ..
                } => Some(key),
                _ => None,
            })
            .expect("codec motif includes XOR");

        assert!(key.iter().all(|byte| *byte == 0xA5));
    }
}
