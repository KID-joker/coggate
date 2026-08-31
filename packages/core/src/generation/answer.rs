use std::collections::HashMap;

use super::{GenerationError, NodeId, NodeKind, ValidatedSemanticGraph};

pub fn evaluate_semantic_graph(
    graph: &ValidatedSemanticGraph,
    fragments: &[&[u8]],
) -> Result<Vec<u8>, GenerationError> {
    validate_fragments(graph, fragments)?;

    let mut values = HashMap::<NodeId, Vec<u8>>::new();
    for node in graph.topological_nodes() {
        let value = match node.kind() {
            NodeKind::Fragment { index } => fragments
                .get(*index)
                .ok_or(GenerationError::ExecutionFailed)?
                .to_vec(),
            NodeKind::Operation { operation, inputs } => {
                let inputs = inputs
                    .iter()
                    .map(|input| {
                        values
                            .get(input)
                            .map(Vec::as_slice)
                            .ok_or(GenerationError::ExecutionFailed)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                operation.evaluate(&inputs)?
            }
        };
        values.insert(node.id(), value);
    }

    let output = values
        .get(&graph.output())
        .ok_or(GenerationError::ExecutionFailed)?
        .clone();
    if output.len() != graph.output_length() {
        return Err(GenerationError::InvalidLength);
    }

    Ok(output)
}

fn validate_fragments(
    graph: &ValidatedSemanticGraph,
    fragments: &[&[u8]],
) -> Result<(), GenerationError> {
    let expected_lengths = graph.fragment_lengths();
    if fragments.len() < expected_lengths.len() {
        return Err(GenerationError::InvalidFragment(fragments.len()));
    }
    if fragments.len() > expected_lengths.len() {
        return Err(GenerationError::InvalidFragment(expected_lengths.len()));
    }

    if fragments
        .iter()
        .zip(expected_lengths)
        .any(|(fragment, expected_length)| fragment.len() != *expected_length)
    {
        return Err(GenerationError::InvalidLength);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::{Operation, SemanticGraphBuilder};

    fn graph() -> ValidatedSemanticGraph {
        let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
        let first = builder.fragment(0).expect("first fragment exists");
        let second = builder.fragment(1).expect("second fragment exists");
        let third = builder.fragment(2).expect("third fragment exists");
        let reversed = builder.operation(Operation::Reverse, vec![first]);
        let rotated = builder.operation(Operation::RotateLeft(1), vec![second]);
        let joined = builder.operation(Operation::Concat, vec![reversed, rotated]);
        let output = builder.operation(Operation::Concat, vec![joined, third]);
        builder.output(output);
        builder.validate().expect("graph is valid")
    }

    #[test]
    fn evaluates_a_validated_semantic_graph() {
        let value = evaluate_semantic_graph(
            &graph(),
            &[b"ab".as_slice(), b"cd".as_slice(), b"ef".as_slice()],
        )
        .expect("validated graph evaluates");

        assert_eq!(value, b"badcef");
    }

    #[test]
    fn rejects_missing_fragments_at_the_first_missing_index() {
        let error = evaluate_semantic_graph(&graph(), &[b"ab".as_slice(), b"cd".as_slice()])
            .expect_err("missing fragment must be rejected");

        assert_eq!(error, GenerationError::InvalidFragment(2));
    }

    #[test]
    fn rejects_extra_fragments_at_the_expected_count_index() {
        let error = evaluate_semantic_graph(
            &graph(),
            &[
                b"ab".as_slice(),
                b"cd".as_slice(),
                b"ef".as_slice(),
                b"gh".as_slice(),
            ],
        )
        .expect_err("extra fragment must be rejected");

        assert_eq!(error, GenerationError::InvalidFragment(3));
    }

    #[test]
    fn rejects_fragments_with_an_unexpected_length_without_echoing_bytes() {
        let error = evaluate_semantic_graph(
            &graph(),
            &[b"ab".as_slice(), b"secret".as_slice(), b"ef".as_slice()],
        )
        .expect_err("incorrect fragment length must be rejected");

        assert_eq!(error, GenerationError::InvalidLength);
        assert!(!error.to_string().contains("secret"));
        assert!(!format!("{error:?}").contains("secret"));
    }
}
