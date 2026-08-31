use std::collections::{HashMap, VecDeque};

use super::{GenerationError, Operation};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Fragment {
        index: usize,
    },
    Operation {
        operation: Operation,
        inputs: Vec<NodeId>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticNode {
    id: NodeId,
    kind: NodeKind,
}

impl SemanticNode {
    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn kind(&self) -> &NodeKind {
        &self.kind
    }
}

pub struct SemanticGraphBuilder {
    fragment_lengths: Vec<usize>,
    nodes: Vec<SemanticNode>,
    outputs: Vec<NodeId>,
    next_id: u32,
}

impl SemanticGraphBuilder {
    pub fn new(fragment_lengths: Vec<usize>) -> Self {
        let nodes = fragment_lengths
            .iter()
            .enumerate()
            .map(|(index, _)| SemanticNode {
                id: NodeId(index as u32),
                kind: NodeKind::Fragment { index },
            })
            .collect();

        Self {
            next_id: fragment_lengths.len() as u32,
            fragment_lengths,
            nodes,
            outputs: Vec::new(),
        }
    }

    pub fn fragment(&self, index: usize) -> Result<NodeId, GenerationError> {
        if index >= self.fragment_lengths.len() {
            return Err(GenerationError::InvalidFragment(index));
        }

        self.nodes
            .iter()
            .find_map(|node| match node.kind {
                NodeKind::Fragment { index: node_index } if node_index == index => Some(node.id),
                _ => None,
            })
            .ok_or(GenerationError::InvalidFragment(index))
    }

    pub fn operation(&mut self, operation: Operation, inputs: Vec<NodeId>) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.nodes.push(SemanticNode {
            id,
            kind: NodeKind::Operation { operation, inputs },
        });
        id
    }

    pub fn output(&mut self, output: NodeId) {
        self.outputs.push(output);
    }

    pub fn validate(self) -> Result<ValidatedSemanticGraph, GenerationError> {
        let Self {
            fragment_lengths,
            nodes,
            outputs,
            next_id: _,
        } = self;

        let node_indices = index_unique_nodes(&nodes)?;
        let output = validate_output(&outputs, &node_indices)?;
        validate_fragments(&fragment_lengths, &nodes)?;
        validate_input_references(&nodes, &node_indices)?;
        validate_operation_count(&nodes)?;
        validate_operations(&nodes)?;
        let topological_indices = topological_indices(&nodes, &node_indices)?;
        validate_reachability(output, &nodes, &node_indices)?;
        let output_length = propagate_lengths(
            output,
            &fragment_lengths,
            &nodes,
            &node_indices,
            &topological_indices,
        )?;
        let topological_order = topological_indices
            .iter()
            .map(|&index| nodes[index].id)
            .collect();
        let nodes = reorder_nodes(nodes, &topological_indices)?;

        Ok(ValidatedSemanticGraph {
            fragment_lengths,
            nodes,
            topological_order,
            output,
            output_length,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSemanticGraph {
    fragment_lengths: Vec<usize>,
    nodes: Vec<SemanticNode>,
    topological_order: Vec<NodeId>,
    output: NodeId,
    output_length: usize,
}

impl ValidatedSemanticGraph {
    pub fn fragment_lengths(&self) -> &[usize] {
        &self.fragment_lengths
    }

    pub fn topological_nodes(&self) -> &[SemanticNode] {
        &self.nodes
    }

    pub fn topological_order(&self) -> &[NodeId] {
        &self.topological_order
    }

    pub fn output(&self) -> NodeId {
        self.output
    }

    pub fn output_length(&self) -> usize {
        self.output_length
    }

    pub fn operation_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| matches!(node.kind, NodeKind::Operation { .. }))
            .count()
    }

    pub fn node(&self, id: NodeId) -> Option<&SemanticNode> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

fn index_unique_nodes(nodes: &[SemanticNode]) -> Result<HashMap<NodeId, usize>, GenerationError> {
    let mut indices = HashMap::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        if indices.insert(node.id, index).is_some() {
            return Err(GenerationError::DuplicateNode(node.id.0));
        }
    }
    Ok(indices)
}

fn validate_output(
    outputs: &[NodeId],
    node_indices: &HashMap<NodeId, usize>,
) -> Result<NodeId, GenerationError> {
    let [output] = outputs else {
        return Err(GenerationError::InvalidOutput);
    };
    if !node_indices.contains_key(output) {
        return Err(GenerationError::MissingNode(output.0));
    }
    Ok(*output)
}

fn validate_fragments(
    fragment_lengths: &[usize],
    nodes: &[SemanticNode],
) -> Result<(), GenerationError> {
    if fragment_lengths.contains(&0) {
        return Err(GenerationError::InvalidLength);
    }

    let mut seen = vec![false; fragment_lengths.len()];
    for node in nodes {
        let NodeKind::Fragment { index } = node.kind else {
            continue;
        };
        let Some(slot) = seen.get_mut(index) else {
            return Err(GenerationError::InvalidFragment(index));
        };
        if *slot {
            return Err(GenerationError::InvalidFragment(index));
        }
        *slot = true;
    }

    if let Some(index) = seen.iter().position(|present| !present) {
        return Err(GenerationError::InvalidFragment(index));
    }
    Ok(())
}

fn validate_input_references(
    nodes: &[SemanticNode],
    node_indices: &HashMap<NodeId, usize>,
) -> Result<(), GenerationError> {
    for node in nodes {
        if let NodeKind::Operation { inputs, .. } = &node.kind {
            for input in inputs {
                if !node_indices.contains_key(input) {
                    return Err(GenerationError::MissingNode(input.0));
                }
            }
        }
    }
    Ok(())
}

fn validate_operation_count(nodes: &[SemanticNode]) -> Result<(), GenerationError> {
    let operation_count = nodes
        .iter()
        .filter(|node| matches!(node.kind, NodeKind::Operation { .. }))
        .count();
    if !(4..=8).contains(&operation_count) {
        return Err(GenerationError::InvalidOperationCount);
    }
    Ok(())
}

fn validate_operations(nodes: &[SemanticNode]) -> Result<(), GenerationError> {
    for node in nodes {
        if let NodeKind::Operation { operation, inputs } = &node.kind {
            operation.validate_arity(inputs.len())?;
        }
    }
    Ok(())
}

fn topological_indices(
    nodes: &[SemanticNode],
    node_indices: &HashMap<NodeId, usize>,
) -> Result<Vec<usize>, GenerationError> {
    let mut indegrees = vec![0_usize; nodes.len()];
    let mut outgoing = vec![Vec::new(); nodes.len()];

    for (node_index, node) in nodes.iter().enumerate() {
        if let NodeKind::Operation { inputs, .. } = &node.kind {
            indegrees[node_index] = inputs.len();
            for input in inputs {
                let Some(&input_index) = node_indices.get(input) else {
                    return Err(GenerationError::MissingNode(input.0));
                };
                outgoing[input_index].push(node_index);
            }
        }
    }

    let mut ready: VecDeque<usize> = indegrees
        .iter()
        .enumerate()
        .filter_map(|(index, &indegree)| (indegree == 0).then_some(index))
        .collect();
    let mut ordered = Vec::with_capacity(nodes.len());
    while let Some(index) = ready.pop_front() {
        ordered.push(index);
        for &dependent in &outgoing[index] {
            indegrees[dependent] -= 1;
            if indegrees[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }

    if ordered.len() != nodes.len() {
        return Err(GenerationError::Cycle);
    }
    Ok(ordered)
}

fn validate_reachability(
    output: NodeId,
    nodes: &[SemanticNode],
    node_indices: &HashMap<NodeId, usize>,
) -> Result<(), GenerationError> {
    let Some(&output_index) = node_indices.get(&output) else {
        return Err(GenerationError::MissingNode(output.0));
    };
    let mut reachable = vec![false; nodes.len()];
    let mut pending = vec![output_index];

    while let Some(index) = pending.pop() {
        if reachable[index] {
            continue;
        }
        reachable[index] = true;
        if let NodeKind::Operation { inputs, .. } = &nodes[index].kind {
            for input in inputs {
                let Some(&input_index) = node_indices.get(input) else {
                    return Err(GenerationError::MissingNode(input.0));
                };
                pending.push(input_index);
            }
        }
    }

    if let Some((node, _)) = nodes.iter().zip(reachable).find(|(_, seen)| !seen) {
        return Err(GenerationError::UnreachableNode(node.id.0));
    }
    Ok(())
}

fn propagate_lengths(
    output: NodeId,
    fragment_lengths: &[usize],
    nodes: &[SemanticNode],
    node_indices: &HashMap<NodeId, usize>,
    topological_indices: &[usize],
) -> Result<usize, GenerationError> {
    let mut lengths = vec![None; nodes.len()];

    for &index in topological_indices {
        let length = match &nodes[index].kind {
            NodeKind::Fragment {
                index: fragment_index,
            } => fragment_lengths
                .get(*fragment_index)
                .copied()
                .ok_or(GenerationError::InvalidFragment(*fragment_index))?,
            NodeKind::Operation { operation, inputs } => {
                let mut input_lengths = Vec::with_capacity(inputs.len());
                for input in inputs {
                    let Some(&input_index) = node_indices.get(input) else {
                        return Err(GenerationError::MissingNode(input.0));
                    };
                    let Some(input_length) = lengths[input_index] else {
                        return Err(GenerationError::Cycle);
                    };
                    input_lengths.push(input_length);
                }
                operation.output_length(&input_lengths)?
            }
        };
        lengths[index] = Some(length);
    }

    let Some(&output_index) = node_indices.get(&output) else {
        return Err(GenerationError::MissingNode(output.0));
    };
    lengths[output_index].ok_or(GenerationError::Cycle)
}

fn reorder_nodes(
    nodes: Vec<SemanticNode>,
    topological_indices: &[usize],
) -> Result<Vec<SemanticNode>, GenerationError> {
    let mut nodes: Vec<Option<SemanticNode>> = nodes.into_iter().map(Some).collect();
    let mut ordered = Vec::with_capacity(nodes.len());
    for &index in topological_indices {
        let Some(node) = nodes.get_mut(index).and_then(Option::take) else {
            return Err(GenerationError::Cycle);
        };
        ordered.push(node);
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::{NodeId, NodeKind, SemanticGraphBuilder};
    use crate::generation::{GenerationError, Operation};

    fn valid_builder() -> SemanticGraphBuilder {
        let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
        let first = builder.fragment(0).unwrap();
        let second = builder.fragment(1).unwrap();
        let third = builder.fragment(2).unwrap();
        let reversed = builder.operation(Operation::Reverse, vec![first]);
        let rotated = builder.operation(Operation::RotateLeft(1), vec![second]);
        let joined = builder.operation(Operation::Concat, vec![reversed, rotated]);
        let output = builder.operation(Operation::Concat, vec![joined, third]);
        builder.output(output);
        builder
    }

    #[test]
    fn validates_a_semantic_graph_and_exposes_read_only_metadata() {
        let graph = valid_builder().validate().unwrap();

        assert_eq!(graph.fragment_lengths(), &[2, 2, 2]);
        assert_eq!(graph.operation_count(), 4);
        assert_eq!(graph.output(), NodeId(6));
        assert_eq!(graph.output_length(), 6);
        assert_eq!(graph.topological_nodes().len(), 7);
        assert_eq!(graph.topological_order().len(), 7);
        assert_eq!(graph.node(NodeId(0)).unwrap().id(), NodeId(0));
        assert_eq!(graph.node(NodeId(999)), None);
        assert!(matches!(
            graph.node(NodeId(3)).unwrap().kind(),
            NodeKind::Operation {
                operation: Operation::Reverse,
                inputs
            } if inputs == &[NodeId(0)]
        ));
    }

    #[test]
    fn fragment_reports_an_undeclared_index() {
        assert_eq!(
            SemanticGraphBuilder::new(vec![2]).fragment(1),
            Err(GenerationError::InvalidFragment(1))
        );
    }

    #[test]
    fn rejects_duplicate_node_ids_first() {
        let mut builder = valid_builder();
        builder.nodes[1].id = builder.nodes[0].id;

        assert_eq!(builder.validate(), Err(GenerationError::DuplicateNode(0)));
    }

    #[test]
    fn rejects_no_declared_output() {
        let mut builder = valid_builder();
        builder.outputs.clear();

        assert_eq!(builder.validate(), Err(GenerationError::InvalidOutput));
    }

    #[test]
    fn rejects_multiple_declared_outputs() {
        let mut builder = valid_builder();
        builder.outputs.push(NodeId(5));

        assert_eq!(builder.validate(), Err(GenerationError::InvalidOutput));
    }

    #[test]
    fn rejects_a_missing_declared_output_node() {
        let mut builder = valid_builder();
        builder.outputs[0] = NodeId(999);

        assert_eq!(builder.validate(), Err(GenerationError::MissingNode(999)));
    }

    #[test]
    fn rejects_an_invalid_fragment_index() {
        let mut builder = valid_builder();
        builder.nodes[0].kind = NodeKind::Fragment { index: 3 };

        assert_eq!(builder.validate(), Err(GenerationError::InvalidFragment(3)));
    }

    #[test]
    fn rejects_zero_fragment_length() {
        let mut builder = valid_builder();
        builder.fragment_lengths[0] = 0;

        assert_eq!(builder.validate(), Err(GenerationError::InvalidLength));
    }

    #[test]
    fn rejects_a_missing_input_node() {
        let mut builder = valid_builder();
        let NodeKind::Operation { inputs, .. } = &mut builder.nodes[3].kind else {
            unreachable!();
        };
        inputs[0] = NodeId(999);

        assert_eq!(builder.validate(), Err(GenerationError::MissingNode(999)));
    }

    #[test]
    fn rejects_too_few_operations() {
        let mut builder = SemanticGraphBuilder::new(vec![2]);
        let fragment = builder.fragment(0).unwrap();
        let first = builder.operation(Operation::Reverse, vec![fragment]);
        let second = builder.operation(Operation::Reverse, vec![first]);
        let output = builder.operation(Operation::Reverse, vec![second]);
        builder.output(output);

        assert_eq!(
            builder.validate(),
            Err(GenerationError::InvalidOperationCount)
        );
    }

    #[test]
    fn rejects_too_many_operations() {
        let mut builder = SemanticGraphBuilder::new(vec![2]);
        let mut output = builder.fragment(0).unwrap();
        for _ in 0..9 {
            output = builder.operation(Operation::Reverse, vec![output]);
        }
        builder.output(output);

        assert_eq!(
            builder.validate(),
            Err(GenerationError::InvalidOperationCount)
        );
    }

    #[test]
    fn rejects_invalid_operation_arity() {
        let mut builder = valid_builder();
        let NodeKind::Operation { inputs, .. } = &mut builder.nodes[3].kind else {
            unreachable!();
        };
        inputs.clear();

        assert_eq!(builder.validate(), Err(GenerationError::InvalidOperation));
    }

    #[test]
    fn rejects_invalid_static_operation_parameters() {
        let mut builder = valid_builder();
        let NodeKind::Operation { operation, .. } = &mut builder.nodes[3].kind else {
            unreachable!();
        };
        *operation = Operation::Xor(Vec::new());

        assert_eq!(builder.validate(), Err(GenerationError::InvalidOperation));
    }

    #[test]
    fn rejects_a_self_cycle() {
        let mut builder = valid_builder();
        let id = builder.nodes[3].id;
        let NodeKind::Operation { inputs, .. } = &mut builder.nodes[3].kind else {
            unreachable!();
        };
        inputs[0] = id;

        assert_eq!(builder.validate(), Err(GenerationError::Cycle));
    }

    #[test]
    fn rejects_a_multi_node_cycle() {
        let mut builder = valid_builder();
        let first = builder.nodes[3].id;
        let second = builder.nodes[4].id;
        let NodeKind::Operation { inputs, .. } = &mut builder.nodes[3].kind else {
            unreachable!();
        };
        inputs[0] = second;
        let NodeKind::Operation { inputs, .. } = &mut builder.nodes[4].kind else {
            unreachable!();
        };
        inputs[0] = first;

        assert_eq!(builder.validate(), Err(GenerationError::Cycle));
    }

    #[test]
    fn rejects_an_unreachable_node() {
        let mut builder = valid_builder();
        let first = builder.fragment(0).unwrap();
        let unreachable = builder.operation(Operation::Reverse, vec![first]);

        assert_eq!(
            builder.validate(),
            Err(GenerationError::UnreachableNode(unreachable.0))
        );
    }

    #[test]
    fn propagates_static_output_length_errors() {
        let mut builder = valid_builder();
        let NodeKind::Operation { operation, .. } = &mut builder.nodes[3].kind else {
            unreachable!();
        };
        *operation = Operation::Slice { start: 0, end: 3 };

        assert_eq!(builder.validate(), Err(GenerationError::InvalidLength));
    }
}
