# AgentGate Phase 2 Semantic Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the fixed-policy V1 semantic operation library, validated DAG, deterministic answer engine, secure secret partitioning, and constrained challenge planner inside `agentgate-core`.

**Architecture:** A public read-only semantic model lives under `agentgate_core::generation`, while mutable construction, secret bytes, RNG injection, and planner internals remain crate-private. Graph validation is the capability boundary: the answer engine and future renderer accept only `ValidatedSemanticGraph`, and the planner constructs bounded known-valid patterns before performing a final validation and evaluation pass.

**Tech Stack:** Rust 2024, `getrandom` 0.3, `base64` 0.22, `hex` 0.4, `sha2` 0.10, `thiserror` 2, Cargo unit/integration tests, deterministic SHA-256 counter RNG for tests.

---

## File map

- Modify `Cargo.toml` to register `getrandom` as a workspace dependency.
- Modify `packages/core/Cargo.toml` to consume `getrandom`.
- Modify `packages/core/src/lib.rs` to publish the safe semantic module.
- Create `packages/core/src/generation/mod.rs` as the semantic API boundary.
- Create `packages/core/src/generation/error.rs` for non-sensitive typed errors.
- Create `packages/core/src/generation/random.rs` for OS randomness, unbiased bounded sampling, shuffling, and deterministic test support.
- Create `packages/core/src/generation/operation.rs` for the complete V1 operation set.
- Create `packages/core/src/generation/graph.rs` for raw construction, validation, topology, and immutable graph inspection.
- Create `packages/core/src/generation/answer.rs` for validated graph execution.
- Create `packages/core/src/generation/secret.rs` for redacted secret generation.
- Create `packages/core/src/generation/partition.rs` for fixed-policy non-empty partitioning.
- Create `packages/core/src/generation/planner.rs` for constrained graph planning and structural metrics.
- Create `packages/core/tests/generation_public_api.rs` to lock the safe external semantic surface.
- Modify `README.md` only after all Phase 2 verification passes.

### Task 1: Randomness and generation module foundation

**Files:**
- Modify: `Cargo.toml`
- Modify: `packages/core/Cargo.toml`
- Modify: `packages/core/src/lib.rs`
- Create: `packages/core/src/generation/mod.rs`
- Create: `packages/core/src/generation/error.rs`
- Create: `packages/core/src/generation/random.rs`

- [ ] **Step 1: Add failing unit tests for bounded sampling and shuffling**

Create `generation/random.rs` with a test-only scripted source and tests that require unbiased range checking, deterministic output, and permutation preservation:

```rust
use super::GenerationError;

pub(crate) trait RandomSource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedRandom(Vec<u8>);

    impl RandomSource for ScriptedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
            if self.0.len() < destination.len() {
                return Err(GenerationError::RandomnessUnavailable);
            }
            destination.copy_from_slice(&self.0[..destination.len()]);
            self.0.drain(..destination.len());
            Ok(())
        }
    }

    #[test]
    fn samples_only_inside_the_requested_bound() {
        let mut random = ScriptedRandom((0_u8..=255).cycle().take(4096).collect());
        for upper in 1..=62 {
            for _ in 0..32 {
                assert!(sample_below(&mut random, upper).unwrap() < upper);
            }
        }
    }

    #[test]
    fn shuffling_preserves_every_element_once() {
        let mut values = vec![1, 2, 3, 4, 5, 6];
        let mut random = ScriptedRandom((0_u8..=255).cycle().take(128).collect());
        shuffle(&mut random, &mut values).unwrap();
        values.sort_unstable();
        assert_eq!(values, vec![1, 2, 3, 4, 5, 6]);
    }
}
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `cargo test -p agentgate-core generation::random::tests -- --nocapture`  
Expected: FAIL because `sample_below` and `shuffle` do not exist and the generation module is not wired.

- [ ] **Step 3: Add the dependency, safe errors, and minimal random implementation**

Add `getrandom = "0.3"` under `[workspace.dependencies]`, add `getrandom.workspace = true` to `packages/core/Cargo.toml`, publish `pub mod generation;` from `lib.rs`, and define:

```rust
// generation/error.rs
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum GenerationError {
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    #[error("operation parameters are invalid")]
    InvalidOperation,
    #[error("semantic graph contains duplicate node {0}")]
    DuplicateNode(u32),
    #[error("semantic graph references missing node {0}")]
    MissingNode(u32),
    #[error("semantic graph references invalid fragment {0}")]
    InvalidFragment(usize),
    #[error("semantic graph contains a cycle")]
    Cycle,
    #[error("semantic graph contains unreachable node {0}")]
    UnreachableNode(u32),
    #[error("semantic graph must declare exactly one output")]
    InvalidOutput,
    #[error("semantic graph has an invalid operation count")]
    InvalidOperationCount,
    #[error("semantic value length is invalid")]
    InvalidLength,
    #[error("semantic value encoding is invalid")]
    InvalidEncoding,
    #[error("semantic graph execution failed")]
    ExecutionFailed,
}
```

```rust
// generation/random.rs
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), GenerationError> {
        getrandom::fill(destination).map_err(|_| GenerationError::RandomnessUnavailable)
    }
}

pub(crate) fn sample_below(
    random: &mut impl RandomSource,
    upper: usize,
) -> Result<usize, GenerationError> {
    if upper == 0 || upper > 256 {
        return Err(GenerationError::InvalidOperation);
    }
    let acceptance = 256 - (256 % upper);
    loop {
        let mut byte = [0_u8; 1];
        random.fill(&mut byte)?;
        let value = usize::from(byte[0]);
        if value < acceptance {
            return Ok(value % upper);
        }
    }
}

pub(crate) fn shuffle<T>(
    random: &mut impl RandomSource,
    values: &mut [T],
) -> Result<(), GenerationError> {
    for index in (1..values.len()).rev() {
        let other = sample_below(random, index + 1)?;
        values.swap(index, other);
    }
    Ok(())
}
```

In `generation/mod.rs`, declare the files and re-export only `GenerationError` at this stage.

- [ ] **Step 4: Run formatting and focused tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::random::tests`  
Expected: PASS, 2 focused tests.

- [ ] **Step 5: Commit the foundation**

```bash
git add Cargo.toml Cargo.lock packages/core/Cargo.toml packages/core/src/lib.rs packages/core/src/generation
git commit -m "feat: add generation randomness foundation"
```

### Task 2: Complete V1 byte-operation library

**Files:**
- Create: `packages/core/src/generation/operation.rs`
- Modify: `packages/core/src/generation/mod.rs`

- [ ] **Step 1: Write failing table tests for every operation family**

Define tests using `Operation::evaluate(&[&[u8]])` and assert these exact vectors:

```rust
#[test]
fn evaluates_fixed_shape_operations() {
    let cases = [
        (Operation::Reverse, vec![b"abcd".as_slice()], b"dcba".to_vec()),
        (Operation::RotateLeft(1), vec![b"abcd".as_slice()], b"bcda".to_vec()),
        (Operation::RotateRight(1), vec![b"abcd".as_slice()], b"dabc".to_vec()),
        (Operation::Xor(vec![0x20]), vec![b"AZ".as_slice()], b"az".to_vec()),
        (Operation::EvenBytes, vec![b"abcdef".as_slice()], b"ace".to_vec()),
        (Operation::OddBytes, vec![b"abcdef".as_slice()], b"bdf".to_vec()),
        (Operation::Permute(vec![2, 0, 1]), vec![b"abc".as_slice()], b"cab".to_vec()),
        (Operation::Slice { start: 1, end: 3 }, vec![b"abcd".as_slice()], b"bc".to_vec()),
        (Operation::Concat, vec![b"ab".as_slice(), b"cd".as_slice()], b"abcd".to_vec()),
        (Operation::AddModulo, vec![&[250, 1], &[10, 2]], vec![4, 3]),
        (Operation::SubModulo, vec![&[4, 1], &[10, 2]], vec![250, 255]),
        (Operation::HexEncode, vec![&[0xab, 0x01]], b"ab01".to_vec()),
        (Operation::HexDecode, vec![b"ab01".as_slice()], vec![0xab, 0x01]),
        (Operation::Base64UrlEncode, vec![b"a?".as_slice()], b"YT8".to_vec()),
        (Operation::Base64UrlDecode, vec![b"YT8".as_slice()], b"a?".to_vec()),
        (Operation::Sha256Prefix(4), vec![b"abc".as_slice()], vec![0xba, 0x78, 0x16, 0xbf]),
        (Operation::RotateLeftDerived, vec![b"abcd".as_slice(), &[5]], b"bcda".to_vec()),
        (Operation::ConditionalOrder, vec![&[2], b"ab".as_slice(), b"cd".as_slice()], b"abcd".to_vec()),
        (Operation::ConditionalOrder, vec![&[3], b"ab".as_slice(), b"cd".as_slice()], b"cdab".to_vec()),
    ];
    for (operation, inputs, expected) in cases {
        assert_eq!(operation.evaluate(&inputs), Ok(expected));
    }
}

#[test]
fn rejects_invalid_parameters_and_inputs() {
    assert_eq!(Operation::Xor(vec![]).validate_arity(1), Err(GenerationError::InvalidOperation));
    assert_eq!(Operation::Permute(vec![0, 0]).evaluate(&[b"ab"]), Err(GenerationError::InvalidOperation));
    assert_eq!(Operation::Slice { start: 2, end: 1 }.evaluate(&[b"ab"]), Err(GenerationError::InvalidOperation));
    assert_eq!(Operation::AddModulo.evaluate(&[b"a", b"bc"]), Err(GenerationError::InvalidLength));
    assert_eq!(Operation::HexDecode.evaluate(&[b"ABC"]), Err(GenerationError::InvalidEncoding));
    assert_eq!(Operation::Base64UrlDecode.evaluate(&[b"YQ=="]), Err(GenerationError::InvalidEncoding));
    assert_eq!(Operation::RotateLeft(1).evaluate(&[b""]), Err(GenerationError::InvalidLength));
    assert_eq!(Operation::Sha256Prefix(33).validate_arity(1), Err(GenerationError::InvalidOperation));
}
```

- [ ] **Step 2: Run the operation tests and confirm failure**

Run: `cargo test -p agentgate-core generation::operation::tests -- --nocapture`  
Expected: FAIL because `Operation` and its methods are undefined.

- [ ] **Step 3: Implement the enum and deterministic semantics**

Create the public enum below and implement `arity`, `validate_arity`, `output_length`, and `evaluate` as specified by the approved design and exact tests:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    Reverse,
    RotateLeft(usize),
    RotateRight(usize),
    Xor(Vec<u8>),
    EvenBytes,
    OddBytes,
    Permute(Vec<usize>),
    Slice { start: usize, end: usize },
    Concat,
    AddModulo,
    SubModulo,
    HexEncode,
    HexDecode,
    Base64UrlEncode,
    Base64UrlDecode,
    Sha256Prefix(usize),
    RotateLeftDerived,
    ConditionalOrder,
}
```

Arity is one except `Concat`, `AddModulo`, `SubModulo`, and `RotateLeftDerived`, which require two, and `ConditionalOrder`, which requires three. `Concat` accepts two or more inputs. `Xor` repeats a non-empty key. `Permute` must contain every input index exactly once. Decoders require canonical lowercase hex or canonical unpadded base64url by decoding and re-encoding. `output_length` uses checked arithmetic and returns `InvalidLength` on overflow or impossible static shape.

Use `base64::engine::general_purpose::URL_SAFE_NO_PAD`, `hex`, and `sha2::Sha256`; do not log or format input bytes in errors. Re-export `Operation` from `generation/mod.rs`.

- [ ] **Step 4: Run focused and existing core tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::operation::tests && cargo test -p agentgate-core --tests`  
Expected: all operation tests and all pre-existing core integration tests PASS.

- [ ] **Step 5: Commit the operation library**

```bash
git add packages/core/src/generation/operation.rs packages/core/src/generation/mod.rs
git commit -m "feat: add v1 semantic operations"
```

### Task 3: Validated semantic DAG capability boundary

**Files:**
- Create: `packages/core/src/generation/graph.rs`
- Modify: `packages/core/src/generation/mod.rs`
- Create: `packages/core/tests/generation_public_api.rs`

- [ ] **Step 1: Write failing graph-validation tests**

Add unit tests in `graph.rs` that construct raw nodes directly and cover every rejection path. The valid fixture uses three fragment nodes plus four operations:

```rust
fn valid_graph() -> SemanticGraphBuilder {
    let mut graph = SemanticGraphBuilder::new(vec![2, 2, 2]);
    let a = graph.fragment(0).unwrap();
    let b = graph.fragment(1).unwrap();
    let c = graph.fragment(2).unwrap();
    let ra = graph.operation(Operation::Reverse, vec![a]);
    let rb = graph.operation(Operation::RotateLeft(1), vec![b]);
    let joined = graph.operation(Operation::Concat, vec![ra, rb]);
    let output = graph.operation(Operation::Concat, vec![joined, c]);
    graph.output(output);
    graph
}

#[test]
fn validates_a_reachable_acyclic_graph() {
    let graph = valid_graph().validate().unwrap();
    assert_eq!(graph.operation_count(), 4);
    assert_eq!(graph.fragment_lengths(), &[2, 2, 2]);
    assert_eq!(graph.output_length(), 6);
    assert_eq!(graph.topological_nodes().len(), 7);
}

#[test]
fn rejects_wrong_output_count_and_operation_bounds() {
    let mut no_output = valid_graph();
    no_output.outputs.clear();
    assert_eq!(no_output.validate(), Err(GenerationError::InvalidOutput));

    let mut two_outputs = valid_graph();
    two_outputs.outputs.push(NodeId(0));
    assert_eq!(two_outputs.validate(), Err(GenerationError::InvalidOutput));
}
```

Add separate exact assertions for `DuplicateNode`, `MissingNode`, `InvalidFragment`, `Cycle`, `UnreachableNode`, `InvalidOperationCount`, invalid arity, and statically invalid output length. Keep these tests inside the module so they can corrupt raw test fixtures without widening the public builder API.

- [ ] **Step 2: Add a failing external API test**

Create `packages/core/tests/generation_public_api.rs`:

```rust
use agentgate_core::generation::{NodeId, Operation, SemanticGraphBuilder};

#[test]
fn exposes_read_only_validated_semantics() {
    let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
    let a = builder.fragment(0).unwrap();
    let b = builder.fragment(1).unwrap();
    let c = builder.fragment(2).unwrap();
    let a = builder.operation(Operation::Reverse, vec![a]);
    let b = builder.operation(Operation::Reverse, vec![b]);
    let ab = builder.operation(Operation::Concat, vec![a, b]);
    let out = builder.operation(Operation::Concat, vec![ab, c]);
    builder.output(out);
    let graph = builder.validate().unwrap();

    assert_eq!(graph.output(), out);
    assert_eq!(graph.operation_count(), 4);
    assert!(graph.node(NodeId(999)).is_none());
}
```

- [ ] **Step 3: Run tests and confirm failure**

Run: `cargo test -p agentgate-core graph -- --nocapture`  
Expected: FAIL because graph types do not exist.

- [ ] **Step 4: Implement graph construction and validation**

Define:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Fragment { index: usize },
    Operation { operation: Operation, inputs: Vec<NodeId> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticNode {
    id: NodeId,
    kind: NodeKind,
}

pub struct SemanticGraphBuilder {
    fragment_lengths: Vec<usize>,
    nodes: Vec<SemanticNode>,
    outputs: Vec<NodeId>,
    next_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSemanticGraph {
    fragment_lengths: Vec<usize>,
    nodes: Vec<SemanticNode>,
    topological_order: Vec<NodeId>,
    output: NodeId,
    output_length: usize,
}
```

`SemanticGraphBuilder::new` creates one fragment node per declared non-zero length. `operation` allocates monotonically increasing IDs. `output` records declarations. `validate` performs, in order: unique-ID check, exactly-one-output check, fragment-index check, reference check, operation-count check (4 through 8), Kahn topological sort, reachability walk backwards from output, and static length propagation through `Operation::output_length`. Return only `ValidatedSemanticGraph`.

Expose read-only accessors for node ID/kind, fragment lengths, nodes in topological order, output, output length, operation count, and node lookup. Do not expose mutable fields or a constructor for `ValidatedSemanticGraph`.

- [ ] **Step 5: Run focused, external API, and workspace tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::graph::tests && cargo test -p agentgate-core --test generation_public_api && cargo test --workspace`  
Expected: all commands PASS.

- [ ] **Step 6: Commit the graph boundary**

```bash
git add packages/core/src/generation/graph.rs packages/core/src/generation/mod.rs packages/core/tests/generation_public_api.rs
git commit -m "feat: add validated semantic graph"
```

### Task 4: Deterministic answer engine

**Files:**
- Create: `packages/core/src/generation/answer.rs`
- Modify: `packages/core/src/generation/mod.rs`
- Modify: `packages/core/tests/generation_public_api.rs`

- [ ] **Step 1: Write failing execution tests**

Add tests that build a four-operation valid graph and execute it:

```rust
fn valid_graph() -> ValidatedSemanticGraph {
    let mut builder = SemanticGraphBuilder::new(vec![2, 2, 2]);
    let a = builder.fragment(0).unwrap();
    let b = builder.fragment(1).unwrap();
    let c = builder.fragment(2).unwrap();
    let a = builder.operation(Operation::Reverse, vec![a]);
    let b = builder.operation(Operation::RotateLeft(1), vec![b]);
    let ab = builder.operation(Operation::Concat, vec![a, b]);
    let out = builder.operation(Operation::Concat, vec![ab, c]);
    builder.output(out);
    builder.validate().unwrap()
}

#[test]
fn evaluates_a_validated_graph_in_topological_order() {
    let graph = valid_graph();
    assert_eq!(evaluate(&graph, &[b"ab", b"cd", b"ef"]), Ok(b"badcef".to_vec()));
}

#[test]
fn rejects_fragment_count_or_length_mismatch_without_echoing_bytes() {
    let graph = valid_graph();
    assert_eq!(evaluate(&graph, &[b"ab", b"cd"]), Err(GenerationError::InvalidFragment(2)));
    assert_eq!(evaluate(&graph, &[b"ab", b"c", b"ef"]), Err(GenerationError::InvalidLength));
}
```

- [ ] **Step 2: Run the answer tests and confirm failure**

Run: `cargo test -p agentgate-core generation::answer::tests -- --nocapture`  
Expected: FAIL because `evaluate` does not exist.

- [ ] **Step 3: Implement topological evaluation**

Implement:

```rust
pub fn evaluate(
    graph: &ValidatedSemanticGraph,
    fragments: &[&[u8]],
) -> Result<Vec<u8>, GenerationError>
```

First require exact fragment count and declared lengths. Then iterate `topological_nodes`; copy fragment inputs into a `HashMap<NodeId, Vec<u8>>`, evaluate operation nodes from referenced values, and insert results. Return a clone of the declared output value and verify its length equals `graph.output_length()`. Missing internal values map to `ExecutionFailed`; never include values in the error. Re-export the function as `evaluate_semantic_graph`.

- [ ] **Step 4: Run focused and workspace tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::answer::tests && cargo test --workspace`  
Expected: PASS.

- [ ] **Step 5: Commit the answer engine**

```bash
git add packages/core/src/generation/answer.rs packages/core/src/generation/mod.rs packages/core/tests/generation_public_api.rs
git commit -m "feat: execute validated semantic graphs"
```

### Task 5: Secure secret generation and fixed-policy partitioning

**Files:**
- Create: `packages/core/src/generation/secret.rs`
- Create: `packages/core/src/generation/partition.rs`
- Create: `packages/core/src/generation/test_random.rs`
- Modify: `packages/core/src/generation/mod.rs`

- [ ] **Step 1: Add deterministic test RNG and failing property-style tests**

Create a test-only SHA-256 counter source seeded by `[u8; 32]`. For each block hash `seed || counter.to_be_bytes()`, increment the counter and fill the destination until complete. Then add tests across seeds 0 through 255:

```rust
#[test]
fn generated_secrets_obey_fixed_policy() {
    for seed in 0_u8..=255 {
        let mut random = DeterministicRandom::new([seed; 32]);
        let secret = generate_with(&mut random).unwrap();
        assert!((8..=16).contains(&secret.len()));
        assert!(secret.expose().iter().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    }
}

#[test]
fn partitions_are_non_empty_and_lossless() {
    for length in 8..=16 {
        for seed in 0_u8..=63 {
            let secret: Vec<u8> = (0..length).map(|index| b'A' + index as u8).collect();
            let mut random = DeterministicRandom::new([seed; 32]);
            let parts = partition_with(&secret, &mut random).unwrap();
            assert_eq!(parts.len(), fragment_count_for_secret_length(length as u8).unwrap() as usize);
            assert!(parts.iter().all(|part| !part.is_empty()));
            assert_eq!(parts.concat(), secret);
        }
    }
}
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `cargo test -p agentgate-core generation::secret::tests generation::partition::tests -- --nocapture`  
Expected: FAIL because secret generation and partitioning are undefined. If Cargo accepts only one filter, run the two module filters as separate commands.

- [ ] **Step 3: Implement redacted secret generation**

Define `Secret(Vec<u8>)` with public `len`/`is_empty`, crate-private `expose`, and a manual `Debug` that prints only `Secret([REDACTED])`. `generate_secret()` constructs `OsRandom`; `generate_with` samples length with `MIN_SECRET_LENGTH + sample_below(range)` and each character from this exact constant:

```rust
const ALPHANUMERIC: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
```

Do not implement `AsRef<[u8]>`, `Display`, serialization, or a public constructor.

- [ ] **Step 4: Implement random non-empty partitioning**

`partition_with` obtains the count from `fragment_count_for_secret_length`, creates every interior split position `1..secret.len()`, shuffles it, truncates to `count - 1`, sorts it, and slices between adjacent boundaries. Reject unsupported lengths with `InvalidLength`. Keep fragment bytes crate-private and never derive `Debug` on a secret-bearing aggregate.

- [ ] **Step 5: Run focused and workspace tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::secret::tests && cargo test -p agentgate-core generation::partition::tests && cargo test --workspace`  
Expected: PASS for all 9 supported lengths across all deterministic seeds, plus all existing tests.

- [ ] **Step 6: Commit secret generation and partitioning**

```bash
git add packages/core/src/generation/secret.rs packages/core/src/generation/partition.rs packages/core/src/generation/test_random.rs packages/core/src/generation/mod.rs
git commit -m "feat: generate and partition challenge secrets"
```

### Task 6: Constrained V1 semantic planner

**Files:**
- Create: `packages/core/src/generation/planner.rs`
- Modify: `packages/core/src/generation/mod.rs`

- [ ] **Step 1: Write failing planner invariant tests**

For secret lengths 8--16 and deterministic seeds 0--127, assert planning never retries into an invalid graph and remains reproducible:

```rust
#[test]
fn planned_graphs_satisfy_v1_invariants() {
    for length in 8..=16 {
        let bytes: Vec<u8> = (0..length).map(|index| b'A' + index as u8).collect();
        let secret = Secret::from_test_bytes(bytes);
        for seed in 0_u8..=127 {
            let mut random = DeterministicRandom::new([seed; 32]);
            let planned = plan_with(&secret, &mut random).unwrap();
            assert!((4..=8).contains(&planned.graph().operation_count()));
            assert!(planned.cross_fragment_dependency_count() >= 2);
            assert_eq!(planned.fragments().concat(), secret.expose());
            assert_eq!(
                evaluate_semantic_graph(planned.graph(), &planned.fragment_slices()).unwrap(),
                planned.answer(),
            );
        }
    }
}

#[test]
fn the_same_secret_and_random_stream_repeat_exactly() {
    let secret = Secret::from_test_bytes(b"AbCdEf12Gh".to_vec());
    let mut first_rng = DeterministicRandom::new([7; 32]);
    let mut second_rng = DeterministicRandom::new([7; 32]);
    let first = plan_with(&secret, &mut first_rng).unwrap();
    let second = plan_with(&secret, &mut second_rng).unwrap();
    assert_eq!(first.graph(), second.graph());
    assert_eq!(first.answer(), second.answer());
}
```

`from_test_bytes`, `fragments`, and `fragment_slices` must be available only under `cfg(test)` or crate-private visibility. `PlannedSemantics` must not derive `Debug`.

- [ ] **Step 2: Run planner tests and confirm failure**

Run: `cargo test -p agentgate-core generation::planner::tests -- --nocapture`  
Expected: FAIL because the planner is undefined.

- [ ] **Step 3: Implement a bounded planner pattern**

Implement this constrained construction for every fragment count:

1. Partition the secret.
2. Create one fragment node per part.
3. Apply one randomly selected unary length-safe operation (`Reverse`, `RotateLeft(1)`, `RotateRight(1)`, or non-empty one-byte `Xor`) to each fragment. This creates 3--5 operations.
4. Concatenate all transformed fragments in a randomized order in one `Concat` operation. This is the first multi-fragment dependency.
5. Use the first transformed fragment as the selector/parameter and the concatenated value as data in one `RotateLeftDerived` operation. This is the second cross-fragment dependency.
6. For 3- and 4-fragment secrets, add one final `Sha256Prefix` operation whose prefix length equals the pre-hash output length. For 5-fragment secrets, omit it so the total remains at 7 operations.
7. Declare the final node as output, validate, evaluate once, and return graph, private fragments, answer, and a computed cross-fragment dependency count.

This yields 6 operations for 3 fragments, 7 for 4 fragments, and 7 for 5 fragments. Compute dependency provenance as fragment-index sets propagated in topological order; count operation nodes whose union contains at least two fragment indices. Require the count to be at least two before returning.

Define:

```rust
pub(crate) struct PlannedSemantics {
    graph: ValidatedSemanticGraph,
    fragments: Vec<Vec<u8>>,
    answer: Vec<u8>,
    cross_fragment_dependency_count: usize,
}

pub(crate) fn plan_semantics() -> Result<PlannedSemantics, GenerationError>;
pub(crate) fn plan_with(
    secret: &Secret,
    random: &mut impl RandomSource,
) -> Result<PlannedSemantics, GenerationError>;
```

`plan_semantics` generates a secret with `OsRandom` and uses the same random instance for partition and planner choices. Keep all secret-bearing accessors crate-private.

- [ ] **Step 4: Run planner, generation, and workspace tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::planner::tests && cargo test -p agentgate-core --test generation_public_api && cargo test --workspace`  
Expected: PASS across all 1,152 deterministic planner cases and all existing tests.

- [ ] **Step 5: Commit the planner**

```bash
git add packages/core/src/generation/planner.rs packages/core/src/generation/mod.rs
git commit -m "feat: plan bounded semantic challenges"
```

### Task 7: Security review, documentation, and Phase 2 verification

**Files:**
- Modify: `README.md`
- Modify if required by findings: `packages/core/src/generation/*.rs`
- Modify if required by findings: `packages/core/tests/generation_public_api.rs`

- [ ] **Step 1: Add or confirm redaction regression tests**

Add exact assertions that every publicly debuggable semantic type contains structural metadata only, `Secret` prints `Secret([REDACTED])`, and `PlannedSemantics` has no `Debug` implementation. Search source for accidental byte formatting:

Run: `rg -n "println!|dbg!|tracing|log::|format!.*(secret|answer|fragment|input|value)" packages/core/src/generation`  
Expected: no production logging or sensitive formatting matches.

- [ ] **Step 2: Verify public artifacts did not change**

Run: `git diff 5e88e39 -- schemas fixtures/contracts packages/contracts/src/challenge.rs`  
Expected: no output.

- [ ] **Step 3: Update workspace status in README**

Replace the Phase 1-only status paragraph with:

```markdown
Phase 1 defines protocol contracts and context-bound answer verification. Phase 2 adds the validated semantic DAG, deterministic answer engine, fixed-policy secret generation and partitioning, and constrained challenge planning. Mixed-language rendering, lifecycle integration, language bindings, and adversarial qualification remain subsequent roadmap phases.
```

- [ ] **Step 4: Run the full required verification suite**

Run each command independently:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
git diff --check
```

Expected: every command exits 0; no warnings, failures, ignored formatting changes, or whitespace errors.

- [ ] **Step 5: Review the final diff against the Phase 2 spec**

Run: `git diff 92ba0d8 --stat && git status --short`  
Expected: only Phase 2 generation implementation, tests, dependency lockfile changes, and README are present; no unrelated user files are modified.

- [ ] **Step 6: Commit documentation and final hardening**

```bash
git add README.md Cargo.toml Cargo.lock packages/core
git commit -m "docs: mark semantic engine phase complete"
```

- [ ] **Step 7: Request code review before integration**

Invoke the `requesting-code-review` skill, address only findings within Phase 2 scope, rerun the full verification suite, and report the exact test and lint results.
