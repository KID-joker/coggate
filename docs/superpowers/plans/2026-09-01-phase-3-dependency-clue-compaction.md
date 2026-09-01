# Phase 3 Dependency-Clue Compaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every legal V1 graph fit the existing Phase 3 renderer bounds by grouping cross-fragment dependency prose per consuming operation.

**Architecture:** Keep operation expressions and semantic validation unchanged. Add one bounded grouped-clue formatter in the emitter, use it both for final assembly and validator byte accounting, and replace per-edge clues with one ordered, deduplicated clue per consumer.

**Tech Stack:** Rust 2024, existing `agentgate-core` renderer, deterministic test RNG, Cargo tests and Clippy.

---

## File map

- Modify `packages/core/src/generation/render/emitter.rs`: format grouped dependency clues and assemble one clue per consuming operation.
- Modify `packages/core/src/generation/render/validate.rs`: account for the exact grouped clue text instead of a fixed per-edge cost.
- Modify `packages/core/src/generation/render/mod.rs`: update the focused repeated-input/grouped-clue oracle.
- Modify `packages/core/src/generation/render/properties.rs`: add the dense legal V1 regression across 128 deterministic streams.

### Task 1: Reproduce the legal high-fan-in failure

**Files:**
- Modify: `packages/core/src/generation/render/properties.rs`

- [ ] **Step 1: Add the dense legal graph fixture and regression test**

Add a fixture that builds five two-byte ASCII fragments and eight successive
`Concat` operations. Each operation consumes all five source nodes and every
earlier operation node, so the eighth operation has 12 inputs and remains under
`MAX_CONCAT_INPUTS`.

```rust
fn dense_dependency_fixture() -> (ValidatedSemanticGraph, Vec<Vec<u8>>) {
    let fragments = vec![
        b"A0".to_vec(),
        b"B1".to_vec(),
        b"C2".to_vec(),
        b"D3".to_vec(),
        b"E4".to_vec(),
    ];
    let mut builder = SemanticGraphBuilder::new(vec![2; 5]);
    let mut prior = (0..5)
        .map(|index| builder.fragment(index).unwrap())
        .collect::<Vec<_>>();
    for _ in 0..8 {
        let output = builder.operation(Operation::Concat, prior.clone());
        prior.push(output);
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
        assert!(rendered.metadata().byte_length() <= MAX_QUESTION_BYTES);
        assert_eq!(
            evaluate_semantic_graph(&graph, &fragment_slices(&fragments)).unwrap(),
            expected
        );
    }
}
```

- [ ] **Step 2: Run the regression and verify RED**

Run:

```bash
cargo test -p agentgate-core generation::render::properties::dense_legal_dependencies_render_for_every_stream_within_fixed_bounds -- --nocapture
```

Expected: FAIL on the first stream because `render_with` returns
`RenderError::LengthLimit`. This proves the test exercises the reported bug.

### Task 2: Group dependency clues per consumer

**Files:**
- Modify: `packages/core/src/generation/render/emitter.rs`
- Modify: `packages/core/src/generation/render/mod.rs`

- [ ] **Step 1: Replace the old exact per-edge clue oracle with the grouped format**

In `render/mod.rs`, retain the existing manual plan whose expression is
`concat(source_x, source_x, source_y)`, then change its clue assertion to:

```rust
let clue = "Dependency: output labels source_x (Fragment 1) are inputs to output label combined in Fragment 2.\n";

assert!(question.contains("concat(source_x, source_x, source_y)"));
assert_eq!(question.matches(clue).count(), 1);
```

This test proves repeated ordered inputs remain in the expression while the
cross-fragment producer appears once in prose.

- [ ] **Step 2: Run the focused oracle and verify RED**

Run:

```bash
cargo test -p agentgate-core generation::render::tests::repeated_ordered_inputs_emit_once_but_dependency_clues_are_deduplicated -- --nocapture
```

Expected: FAIL because the emitter still produces the old per-edge sentence.

- [ ] **Step 3: Implement one bounded grouped-clue formatter**

Replace `format_dependency_clue` with a crate-private formatter that accepts
ordered producer label/location pairs:

```rust
pub(super) fn format_dependency_clue(
    producers: &[(&str, usize)],
    output_label: &str,
    output_display_index: usize,
) -> Result<String, RenderError> {
    if producers.is_empty() {
        return Err(RenderError::InvalidPlan);
    }
    let mut clue = String::new();
    push_with_limit(
        &mut clue,
        "Dependency: output labels ",
        MAX_FRAGMENT_BYTES,
    )?;
    for (index, (label, display_index)) in producers.iter().enumerate() {
        if index != 0 {
            push_with_limit(&mut clue, ", ", MAX_FRAGMENT_BYTES)?;
        }
        push_with_limit(
            &mut clue,
            &format!("{label} (Fragment {})", display_index + 1),
            MAX_FRAGMENT_BYTES,
        )?;
    }
    push_with_limit(
        &mut clue,
        &format!(
            " are inputs to output label {output_label} in Fragment {}.\n",
            output_display_index + 1
        ),
        MAX_FRAGMENT_BYTES,
    )?;
    Ok(clue)
}
```

Remove `DEPENDENCY_CLUE_FIXED_BYTES` and its test-only measurement helper.

- [ ] **Step 4: Assemble one clue per consuming operation**

Inside `emit_question`, replace the per-input clue push with local ordered
deduplication for each operation:

```rust
let mut seen_producers = BTreeSet::new();
let mut producers = Vec::new();
for input in inputs {
    let producer = locations
        .get(input)
        .ok_or(RenderError::MissingReference(*input))?;
    if producer.display_index != display_index && seen_producers.insert(*input) {
        producers.push((producer.output_label.as_str(), producer.display_index));
    }
}
if !producers.is_empty() {
    let clue = format_dependency_clue(&producers, &step.output_label, display_index)?;
    let clue_bytes = dependency_bytes_by_fragment[display_index]
        .checked_add(clue.len())
        .ok_or(RenderError::LengthLimit)?;
    if rendered_fragment
        .len()
        .checked_add(clue_bytes)
        .ok_or(RenderError::LengthLimit)?
        > MAX_FRAGMENT_BYTES
    {
        return Err(RenderError::LengthLimit);
    }
    dependency_bytes_by_fragment[display_index] = clue_bytes;
    dependency_clues.push(clue);
}
```

Delete the now-unused global `seen_dependency_edges` from `emit_question`.

- [ ] **Step 5: Run the focused emitter and render tests**

Run:

```bash
cargo test -p agentgate-core generation::render::tests::repeated_ordered_inputs_emit_once_but_dependency_clues_are_deduplicated -- --nocapture
cargo test -p agentgate-core generation::render::emitter::tests -- --nocapture
```

Expected: the grouped clue oracle and all emitter tests PASS.

### Task 3: Make validator accounting identical to emission

**Files:**
- Modify: `packages/core/src/generation/render/validate.rs`
- Modify: `packages/core/src/generation/render/properties.rs`

- [ ] **Step 1: Use the grouped formatter during plan-length validation**

Import `format_dependency_clue` and remove `DEPENDENCY_CLUE_FIXED_BYTES`. For
each operation, gather its ordered unique cross-fragment producers, format one
clue, and add the exact `clue.len()` to the consumer fragment budget:

```rust
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
        let clue = format_dependency_clue(
            &producers,
            &step.output_label,
            *fragment_index,
        )?;
        fragment_budgets[*fragment_index] =
            checked_add(fragment_budgets[*fragment_index], clue.len())?;
    }
}
```

The validator's effective indices may differ from final display indices when a
distractor is interleaved, but both ranges are one digit (`1..=6`), so the
formatted UTF-8 byte length is exact. Actual location text continues to be
produced by the emitter from final display indices.

- [ ] **Step 2: Replace the obsolete fixed-clue property**

Delete `dependency_clue_budget_matches_the_real_emitter_format`. Add a direct
formatter property:

```rust
#[test]
fn grouped_dependency_clue_names_every_ordered_unique_producer() {
    let clue = emitter::format_dependency_clue(
        &[("source_a", 0), ("source_b", 2)],
        "result_x",
        3,
    )
    .unwrap();

    assert_eq!(
        clue,
        "Dependency: output labels source_a (Fragment 1), source_b (Fragment 3) are inputs to output label result_x in Fragment 4.\n"
    );
}
```

- [ ] **Step 3: Run focused tests and verify GREEN**

Run:

```bash
cargo test -p agentgate-core generation::render::properties::dense_legal_dependencies_render_for_every_stream_within_fixed_bounds -- --nocapture
cargo test -p agentgate-core generation::render::properties::grouped_dependency_clue_names_every_ordered_unique_producer -- --nocapture
cargo test -p agentgate-core generation::render::validate::tests -- --nocapture
```

Expected: all focused tests PASS; the dense graph succeeds for all 128 streams
without changing either fixed byte limit.

- [ ] **Step 4: Commit the behavioral repair**

```bash
git add packages/core/src/generation/render/emitter.rs \
  packages/core/src/generation/render/mod.rs \
  packages/core/src/generation/render/properties.rs \
  packages/core/src/generation/render/validate.rs
git commit -m "fix: compact renderer dependency clues"
```

### Task 4: Full verification

**Files:**
- Verify only; no expected source changes.

- [ ] **Step 1: Check formatting**

Run: `cargo fmt --all --check`  
Expected: PASS.

- [ ] **Step 2: Run Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`  
Expected: PASS with no warnings.

- [ ] **Step 3: Run the complete test suite**

Run: `cargo test --workspace`  
Expected: PASS, including the dense 128-stream regression.

- [ ] **Step 4: Run documentation tests and diff checks**

Run: `cargo test --workspace --doc`  
Expected: PASS.

Run: `git diff --check`  
Expected: PASS with no whitespace errors.
