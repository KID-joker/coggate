# AgentGate Phase 3 Mixed-Language Renderer Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render every validated V1 semantic graph as a deterministic, bounded, shuffled question using two or three of six supported code styles without changing the graph's answer.

**Architecture:** Add a private `generation::render` pipeline that first builds an immutable language-independent `RenderPlan`, validates its exact correspondence with the semantic graph, and only then emits mixed-language text and natural-language glue. The crate-private entry point accepts a validated graph, its original fragments, and the existing cryptographic random-source boundary; only redaction-safe, read-only rendered result types are re-exported for future Phase 4 integration.

**Tech Stack:** Rust 2024, existing `agentgate-core` semantic graph and deterministic test RNG, Cargo unit/integration tests, table-driven emitter tests, bounded UTF-8 templates, no new dependencies.

---

## File map

- Modify `packages/core/src/generation/mod.rs` to register the private renderer and re-export only safe read-only result types.
- Modify `packages/core/src/generation/planner.rs` to add crate-private read-only accessors for future rendering integration without widening the public API.
- Create `packages/core/src/generation/render/mod.rs` for the atomic render entry point and module boundary.
- Create `packages/core/src/generation/render/error.rs` for redaction-safe renderer failures.
- Create `packages/core/src/generation/render/model.rs` for languages, templates, plan steps, display fragments, metadata, and rendered results.
- Create `packages/core/src/generation/render/names.rs` for deterministic collision-free bounded names.
- Create `packages/core/src/generation/render/planner.rs` for language selection, node mapping, grouping, distractor selection, and display shuffling.
- Create `packages/core/src/generation/render/emitter.rs` for common question assembly and language dispatch.
- Create `packages/core/src/generation/render/languages/mod.rs` plus `c.rs`, `cpp.rs`, `rust.rs`, `go.rs`, `java.rs`, and `pseudocode.rs` for focused syntax emitters.
- Create `packages/core/src/generation/render/validate.rs` for semantic correspondence, ambiguity, distractor, and length validation.
- Modify `packages/core/tests/generation_public_api.rs` to lock the read-only renderer surface.
- Modify `README.md` only after the complete Phase 3 verification gate passes.

### Task 1: Renderer model, safe errors, and bounded name allocation

**Files:**
- Modify: `packages/core/src/generation/mod.rs`
- Create: `packages/core/src/generation/render/mod.rs`
- Create: `packages/core/src/generation/render/error.rs`
- Create: `packages/core/src/generation/render/model.rs`
- Create: `packages/core/src/generation/render/names.rs`

- [ ] **Step 1: Write failing name-allocation and redaction tests**

Create `packages/core/src/generation/render/names.rs` with tests that use the existing deterministic RNG and require bounded unique names:

```rust
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::generation::test_random::DeterministicRandom;

    use super::*;

    #[test]
    fn allocates_unique_bounded_identifiers_and_labels() {
        let mut random = DeterministicRandom::new([9; 32]);
        let mut allocator = NameAllocator::new(&mut random);
        let names = (0..MAX_ALLOCATED_NAMES)
            .map(|_| allocator.allocate_identifier())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), names.len());
        assert!(names.iter().all(|name| name.len() <= MAX_IDENTIFIER_BYTES));
        assert!(names.iter().all(|name| {
            name.bytes().all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        }));
    }

    #[test]
    fn rejects_allocation_past_the_fixed_namespace() {
        let mut random = DeterministicRandom::new([4; 32]);
        let mut allocator = NameAllocator::new(&mut random);
        for _ in 0..MAX_ALLOCATED_NAMES {
            allocator.allocate_identifier().unwrap();
        }
        assert_eq!(allocator.allocate_identifier(), Err(RenderError::NameExhausted));
    }
}
```

Add a test in `render/error.rs` that formats every error variant and asserts the result contains only structural metadata supplied by the test and no marker secret:

```rust
#[test]
fn errors_do_not_accept_or_render_secret_values() {
    let errors = [
        RenderError::NameExhausted,
        RenderError::InvalidPlan,
        RenderError::MissingReference(NodeId(7)),
        RenderError::DuplicateReference(NodeId(8)),
        RenderError::SemanticMismatch(NodeId(9)),
        RenderError::AmbiguousOutput,
        RenderError::DistractorReferenced,
        RenderError::LengthLimit,
    ];
    for error in errors {
        assert!(!error.to_string().contains("SECRET_MARKER"));
    }
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `cargo test -p agentgate-core generation::render::names::tests -- --nocapture && cargo test -p agentgate-core generation::render::error::tests -- --nocapture`  
Expected: FAIL because the render module, `NameAllocator`, model types, and `RenderError` do not exist.

- [ ] **Step 3: Add the model and safe error boundary**

Create the module tree and define these exact public read-only types in `model.rs`:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RenderLanguage { C, Cpp, Rust, Go, Java, Pseudocode }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateFamily { Direct, Helper }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DisplayStepKind {
    Fragment { index: usize },
    Operation { operation: Operation, inputs: Vec<NodeId> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DisplayStep {
    pub(super) node: NodeId,
    pub(super) output_label: String,
    pub(super) local_name: String,
    pub(super) template: TemplateFamily,
    pub(super) kind: DisplayStepKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DisplayFragment {
    pub(super) heading: String,
    pub(super) language: RenderLanguage,
    pub(super) steps: Vec<DisplayStep>,
    pub(super) distractor: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RenderPlan {
    pub(super) fragments: Vec<DisplayFragment>,
    pub(super) output: NodeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderMetadata {
    languages: Vec<RenderLanguage>,
    effective_fragment_count: usize,
    has_distractor: bool,
    byte_length: usize,
}

pub struct RenderedQuestion {
    question: String,
    metadata: RenderMetadata,
}
```

Add read-only accessors `question()`, `metadata()`, `languages()`, `effective_fragment_count()`, `has_distractor()`, and `byte_length()`. Implement a custom `Debug` for `RenderedQuestion` that prints `question: "[REDACTED]"` and safe metadata only. Do not expose constructors or mutable fields publicly.

Define `RenderError` in `error.rs` exactly as a crate-private `thiserror::Error` with these variants: `NameExhausted`, `InvalidPlan`, `MissingReference(NodeId)`, `DuplicateReference(NodeId)`, `SemanticMismatch(NodeId)`, `AmbiguousOutput`, `DistractorReferenced`, `UnsupportedTemplate`, and `LengthLimit`. No variant accepts strings, bytes, operations, fragments, or rendered text.

- [ ] **Step 4: Implement the fixed name allocator**

Use a fixed dictionary of ASCII stems and bounded numeric suffixes. Set:

```rust
pub(super) const MAX_IDENTIFIER_BYTES: usize = 16;
pub(super) const MAX_ALLOCATED_NAMES: usize = 32;
```

`NameAllocator` owns a `BTreeSet<String>` and borrows `&mut impl RandomSource`. `allocate_identifier` randomly chooses a start offset, then probes the fixed namespace once, inserting the first unused value. It returns `NameExhausted` after all 32 values are allocated. Use `sample_below`; do not add a seed API or format any secret bytes.

- [ ] **Step 5: Run focused tests and the existing workspace suite**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::render::names::tests && cargo test -p agentgate-core generation::render::error::tests && cargo test --workspace`  
Expected: all focused tests and all existing workspace tests PASS.

- [ ] **Step 6: Commit the renderer foundation**

```bash
git add packages/core/src/generation/mod.rs packages/core/src/generation/render
git commit -m "feat: add renderer model foundation"
```

### Task 2: Complete six-language V1 operation emitters

**Files:**
- Create: `packages/core/src/generation/render/emitter.rs`
- Create: `packages/core/src/generation/render/languages/mod.rs`
- Create: `packages/core/src/generation/render/languages/c.rs`
- Create: `packages/core/src/generation/render/languages/cpp.rs`
- Create: `packages/core/src/generation/render/languages/rust.rs`
- Create: `packages/core/src/generation/render/languages/go.rs`
- Create: `packages/core/src/generation/render/languages/java.rs`
- Create: `packages/core/src/generation/render/languages/pseudocode.rs`
- Modify: `packages/core/src/generation/render/mod.rs`

- [ ] **Step 1: Write the failing operation-language coverage matrix**

In `emitter.rs`, add a table containing one valid representative of every V1 operation:

```rust
fn operations() -> Vec<Operation> {
    vec![
        Operation::Reverse,
        Operation::RotateLeft(3),
        Operation::RotateRight(2),
        Operation::Xor(vec![1, 2]),
        Operation::EvenBytes,
        Operation::OddBytes,
        Operation::Permute(vec![2, 0, 1]),
        Operation::Slice { start: 1, end: 3 },
        Operation::Concat,
        Operation::AddModulo,
        Operation::SubModulo,
        Operation::HexEncode,
        Operation::HexDecode,
        Operation::Base64UrlEncode,
        Operation::Base64UrlDecode,
        Operation::Sha256Prefix(8),
        Operation::RotateLeftDerived,
        Operation::ConditionalOrder,
    ]
}

#[test]
fn every_language_emits_every_v1_operation() {
    for language in RenderLanguage::ALL {
        for operation in operations() {
            let input_count = operation.arity().unwrap_or(3);
            let inputs = (0..input_count)
                .map(|index| format!("source_{index}"))
                .collect::<Vec<_>>();
            let rendered = emit_operation(
                language,
                TemplateFamily::Direct,
                "result_0",
                "local_0",
                &operation,
                &inputs,
            )
            .unwrap();
            assert!(rendered.contains("result_0"));
            assert!(inputs.iter().all(|input| rendered.contains(input)));
            assert!(rendered.len() <= MAX_STEP_BYTES);
        }
    }
}
```

Add exact golden tests for one operation in each language and parameter assertions for XOR, permutation, slice, rotations, hash prefix, derived rotation, and conditional ordering. Also test fragment literals reject non-alphanumeric bytes rather than escaping arbitrary secret content.

- [ ] **Step 2: Run the emitter tests and confirm RED**

Run: `cargo test -p agentgate-core generation::render::emitter::tests -- --nocapture`  
Expected: FAIL because emitters and language modules do not exist.

- [ ] **Step 3: Implement the shared operation-call formatter**

In `emitter.rs`, add `operation_expression(operation, inputs)` that returns bounded helper-call text with explicit parameters. Use these stable helper names:

```text
reverse, rotate_left, rotate_right, xor_repeat, even_bytes, odd_bytes,
permute, slice, concat, add_u8, sub_u8, hex_lower, hex_decode_lower,
base64url_no_pad, base64url_decode_no_pad, sha256_prefix,
rotate_left_derived, conditional_order
```

Format byte keys as bracketed unsigned decimal integers, permutations as bracketed indices, and slices as explicit `start, end` arguments. Check all additions against `MAX_STEP_BYTES = 512`; return `LengthLimit` on overflow or excess. This formatter is the single exhaustive `match Operation` so a future enum addition causes a compiler error until rendering is defined.

- [ ] **Step 4: Implement the six focused syntax wrappers**

Each file exposes one `emit_assignment(template, output_label, local_name, expression)` function. Required direct forms are:

```text
C:          bytes result_0 = EXPRESSION;  // exports result_0
C++:        auto result_0 = EXPRESSION;  // exports result_0
Rust:       let result_0 = EXPRESSION; // exports result_0
Go:         result_0 := EXPRESSION // exports result_0
Java:       byte[] result_0 = EXPRESSION; // exports result_0
Pseudocode: result_0 <- EXPRESSION  # exports result_0
```

The `Helper` family wraps the same expression in a bounded local helper/function-shaped snippet but must still export the exact output label. These are intentionally incomplete snippets; do not import runtimes or emit complete programs.

Add public `RenderLanguage::ALL` and a dispatch `emit_operation` that calls only these wrappers. Add `emit_fragment` using `bytes_ascii("...")` and reject empty, non-ASCII-alphanumeric, or over-16-byte inputs as `InvalidPlan`. Add a crate-private `declared_template_max_bytes(language, family)` match with one conservative constant for every language/family pair; Task 6 will exhaustively prove these declarations against worst-case legal inputs.

- [ ] **Step 5: Verify the full matrix and regressions**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::render::emitter::tests && cargo test --workspace`  
Expected: the complete 18-operation by 6-language matrix, golden tests, and all workspace tests PASS.

- [ ] **Step 6: Commit the emitters**

```bash
git add packages/core/src/generation/render
git commit -m "feat: render v1 operations in six styles"
```

### Task 3: Deterministic presentation planner and isolated distractor

**Files:**
- Create: `packages/core/src/generation/render/planner.rs`
- Modify: `packages/core/src/generation/render/model.rs`
- Modify: `packages/core/src/generation/render/mod.rs`

- [ ] **Step 1: Write failing planner property tests**

Build a valid three-fragment graph with six operations in `planner.rs` tests, then plan it across 128 deterministic streams:

```rust
#[test]
fn plans_bounded_mixed_language_presentations() {
    let (graph, fragments) = fixture();
    for seed in 0_u8..=127 {
        let mut random = DeterministicRandom::new([seed; 32]);
        let plan = plan_rendering(&graph, &fragments, &mut random).unwrap();
        let effective = plan.fragments.iter().filter(|item| !item.distractor).collect::<Vec<_>>();
        let languages = effective.iter().map(|item| item.language).collect::<BTreeSet<_>>();
        let steps = effective.iter().flat_map(|item| &item.steps).collect::<Vec<_>>();

        assert_eq!(effective.len(), graph.fragment_lengths().len());
        assert!((2..=3).contains(&languages.len()));
        assert_eq!(steps.len(), graph.topological_nodes().len());
        assert!(plan.fragments.iter().filter(|item| item.distractor).count() <= 1);
        assert_eq!(plan.output, graph.output());
    }
}
```

Add tests requiring identical plans for identical graph/fragments/random streams, surface variation over 128 streams, every graph node exactly once, and any distractor to have no effective steps or semantic node ID.

- [ ] **Step 2: Run the planner tests and confirm RED**

Run: `cargo test -p agentgate-core generation::render::planner::tests -- --nocapture`  
Expected: FAIL because `plan_rendering` does not exist.

- [ ] **Step 3: Validate renderer inputs before planning**

`plan_rendering(graph, fragments, random)` must reject unless:

- fragment count equals `graph.fragment_lengths().len()` and is in `3..=5`;
- every fragment length equals the corresponding declared length;
- every fragment is non-empty, at most 16 bytes, and ASCII alphanumeric;
- the graph has 4--8 operations (already guaranteed by validation, asserted defensively).

Return `InvalidPlan` without embedding fragment bytes in the error.

- [ ] **Step 4: Select languages, names, templates, and groups**

Use `sample_below` and `shuffle` only. Select a language count of two or three, shuffle `RenderLanguage::ALL`, and take that many without replacement. The effective display-fragment count equals the graph's input-fragment count, so it is always three to five.

Create one `DisplayStep` per topological semantic node. Fragment steps retain only their fragment index; operation steps clone the exact `Operation` and ordered inputs. Allocate separate bounded output labels and local names. Distribute topological steps into the fixed number of effective display fragments while keeping the order of steps inside each group stable. Assign selected languages so each selected language appears at least once.

Choose `TemplateFamily::Direct` or `Helper` per step. Set `plan.output` to `graph.output()` without randomization.

- [ ] **Step 5: Add and shuffle the optional distractor**

Consume one bounded random choice to decide whether to add a distractor. A distractor is a `DisplayFragment { heading, distractor: true, steps: Vec::new(), ... }` with a selected language and a bounded separately allocated heading. It never stores a semantic node or reference. After the plan is complete, shuffle the display fragments. Do not shuffle steps inside a fragment.

- [ ] **Step 6: Verify planner properties and workspace tests**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::render::planner::tests && cargo test --workspace`  
Expected: all planner properties and all existing tests PASS.

- [ ] **Step 7: Commit the presentation planner**

```bash
git add packages/core/src/generation/render
git commit -m "feat: plan mixed-language presentations"
```

### Task 4: Semantic correspondence, ambiguity, and length validator

**Files:**
- Create: `packages/core/src/generation/render/validate.rs`
- Modify: `packages/core/src/generation/render/model.rs`
- Modify: `packages/core/src/generation/render/mod.rs`

- [ ] **Step 1: Write failing validator rejection tests**

Start from a planner-produced valid plan, mutate one private field per test, and assert the exact error:

```rust
#[test]
fn rejects_missing_duplicate_and_changed_semantics() {
    let (graph, fragments, mut plan) = fixture_plan();
    let removed = plan.fragments.iter_mut().find(|part| !part.distractor).unwrap().steps.pop().unwrap();
    assert_eq!(validate_plan(&graph, &fragments, &plan), Err(RenderError::MissingReference(removed.node)));

    let (_, _, mut plan) = fixture_plan();
    let duplicate = plan.fragments.iter().flat_map(|part| &part.steps).next().unwrap().clone();
    plan.fragments.iter_mut().find(|part| !part.distractor).unwrap().steps.push(duplicate.clone());
    assert_eq!(validate_plan(&graph, &fragments, &plan), Err(RenderError::DuplicateReference(duplicate.node)));

    let (_, _, mut plan) = fixture_plan();
    let changed_node = {
        let operation = plan.fragments.iter_mut().flat_map(|part| &mut part.steps)
            .find(|step| matches!(step.kind, DisplayStepKind::Operation { .. })).unwrap();
        operation.kind = DisplayStepKind::Operation { operation: Operation::Reverse, inputs: vec![] };
        operation.node
    };
    assert_eq!(validate_plan(&graph, &fragments, &plan), Err(RenderError::SemanticMismatch(changed_node)));
}
```

Add separate negative tests for duplicate output labels, references to missing producers, wrong declared output, invalid selected-language count, empty effective fragments, more than one distractor, a distractor containing an effective step, dependency cycles in a manually corrupted plan, and oversized names or accumulated plan fields.

- [ ] **Step 2: Run validator tests and confirm RED**

Run: `cargo test -p agentgate-core generation::render::validate::tests -- --nocapture`  
Expected: FAIL because `validate_plan` and bounds do not exist.

- [ ] **Step 3: Implement exact graph-to-plan correspondence**

Build maps keyed by `NodeId` for graph nodes and effective display steps. Reject duplicate or missing step IDs. For each graph node require exact equality:

```text
NodeKind::Fragment { index } == DisplayStepKind::Fragment { index }
NodeKind::Operation { operation, inputs } == DisplayStepKind::Operation { operation, inputs }
```

Require the plan output to equal `graph.output()`. Require output labels and local names to be non-empty, within their fixed byte bounds, ASCII identifiers, and globally unique. Resolve every operation input through the source node's unique output label.

- [ ] **Step 4: Validate display dependencies and distractor isolation**

Derive display-fragment dependency edges from operation inputs whose producer is in a different effective display fragment. Run Kahn's algorithm and reject a cycle as `InvalidPlan`. Require two or three distinct effective languages, three to five non-empty effective fragments, and every effective language to be supported.

Require zero or one distractor. A distractor must have no effective steps and cannot own or reference the plan output; otherwise return `DistractorReferenced`.

- [ ] **Step 5: Enforce checked plan-level length bounds**

Define and document these internal constants in `model.rs`:

```rust
pub(super) const MAX_STEP_BYTES: usize = 512;
pub(super) const MAX_FRAGMENT_BYTES: usize = 2_048;
pub const MAX_QUESTION_BYTES: usize = 12_288;
```

Before emission, compute conservative checked bounds for every label, local name, operation parameter list, fragment literal, dependency clue, and template wrapper. Reject overflow or a fragment bound above `MAX_FRAGMENT_BYTES`. Keep `MAX_QUESTION_BYTES` fixed and non-configurable.

- [ ] **Step 6: Verify validator negatives and regressions**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::render::validate::tests && cargo test --workspace`  
Expected: every corruption test and all existing tests PASS.

- [ ] **Step 7: Commit the validator**

```bash
git add packages/core/src/generation/render
git commit -m "feat: validate rendered semantic plans"
```

### Task 5: Atomic question assembly and read-only renderer surface

**Files:**
- Modify: `packages/core/src/generation/render/mod.rs`
- Modify: `packages/core/src/generation/render/emitter.rs`
- Modify: `packages/core/src/generation/render/model.rs`
- Modify: `packages/core/src/generation/planner.rs`
- Modify: `packages/core/src/generation/mod.rs`
- Modify: `packages/core/tests/generation_public_api.rs`

- [ ] **Step 1: Write failing end-to-end render tests**

In `render/mod.rs`, create a planned semantic fixture and assert:

```rust
#[test]
fn renders_an_atomic_bounded_question_without_changing_the_answer() {
    let semantics = planned_fixture();
    let before = evaluate_semantic_graph(semantics.graph(), fragment_slices(semantics.fragments())).unwrap();
    let mut random = DeterministicRandom::new([23; 32]);
    let rendered = render_with(semantics.graph(), semantics.fragments(), &mut random).unwrap();
    let after = evaluate_semantic_graph(semantics.graph(), fragment_slices(semantics.fragments())).unwrap();

    assert_eq!(before, after);
    assert_eq!(before, semantics.answer());
    assert!(rendered.question().contains("unpadded base64url"));
    assert!(rendered.question().contains("Display order is not evaluation order"));
    assert_eq!(rendered.question().len(), rendered.metadata().byte_length());
    assert!(rendered.question().len() <= MAX_QUESTION_BYTES);
}
```

Add tests for exact determinism with the same stream, surface variation across streams, all displayed output labels occurring in question text, a redacted `Debug` implementation, and rejection without partial output when final assembly is oversized.

- [ ] **Step 2: Add a failing external API-surface test**

Extend `packages/core/tests/generation_public_api.rs`:

```rust
use agentgate_core::generation::{MAX_QUESTION_BYTES, RenderLanguage, RenderMetadata, RenderedQuestion};

#[test]
fn exposes_read_only_renderer_diagnostics() {
    assert_eq!(RenderLanguage::ALL.len(), 6);
    assert!(MAX_QUESTION_BYTES >= 8_192);
    assert!(std::mem::size_of::<RenderMetadata>() > 0);
    assert!(std::mem::size_of::<RenderedQuestion>() > 0);
}
```

The test intentionally has no public way to construct a `RenderPlan` or call the crate-private RNG-injected renderer.

- [ ] **Step 3: Run end-to-end and public-surface tests and confirm RED**

Run: `cargo test -p agentgate-core generation::render::tests -- --nocapture && cargo test -p agentgate-core --test generation_public_api -- --nocapture`  
Expected: FAIL because atomic assembly, planner accessors, and public re-exports are missing.

- [ ] **Step 4: Assemble the common question text**

`emit_question(plan, fragments)` emits, in this order:

1. a fixed byte-semantics preamble covering zero-based indices, half-open slices, wrapping `u8`, modulo rotation, lowercase hex, and unpadded base64url;
2. the shuffled display fragments with stable visible labels such as `[Fragment 1 — Rust]`;
3. explicit dependency clues generated from cross-fragment source labels;
4. optional fixed distractor wording that says the audit/example branch does not contribute to the requested result;
5. `Display order is not evaluation order.`;
6. the exact final output label and instruction to submit its byte array as unpadded base64url.

Use checked string growth, enforce `MAX_STEP_BYTES`, `MAX_FRAGMENT_BYTES`, and `MAX_QUESTION_BYTES` against actual UTF-8 byte lengths, and return only a complete `String`.

- [ ] **Step 5: Implement the atomic render entry point and safe metadata**

In `render/mod.rs`:

```rust
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
```

No function returns a partial plan or question. Re-export `RenderLanguage`, `RenderMetadata`, `RenderedQuestion`, and `MAX_QUESTION_BYTES` from `generation/mod.rs`, but keep `render_with`, `RenderPlan`, `DisplayStep`, `RandomSource`, and `RenderError` crate-private.

Add crate-private `graph()`, `fragments()`, and `answer()` accessors to `PlannedSemantics`; do not make its fields or type public.

- [ ] **Step 6: Verify end-to-end behavior, redaction, and API surface**

Run: `cargo fmt --all && cargo test -p agentgate-core generation::render && cargo test -p agentgate-core --test generation_public_api && cargo test --workspace`  
Expected: all renderer, public API, and workspace tests PASS.

- [ ] **Step 7: Commit atomic rendering**

```bash
git add packages/core/src/generation packages/core/tests/generation_public_api.rs
git commit -m "feat: assemble validated mixed-language questions"
```

### Task 6: Exhaustive properties, worst-case bounds, and regression hardening

**Files:**
- Modify: `packages/core/src/generation/render/mod.rs`
- Modify: `packages/core/src/generation/render/emitter.rs`
- Modify: `packages/core/src/generation/render/planner.rs`
- Modify: `packages/core/src/generation/render/validate.rs`

- [ ] **Step 1: Add failing worst-case and multi-seed property tests**

Add a renderer property test that uses every supported secret length and 128 fixed planner streams, then a separate 128 render streams per representative 3-, 4-, and 5-fragment graph. For every successful candidate assert:

```rust
assert_eq!(rendered.metadata().effective_fragment_count(), graph.fragment_lengths().len());
assert!((2..=3).contains(&rendered.metadata().languages().len()));
assert!(rendered.metadata().byte_length() <= MAX_QUESTION_BYTES);
assert_eq!(evaluate_semantic_graph(&graph, &fragment_refs).unwrap(), expected_answer);
```

Construct worst-case valid steps for the 16-byte XOR key, longest permutation, largest legal slice indices, 32-byte SHA prefix, maximum operation count, five fragments, helper templates, maximum identifier lengths, and a distractor. Require actual emitted text to remain within every declared bound.

Add a test that iterates `RenderLanguage::ALL × all V1 operations × both TemplateFamily variants` and requires each output's actual size to be no greater than both `declared_template_max_bytes(language, family)` and `MAX_STEP_BYTES`. Add a deliberately longest legal helper case for each language; this new per-template declaration check is the behavior that must fail before the declarations are complete.

- [ ] **Step 2: Run the new properties and confirm RED where bounds are incomplete**

Run: `cargo test -p agentgate-core generation::render -- --nocapture`  
Expected: FAIL because at least one language/family declaration is still absent or below the longest legal helper case. Confirm the failure names that exact language/family pair rather than an unrelated property.

- [ ] **Step 3: Close only the discovered bound and coverage gaps**

Complete `declared_template_max_bytes` and adjust conservative checked calculations, not runtime configuration. If any legal operation/template exceeds a declaration, either shorten that finite template or raise that language/family declaration to the smallest documented value that covers the enumerated legal maximum. Keep the global `MAX_STEP_BYTES` as a final ceiling. Do not truncate output and do not silently skip a language or operation.

- [ ] **Step 4: Run focused properties and the full quality gate**

Run: `cargo fmt --all --check`  
Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings`  
Expected: PASS with no warnings.

Run: `cargo test --workspace`  
Expected: PASS, including all Phase 1, Phase 2, operation-language matrix, ambiguity negatives, multi-seed properties, and worst-case bounds.

Run: `cargo test --workspace --doc`  
Expected: PASS.

- [ ] **Step 5: Commit the regression hardening**

```bash
git add packages/core/src/generation/render
git commit -m "test: harden renderer bounds and properties"
```

### Task 7: Phase 3 documentation and final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the workspace status only after Task 6 is green**

Replace the README workspace-status paragraph with:

```markdown
Phase 1 defines protocol contracts and context-bound answer verification. Phase 2 adds the validated semantic DAG, deterministic answer engine, fixed-policy secret generation and partitioning, and constrained challenge planning. Phase 3 adds bounded mixed-language rendering with deterministic presentation planning, dependency clues, name randomization, distractor isolation, ambiguity validation, and complete V1 operation coverage. Public challenge generation and lifecycle integration are the next roadmap phase; language bindings and adversarial qualification remain later phases.
```

- [ ] **Step 2: Run the final clean verification gate**

Run: `cargo fmt --all --check`  
Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings`  
Expected: PASS.

Run: `cargo test --workspace`  
Expected: PASS.

Run: `cargo test --workspace --doc`  
Expected: PASS.

Run: `git diff --check`  
Expected: PASS with no whitespace errors.

- [ ] **Step 3: Commit the Phase 3 completion marker**

```bash
git add README.md
git commit -m "docs: mark renderer pipeline phase complete"
```
