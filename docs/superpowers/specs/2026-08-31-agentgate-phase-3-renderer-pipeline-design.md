# AgentGate Phase 3 Mixed-Language Renderer Pipeline Design

Date: 2026-08-31  
Status: approved for implementation planning

## 1. Scope

Phase 3 adds a mixed-language renderer pipeline to `agentgate-core`. It turns a
validated semantic graph and its original secret fragments into a bounded,
shuffled question that preserves the graph's exact byte semantics.

The renderer supports C, C++, Rust, Go, Java, and language-independent
pseudocode. Each question uses two or three distinct code styles. Natural
language is a constraint and glue layer for byte semantics, dependencies,
custom helpers, final-output selection, and answer encoding; it is not a
seventh standalone fragment language.

Phase 3 includes collision-free name randomization, dependency clues, fragment
shuffling, one optional provably irrelevant distractor fragment, ambiguity
checks, and bounded-template length enforcement. It does not add the public
challenge-generation API, retry policy, lifecycle integration, language
bindings, or adversarial benchmarks. Those remain later roadmap phases.

## 2. Architecture

Rendering is split into a language-independent presentation plan and small
language emitters:

```text
ValidatedSemanticGraph + fragments + CSPRNG
        |
        v
Presentation Planner
  - group 4--8 operations into 3--5 display fragments
  - select 2--3 distinct languages
  - allocate bounded unique labels and names
  - record explicit dependency clues
  - optionally add one irrelevant distractor
        |
        v
Immutable RenderPlan
        |
        v
Language Emitters + Natural-Language Glue
        |
        v
Display Shuffle
        |
        v
Static Render Validation
  - exact semantic-node and edge coverage
  - unique producers and references
  - recoverable output dependency graph
  - irrelevant distractor proof
  - template and final-text length bounds
        |
        v
RenderedQuestion
```

The presentation planner decides all semantic associations before text is
emitted. Emitters never traverse the graph independently, compute values, or
choose dependencies. This prevents language-specific semantic drift.

The renderer entry point remains crate-private until Phase 4 exposes the
one-shot challenge-generation API. Stable read-only rendering result and
diagnostic types may be public so integration and contract tests can inspect
non-sensitive metadata without constructing invalid plans.

## 3. Module boundaries

Phase 3 adds a focused `generation::render` subtree:

- `render/mod.rs` defines the internal entry point and exposes the minimum
  read-only result types.
- `render/model.rs` defines `RenderLanguage`, immutable display steps,
  `RenderPlan`, display fragments, dependency clues, and `RenderedQuestion`.
- `render/names.rs` allocates collision-free bounded identifiers and labels
  from the existing cryptographic random-source boundary.
- `render/planner.rs` maps every semantic node and edge into a presentation
  plan, groups steps, selects languages and templates, and optionally adds a
  distractor.
- `render/emitter.rs` dispatches to the language emitters and assembles the
  common natural-language preamble, dependency glue, and answer instruction.
- `render/languages/` contains one focused emitter for C, C++, Rust, Go, Java,
  and pseudocode. Emitters consume presentation steps rather than graph nodes.
- `render/validate.rs` checks semantic correspondence, name/reference
  integrity, dependency recovery, distractor isolation, and all length bounds
  before a question can be returned.
- `render/error.rs` defines safe rendering failures without secret-bearing
  payloads.

The existing `Operation`, `ValidatedSemanticGraph`, answer engine, secret
generator, and partitioner remain authoritative and unchanged in meaning.

## 4. Presentation model

`RenderLanguage` has exactly six variants: C, C++, Rust, Go, Java, and
Pseudocode. A plan selects two or three distinct variants without replacement.

Each effective `DisplayStep` records:

- the source semantic `NodeId`;
- the exact `Operation` for operation nodes, or the exact fragment index for
  fragment inputs;
- the ordered source `NodeId` list;
- one unique output label;
- bounded presentation names and a template-family identifier.

Every semantic node has exactly one effective display step. Every effective
reference resolves to the one label owned by its source node. The plan records
the graph's declared output node as its only final output.

The 4--8 semantic operations are grouped into 3--5 effective display
fragments. Grouping does not alter node order inside a fragment or collapse
semantic operations. A display fragment may contain multiple steps, and a
dependency may cross display-fragment and language boundaries.

The optional distractor uses a separate identifier namespace, contains no
effective semantic `NodeId`, has no effective consumer, and cannot be the
declared output. Its fixed text identifies it as an audit or example branch
that does not contribute to the requested result. Removing it leaves the
effective plan and answer unchanged.

The final display order is shuffled only after labels and dependencies are
fixed. Display order never defines evaluation order.

## 5. Rendering semantics

All six emitters cover every V1 `Operation`, including operations not emitted
by the current Phase 2 planner. A validated graph accepted by the semantic
engine must not fail merely because it uses a less common V1 operation.

Every question states the shared byte rules:

- values are byte arrays;
- indices are zero-based;
- slices are half-open `[start, end)` ranges;
- byte addition and subtraction wrap modulo 256;
- rotation amounts are reduced modulo the current non-empty array length;
- hex is canonical lowercase;
- base64url is canonical and unpadded.

Original fragments appear only as bounded ASCII byte literals. Operation
parameters such as XOR keys, permutations, slice bounds, and hash prefix
lengths appear as explicit bounded constants. Binary intermediate values are
never interpolated into the question; they are referenced only by labels.

The snippets are deliberately incomplete programs. A helper may be defined in
another snippet or by the natural-language glue, and execution order follows
the explicit dependency labels rather than presentation order. Despite being
non-compilable as a whole, each operation has one complete interpretation.

The closing instruction names the graph's unique output label and requires the
caller to submit the unpadded base64url encoding of that label's byte array,
matching the existing `AnswerEncoding::Base64Url` contract.

## 6. Ambiguity and semantic-preservation rules

The validator compares the plan with the immutable validated graph before any
question is returned. It requires:

- a one-to-one mapping between semantic nodes and effective display steps;
- exact equality of each operation and its ordered input-node list;
- one unique producer for every effective label;
- every effective reference to resolve to its declared producer;
- the declared display output to equal the semantic graph output;
- all effective steps to remain reachable from that output;
- display-fragment dependencies to remain acyclic;
- the distractor, when present, to have no effective reference or output role;
- every selected language and template to be supported.

"Unique execution order" means that the question recovers one semantic
dependency graph and one final result. Independent operations may execute in
either order when both schedules are semantically identical; this is not an
ambiguity.

Rendering never evaluates or reparses the emitted question. Semantic
preservation is established structurally by matching every displayed step and
edge to the validated graph, then re-evaluating that same graph with the same
fragments in tests.

## 7. Randomization and determinism

The presentation planner uses the existing `RandomSource` abstraction for:

- language selection without replacement;
- operation grouping and template-family selection;
- bounded identifier and label selection;
- optional distractor selection;
- final display-fragment shuffling.

No production seed API is added. Tests inject the existing deterministic test
source. The same graph, fragments, and random byte stream produce the same
plan and exact question. Different streams should vary at least one permitted
surface dimension over a representative seed set while leaving the semantic
graph and answer unchanged.

Names are selected from fixed bounded dictionaries plus bounded numeric
suffixes. Allocation rejects namespace exhaustion rather than producing a
collision or an unbounded name.

## 8. Length enforcement

Phase 3 does not add a tokenizer or caller-configurable token budget. Length is
controlled by finite templates and bounded interpolation fields, as required
by the approved V1 design.

Every template family declares a static maximum byte length. Identifier,
label, integer-list, key-literal, fragment-literal, dependency-glue, and final
instruction fields each have explicit internal maximum lengths derived from
V1 graph and secret limits. Checked arithmetic is used when accumulating
lengths.

The validator checks both the declared template budget and a fixed internal
maximum for the assembled UTF-8 question. A mismatch or overflow rejects the
candidate. New or modified templates must update and pass worst-case length
tests; no runtime configuration can raise these limits.

## 9. Error handling and sensitive data

Rendering failures distinguish unsupported templates, name exhaustion,
invalid plan shape, missing or duplicate references, semantic mismatch,
ambiguous output, non-isolated distractors, and length-limit failures.

Errors may carry safe structural facts such as a language, template family,
or node ID. They never contain fragment bytes, operation keys, rendered source
text, intermediate bytes, the answer, or secret-bearing debug output.

Planner, emitter, and validator failures are atomic: no partial plan or partial
question is returned. Phase 4 will own bounded retry behavior and public error
mapping.

## 10. Testing strategy

Testing is deterministic and layered:

1. An operation-language matrix covers every V1 operation in every language,
   checking parameters, ordered references, output labels, and shared semantic
   wording.
2. Presentation-plan property tests cover two or three distinct languages,
   three to five effective display fragments, complete node coverage, unique
   names, unique producers, output reachability, and at most one isolated
   distractor over many fixed streams.
3. Semantic-preservation tests compare every displayed operation and input edge
   with the source graph, then confirm that graph evaluation yields the same
   answer before and after rendering.
4. Determinism and variation tests require identical output for identical
   streams and permitted surface variation across representative streams.
5. Negative ambiguity tests reject duplicate labels, missing producers, wrong
   references, wrong output nodes, omitted effective nodes, cycles, and
   referenced distractors.
6. Length tests enumerate worst-case legal operations and fields, verify every
   template declaration, prove the assembled legal maximum fits the global
   bound, and reject intentionally oversized plans.
7. Existing schemas, fixtures, verifier tests, and semantic-engine tests remain
   unchanged and pass with the new renderer suite.

## 11. Acceptance criteria

Phase 3 is complete when:

- every V1 operation renders in all six supported styles;
- every generated question uses two or three distinct styles and three to five
  effective display fragments;
- names, labels, dependency clues, templates, and display order vary only
  through the bounded deterministic randomization boundary;
- the validator proves exact graph correspondence and a unique output;
- an optional distractor is provably irrelevant;
- no template or assembled question can exceed its fixed internal bound;
- renderer errors and debug output disclose no secret-bearing values;
- formatting, linting, workspace tests, and documentation tests pass;
- README reports Phase 3 complete and identifies Phase 4 generation and
  lifecycle integration as the next phase.
