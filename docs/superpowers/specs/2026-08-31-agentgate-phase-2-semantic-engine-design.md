# AgentGate Phase 2 Semantic Engine Design

Date: 2026-08-31  
Status: approved for implementation planning

## 1. Scope

Phase 2 adds the internal semantic engine and challenge planner to the existing
`agentgate-core` crate. It implements the V1 byte-operation library, validated
semantic DAG, deterministic answer engine, cryptographically secure secret
generation, random secret partitioning, and a fixed-policy planner.

Phase 2 does not implement mixed-language rendering, the public challenge
generation API, lifecycle storage, language bindings, or adversarial benchmark
packaging. It does not reintroduce difficulty levels or caller-configurable
secret length, fragment count, question size, or TTL.

The existing protocol types, JSON Schemas, answer canonicalization, and
context-bound MAC verifier remain unchanged.

## 2. Architecture

The implementation extends `agentgate-core` with a focused `generation`
module rather than introducing a new crate. This keeps the single Rust
reference implementation authoritative while giving the future renderer a
stable, read-only semantic model.

The data flow is:

```text
OS CSPRNG -> Secret -> random non-empty partitions
                               |
Operation Library -> Planner -> Validated Semantic Graph -> Answer Engine
                                                               |
                                                        canonical bytes
```

The planner constructs graphs from known-valid bounded patterns and validates
every finished graph. The answer engine executes only validated graphs and
never parses rendered questions. Phase 3 will consume the same immutable graph
to render a question without changing its meaning.

## 3. Module boundaries

The new code is divided by responsibility:

- `generation/error.rs` defines stable internal generation, graph-validation,
  and execution failures. Error values and messages never include the secret,
  operation inputs, intermediate bytes, or answer bytes.
- `generation/operation.rs` defines the V1 byte operations, their parameter
  validation, output-length rules, and deterministic evaluation.
- `generation/graph.rs` defines node identifiers, input references, operation
  nodes, fragment-input nodes, the single output node, graph validation, and
  the immutable validated-graph wrapper.
- `generation/answer.rs` evaluates a validated graph in topological order and
  returns its answer bytes.
- `generation/secret.rs` generates an 8--16 byte alphanumeric secret from an OS
  cryptographic random source. A generic RNG boundary exists for deterministic
  tests but is not exposed as a production seed API.
- `generation/partition.rs` derives the required 3--5 fragment count from the
  existing contract policy, chooses legal split points, and returns non-empty
  fragments whose ordered concatenation exactly reproduces the secret.
- `generation/planner.rs` constructs a bounded graph from the fragments and a
  cryptographic random source, then returns only a validated graph.
- `generation/mod.rs` exposes the minimum types and functions needed by later
  internal phases without publishing mutable graph internals.

## 4. V1 operation semantics

All internal values are byte arrays. Indices are zero-based, slices are
half-open, arithmetic is unsigned and wraps modulo 256, and rotations reduce
their amount modulo the current byte length. Operations with undefined input,
such as rotating an empty value or decoding malformed text, return a typed
execution error.

Phase 2's operation library covers the approved V1 set:

- byte reversal;
- rotate left and rotate right;
- XOR with a fixed byte or a bounded repeating byte key;
- extraction of even-indexed or odd-indexed bytes;
- validated fixed permutation;
- half-open slicing;
- concatenation of ordered inputs;
- byte-wise wrapping addition and subtraction;
- lowercase hexadecimal encoding and strict decoding;
- unpadded base64url encoding and strict decoding;
- SHA-256 followed by a validated bounded prefix;
- upstream-derived parameter selection or input ordering.

Every operation declares its arity and validates its parameters before graph
execution. Where output length is statically derivable, graph validation
records and checks it. The planner initially samples only the subset and
compositions for which bounded length and a unique result can be demonstrated
directly. The remaining operations are still implemented and unit-tested so
they can enter later planner patterns without changing the semantic model.

## 5. Semantic graph

A graph contains fragment-input nodes and operation nodes identified by unique
opaque node IDs, plus exactly one declared output. Operation inputs reference
other node IDs; raw secret bytes are supplied separately during evaluation and
are not embedded in the graph.

Graph validation rejects:

- duplicate node IDs;
- missing input references;
- references to nonexistent fragment indices;
- cycles, including self-cycles;
- nodes not reachable from the declared output;
- no output or multiple effective outputs;
- operation arity or parameter violations;
- statically provable length mismatches;
- a graph outside the fixed V1 operation-count bounds.

Successful validation consumes the mutable graph builder and returns a
`ValidatedSemanticGraph`. Its nodes, edges, and output may be inspected through
read-only accessors, but consumers cannot mutate it back into an invalid state.

The graph deliberately contains semantic structure only. Display language,
fragment order, variable names, prose, comments, and distraction fragments are
Phase 3 renderer concerns.

## 6. Secret generation and partitioning

Production secret generation uses the operating system cryptographic random
source. It selects the secret length uniformly from the inclusive 8--16 range
and selects every byte from `A-Z`, `a-z`, and `0-9`. Callers cannot provide a
length or seed through the production API.

Partitioning uses `fragment_count_for_secret_length` from
`agentgate-contracts`:

- 8--10 bytes produce 3 fragments;
- 11--13 bytes produce 4 fragments;
- 14--16 bytes produce 5 fragments.

The partitioner samples distinct split positions from the valid interior byte
boundaries, sorts them, and slices the secret. Every fragment is non-empty, the
number of fragments matches policy, and concatenating fragments in order
reconstructs the secret exactly.

RNG-generic helper functions are crate-private. Tests use a deterministic
cryptographic RNG to reproduce results; production code always selects the OS
source internally.

## 7. Planner guarantees

The planner uses constrained construction rather than unrestricted random graph
generation followed by repeated retries. For each challenge it:

1. creates the policy-selected non-empty fragments;
2. applies at least one independent transform to every fragment;
3. introduces at least two dependencies whose inputs originate from different
   fragments, using concatenation, upstream-derived parameters, or conditional
   ordering;
4. produces 4--8 effective semantic operation nodes;
5. declares one output and validates the completed graph;
6. evaluates the graph once to prove that it produces a deterministic answer.

Given the same generator version, secret, and deterministic test RNG stream,
planning produces the same graph and answer. Production generation remains
nondeterministic because both the secret and planner choices use the OS CSPRNG.

Planner failure returns a typed error. It does not return a partial graph and
does not expose the secret or intermediate state.

## 8. Error handling and sensitive data

Errors distinguish random-source failure, invalid operation parameters,
invalid references, cycles, unreachable nodes, invalid graph shape, length
mismatch, invalid encoded data, and execution failure. Error variants carry
safe structural facts such as a node ID or expected arity when useful, but
never byte values.

Secret-bearing types use redacted `Debug` implementations or avoid `Debug`
entirely. No Phase 2 path logs secrets, fragment bytes, operation inputs,
intermediate values, or answers.

## 9. Testing strategy

Testing is layered and deterministic:

1. Table-driven operation tests cover normal behavior, empty input, boundary
   parameters, malformed encodings, permutations, and output-length changes.
2. Graph-validation tests cover duplicate IDs, missing references, cycles,
   unreachable nodes, invalid fragments, invalid arity, invalid lengths,
   operation-count bounds, and valid topological execution.
3. Secret and partition property tests cover the exact character set, inclusive
   length range, fragment-count mapping, non-empty fragments, varied split
   points, and lossless reconstruction over many fixed seeds.
4. Planner and answer-engine property tests cover 4--8 operations, at least two
   cross-fragment dependencies, full reachability, deterministic results,
   unique output, and repeatability over many fixed seeds.
5. Existing contract, schema, answer-canonicalization, and MAC-verification
   tests remain unchanged and pass alongside the new suite.

No test relies on a production seed API. Golden deterministic cases use only
crate-private RNG injection.

## 10. Acceptance criteria

Phase 2 is complete when:

- the complete V1 operation library is implemented with explicit semantics and
  boundary tests;
- arbitrary graph builders cannot bypass validation before execution;
- generated secrets and partitions satisfy the fixed V1 policy;
- every planned graph has 4--8 effective operations and at least two
  cross-fragment dependencies;
- the answer engine evaluates every accepted planner output deterministically;
- existing public JSON Schemas and protocol fixtures are unchanged;
- formatting, linting, all workspace tests, and documentation tests pass;
- README reports Phase 2 as complete and Phase 3 rendering as the next phase.

