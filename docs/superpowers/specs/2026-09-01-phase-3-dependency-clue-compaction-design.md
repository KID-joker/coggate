# Phase 3 Dependency-Clue Compaction Design

Date: 2026-09-01  
Status: approved for implementation planning

## 1. Problem

The Phase 3 renderer currently emits one natural-language dependency clue for
every unique cross-fragment `(consumer, producer)` edge. A valid V1 graph can
contain several high-fan-in operations in the same display fragment. The
individual snippets remain bounded, but the repeated prose can exceed the
2,048-byte per-fragment budget and cause every deterministic rendering of that
graph to fail with `LengthLimit`.

This violates the Phase 3 requirement that the fixed bounds cover the legal V1
maximum. Phase 3 has no retry policy, so a legal graph must not depend on a
lucky presentation stream to render successfully.

## 2. Scope and invariants

The fix changes only the representation and accounting of cross-fragment
dependency clues.

The following remain unchanged:

- `MAX_FRAGMENT_BYTES` is 2,048 and `MAX_QUESTION_BYTES` is 12,288;
- the V1 semantic-graph and operation limits;
- display-fragment grouping, language selection, labels, and shuffling;
- operation expressions, including ordered and repeated inputs;
- the crate-private render entry point and the public read-only result API;
- the absence of retry behavior in Phase 3.

Every unique cross-fragment producer used by an operation must still be named,
and its producer display fragment must remain recoverable from the question.

## 3. Compact clue format

Dependency clues are grouped by consuming operation. A consumer with one or
more cross-fragment inputs emits exactly one clue in this form:

```text
Dependency: output labels a (Fragment 1), b (Fragment 2) are inputs to output x in Fragment 4.
```

The producer entries appear in the order of their first occurrence in the
operation's ordered input list. Repeated references to the same producer are
listed once in the clue. Their multiplicity and exact order remain visible in
the operation expression, for example `concat(a, a, b)`.

Operations with no cross-fragment inputs emit no dependency clue. Display
fragment numbers remain one-based and refer to the final shuffled display
order.

## 4. Shared formatting and accounting

The emitter owns one bounded helper that formats a grouped clue from:

- the ordered unique producer label and display-fragment pairs;
- the consumer output label;
- the consumer display-fragment index.

The same helper is used during validation to measure the exact emitted UTF-8
byte length. The validator must not maintain a separate fixed-per-edge prose
constant. It adds each grouped clue's actual length to the consuming display
fragment budget using checked arithmetic.

The final emitter uses the same formatted string when assembling the question,
so pre-emission accounting and actual output cannot drift.

## 5. Failure behavior

Checked arithmetic and all existing fixed limits remain authoritative. A truly
oversized plan still returns the payload-safe `RenderError::LengthLimit` and no
partial question. Formatting failures do not include fragments, operation
keys, intermediate bytes, answers, or rendered source text in the error.

## 6. Testing

Implementation follows a red-green cycle:

1. Add a legal five-fragment, eight-operation graph in which each successive
   `Concat` consumes all five sources and every earlier operation result. The
   final operation has arity 12, within the V1 maximum of 13. Confirm the graph
   validates and all 128 renderer streams currently fail the new success
   assertion with `LengthLimit`.
2. Add an exact grouped-clue test proving producer labels and final shuffled
   fragment numbers are preserved.
3. Retain the repeated-input oracle: the operation expression contains repeated
   ordered labels while the grouped clue lists each producer once.
4. Update the worst-case dependency test to exercise dense unique dependency
   edges rather than fixing the supposed maximum at 12.
5. Require all 128 render streams for the dense legal graph to succeed within
   both fixed limits and preserve the evaluated answer.
6. Run formatting, Clippy with warnings denied, the full workspace tests,
   documentation tests, and `git diff --check`.

## 7. Acceptance criteria

The repair is complete when:

- the dense legal V1 graph renders successfully for every tested deterministic
  stream without retry;
- every cross-fragment producer label and producer display location remains
  recoverable from the grouped clues;
- ordered and repeated operation inputs remain exact in emitted expressions;
- validator accounting uses the exact grouped text emitted at runtime;
- existing global and per-fragment bounds remain unchanged;
- all existing Phase 1 through Phase 3 quality gates pass.
