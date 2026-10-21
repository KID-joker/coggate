# Adaptive attack against composed challenges

This second mechanism experiment tests whether a solver that reads the public
generator can adapt to semantic composition rather than just match ten task
labels. It is available only with `dev-tools`; it is not a replacement for the
default production generator.

## Mechanism

Each challenge has three to six ordered array operations. Filtering and affine
mapping are mandatory, shuffled with numeric sorting, reversal, first/last
deduplication or truncation. Some operations run only when any or all current
values satisfy a predicate. The result is an integer array or its sum.

Two atomic predicates feed three alias levels with AND, OR and NOT. Names are
assigned afresh from a shared word pool, so the same word can mean different
things in different challenges. Alias and operation descriptions have wording
variants. All definitions and ordering rules remain explicit in the prompt.

Key, business factor, nonce, wording and hidden tests have independent derivation
domains. Tests include empty input, extreme values, repeated elements and
predicate boundaries. The generator and reference implementation are public.

## Adaptive solver

The separate attack implementation reads only public challenge JSON. It
tokenizes declarations, resolves local references, parses guarded operations
and emits a fixed JavaScript interpreter with the extracted operation plan.
It does not import the generator or read private cases or reference source.

The attack was developed from the frozen public grammar and manually written
public examples. The first frozen script already passed 1,000/1,000 fresh
challenges and 32,000 hidden cases in the macOS development engine. It did not
need a failed evaluation followed by private-feedback-driven revisions.

| Evidence | Value |
| --- | --- |
| Solver SHA-256 | `ae058fd2627cf7f2491960cfb6fc9414bcb1f93fe4fc0dbd6e917beebb0d6cbb` |
| Fixture SHA-256 | `42f4ef9a2dbe9d9177f01e22a9538835da4ffca7b5593b6a23ef0981fba8497d` |
| Three-stage challenges | 252 / 252 passed |
| Four-stage challenges | 234 / 234 passed |
| Five-stage challenges | 265 / 265 passed |
| Six-stage challenges | 249 / 249 passed |
| Model calls during solving | Zero in the source-reviewed included solver |

The obsolete ten-family solver passed 0/1,000, failing to recognize the grammar
before any worker execution. These are independent fresh-key samples rather
than a paired comparison on the same challenges. The adaptive script is 10,930
bytes of Python using only the standard library. Its development took one short
agent programming session; no controlled human-effort or monetary comparison
was measured. The [local control reports](results/macos-composition-control.json)
retain the exact sample and script hashes.

This local run uses the explicitly unsandboxed compatibility worker. Linux
isolation and runtime recovery are tested separately.

## Strict Linux rerun

[CI run 39545223464](https://github.com/KID-joker/coggate/actions/runs/39545223464)
completed successfully for commit
`201d25d6459fbfebc7ba0be0f077c0a753577d8c`. The unchanged frozen adaptive
solver again passed **1,000/1,000** new composition challenges and all 32,000
hidden cases through the strict Linux release worker.

The 3/4/5/6-stage strata had 236/252/252/260 challenges respectively; every
stratum passed completely. The new fixture hash was
`6b7af39d34987040ad31be13477f091b9830ed0dbb8c051e0337365defd7d0e3`.
The original ten-family baseline also passed 1,000/1,000 on a separate fresh
sample. [Complete Linux evidence](results/linux-composition.json) includes
the compiler, platform, per-family results, hashes and observed cold timings.

The same CI run passed malicious recursion, retained heap growth, infinite
serialization getters and deeply nested source tests. Each malicious request
was followed by a successful reference request through the same Runtime,
checking that process cleanup and admission capacity recovered.

The default Rust host increment remained 347,160 bytes. Development composition
code is excluded from that production build. These successful engineering
checks do not alter the failed attack-resistance result.

```sh
# macOS compatibility experiment
python3 scripts/evaluate_solver.py --composition --engine-only --samples 1000

# Linux reference correctness and adaptive attack
cargo run -p coggate --example demo --features dev-tools -- --composition-run 100
python3 scripts/evaluate_solver.py --composition --samples 1000

# Obsolete-solver control; failure here is not evidence of defense
python3 scripts/evaluate_solver.py --composition \
  --solver scripts/offline_solver.py --samples 1000
```

## Decision

The composed grammar still fails the anti-solver hypothesis. Random combinations,
synonyms and temporary meanings increased the parser's implementation work but
did not provide a useful admission barrier against this adaptive attack.
Rejecting an obsolete solver alone would have produced a misleading conclusion.

Do not promote this experiment, extend template variation as the sole defense,
or expand five-language packaging on the premise that the mechanism is secure.
The tested Rust core and Linux worker remain useful infrastructure, but a new
mechanism needs a separate falsifiable hypothesis and an adaptive evaluation.

These are two small, source-visible experiments, not a proof that every possible
mechanism is impossible. No model success benchmark, two-team five-day attack
exercise or 24-hour fuzz campaign has been completed. The measured 347,160-byte
increment belongs to the default Rust/Linux baseline, not a production package
containing this development experiment.

## Why the complete offline solver survives

The attack is a small compiler: public declarations become a local symbol table,
aliases become Boolean expressions, and numbered operations become a guarded
execution plan. A fixed JavaScript interpreter executes that plan on each new
input. It does not need to predict tomorrow's challenge or recover the hidden
test seed. The current public prompt supplies the necessary semantics.

| Proposed obstacle | How an adapted script handles it |
| --- | --- |
| Fresh names and different meanings for the same word | Rebuild the symbol table for each prompt |
| Synonyms and more alias levels | Parse the public grammar and resolve references |
| Secret factors and many random combinations | Compile the newly issued instance |
| Independent private tests | Execute the correct semantics on arbitrary inputs |
| Unspecified operation order, constrained by examples | Search candidate orders against public examples |

The last row is a different hypothesis and now has its own falsifiable pilot.
Program synthesis from examples already has non-model approaches:
[FlashFill++](https://www.microsoft.com/en-us/research/publication/flashfill-scaling-programming-by-example-by-cutting-to-the-chase/)
combines enumeration and deductive search, while the
[SemGuS toolkit](https://arxiv.org/abs/2406.01792) includes enumerative solvers for
user-defined syntax and semantics. These works motivate testing an adapted
synthesizer; they do not establish the cost of solving this particular generator.

## Public-example order synthesis pilot

The development-only `order-synthesis/v1` generator presents four unordered
operation cards with complete semantics. A solution must apply each card once,
in one fixed order for every input. Public input/output examples must uniquely
identify one of the 24 card-ID permutations and contain at least two different
outputs. Exchangeable cards are rejected even when multiple orders compute the
same function. The card labels and display order reveal no execution ordering.

Issuance tries at most 64 candidates and 32 public probes per candidate. Only
after public-only uniqueness succeeds does a separate random stream create
32 distinct private inputs, excluding every public-example input, with at most
128 draws. Exhaustion is an explicit availability failure, never a defense
success or a fallback to an ambiguous challenge. Private tests do not decide
which interpretation the user was supposed to choose.

`scripts/order_solver.py` adapts the original parser and JavaScript interpreter.
Its added Python simulator enumerates all 24 orders and checks the public
examples, then emits code for the unique surviving plan. The solver is frozen
before fresh keys and challenges are generated and receives only allowlisted
public fields. It uses no model during solving; that statement is based on
source review, not on the solver's self-reported `model_calls` field.

Two controls share the same private fixtures: the previous composition parser,
which cannot read card syntax, and an exact public-example lookup program,
which returns `null` for all unseen inputs. Their failure alone is not evidence
of resistance to an adapted solver.

The first macOS engine-only batch passed **200/200** challenges and all 6,400
private cases, with no issuance failures. The solver's diagnostic mean search
time was about 0.50 ms; the trusted evaluator measured about 46 ms per cold
Python process including startup. Those diagnostics are not a warm gateway
latency benchmark, and macOS engine-only testing does not validate isolation.
The strict Linux rerun below confirms the same outcome.

```sh
# Run on Linux without --engine-only; add it for macOS compatibility testing.
# PRIVATE contains judging data and must never be published.
python3 scripts/evaluate_solver.py --order-synthesis --samples 1000 \
  --retain-private-dir artifacts/order-PRIVATE > artifacts/order-solver.json
python3 scripts/evaluate_solver.py --order-synthesis --samples 1000 \
  --fixtures artifacts/order-PRIVATE/private-fixtures.jsonl \
  --solver scripts/composition_solver.py > artifacts/order-legacy.json
python3 scripts/evaluate_solver.py --order-synthesis --samples 1000 \
  --fixtures artifacts/order-PRIVATE/private-fixtures.jsonl \
  --solver-arg=--examples-only > artifacts/order-lookup.json
```

The paired controls correctly label their supplied fixtures' freshness as
unverified in isolation; the matching fixture hash links them to the fresh
adaptive run. CI records both solver hashes before generating that shared batch.
Uploaded artifacts explicitly exclude private fixture directories. Internal
parse/search/code-generation timings are untrusted diagnostics; pass/fail,
stdout source bytes and subprocess timing come from the evaluator.
The attacker Python runner is not an OS, filesystem or network sandbox.
The included frozen source was reviewed to use only stdin, but the evaluator
does not enforce that access policy for arbitrary replacement solvers.

### Strict Linux paired results

The `order_synthesis` job in
[run 39562720878](https://github.com/KID-joker/coggate/actions/runs/39562720878/job/119097538889)
succeeded for commit `750a24f805d85a6322ec98ebb502d2665d226780`.
The strict release worker checked all three solvers on the same 1,000 newly
issued challenges. There were no issuance failures, and the separate reference
control passed 100/100.

| Frozen attack | Passed | Failure category |
| --- | --- | --- |
| Adapted parser plus complete order enumeration | 1,000 / 1,000 | None |
| Previous ordered-composition parser | 0 / 1,000 | Unsupported public syntax, before worker execution |
| Public-example lookup only | 0 / 1,000 | Wrong answer on unseen private inputs |

The adapted solver passed all 32,000 private cases. Every challenge had one
surviving permutation out of 24; public example counts ranged from 2 to 8.
Its source was 23,611 bytes, including self-tests, and emitted JavaScript averaged
1,930 bytes. It reused the original parser and interpreter; no independent
person-day or model-cost comparison is claimed.

| Observed cost | Mean | p95 |
| --- | --- | --- |
| Solver process, including cold Python startup | 29.059 ms | 30.324 ms |
| Strict worker process, compile, 32 cases and IPC | 13.387 ms | 14.496 ms |
| Debug-build challenge issuance | 17.840 ms | 47.912 ms |
| Internal search diagnostics, solver-reported | 0.727 ms | 1.643 ms |

The first three rows are evaluator measurements; the last is untrusted internal
instrumentation, useful for diagnosis only. Neither cold worker timing nor
debug issuance is the formal warmed gateway latency gate. Candidate search
averaged 6.08 generated tasks and 1,472 candidate/example evaluations per issued
challenge; the attacker averaged 42.809 public-example evaluations. Different
builds and implementations prevent a direct production speed ratio.

[Complete public evidence](results/linux-order-synthesis.json) includes exact
hashes, platform, failure categories and costs. The artifact ZIP SHA-256 was
verified against GitHub's metadata:
`c7e6cffef78b47f63637d047f29cfb9db324fe348a83f5bc1d52790760ddd905`.
The adapted solver SHA-256 was
`47e76c5c0fc7249a0dd15be80648d1767f53a030dd90bdd61325ea8e3f256011`;
the shared private fixture hash was
`16714ef894c5cd3f27729a006d499d9f24fe1514ac34c8bfc36af67a0145e8d5`.
Only the hash, not the private fixtures, is published.

Both jobs in that workflow completed successfully. The existing regression job
passed 57 Rust tests, formatting, lint, strict isolation and the frozen attack
checks. Its latest default and screened Rust-host increments were 347,664 and
371,536 bytes respectively; neither measures a production order-synthesis
package. The evidence file also retains that job's full public JSON reports.
Some older screened batches exhausted one issuance out of 1,000 attempts;
those remain availability failures in their own reports. They are separate
from the new order-synthesis batch's zero issuance failures.

The pilot rejects the claim that hiding a four-card order forces model
use. It adds a small finite search, not a measured model advantage. Increasing
the number of cards alone also increases the issuer's uniqueness search, and
does not establish favorable attacker/defender cost. No controlled model
baseline or adaptation labor comparison has been measured. This failed pilot
stays development-only; its complete production size has not been qualified.

### Criteria for a subsequent experiment

A different hypothesis would ask for a small program that satisfies a complete
functional specification under a public operation budget, with operation
selection, operand connections and intermediate reuse left unknown. A finite
8-bit domain permits exhaustive correctness checking. The issuer could generate
a legal program and publish its 256-entry truth table without using a model or
solving a synthesis problem itself.

This is an unimplemented candidate, not an adopted defense. Without an enforced
syntax and operation budget, a table-lookup script solves it immediately. Adding
that enforcement would require a restricted JavaScript parser and a new size
measurement, and would narrow the currently accepted submission language.

The attack baseline must also change. Constraint-based loop-free synthesis is
an established non-model technique, as demonstrated by
[Brahma](https://www.microsoft.com/en-us/research/publication/synthesis-loop-free-programs/).
[Souper](https://github.com/google/souper) uses SMT in program optimization.
Our inference is that a new pilot must include enumerative search with semantic
deduplication and a constraint solver, not just adapt this 24-order script.
Neither source establishes a model advantage for the proposed tasks.

Reject the candidate if these adapted methods solve it cheaply, if increasing
difficulty loses the required model success rate, or if complete runtime size
and verification cost fail the frozen product gates. Do not claim progress from
a larger theoretical search space without that comparison.
