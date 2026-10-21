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
