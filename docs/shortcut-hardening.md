# Shortcut resistance and discriminating hidden tests

This iteration addresses two observed weaknesses: composition challenges that
accept a constant or a program that ignores conditions, and baseline hidden
tests that miss inclusive comparison boundaries. It keeps gateway generation
and verification entirely local and model-free.

It does **not** introduce a new source of semantic uncertainty for a correct
public-grammar solver. Improving these weaknesses does not qualify the SDK as
an agent detector or satisfy the product's offline-solver gate.

## Default generator boundary fixes

Adjacent-difference tasks now include both signs of `limit - 1`, `limit` and
`limit + 1` as two-element inputs. Window tasks include one complete window
whose sum is exactly `threshold - 1`, `threshold` or `threshold + 1`.

The suite still contains 32 cases. Targeted inputs replace some random cases;
all existing fixed cases remain. Public semantics and correct solutions are
unchanged. `scripts/check_boundary_mutants.py` freezes a separate copy of the
baseline solver with two deliberately incorrect strict comparisons, then
generates fresh challenges. The two affected families must fail with wrong
answers, while the other eight families must pass. Missing families, execution
errors or unverified fixture freshness fail this regression check.

## Development-only screened composition

`Engine::issue_screened_composition` preserves the old public composition
language and reference semantics. The original `issue_composition` remains
available as the before-control. The new experiment has separate HMAC domains
(`composition-screened/v2/*`) for problem selection, wording, hidden inputs and
challenge IDs.

For each candidate, the generator builds at most 128 distinct input probes,
using the original cases, small integer singletons and bounded random arrays.
It looks for inputs that distinguish the reference behavior from:

- A constant output and 15 simple array transformations, using the public
  output shape. Scalar tasks also face sums of those transformations.
- Deleting each individual stage.
- Executing each conditional stage unconditionally.
- Executing all conditional stages unconditionally together.
- Evaluating every condition on the original input while applying operations
  to the current sequence.

A candidate without every required witness is rejected. This can mean a truly
redundant task or merely an unsuccessful finite witness search; the code does
not claim to prove equivalence.

The generator uses greedy coverage to retain the distinguishing inputs inside
the final 32-case budget. Empty input, positive/negative input extremes and a
64-element alternating extreme input are mandatory. It fills remaining slots
and shuffles the final suite. The selected cases, rather than just the larger
probe pool, must reject every screened shortcut and mutation.

Generation tries at most 64 candidates and returns `GenerationExhausted` if
none qualifies. It never falls back to an unscreened challenge. Development
statistics record candidate rejections, evaluation counts and witness counts;
they are not part of the public challenge.

The evaluator records an exhausted attempt as an issuance failure and continues
the remaining requested issuance attempts. It reports issued challenges and
issuance failures separately. Solver pass rate uses only issued challenges;
generation failures must never be counted as blocked attacks. Generation timing
includes exhausted attempts. A zero-issuance run is an evaluation failure.

This is a task-distribution change, not just a hidden-test change. Requiring
every stage to affect an observable result can favor shorter tasks and particular
operation combinations. Report these effects alongside issuance cost.

The original-input guard check was added after an independent development
probe of the first screening version. That previously unscreened mutation
passed 12 of 100 issued challenges; additional inputs demonstrated incorrect
results in four of those passes. The other eight were not distinguished within
1,024 additional probes and must not be labelled incorrect. The original fixture
batch was not retained, so these exploratory figures cannot be replayed
instance-for-instance. The final CLI variant and fresh Linux regression provide
the repeatable check. Once added to the screening bank, this variant is no
longer a held-out attack.

## Reproducible attack comparison

`scripts/shortcut_solver.py` reads only the public return-type sentence and
defaults to returning `[]` or `0`. `scripts/composition_solver.py --ignore-guards`
parses the full public specification but deliberately executes all stages.
Its normal mode retains the complete, correct parser as the stronger control.
The `--original-input-guards` mode separately exercises the timing of condition
evaluation.

For each run, the evaluator copies and hashes the solver before creating fresh
keys and instances. Arguments are recorded. Only the allowlisted public fields
reach the solver; screening statistics and private cases stay with the trusted
evaluator. The before/after runs use independent fresh samples, not paired
instances.

```sh
# Linux, with the exact built worker path; omit --worker for a debug build.
python3 scripts/check_boundary_mutants.py --samples 1000 --worker /path/to/coggate-worker
python3 scripts/evaluate_solver.py --composition \
  --solver scripts/shortcut_solver.py --samples 1000
python3 scripts/evaluate_solver.py --screened-composition \
  --solver scripts/shortcut_solver.py --samples 1000
python3 scripts/evaluate_solver.py --composition \
  --solver-arg=--ignore-guards --samples 1000
python3 scripts/evaluate_solver.py --screened-composition \
  --solver-arg=--ignore-guards --samples 1000
python3 scripts/evaluate_solver.py --composition \
  --solver-arg=--original-input-guards --samples 1000
python3 scripts/evaluate_solver.py --screened-composition \
  --solver-arg=--original-input-guards --samples 1000
python3 scripts/evaluate_solver.py --screened-composition --samples 1000
```

On macOS, `--engine-only` explicitly selects the unsandboxed compatibility
worker and makes no Linux isolation claim.

The CI regression requires the three screened shortcut attacks to fail specifically
with wrong answers and the full adaptive solver to keep passing as a correctness
control. Its success therefore does not imply successful anti-agent
discrimination. Zero successes in 1,000 shortcut samples is also insufficient
for the frozen formal 0.1% confidence-bound gate.

## Scope and remaining limitations

Only the small boundary-input fix changes the default runtime. The screened
generator and its development statistics remain behind `dev-tools`. The default
host size measurement does not qualify a runtime that includes screening.
Production promotion would require a separate complete size measurement,
issuance-cost limits and a successful adaptive attack evaluation.

The current screening bank is public and finite. It cannot detect every partial
implementation, and killing its own chosen mutations is a regression property,
not independent evidence of general script resistance. Model success rates,
the two-team attack exercise and the long fuzz campaign remain unmeasured.

For background, [EvalPlus](https://arxiv.org/abs/2305.01210) studies how stronger
test inputs reveal incorrect generated programs. This experiment uses only
local deterministic evaluation and randomized probing; it does not import
EvalPlus's model-assisted input generation or claim its results.
