# Frozen initial acceptance gates

These are design targets agreed before implementation, not achieved claims.
Every report must identify commit, compiler, CPU, kernel, architecture, input
profile and enabled features. Do not lower a threshold after a test to call it
a success; design revisions require an explicit new acceptance version.

| Area | Gate |
| --- | --- |
| Complete runtime size increment | <=512,000 uncompressed bytes per supported language/platform, counting all mandatory newly shipped files |
| Model evaluation | Three different model families, pinned versions and parameters, >=1,000 fresh challenges each |
| Model success | One-sided exact 95% lower bound >=95% on first attempt and >=99% within two submissions |
| Offline-developed solver | >=10,000 fresh challenge sessions per frozen solver; one-sided exact 95% upper bound <=0.1% overall and <=1% in each task family |
| Attack-development budget | At least two independent solver implementations, five person-days each; model-assisted development and unlimited local generation permitted; record usage |
| Local verification latency | Fixed Linux x86_64 reference machine, warm worker, one request at a time, 32 private cases: p95 <=50 ms, p99 <=100 ms |
| Input/memory | Source <=64 KiB, test input <=4 KiB, worker peak RSS <=32 MiB |
| Execution budget | 200 ms CPU and 500 ms wall time per submission, from parsing through judging, with termination/reaping |
| Isolation/stability | All fixed malicious cases pass; >=24 hours fuzzing; reproducible host crash, unauthorized access, cross-request leak or incorrect acceptance blocks release |

## Statistical and adversarial rules

The sampling unit is a complete challenge session, not each submission. Report
model, family, difficulty and namespace strata. Allocate enough samples per
family to evaluate its confidence bound. Report skipped challenges as well as
attempted ones: a solver that keeps refreshing until it finds easy tasks is an
attack, not a low score.

Freeze/hash solver code before making evaluation keys and nonces. The attacker
knows generator source and algorithms. Only current keys/private tests are
withheld; the complete public problem is available during solving. No model
inference is allowed during formal solving. Source inspection of one Python
script is useful evidence but does not constitute enforcement of this rule for
arbitrary supplied solvers.

Any discovered reusable cheap high-success method blocks the mechanism even
when aggregate averages look acceptable. Measure successful-admission cost,
challenge refresh count and observed latency. Per-challenge success does not
bound an attacker allowed unlimited retries.

## Honest milestone separation

- Native language tests on macOS do not validate Linux isolation.
- A fail-closed non-Linux worker stub does not measure a deployable engine.
- Core/unit tests do not establish attack resistance.
- A small baseline attack is enough to reject a broken generator but is not the
  complete two-team, five-day adversarial acceptance exercise.
- Cold per-request process measurements do not meet the warm-worker latency gate.
- A Rust size result does not qualify Go/Java/Python/Node.js packages.
- A CI success means its named engineering checks passed, not these entire gates.

No paid model evaluation is initiated by this repository's tests or workflows.
The model baseline, full attack exercise and long fuzz campaign remain explicit
future work. No production access decision should rely on the baseline generator.
