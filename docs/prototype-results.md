# First prototype experiment

The first baseline is **not suitable for admission decisions**. An independent
Python solver reads the public prompt, selects an algorithm and emits JavaScript
without calling a model. On 2026-10-21 it passed all 1,000 fresh challenges and
their 32,000 hidden cases across all ten task families.

The solver source was frozen before the evaluation key and challenges were
generated. The solver received only allowlisted public challenge fields.

| Evidence | Result |
| --- | --- |
| Platform | macOS 15.3.1, arm64; explicit development engine |
| Solver SHA-256 | `c73aa271393fdc9c886754136bb4e2d56dbf6cfb3c507c7cc733439886f99389` |
| Private fixture SHA-256 | `65cb59bc4a996a5639fa8eedd532c9aaf2908e6e4125ee4b0e72115fa90b981a` |
| Success | 1,000 / 1,000 challenges, one submission each |
| Model calls while solving | Zero in the included, source-reviewed solver |
| Core, store, framing and engine tests | 27 passed locally |
| Formatting and Clippy | Passed locally |
| Linux kernel isolation | Pending actual Linux execution |
| Complete Linux size increment | Pending actual Linux release build |

The development worker does not validate Linux OS isolation and cannot be used
by the production runtime. These are cold subprocess measurements, not the
warm-worker performance gate. No model baseline, 24-hour fuzz campaign or full
two-team attack exercise has been completed.

Reproduce the compatibility experiment with:

```sh
python3 scripts/evaluate_solver.py --engine-only --samples 1000
```

Each run makes new secret material and fixtures; hashes and family counts will
change. On Linux, omit `--engine-only` to exercise the strict worker. The Linux
workflow also measures the entire Rust host increment plus required worker.

The result rejects this finite public grammar as an effective barrier to a
specialized solver. It does not establish that all future challenge mechanisms
are impossible. More template names, secrets or paraphrases alone do not
address this attack. The next mechanism experiment must be evaluated against
an adaptive solver before expanding the five-language packaging work.
