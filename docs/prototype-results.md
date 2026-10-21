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
| Linux kernel isolation | Subsequently passed fixed checks; see Linux run below |
| Complete Linux size increment | Subsequently measured 347,160 bytes; see Linux run below |

The development worker does not validate Linux OS isolation and cannot be used
by the production runtime. These are cold subprocess measurements, not the
warm-worker performance gate. No model baseline, 24-hour fuzz campaign or full
two-team attack exercise has been completed.

## Linux engineering result

[CI run 39544320369](https://github.com/KID-joker/coggate/actions/runs/39544320369)
tested commit `dc27cc29ae06157fd2a43b2ea90e76e2335143a1` on Ubuntu 24.04,
x86_64, glibc 2.39, kernel 7.0.0-1017-azure and AMD EPYC 7763. Rust was 1.99.1;
the C compiler was GCC 13.3.0.

The complete release increment was:

```text
435,992 integrated host
- 283,600 baseline host
+ 194,768 mandatory worker
= 347,160 bytes, below 512,000
```

The build used the same release profile for both hosts and did not enable
development features. This qualifies only the measured Rust/Linux x86_64
prototype. It does not qualify other architectures or language bindings.

Core, concurrency, lifecycle, framing, engine, and Linux isolation tests passed.
The independent solver then passed another 1,000/1,000 fresh challenges
(32,000 hidden cases) using the strict release worker. Its cold worker p95 was
7.131 ms and p99 was 7.419 ms; these are observations, not the warmed-worker
latency acceptance result.

The [machine-readable evidence](results/linux-rust-baseline.json) includes
compiler details, binary/solver/fixture hashes, per-family results and timing.
Passing the fixed isolation tests does not replace the planned fuzz campaign
or establish that the native engine cannot contain vulnerabilities.

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
