# v0.1 product and security contract

## Goal

Raise the cost of automation that answers fresh challenges without model
inference during the challenge. The principal adversary may use models during
development to build a reusable solver. Source code and generator structure
are public. A correct program demonstrates tested behavior, not its provenance.

Five gateway-side language integrations remain the intended delivery scope:
Rust, Go, Java, Python and server-side JavaScript. A single JavaScript subset is
the submission language. Browser-side verification is not a trust boundary.

## Runtime dependency boundary

The gateway SDK must complete challenge generation, wording, hidden-test
construction, sandboxed source execution and result comparison using local
algorithms. None of these steps may require local or remote model inference,
model weights, model credentials or an external model service. This applies to
both issuance and verification, including any future challenge mechanism.

A visiting agent may use its own model to solve the public challenge. Model use
in development and separately run evaluations is also permitted; it must not
become a gateway runtime dependency. The host remains responsible for granting
access after an SDK result.

This dependency requirement is separate from attack resistance. A model-free
gateway does not establish that a successful visitor used a model. Any candidate
generator must still pass the frozen model and offline-solver acceptance gates.
The current baseline and composition experiment have failed the solver gate.

## Trusted and untrusted data

Trusted: host configuration, namespace assignment, secret key, state store,
reference semantics, packaged worker executable and upstream engine dependency.
Untrusted: submitted source and any result or failure message from the worker.

The SDK accepts a 32-byte secret key, a bounded namespace and an optional bounded
business factor. It generates a new 32-byte OS-random nonce. Versioned,
length-delimited HMAC-SHA-256 inputs derive independent problem, wording, hidden
test and challenge-ID seeds. Factors are resolved at issuance, never re-read
from changing business data at verification.

The public challenge includes all semantics necessary to solve it, but no
secret, factor bytes, test seed, private examples or reference implementation.
Its ID is not a seed from which private state is reconstructed.

Secrets prevent advance prediction of particular instances. They do not stop
a parser from learning the public task grammar. More random combinations do
not by themselves establish more resistance.

## Lifecycle and responsibilities

The host owns HTTP routing, client identity, challenge issuance quotas and any
authorization/token after success. Scope is supplied by trusted host logic.

The SDK owns task generation, finite judging, resource bounds and the lifecycle
contract. The in-memory store has a configurable finite capacity:

1. Issue: retain the private resolved challenge for 180 seconds.
2. Claim: atomically check scope/expiry/remaining tries and reserve one attempt.
3. While claimed: reject concurrent submissions.
4. Pass: retain a consumed tombstone until expiry.
5. Reject/resource exhaustion/worker failure: spend the attempt.
6. Failure before starting a worker or unsupported platform: refund the attempt.
7. Complete after expiry or with a stale lease: never accept.

There are at most two chargeable execution attempts per challenge. Oversized or malformed outer
requests are rejected before worker startup. The SDK's finite execution capacity
returns Busy before reserving challenge state. Hosts must also rate-limit
challenge creation and retries; continuously requesting new challenges can
defeat a low per-challenge success rate.

A crashed host does not automatically reclaim an in-flight lease. A production
shared adapter must either prove the previous execution is terminated before
recovery or let the challenge expire. The prototype currently implements only
in-memory storage; persistent private-state encoding and remote adapters remain
work, not a claimed implemented capability.

## Worker boundary

Rust sends source and JSON inputs through anonymous pipes. Expected outputs
remain in the parent. The worker initializes kernel isolation before parsing
untrusted source or protocol input.

Linux setup clears the environment, closes descriptors above stdout, refuses
regular-file stdin/stdout, sets no-new-privileges and disables core dumps. A
seccomp filter permits reads only from stdin, writes only to stdout, clocks,
signal return and process exit. It denies opens, networking, exec, process
creation, descriptor duplication, ptrace and memory mappings after startup.

MicroQuickJS has a fixed 2 MiB arena; every case starts a new context. A captured
built-in serializer prevents replacement of global JSON.stringify from changing
the host's output conversion. Its code still has C memory-safety risk: the OS
boundary and the fact that the worker lacks secrets/expected answers are
required, not optional.

Independent native CPU/wall timers and the parent deadline cover parser and
native-library work as well as interpreted loops. A per-request process is used
for the first spike; a prestarted worker pool has not been implemented or
performance-qualified. Running on non-Linux returns Unsupported.

## Wire framing

All lengths use unsigned big-endian u32:

- Request: `CGW1`, source byte length, source, case count, then input length and
  input JSON for each case. EOF is mandatory.
- Response: `CGR1`, count, then status byte, payload length and payload per case.
- Status: 0 JSON result, 1 submission failure, 2 resource limit, 3 worker failure.
- Source: at most 65,536 bytes; input at most 4,096 bytes; at most 32 cases;
  output at most 65,536 bytes per case.

An exit failure, invalid framing, extra/truncated data, wrong count, error status
or mismatch cannot be accepted. No worker-provided boolean can declare a pass.
The development-only executable uses `CGE1`; production never accepts it.

## Current task mechanism

The ten baseline families cover filtered sums, transformed ordering, first/last
deduplication, remainder buckets, conditional prefixes, longest runs, adjacent
differences, windows, stable partitions and symmetric pairs. Integer domains,
empty cases, ties and ordering are specified. Input length is at most 64; values
are within [-10000, 10000]. Outputs remain exactly representable.

This baseline is susceptible to a prompt parser plus code templates. It is an
engineering fixture and adversarial baseline, not evidence that the planned
anti-solver product is viable. A failed attack-resistance gate blocks promoting
this generator to production; changing labels or keys alone does not fix it.
