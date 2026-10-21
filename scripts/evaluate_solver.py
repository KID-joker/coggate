#!/usr/bin/env python3
"""Evaluate a frozen public-only solver against trusted development fixtures.

By default: hash and copy the solver, THEN invoke the demo's --dump mode, which
uses a fresh OS-random server key, and run the strict Linux worker. An explicit
--engine-only uses the UNSANDBOXED compatibility binary, and makes NO OS
isolation claim. No expected value or reference source enters either process.

This is a small baseline attack experiment, not the two independent five-day
red-team campaigns or a model benchmark required by the product specification.
"""

import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCE_LIMIT = 65_536
CASE_LIMIT = 32
INPUT_LIMIT = 4_096
OUTPUT_LIMIT = 65_536
STATUS_NAMES = {0: "ok", 1: "submission_failure", 2: "resource_limit", 3: "internal_failure"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pack_u32(value):
    return struct.pack(">I", value)


def request(source, inputs):
    source = source.encode("utf-8")
    if not 0 < len(source) <= SOURCE_LIMIT:
        raise ValueError("source size outside worker limits")
    if not 0 < len(inputs) <= CASE_LIMIT:
        raise ValueError("case count outside worker limits")
    pieces = [b"CGW1", pack_u32(len(source)), source, pack_u32(len(inputs))]
    for value in inputs:
        data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if not 0 < len(data) <= INPUT_LIMIT:
            raise ValueError("input size outside worker limits")
        pieces.extend((pack_u32(len(data)), data))
    return b"".join(pieces)


def response(data, expected_count, engine_only=False):
    magic = b"CGE1" if engine_only else b"CGR1"
    if len(data) < 8 or data[:4] != magic:
        raise ValueError("invalid response header")
    count = struct.unpack_from(">I", data, 4)[0]
    if count != expected_count:
        raise ValueError("response case count mismatch")
    cursor = 8
    result = []
    for _ in range(count):
        if cursor + 5 > len(data):
            raise ValueError("truncated response")
        status, length = struct.unpack_from(">BI", data, cursor)
        cursor += 5
        if status not in STATUS_NAMES or length > OUTPUT_LIMIT or cursor + length > len(data):
            raise ValueError("invalid response item")
        result.append((status, data[cursor:cursor + length].decode("utf-8")))
        cursor += length
    if cursor != len(data):
        raise ValueError("extra response bytes")
    return result


def reject_constant(value):
    raise ValueError("non-JSON numeric constant: " + value)


def result_matches(actual, expected):
    # bool is a Python int subclass but is not an integer submission result.
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            result_matches(a, e) for a, e in zip(actual, expected)
        )
    if type(expected) is int:
        return type(actual) in (int, float) and math.isfinite(actual) and actual == expected
    raise ValueError("unexpected fixture result type")


def timing_summary(values):
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "total_ms": round(sum(values), 3),
        "mean_ms": round(sum(values) / len(values), 3),
        "p50_ms": round(ordered[max(0, math.ceil(len(values) * 0.50) - 1)], 3),
        "p95_ms": round(ordered[max(0, math.ceil(len(values) * 0.95) - 1)], 3),
        "p99_ms": round(ordered[max(0, math.ceil(len(values) * 0.99) - 1)], 3),
        "max_ms": round(ordered[-1], 3),
    }


def worker_path(arguments):
    name = "coggate-engine-test-UNSANDBOXED" if arguments.engine_only else "coggate-worker"
    if arguments.worker:
        candidate = Path(arguments.worker).resolve()
        if not candidate.is_file():
            raise ValueError("worker does not exist: " + str(candidate))
        if "UNSANDBOXED" in candidate.name and not arguments.engine_only:
            raise ValueError("unsandboxed worker requires explicit --engine-only")
        return candidate
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    candidates = [p for p in target.glob("debug/build/coggate-worker-*/out/" + name) if p.is_file()]
    if not candidates:
        raise ValueError("worker not found; build the workspace or supply --worker")
    return max(candidates, key=lambda item: item.stat().st_mtime_ns).resolve()


def check_isolation(worker):
    completed = subprocess.run(
        [str(worker), "--isolation-self-test"], input=b"", stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=3, env={},
    )
    items = response(completed.stdout, 1)
    if completed.returncode != 0 or items != [(0, "isolated")]:
        raise ValueError("strict worker isolation self-test failed")


def public_challenge(fixture):
    public = fixture.get("public")
    if not isinstance(public, dict) or not isinstance(public.get("prompt"), str):
        raise ValueError("fixture missing public challenge")
    # Explicit allowlist: no fixture fields can reach the solver by accident.
    return {key: public[key] for key in ("id", "scope", "expires_at", "max_attempts", "prompt") if key in public}


def fixture_data(arguments):
    if arguments.fixtures:
        return Path(arguments.fixtures).read_bytes(), "supplied_fixtures_freshness_unverified"
    completed = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "coggate", "--example", "demo",
         "--features", "dev-tools", "--", "--dump", str(arguments.samples)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
    )
    if completed.returncode != 0:
        raise ValueError("fixture generation failed: " + completed.stderr.decode("utf-8", errors="replace")[-2000:])
    return completed.stdout, "fresh_key_generated_after_solver_snapshot"


def evaluate(arguments):
    started = time.perf_counter()
    solver_bytes = Path(arguments.solver).read_bytes()
    solver_sha = digest(solver_bytes)
    if platform.system() != "Linux" and not arguments.engine_only:
        raise ValueError("strict OS isolation evaluation requires Linux; --engine-only explicitly runs UNSANDBOXED compatibility testing")
    report = {
        "schema_version": 1,
        "experiment": "public_grammar_white_box_baseline",
        "formal_red_team_complete": False,
        "solver_sha256": solver_sha,
        "solver_input": "allowlisted_public_challenge_only",
        "model_calls_during_solving": (
            0 if Path(arguments.solver).resolve() == ROOT / "scripts/offline_solver.py" else None
        ),
        "model_use_audit": "included_solver_source_review_only_not_enforced_by_evaluator",
        "submissions_per_challenge": 1,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "os_isolation": "NOT_VALIDATED_UNSANDBOXED_ENGINE_ONLY" if arguments.engine_only else "strict_worker_self_test",
        "sample_count": 0,
        "passed": 0,
        "case_count": 0,
    }
    statuses = collections.Counter()
    family_results = {}
    failures = []
    solver_times, worker_times = [], []
    with tempfile.TemporaryDirectory(prefix="coggate-offline-solver-") as temporary:
        frozen_solver = Path(temporary) / "offline_solver.py"
        frozen_solver.write_bytes(solver_bytes)
        # This order is intentional: all fresh random keys and fixtures are
        # created after the executable attack source has been frozen.
        data, provenance = fixture_data(arguments)
        report["fixture_provenance"] = provenance
        report["fixtures_sha256"] = digest(data)
        worker = worker_path(arguments)
        report["worker"] = str(worker)
        report["worker_sha256"] = digest(worker.read_bytes())
        if not arguments.engine_only:
            check_isolation(worker)
        for line_number, line in enumerate(data.splitlines(), 1):
            if not line.strip():
                continue
            if report["sample_count"] >= arguments.samples:
                break
            fixture = json.loads(line)
            public = public_challenge(fixture)
            cases = fixture.get("cases")
            if not isinstance(cases, list) or not 0 < len(cases) <= CASE_LIMIT:
                raise ValueError("fixture has invalid cases")
            # Never inspect reference_source. Only this trusted evaluator sees
            # cases; the source-generation subprocess receives public JSON only.
            inputs = [case["input"] for case in cases]
            expected = [case["expected"] for case in cases]
            report["sample_count"] += 1
            report["case_count"] += len(cases)
            outcome, family, detail = "solver_failure", "unrecognized", ""
            before = time.perf_counter()
            try:
                generated = subprocess.run(
                    [sys.executable, "-I", str(frozen_solver)],
                    input=json.dumps(public).encode("utf-8"),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
                    cwd=temporary, env={"PATH": os.defpath, "LC_ALL": "C"},
                )
                solver_times.append((time.perf_counter() - before) * 1000)
                if generated.returncode:
                    detail = generated.stderr.decode("utf-8", errors="replace")[:300]
                else:
                    source = generated.stdout.decode("utf-8")
                    first_line = source.splitlines()[0] if source else ""
                    if first_line.startswith("// public-grammar family: "):
                        family = first_line.split(": ", 1)[1]
                    payload = request(source, inputs)
                    before = time.perf_counter()
                    executed = subprocess.run(
                        [str(worker)], input=payload, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=2, env={},
                    )
                    worker_times.append((time.perf_counter() - before) * 1000)
                    if executed.returncode:
                        outcome, detail = "worker_exit_failure", str(executed.returncode)
                    else:
                        results = response(executed.stdout, len(cases), arguments.engine_only)
                        error = next(((status, message) for status, message in results if status), None)
                        if error:
                            outcome, detail = STATUS_NAMES[error[0]], error[1][:300]
                        else:
                            actual = [json.loads(value, parse_constant=reject_constant) for _, value in results]
                            if all(result_matches(a, e) for a, e in zip(actual, expected)):
                                outcome = "passed"
                            else:
                                outcome = "wrong_answer"
            except subprocess.TimeoutExpired:
                outcome, detail = "process_timeout", "solver or worker exceeded evaluator deadline"
            except (ValueError, UnicodeError, KeyError) as error:
                outcome, detail = "protocol_failure", str(error)[:300]
            statuses[outcome] += 1
            family_report = family_results.setdefault(family, {"sample_count": 0, "passed": 0})
            family_report["sample_count"] += 1
            if outcome == "passed":
                report["passed"] += 1
                family_report["passed"] += 1
            elif len(failures) < 20:
                failures.append({"fixture_line": line_number, "family": family, "status": outcome, "detail": detail})
    if not report["sample_count"]:
        raise ValueError("no fixture samples")
    for family_report in family_results.values():
        family_report["pass_rate"] = family_report["passed"] / family_report["sample_count"]
    report["pass_rate"] = report["passed"] / report["sample_count"]
    report["by_family"] = dict(sorted(family_results.items()))
    report["statuses"] = dict(statuses)
    report["failure_examples"] = failures
    report["runtime_cost"] = {
        "solver_process_including_python_startup": timing_summary(solver_times),
        "worker_process_including_startup_compile_execute_ipc": timing_summary(worker_times),
        "evaluation_total_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    report["conclusion"] = (
        "current_generator_is_solved_by_a_non_model_specialized_script"
        if report["pass_rate"] == 1.0
        else "attack_success_observed" if report["passed"] else "no_success_in_this_sample"
    )
    report["limitations"] = [
        "One source-visible specialized solver; not two independent five-day attack teams.",
        "Hidden-case pass rate does not prove correctness on all possible inputs.",
        "Direct worker evaluation bypasses gateway admission and challenge lifecycle handling.",
        "No LLM baseline or formal confidence-bound acceptance result is included.",
        "Timing includes cold subprocess startup and is not the warmed-worker performance gate.",
    ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--solver", default=str(ROOT / "scripts/offline_solver.py"))
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--fixtures", help="trusted JSONL fixture file; fresh-key provenance is then unverified")
    parser.add_argument("--worker", help="worker executable; default is the latest debug native build")
    parser.add_argument("--engine-only", action="store_true", help="explicitly use UNSANDBOXED engine compatibility mode")
    arguments = parser.parse_args()
    if not 1 <= arguments.samples <= 100_000:
        parser.error("--samples must be in 1..100000")
    try:
        report = evaluate(arguments)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "evaluation_error", "error": str(error),
                          "os_isolation": "not_validated"}, indent=2))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
