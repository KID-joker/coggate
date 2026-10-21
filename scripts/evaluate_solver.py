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
METRICS_PREFIX = b"COGGATE_SOLVER_METRICS "
METRICS_STDERR_LIMIT = 65_536
METRICS_LINE_LIMIT = 4_096
METRICS_VALUE_LIMIT = 1_000_000_000_000
METRICS_FIELDS = frozenset({
    "permutations_enumerated", "example_evaluations", "matching_orders",
    "card_count", "public_example_count", "parse_ms", "search_ms",
    "codegen_ms", "source_bytes", "model_calls",
})


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


def numeric_summary(values):
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "total": sum(values),
        "min": ordered[0],
        "max": ordered[-1],
        "mean": round(sum(values) / len(values), 6),
        "p50": ordered[max(0, math.ceil(len(values) * 0.50) - 1)],
        "p95": ordered[max(0, math.ceil(len(values) * 0.95) - 1)],
        "p99": ordered[max(0, math.ceil(len(values) * 0.99) - 1)],
    }


def solver_metrics(stderr):
    """Return optional untrusted diagnostics; malformed metrics never judge code."""
    if len(stderr) > METRICS_STDERR_LIMIT:
        return None, 1
    records = [line[len(METRICS_PREFIX):] for line in stderr.splitlines()
               if line.startswith(METRICS_PREFIX)]
    if not records:
        return None, 0
    if len(records) != 1 or len(records[0]) > METRICS_LINE_LIMIT:
        return None, 1
    try:
        value = json.loads(records[0].decode("utf-8"), parse_constant=reject_constant)
        if not isinstance(value, dict) or value.get("schema") != "coggate-order-solver-v1":
            return None, 1
        metrics = {key: value[key] for key in METRICS_FIELDS if key in value}
        if not metrics or any(
            type(number) not in (int, float)
            or not 0 <= number <= METRICS_VALUE_LIMIT
            or not math.isfinite(number)
            for number in metrics.values()
        ):
            return None, 1
        return metrics, 0
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        return None, 1


def retain_private_snapshot(path, solver_bytes, data, report):
    directory = Path(path).expanduser().resolve()
    if "PRIVATE" not in directory.name:
        raise ValueError("--retain-private-dir directory name must contain PRIVATE")
    # An explicit private directory is separate from the solver's working
    # directory, owner-only, and never overwrites a previous evidence bundle.
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, content in (("frozen-solver.py", solver_bytes), ("private-fixtures.jsonl", data)):
        with (directory / name).open("xb") as handle:
            handle.write(content)
    manifest = {
        "contains_private_judging_data": True,
        "experiment": report["experiment"],
        "solver_sha256": report["solver_sha256"],
        "fixtures_sha256": report["fixtures_sha256"],
        "fixture_provenance": report["fixture_provenance"],
    }
    with (directory / "manifest.json").open("x") as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {"directory": str(directory), "contains_private_judging_data": True}


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
         "--features", "dev-tools", "--",
         "--order-dump" if getattr(arguments, "order_synthesis", False) else
         "--screened-dump" if arguments.screened_composition else (
             "--composition-dump" if arguments.composition else "--dump"
         ),
         str(arguments.samples)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
    )
    if completed.returncode != 0:
        raise ValueError("fixture generation failed: " + completed.stderr.decode("utf-8", errors="replace")[-2000:])
    return completed.stdout, "fresh_key_generated_after_solver_snapshot"


def evaluate(arguments):
    started = time.perf_counter()
    order_synthesis = getattr(arguments, "order_synthesis", False)
    solver_bytes = Path(arguments.solver).read_bytes()
    solver_sha = digest(solver_bytes)
    if platform.system() != "Linux" and not arguments.engine_only:
        raise ValueError("strict OS isolation evaluation requires Linux; --engine-only explicitly runs UNSANDBOXED compatibility testing")
    report = {
        "schema_version": 1,
        "experiment": (
            "public_examples_order_synthesis"
            if order_synthesis else "screened_composition_shortcut_resistance"
            if arguments.screened_composition else "composition_grammar_adaptive_white_box"
            if arguments.composition else "public_grammar_white_box_baseline"
        ),
        "formal_red_team_complete": False,
        "solver_sha256": solver_sha,
        "solver_filename": Path(arguments.solver).name,
        "solver_arguments": arguments.solver_arg,
        "solver_input": "allowlisted_public_challenge_only",
        "model_calls_during_solving": None,
        "model_use_audit": "not_verified_by_evaluator_requires_review_of_frozen_solver_sha256",
        "submissions_per_challenge": 1,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "os_isolation": "NOT_VALIDATED_UNSANDBOXED_ENGINE_ONLY" if arguments.engine_only else "strict_worker_self_test",
        "sample_count": 0,
        "issuance_attempts": 0,
        "issuance_failures": 0,
        "passed": 0,
        "case_count": 0,
    }
    statuses = collections.Counter()
    issuance_errors = collections.Counter()
    family_results = {}
    failures = []
    solver_times, worker_times, generation_times = [], [], []
    solver_timeout_count = worker_timeout_count = 0
    source_sizes = []
    screening_stats = collections.defaultdict(list)
    order_stats = collections.defaultdict(list)
    reported_metrics = collections.defaultdict(list)
    valid_metrics = invalid_metrics = 0
    with tempfile.TemporaryDirectory(prefix="coggate-offline-solver-") as temporary:
        frozen_solver = Path(temporary) / "offline_solver.py"
        frozen_solver.write_bytes(solver_bytes)
        # This order is intentional: all fresh random keys and fixtures are
        # created after the executable attack source has been frozen.
        data, provenance = fixture_data(arguments)
        report["fixture_provenance"] = provenance
        report["fixtures_sha256"] = digest(data)
        if getattr(arguments, "retain_private_dir", None):
            report["retained_private_evidence"] = retain_private_snapshot(
                arguments.retain_private_dir, solver_bytes, data, report
            )
        worker = worker_path(arguments)
        report["worker"] = str(worker)
        report["worker_sha256"] = digest(worker.read_bytes())
        if not arguments.engine_only:
            check_isolation(worker)
        for line_number, line in enumerate(data.splitlines(), 1):
            if not line.strip():
                continue
            if report["issuance_attempts"] >= arguments.samples:
                break
            fixture = json.loads(line)
            report["issuance_attempts"] += 1
            if isinstance(fixture.get("generation_ms"), (int, float)):
                generation_times.append(fixture["generation_ms"])
            if "generation_error" in fixture:
                if (
                    not (arguments.screened_composition or order_synthesis)
                    or fixture["generation_error"] != "candidate_budget_exhausted"
                    or any(key in fixture for key in ("public", "cases", "reference_source"))
                ):
                    raise ValueError("invalid issuance-failure fixture")
                report["issuance_failures"] += 1
                issuance_errors[fixture["generation_error"]] += 1
                continue
            public = public_challenge(fixture)
            cases = fixture.get("cases")
            if not isinstance(cases, list) or not 0 < len(cases) <= CASE_LIMIT:
                raise ValueError("fixture has invalid cases")
            # Never inspect reference_source. Only this trusted evaluator sees
            # cases; the source-generation subprocess receives public JSON only.
            inputs = [case["input"] for case in cases]
            expected = [case["expected"] for case in cases]
            if isinstance(fixture.get("screening"), dict):
                for key, value in fixture["screening"].items():
                    if type(value) in (int, float):
                        screening_stats[key].append(value)
            if isinstance(fixture.get("order_synthesis"), dict):
                for key, value in fixture["order_synthesis"].items():
                    if type(value) in (int, float):
                        order_stats[key].append(value)
            report["sample_count"] += 1
            report["case_count"] += len(cases)
            outcome, family, detail = "solver_failure", "unrecognized", ""
            before = time.perf_counter()
            try:
                try:
                    generated = subprocess.run(
                        [sys.executable, "-I", str(frozen_solver), *arguments.solver_arg],
                        input=json.dumps(public).encode("utf-8"),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
                        cwd=temporary, env={"PATH": os.defpath, "LC_ALL": "C"},
                    )
                except subprocess.TimeoutExpired:
                    solver_timeout_count += 1
                    raise
                finally:
                    solver_times.append((time.perf_counter() - before) * 1000)
                metrics, invalid = solver_metrics(generated.stderr)
                invalid_metrics += invalid
                if metrics is not None:
                    valid_metrics += 1
                    for key, value in metrics.items():
                        reported_metrics[key].append(value)
                if generated.returncode:
                    detail = generated.stderr.decode("utf-8", errors="replace")[:300]
                else:
                    source_sizes.append(len(generated.stdout))
                    source = generated.stdout.decode("utf-8")
                    first_line = source.splitlines()[0] if source else ""
                    if first_line.startswith("// public-grammar family: "):
                        family = first_line.split(": ", 1)[1]
                    payload = request(source, inputs)
                    before = time.perf_counter()
                    try:
                        executed = subprocess.run(
                            [str(worker)], input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=2, env={},
                        )
                    except subprocess.TimeoutExpired:
                        worker_timeout_count += 1
                        raise
                    finally:
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
    report["pass_rate_denominator"] = "issued_challenges_only"
    report["pass_rate_per_issuance_attempt"] = report["passed"] / report["issuance_attempts"]
    report["issuance_failure_reasons"] = dict(issuance_errors)
    report["by_family"] = dict(sorted(family_results.items()))
    report["statuses"] = dict(statuses)
    report["failure_examples"] = failures
    report["runtime_cost"] = {
        "solver_process_including_python_startup": timing_summary(solver_times),
        "worker_process_including_startup_compile_execute_ipc": timing_summary(worker_times),
        "solver_timeout_count": solver_timeout_count,
        "worker_timeout_count": worker_timeout_count,
        "timing_scope": "all_started_solver_and_worker_runs_including_timeout_termination_and_cleanup",
        "timeout_censoring": "timeout_wall_cost_is_observed_but_uninterrupted_completion_time_is_unknown",
        "evaluation_total_ms": round((time.perf_counter() - started) * 1000, 3),
        "generator_per_challenge": timing_summary(generation_times),
    }
    report["solver_stdout_source_bytes"] = {
        "provenance": "trusted_evaluator_measurement_of_successful_solver_stdout",
        **numeric_summary(source_sizes),
    }
    report["solver_self_reported_metrics"] = {
        "provenance": "untrusted_solver_stderr_diagnostics_not_used_for_verdict",
        "schema": "coggate-order-solver-v1",
        "valid_records": valid_metrics,
        "invalid_records": invalid_metrics,
        "fields": {key: numeric_summary(values) for key, values in sorted(reported_metrics.items())},
    }
    if screening_stats:
        report["screening"] = {
            key: {"count": len(values), "total": sum(values),
                  "min": min(values), "max": max(values),
                  "mean": round(sum(values) / len(values), 3)}
            for key, values in sorted(screening_stats.items())
        }
    if order_stats:
        report["order_synthesis"] = {
            key: numeric_summary(values) for key, values in sorted(order_stats.items())
        }
    report["conclusion"] = (
        "all_issued_challenges_passed"
        if report["pass_rate"] == 1.0
        else "attack_success_observed" if report["passed"] else "no_success_in_this_sample"
    )
    report["limitations"] = [
        "One source-visible specialized solver; not two independent five-day attack teams.",
        "Hidden-case pass rate does not prove correctness on all possible inputs.",
        "Direct worker evaluation bypasses gateway admission and challenge lifecycle handling.",
        "No LLM baseline or formal confidence-bound acceptance result is included.",
        "Timing includes cold subprocess startup and is not the warmed-worker performance gate.",
        "Issuance failures are availability failures, not successful defenses against a solver.",
        "Solver-reported metrics, including model_calls, are diagnostics rather than verified evidence.",
        "The solver runner is not an OS, filesystem, or network sandbox; included attack access claims require review of its frozen source.",
    ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--solver", help="solver script; defaults to the included solver for the selected generator")
    parser.add_argument("--solver-arg", action="append", default=[],
                        help="frozen solver argument; use --solver-arg=--flag for options")
    mechanism = parser.add_mutually_exclusive_group()
    mechanism.add_argument("--composition", action="store_true", help="evaluate the development-only composition generator")
    mechanism.add_argument("--screened-composition", action="store_true",
                           help="evaluate the development-only screened composition generator")
    mechanism.add_argument("--order-synthesis", action="store_true",
                           help="evaluate the development-only public-example order synthesis generator")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--fixtures", help="trusted JSONL fixture file; fresh-key provenance is then unverified")
    parser.add_argument("--retain-private-dir",
                        help="new owner-only directory with PRIVATE in its name; saves frozen source and PRIVATE fixtures, never upload")
    parser.add_argument("--worker", help="worker executable; default is the latest debug native build")
    parser.add_argument("--engine-only", action="store_true", help="explicitly use UNSANDBOXED engine compatibility mode")
    arguments = parser.parse_args()
    if arguments.solver is None:
        name = (
            "order_solver.py" if arguments.order_synthesis else
            "composition_solver.py" if arguments.composition or arguments.screened_composition else
            "offline_solver.py"
        )
        arguments.solver = str(ROOT / "scripts" / name)
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
