#!/usr/bin/env python3
"""Check two frozen off-by-one solvers against fresh private tests.

Only the adjacent-difference and window-sum comparisons are changed. All ten
families must be sampled: the two mutants must yield wrong answers, while the
other eight families remain positive controls. This is a hidden-test coverage
regression, not evidence of model use or resistance to a correct solver.

The evaluator snapshots the standalone mutated solver before generating new
OS-random challenge keys. --engine-only explicitly skips Linux OS isolation.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import evaluate_solver


ROOT = Path(__file__).resolve().parents[1]
TARGET_FAMILIES = frozenset({"adjacent_difference", "window_sum"})
ALL_FAMILIES = frozenset({
    "filter_sum", "sort_limit", "unique_occurrence", "residue_buckets",
    "prefix_total", "longest_run", "adjacent_difference", "window_sum",
    "stable_partition", "outside_in_pairs",
})
MUTATIONS = (
    (
        "adjacent_difference_strict_bounds",
        "if(x>=%d && x<=%d){result.push(a*x+b);}",
        "if(x>%d && x<%d){result.push(a*x+b);}",
    ),
    (
        "window_sum_strict_threshold",
        "if(total>=threshold){result.push(total);}",
        "if(total>threshold){result.push(total);}",
    ),
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def mutated_source(original):
    source = original.decode("utf-8")
    for name, before, after in MUTATIONS:
        count = source.count(before)
        if count != 1:
            raise ValueError(
                f"{name}: expected exactly one source occurrence, found {count}"
            )
        source = source.replace(before, after, 1)
    return source.encode("utf-8")


def check_results(evaluation, samples, mutation_sha):
    failures = []
    families = evaluation["by_family"]
    checks = {}
    if evaluation["solver_sha256"] != mutation_sha:
        failures.append("evaluated solver differs from frozen mutation source")
    if evaluation["fixture_provenance"] != "fresh_key_generated_after_solver_snapshot":
        failures.append("fixtures were not generated after solver snapshot")
    if evaluation["sample_count"] != samples:
        failures.append("evaluation did not process the requested sample count")
    unexpected = set(families) - ALL_FAMILIES
    if unexpected:
        failures.append("unexpected families: " + ", ".join(sorted(unexpected)))
    target_samples = 0
    for family in sorted(ALL_FAMILIES):
        actual = families.get(family, {})
        count = actual.get("sample_count", 0)
        passed = actual.get("passed", 0)
        target = family in TARGET_FAMILIES
        expected_passed = 0 if target else count
        valid = count > 0 and passed == expected_passed
        checks[family] = {
            "role": "incorrect_boundary_mutant" if target else "correct_control",
            "sample_count": count,
            "passed": passed,
            "expected_passed": expected_passed,
            "check_passed": valid,
        }
        if not count:
            failures.append(f"{family}: no samples; all ten families are required")
        elif not valid:
            failures.append(
                f"{family}: expected {expected_passed}/{count} passes, got {passed}"
            )
        if target:
            target_samples += count
    # A timeout, compile failure, or protocol error is not proof that a hidden
    # input detected the boundary mistake. Require semantic wrong-answer results.
    expected_statuses = {
        "wrong_answer": target_samples,
        "passed": samples - target_samples,
    }
    statuses = {name: count for name, count in evaluation["statuses"].items() if count}
    if statuses != {name: count for name, count in expected_statuses.items() if count}:
        failures.append(
            "outcomes must contain only wrong_answer for mutant families and "
            "passed for controls; infrastructure failures cannot satisfy this gate"
        )
    return checks, failures


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--worker", help="explicit worker executable to evaluate")
    parser.add_argument(
        "--engine-only", action="store_true",
        help="explicitly run the UNSANDBOXED local compatibility worker",
    )
    arguments = parser.parse_args()
    if not 1 <= arguments.samples <= 100_000:
        parser.error("--samples must be in 1..100000")
    report = {
        "schema_version": 1,
        "experiment": "hidden_test_boundary_mutant_regression",
        "status": "evaluation_error",
        "requested_samples": arguments.samples,
        "mutations": [
            {"name": name, "before": before, "after": after}
            for name, before, after in MUTATIONS
        ],
        "limitations": [
            "Tests two specific incorrect implementations, not model use.",
            "Does not establish resistance to a correct specialized solver.",
            "Engine-only results make no Linux OS isolation claim.",
        ],
    }
    try:
        original = (ROOT / "scripts/offline_solver.py").read_bytes()
        mutation = mutated_source(original)
        report["original_solver_sha256"] = sha256(original)
        report["mutation_source_sha256"] = sha256(mutation)
        with tempfile.TemporaryDirectory(prefix="coggate-boundary-mutants-") as directory:
            solver = Path(directory) / "boundary_mutant_solver.py"
            solver.write_bytes(mutation)
            evaluation = evaluate_solver.evaluate(argparse.Namespace(
                solver=str(solver),
                solver_arg=[],
                composition=False,
                screened_composition=False,
                samples=arguments.samples,
                fixtures=None,
                worker=arguments.worker,
                engine_only=arguments.engine_only,
            ))
        report["evaluation"] = evaluation
        checks, failures = check_results(
            evaluation, arguments.samples, report["mutation_source_sha256"]
        )
        report["family_checks"] = checks
        report["failures"] = failures
        report["status"] = "passed" if not failures else "failed"
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] == "evaluation_error":
        return 2
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
