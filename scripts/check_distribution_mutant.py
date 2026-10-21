#!/usr/bin/env python3
"""Probe hidden-test distribution with one frozen, deliberately wrong program.

The program parses the complete public prompt, but returns null when an input
contains both zero and a medium-magnitude value. This is a test-coverage mutant,
NOT a cheaper solver. The complete correct parser remains the control.
Freeze both programs before fresh issuance; never send private fixtures to them.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import evaluate_solver as evaluator


ROOT = Path(__file__).resolve().parents[1]
TRIGGER = """function solve(input){
  var sawZero=false,sawMedium=false,probe;
  for(probe=0;probe<input.length;probe++){
    if(input[probe]===0){sawZero=true;}
    if((input[probe]>=128 && input[probe]<=4096) ||
       (input[probe]<=-128 && input[probe]>=-4096)){sawMedium=true;}
  }
  if(sawZero && sawMedium){return null;}
"""
# Chosen independently of the private suite; valid under the public contract.
COUNTEREXAMPLE = [0, 257, -193]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mutant_source(original):
    source = original.decode("utf-8")
    marker = "function solve(input){\n"
    if source.count(marker) != 1:
        raise ValueError("expected exactly one composition interpreter entry")
    return source.replace(marker, TRIGGER, 1).encode("utf-8")


def execute(worker, source, inputs, engine_only):
    result = subprocess.run(
        [str(worker)], input=evaluator.request(source, inputs),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, timeout=2,
    )
    if result.returncode:
        raise ValueError("counterexample worker failed")
    values = evaluator.response(result.stdout, len(inputs), engine_only)
    if any(status for status, _ in values):
        raise ValueError("counterexample had an execution failure")
    return [json.loads(text, parse_constant=evaluator.reject_constant) for _, text in values]


def run(arguments):
    original = (ROOT / "scripts/composition_solver.py").read_bytes()
    mutated = mutant_source(original)
    report = {
        "schema_version": 1,
        "experiment": "mixed_scale_input_coverage_mutant",
        "control_sha256": sha(original),
        "mutant_sha256": sha(mutated),
        "harness_sha256": sha(Path(__file__).read_bytes()),
        "trigger": "input contains 0 and a value with 128 <= abs(x) <= 4096",
        "mutation": "return null on trigger; otherwise use the complete public parser",
        "model_calls_during_solving": 0,
        "model_use_audit": "frozen included source review, not enforced model isolation",
        "counterexample_input": COUNTEREXAMPLE,
        "limitations": [
            "A diagnostic incorrect program, not a cheaper solver.",
            "Finite tests cannot cover all rare input-dependent mistakes.",
            "Direct worker evaluation does not test gateway lifecycle or retry policy.",
            "Python solver data separation relies on reviewed source, not filesystem isolation.",
            "Engine-only mode makes no Linux isolation claim.",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="coggate-distribution-") as temporary:
        directory = Path(temporary)
        control = directory / "control.py"
        mutant = directory / "mutant.py"
        control.write_bytes(original)
        mutant.write_bytes(mutated)
        # Both executable sources are frozen before the generator creates keys.
        options = argparse.Namespace(
            solver=str(mutant), solver_arg=[], composition=False,
            screened_composition=True, samples=arguments.samples, fixtures=None,
            worker=arguments.worker, engine_only=arguments.engine_only,
        )
        if arguments.fixture_generator:
            generator = Path(arguments.fixture_generator).resolve(strict=True)
            report["generator_binary_sha256"] = sha(generator.read_bytes())
            generated = subprocess.run(
                [str(generator), "--screened-dump", str(arguments.samples)],
                capture_output=True, timeout=180, check=True,
            )
            data = generated.stdout
        else:
            data, _ = evaluator.fixture_data(options)
        report["fixtures_sha256"] = sha(data)
        report["fixture_provenance"] = "fresh_key_generated_after_both_source_snapshots"
        fixtures = directory / "private-fixtures.jsonl"
        fixtures.write_bytes(data)
        if arguments.retain_private_dir:
            retained = Path(arguments.retain_private_dir)
            retained.mkdir(parents=True, exist_ok=True)
            # These files contain private judging data. Never upload this folder.
            for name, content in (("control.py", original), ("mutant.py", mutated),
                                  ("private-fixtures.jsonl", data)):
                path = retained / name
                with path.open("xb") as handle:
                    handle.write(content)
        options.fixtures = str(fixtures)
        report["evaluation"] = evaluator.evaluate(options)
        options.solver = str(control)
        report["control"] = evaluator.evaluate(options)
        worker = evaluator.worker_path(options)
        witnessed = issued = 0
        # A separate probe establishes that the mutant is wrong on every issued
        # challenge, not merely different on a guessed equivalent semantics.
        for line in data.splitlines():
            fixture = json.loads(line)
            if "generation_error" in fixture:
                continue
            issued += 1
            public = evaluator.public_challenge(fixture)
            generated = subprocess.run(
                [sys.executable, "-I", str(mutant)], input=json.dumps(public).encode(),
                capture_output=True, timeout=3, check=True, cwd=temporary,
                env={"PATH": os.defpath, "LC_ALL": "C"},
            )
            actual = execute(worker, generated.stdout.decode(), [COUNTEREXAMPLE], arguments.engine_only)
            expected = execute(worker, fixture["reference_source"], [COUNTEREXAMPLE], arguments.engine_only)
            if evaluator.result_matches(actual[0], expected[0]):
                raise ValueError("independent probe did not distinguish the mutant")
            witnessed += 1
        report["independently_wrong_programs"] = witnessed
        result, control_result = report["evaluation"], report["control"]
        failures = []
        for name, evaluation in (("mutant", result), ("control", control_result)):
            if evaluation["issuance_attempts"] != arguments.samples:
                failures.append(name + ": incomplete issuance batch")
            if evaluation["sample_count"] != issued or not issued:
                failures.append(name + ": invalid issued count")
            if evaluation["fixtures_sha256"] != report["fixtures_sha256"]:
                failures.append(name + ": fixture hash mismatch")
            expected_sha = report["mutant_sha256" if name == "mutant" else "control_sha256"]
            if evaluation["solver_sha256"] != expected_sha:
                failures.append(name + ": frozen source hash mismatch")
        if control_result["statuses"] != {"passed": issued}:
            failures.append("complete correct parser did not pass every issued challenge")
        if set(result["statuses"]) - {"passed", "wrong_answer"}:
            failures.append("execution errors cannot count as detected mutations")
        if arguments.require_rejected and result["statuses"] != {"wrong_answer": issued}:
            failures.append("the incorrect program still passes hidden tests")
        report["confirmed_incorrect_passes"] = result["passed"]
        report["failures"] = failures
        report["status"] = "failed" if failures else "passed"
        report["requires_all_mutants_rejected"] = arguments.require_rejected
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--worker")
    parser.add_argument("--engine-only", action="store_true")
    parser.add_argument("--fixture-generator", help="trusted pinned demo binary for a before comparison")
    parser.add_argument("--retain-private-dir", help="new local directory; PRIVATE, never upload")
    parser.add_argument("--require-rejected", action="store_true")
    arguments = parser.parse_args()
    if not 1 <= arguments.samples <= 100_000:
        parser.error("--samples must be in 1..100000")
    try:
        report = run(arguments)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report = {"status": "evaluation_error", "error": str(error)}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 2 if report["status"] == "evaluation_error" else 1


if __name__ == "__main__":
    sys.exit(main())
