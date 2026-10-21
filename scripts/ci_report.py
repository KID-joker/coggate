#!/usr/bin/env python3
"""Expose compact diagnostics; retain full evidence in the uploaded artifact."""
import os
import json
import platform
import subprocess
from pathlib import Path


def notice(title, body):
    # Long annotation messages were truncated at 4 KiB in the public API.
    # Preserve complete JSON evidence as independently bounded UTF-8 chunks.
    remaining = body.encode("utf-8")
    chunks = []
    while remaining:
        chunk = remaining[:3000].decode("utf-8", errors="ignore")
        chunks.append(chunk)
        remaining = remaining[len(chunk.encode("utf-8")):]
    for index, chunk in enumerate(chunks or [""]):
        name = title if len(chunks) <= 1 else f"{title} [part {index + 1}/{len(chunks)}]"
        escaped = chunk.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::notice title={name}::{escaped}")


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


cpu_info = Path("/proc/cpuinfo")
cpu = next(
    (line.split(":", 1)[1].strip() for line in cpu_info.read_text().splitlines()
     if line.startswith("model name")),
    "unavailable",
) if cpu_info.exists() else platform.processor()
artifact_name = os.environ.get("EVIDENCE_ARTIFACT", "prototype-evidence")
size_reports = {}
for name in ("size.json", "screened-size.json"):
    path = Path("artifacts") / name
    if path.is_file():
        report = json.loads(path.read_text())
        # Each size report carries the actual feature selection and scope.
        # Building a host/worker alone is not a complete size measurement.
        size_reports[name] = {
            key: report[key] for key in ("mechanism", "build_features", "scope", "note")
            if key in report
        }
provenance = {
    "commit": os.environ.get("GITHUB_SHA", command("git", "rev-parse", "HEAD")),
    "job": os.environ.get("GITHUB_JOB", "local"),
    "artifact": artifact_name,
    "platform": platform.platform(),
    "architecture": platform.machine(),
    "cpu": cpu,
    "rustc": command("rustc", "-Vv"),
    "cc": command("cc", "--version"),
    "size_build": {
        "status": "see_individual_size_reports" if size_reports else "not_measured_in_this_job",
        "reports": size_reports,
    },
    "tests": os.environ.get("EVIDENCE_TEST_SCOPE", "workspace with coggate/dev-tools"),
}
Path("artifacts").mkdir(exist_ok=True)
Path("artifacts/provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")

REPORTS = (
    "size.json", "offline-solver.json", "composition-solver.json",
    "boundary-mutants.json", "shortcut-before.json", "guards-before.json",
    "shortcut-after.json", "guards-after.json", "original-guards-before.json",
    "original-guards-after.json", "screened-adaptive.json",
    "screened-size.json", "distribution-before.json", "distribution-after.json",
    "order-adapted.json", "order-legacy-parser.json", "order-examples-only.json",
)
# GitHub also caps the number of annotations per step. Put one compact overview
# first, so large early reports cannot hide the later experimental outcomes.
# Full JSON (including provenance and hashes) is uploaded in the named artifact.
summary = {
    "commit": provenance["commit"], "job": provenance["job"],
    "full_reports": artifact_name, "reports": {},
}
for name in REPORTS:
    path = Path("artifacts") / name
    if not path.is_file():
        continue
    report = json.loads(path.read_text())
    evaluation = report.get("evaluation", report)
    fields = ("status", "increment_bytes", "budget_passed", "passed",
              "sample_count", "issuance_attempts", "issuance_failures")
    summary["reports"][name] = {key: evaluation[key] for key in fields if key in evaluation}
    if "status" in report:
        summary["reports"][name]["status"] = report["status"]
notice("Experiment overview", json.dumps(summary, separators=(",", ":")))
notice("provenance.json", json.dumps(provenance, indent=2))

for name in REPORTS:
    path = Path("artifacts") / name
    if path.is_file():
        notice(name, path.read_text())

if os.environ.get("JOB_STATUS") != "success":
    logs = sorted(Path("artifacts").glob("*.log"), key=lambda p: p.stat().st_mtime_ns)
    if logs:
        path = logs[-1]
        notice("Last diagnostic: " + path.name, path.read_text(errors="replace")[-16000:])
