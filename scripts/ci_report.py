#!/usr/bin/env python3
"""Expose bounded public experiment diagnostics in GitHub check annotations."""
import os
import json
import platform
import subprocess
from pathlib import Path


def notice(title, body):
    body = body.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::notice title={title}::{body}")


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


cpu_info = Path("/proc/cpuinfo")
cpu = next(
    (line.split(":", 1)[1].strip() for line in cpu_info.read_text().splitlines()
     if line.startswith("model name")),
    "unavailable",
) if cpu_info.exists() else platform.processor()
provenance = {
    "commit": os.environ.get("GITHUB_SHA", command("git", "rev-parse", "HEAD")),
    "platform": platform.platform(),
    "architecture": platform.machine(),
    "cpu": cpu,
    "rustc": command("rustc", "-Vv"),
    "cc": command("cc", "--version"),
    "size_build": "release profile, Rust baseline/integrated host, no dev-tools",
    "tests": "workspace with coggate/dev-tools",
}
Path("artifacts").mkdir(exist_ok=True)
Path("artifacts/provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
notice("provenance.json", json.dumps(provenance, indent=2))

for name in (
    "size.json", "offline-solver.json", "composition-solver.json",
    "boundary-mutants.json", "shortcut-before.json", "guards-before.json",
    "shortcut-after.json", "guards-after.json", "screened-adaptive.json",
):
    path = Path("artifacts") / name
    if path.is_file():
        notice(name, path.read_text()[-16000:])

if os.environ.get("JOB_STATUS") != "success":
    logs = sorted(Path("artifacts").glob("*.log"), key=lambda p: p.stat().st_mtime_ns)
    if logs:
        path = logs[-1]
        notice("Last diagnostic: " + path.name, path.read_text(errors="replace")[-16000:])
