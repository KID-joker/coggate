#!/usr/bin/env python3
"""Expose bounded public experiment diagnostics in GitHub check annotations."""
import os
from pathlib import Path


def notice(title, body):
    body = body.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::notice title={title}::{body}")


for name in ("size.json", "offline-solver.json"):
    path = Path("artifacts") / name
    if path.is_file():
        notice(name, path.read_text()[-16000:])

if os.environ.get("JOB_STATUS") != "success":
    logs = sorted(Path("artifacts").glob("*.log"), key=lambda p: p.stat().st_mtime_ns)
    if logs:
        path = logs[-1]
        notice("Last diagnostic: " + path.name, path.read_text(errors="replace")[-16000:])
