#!/usr/bin/env python3
"""Read an exact build-script output path from cargo's JSON stream."""
import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--engine-only", action="store_true")
args = parser.parse_args()
key = "COGGATE_ENGINE_TEST_PATH" if args.engine_only else "COGGATE_WORKER_PATH"
paths = []
for line in sys.stdin:
    try:
        item = json.loads(line)
    except ValueError:
        continue
    if item.get("reason") == "build-script-executed":
        for name, value in item.get("env", []):
            if name == key:
                paths.append(value)
if not paths:
    raise SystemExit("No matching worker path in cargo build messages")
if len(set(paths)) != 1:
    raise SystemExit("Multiple worker builds: use a single explicit target/profile")
print(paths[0])
