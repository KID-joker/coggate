#!/usr/bin/env python3
"""Measure the complete native Rust-host increment, not just a compressed crate."""
import argparse
import hashlib
import json
import platform
from pathlib import Path


def inspect(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {
        "path": str(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf": data.startswith(b"\x7fELF"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--integrated", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--output")
    parser.add_argument(
        "--mechanism", choices=("baseline", "screened-composition"), default="baseline",
        help="identify the linked generator; screened-composition requires host-screened with dev-tools",
    )
    args = parser.parse_args()
    baseline, integrated, worker = [inspect(p) for p in (args.baseline, args.integrated, args.worker)]
    if "UNSANDBOXED" in Path(worker["path"]).name:
        parser.error("--worker must name the strict production worker, not the development engine")
    comparable = platform.system() == "Linux" and all(x["elf"] for x in (baseline, integrated, worker))
    delta = integrated["bytes"] - baseline["bytes"] + worker["bytes"]
    screened = args.mechanism == "screened-composition"
    report = {
        "schema": 1,
        "scope": "Rust minimal host + mandatory worker; other bindings not measured",
        "mechanism": args.mechanism,
        "build_features": ["dev-tools"] if screened else [],
        "platform": platform.platform(),
        "baseline": baseline,
        "integrated": integrated,
        "worker": worker,
        "increment_bytes": delta,
        "limit_bytes": 512000,
        "linux_measurement": comparable,
        "budget_passed": delta <= 512000 if comparable else None,
        "note": "Same toolchain/profile; uncompressed required files. "
                + (
                    "Includes the screened composition generator with dev-tools enabled. "
                    "The development-only engine-test binary is not needed by the host and is excluded. "
                    if screened else "No dev-tools feature. "
                )
                + "Only the strict production worker is counted. "
                "A non-Linux production worker is only an unsupported-platform stub.",
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n")
    return 0 if not comparable or delta <= 512000 else 1


if __name__ == "__main__":
    raise SystemExit(main())
