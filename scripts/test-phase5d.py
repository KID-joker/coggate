#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import platform
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType


ROOT = Path(__file__).resolve().parents[1]


class RunnerError(Exception):
    pass


class RunnerSelfTests(unittest.TestCase):
    def test_linux_x86_64_target(self):
        target = Target.for_host("Linux", "x86_64")
        self.assertEqual(
            target,
            Target(
                "Linux",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                "libagentgate_ffi.so",
                "libagentgate_ffi.a",
                None,
            ),
        )

    def test_darwin_x86_64_target(self):
        target = Target.for_host("Darwin", "x86_64")
        self.assertEqual(
            target,
            Target(
                "Darwin",
                "x86_64",
                "x86_64-apple-darwin",
                "libagentgate_ffi.dylib",
                "libagentgate_ffi.a",
                None,
            ),
        )

    def test_windows_amd64_target(self):
        target = Target.for_host("Windows", "AMD64")
        self.assertEqual(
            target,
            Target(
                "Windows",
                "x86_64",
                "x86_64-pc-windows-msvc",
                "agentgate_ffi.dll",
                "agentgate_ffi.lib",
                "agentgate_ffi.dll.lib",
            ),
        )

    def test_padded_platform_and_arch_aliases_are_normalized(self):
        self.assertEqual(normalize_system(" Linux "), "Linux")
        self.assertEqual(normalize_system(" DARWIN "), "Darwin")
        self.assertEqual(normalize_system(" Windows "), "Windows")
        self.assertEqual(normalize_arch(" AMD64 "), "x86_64")
        self.assertEqual(normalize_arch(" x64 "), "x86_64")
        self.assertEqual(normalize_arch(" AARCH64 "), "arm64")

    def test_ci_rejects_darwin_arm64(self):
        with self.assertRaisesRegex(
            RunnerError, "Phase 5D qualification requires x86_64"
        ):
            validate_target("Darwin", "arm64", ci=True)

    def test_ci_rejects_unsupported_platform(self):
        with self.assertRaisesRegex(RunnerError, "unsupported platform: plan9"):
            validate_target("Plan9", "x86_64", ci=True)

    def test_local_darwin_arm64_is_not_qualified(self):
        self.assertEqual(
            validate_target("Darwin", "arm64", ci=False),
            Validation(False, "local architecture arm64 is not x86_64"),
        )

    def test_cli_accepts_phase5d_contract_arguments(self):
        output = ROOT / "target" / "phase5d"
        arguments = build_parser().parse_args(
            [
                "--dry-run",
                "--ci",
                "--stage",
                "artifact",
                "--output",
                str(output),
            ]
        )
        self.assertTrue(arguments.dry_run)
        self.assertTrue(arguments.ci)
        self.assertEqual(arguments.stage, "artifact")
        self.assertEqual(arguments.output, output)

    def test_local_arm64_without_stage_reports_not_run(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = main([], system="Darwin", arch="arm64")
        self.assertEqual(result, 0)
        self.assertIn("phase5d: qualification=NOT_RUN reason=", stdout.getvalue())
        self.assertNotIn("PASS", stdout.getvalue())

    def test_local_arm64_artifact_stage_fails(self):
        with self.assertRaisesRegex(
            RunnerError, "Phase 5D qualification requires x86_64"
        ):
            main(["--stage", "artifact"], system="Darwin", arch="arm64")

    def test_x86_64_unimplemented_stages_fail_closed(self):
        for stage in ("all", "qualification", "sanitizers", "artifact"):
            with self.subTest(stage=stage), self.assertRaisesRegex(
                RunnerError, f"Phase 5D stage is not implemented: {stage}"
            ):
                main(["--stage", stage], system="Linux", arch="x86_64")

    def test_x86_64_bare_ci_fails_closed(self):
        with self.assertRaisesRegex(
            RunnerError, "Phase 5D CI requires an explicit stage"
        ):
            main(["--ci"], system="Linux", arch="x86_64")


@dataclass(frozen=True)
class Validation:
    qualified: bool
    reason: str | None = None


PLATFORM_TARGETS = MappingProxyType(
    {
        "Linux": (
            "x86_64-unknown-linux-gnu",
            "libagentgate_ffi.so",
            "libagentgate_ffi.a",
            None,
        ),
        "Darwin": (
            "x86_64-apple-darwin",
            "libagentgate_ffi.dylib",
            "libagentgate_ffi.a",
            None,
        ),
        "Windows": (
            "x86_64-pc-windows-msvc",
            "agentgate_ffi.dll",
            "agentgate_ffi.lib",
            "agentgate_ffi.dll.lib",
        ),
    }
)


@dataclass(frozen=True)
class Target:
    system: str
    arch: str
    triple: str
    shared_name: str
    static_name: str
    import_name: str | None

    @classmethod
    def for_host(cls, system: str, arch: str) -> Target:
        normalized_system = normalize_system(system)
        normalized_arch = normalize_arch(arch)
        if normalized_system not in PLATFORM_TARGETS:
            raise RunnerError(f"unsupported platform: {normalized_system}")
        if normalized_arch != "x86_64":
            raise RunnerError("Phase 5D qualification requires x86_64")
        return cls(
            normalized_system,
            normalized_arch,
            *PLATFORM_TARGETS[normalized_system],
        )


def normalize_system(system: str) -> str:
    normalized = system.strip().casefold()
    return {
        "linux": "Linux",
        "darwin": "Darwin",
        "windows": "Windows",
    }.get(normalized, normalized)


def normalize_arch(arch: str) -> str:
    normalized = arch.strip().casefold()
    return {
        "amd64": "x86_64",
        "x64": "x86_64",
        "aarch64": "arm64",
    }.get(normalized, normalized)


def validate_target(system: str, arch: str, ci: bool) -> Validation:
    normalized_system = normalize_system(system)
    normalized_arch = normalize_arch(arch)
    if normalized_system not in PLATFORM_TARGETS:
        raise RunnerError(f"unsupported platform: {normalized_system}")
    if normalized_arch != "x86_64":
        if ci:
            raise RunnerError("Phase 5D qualification requires x86_64")
        return Validation(
            False, f"local architecture {normalized_arch} is not x86_64"
        )
    Target.for_host(normalized_system, normalized_arch)
    return Validation(True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument(
        "--stage", choices=("all", "qualification", "sanitizers", "artifact")
    )
    parser.add_argument("--output", type=Path, default=ROOT / "target" / "phase5d")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    system: str | None = None,
    arch: str | None = None,
) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.self_test:
        return _run_self_tests()

    host_system = platform.system() if system is None else system
    host_arch = platform.machine() if arch is None else arch
    validation = validate_target(host_system, host_arch, arguments.ci)
    if not validation.qualified and arguments.stage is not None:
        raise RunnerError("Phase 5D qualification requires x86_64")
    if arguments.stage is not None:
        raise RunnerError(f"Phase 5D stage is not implemented: {arguments.stage}")
    if arguments.ci:
        raise RunnerError("Phase 5D CI requires an explicit stage")

    reason = validation.reason or "no qualification stage has run"
    print(f"phase5d: qualification=NOT_RUN reason={reason}")
    return 0


def _run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerSelfTests)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RunnerError as error:
        print(f"phase5d: qualification=FAIL reason={error}", file=sys.stderr)
        raise SystemExit(1)
