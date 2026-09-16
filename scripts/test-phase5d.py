#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class RunnerError(Exception):
    pass


def complete_capabilities():
    versions = {
        "cargo": (1, 85, 0), "rustc": (1, 85, 0), "python": (3, 11, 0),
        "go": (1, 24, 0), "java": (17, 0, 0), "javac": (17, 0, 0),
        "cmake": (3, 31, 0), "ctest": (3, 31, 0), "maven": (3, 9, 9),
        "node": (22, 18, 0), "node_api": (9,), "node_gyp": (12, 1, 0),
        "cc": (17, 0, 0), "cxx": (17, 0, 0),
    }
    names = {
        "cargo": "Cargo", "rustc": "rustc", "python": "Python",
        "go": "Go", "java": "Java", "javac": "javac", "cmake": "CMake",
        "ctest": "CTest", "maven": "Maven", "node": "Node",
        "node_api": "Node-API", "node_gyp": "node-gyp", "cc": "C compiler",
        "cxx": "C++ compiler",
    }
    return {key: Capability(names[key], f"/tools/{key}", version)
            for key, version in versions.items()}


class RunnerSelfTests(unittest.TestCase):
    def test_ci_requires_every_tool_and_minimum_version(self):
        capabilities = complete_capabilities()
        capabilities["go"] = Capability("Go", "/tools/go", (1, 23, 9))
        with self.assertRaisesRegex(RunnerError, "Go 1.24"):
            require_ci_capabilities(capabilities)
        capabilities = complete_capabilities()
        capabilities["cmake"] = Capability("CMake", None, None)
        with self.assertRaisesRegex(RunnerError, "CMake 3.26"):
            require_ci_capabilities(capabilities)
        capabilities = complete_capabilities()
        del capabilities["go"]
        with self.assertRaisesRegex(RunnerError, "Go 1.24"):
            require_ci_capabilities(capabilities)

    def test_capability_detection_falls_back_to_python_executable_name(self):
        looked_up = []

        def lookup(name):
            looked_up.append(name)
            return "/tools/python" if name == "python" else None

        capabilities = detect_capabilities(
            "Linux", lookup, lambda path, *args: "Python 3.11.0"
        )
        self.assertEqual(
            capabilities["python"], Capability("Python", "/tools/python", (3, 11, 0))
        )
        self.assertLess(looked_up.index("python3"), looked_up.index("python"))

    def test_qualification_plan_is_complete_and_ordered(self):
        plan = qualification_plan(
            Target.for_host("Linux", "x86_64"),
            Path("/repo"),
            Path("/repo/target/phase5d/x86_64-unknown-linux-gnu"),
            complete_capabilities(),
        )
        commands = [item.argv for item in plan]
        self.assertIn(("cargo", "fmt", "--check"), commands)
        self.assertIn(
            ("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"),
            commands,
        )
        self.assertIn(("cargo", "test", "--workspace"), commands)
        self.assertLess(
            commands.index(("cargo", "test", "--workspace")),
            next(i for i, command in enumerate(commands)
                 if "test-phase5b.py" in " ".join(command)),
        )
        self.assertLess(
            next(i for i, command in enumerate(commands)
                 if "test-phase5b.py" in " ".join(command)),
            next(i for i, command in enumerate(commands)
                 if "test-phase5c.py" in " ".join(command)),
        )

    def test_detect_capabilities_parses_numeric_versions(self):
        paths = {
            "cargo": "/tools/cargo", "rustc": "/tools/rustc",
            "python3": "/tools/python", "go": "/tools/go",
            "java": "/tools/java", "javac": "/tools/javac",
            "cmake": "/tools/cmake", "ctest": "/tools/ctest",
            "mvn": "/tools/mvn", "node": "/tools/node",
            "node-gyp": "/tools/node-gyp", "cc": "/tools/cc",
            "c++": "/tools/c++",
        }
        outputs = {
            ("/tools/cargo", "--version"): "cargo 1.85.0 (x)",
            ("/tools/rustc", "--version"): "rustc 1.85.0 (x)",
            ("/tools/python", "--version"): "Python 3.11.0",
            ("/tools/go", "version"): "go version go1.24.0 linux/amd64",
            ("/tools/java", "-version"): 'openjdk version "17.0.0"',
            ("/tools/javac", "-version"): "javac 17.0.0",
            ("/tools/cmake", "--version"): "cmake version 3.31.0",
            ("/tools/ctest", "--version"): "ctest version 3.31.0",
            ("/tools/mvn", "--version"): "Apache Maven 3.9.9",
            ("/tools/node", "--version"): "v22.18.0",
            ("/tools/node", "-p", "process.versions.napi"): "9\n",
            ("/tools/node-gyp", "--version"): "v12.1.0",
            ("/tools/cc", "--version"): "clang version 17.0.0",
            ("/tools/c++", "--version"): "clang version 17.0.0",
        }
        capabilities = detect_capabilities(
            "Linux", paths.get, lambda path, *args: outputs[(path, *args)]
        )
        expected = complete_capabilities()
        self.assertEqual(
            {key: capability.version for key, capability in capabilities.items()},
            {key: capability.version for key, capability in expected.items()},
        )
        self.assertEqual(
            {key: capability.name for key, capability in capabilities.items()},
            {key: capability.name for key, capability in expected.items()},
        )

    def test_windows_plan_uses_import_library_for_phase5b_and_dll_for_phase5c(self):
        root = Path("C:/repo")
        artifacts = Path("C:/artifacts")
        plan = qualification_plan(
            Target.for_host("Windows", "AMD64"), root, artifacts,
            complete_capabilities(),
        )
        phase5b_dynamic = plan[4]
        phase5c = plan[6]
        self.assertEqual(
            phase5b_dynamic.argv[-1], str(artifacts / "agentgate_ffi.dll.lib")
        )
        self.assertEqual(phase5c.argv[-1], str(artifacts / "agentgate_ffi.dll"))
        self.assertEqual(dict(phase5b_dynamic.env)["CC"], "/tools/cc")
        self.assertEqual(dict(phase5c.env)["CXX"], "/tools/cxx")

    def test_run_command_preserves_environment_and_never_uses_a_shell(self):
        command = PlannedCommand(
            ("tool", "an argument"), Path("/repo"), (("EXTRA", "value"),)
        )
        with mock.patch.dict(os.environ, {"PRESERVED": "yes"}, clear=True):
            runner = mock.Mock(return_value=mock.Mock(returncode=0))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(run_command(command, runner, windows=False), "PASS")
        runner.assert_called_once()
        _, kwargs = runner.call_args
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["env"]["PRESERVED"], "yes")
        self.assertEqual(kwargs["env"]["EXTRA"], "value")
        self.assertEqual(stdout.getvalue(), "+ tool 'an argument'\n")

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
        for stage in ("sanitizers", "artifact"):
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


@dataclass(frozen=True)
class Capability:
    name: str
    path: str | None
    version: tuple[int, ...] | None


@dataclass(frozen=True)
class PlannedCommand:
    argv: tuple[str, ...]
    cwd: Path
    env: tuple[tuple[str, str], ...] = ()


MINIMUMS = {
    "cargo": (1, 85),
    "rustc": (1, 85),
    "python": (3, 11),
    "go": (1, 24),
    "java": (17,),
    "javac": (17,),
    "cmake": (3, 26),
    "ctest": (3, 26),
    "maven": (3, 9),
    "node": (22,),
    "node_api": (9,),
    "node_gyp": (10,),
}

CAPABILITY_NAMES = {
    "cargo": "Cargo",
    "rustc": "rustc",
    "python": "Python",
    "go": "Go",
    "java": "Java",
    "javac": "javac",
    "cmake": "CMake",
    "ctest": "CTest",
    "maven": "Maven",
    "node": "Node",
    "node_api": "Node-API",
    "node_gyp": "node-gyp",
    "cc": "C compiler",
    "cxx": "C++ compiler",
}


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


def parse_version(output: str) -> tuple[int, ...] | None:
    match = re.search(r"(?<!\d)(\d+(?:\.\d+)*)(?!\d)", output)
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _version_output(path: str, *arguments: str) -> str:
    completed = subprocess.run(
        [path, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        shell=False,
    )
    return completed.stdout


def detect_capabilities(
    system: str,
    tool_lookup=shutil.which,
    version_output=_version_output,
) -> dict[str, Capability]:
    normalized_system = normalize_system(system)
    compiler_names = ("cl", "cl") if normalized_system == "Windows" else ("cc", "c++")
    executables = {
        "cargo": "cargo",
        "rustc": "rustc",
        "python": "python3",
        "go": "go",
        "java": "java",
        "javac": "javac",
        "cmake": "cmake",
        "ctest": "ctest",
        "maven": "mvn",
        "node": "node",
        "node_gyp": "node-gyp",
        "cc": compiler_names[0],
        "cxx": compiler_names[1],
    }
    version_arguments = {
        "cargo": ("--version",),
        "rustc": ("--version",),
        "python": ("--version",),
        "go": ("version",),
        "java": ("-version",),
        "javac": ("-version",),
        "cmake": ("--version",),
        "ctest": ("--version",),
        "maven": ("--version",),
        "node": ("--version",),
        "node_gyp": ("--version",),
        "cc": ("--version",),
        "cxx": ("--version",),
    }
    paths = {key: tool_lookup(executable) for key, executable in executables.items()}
    if paths["python"] is None:
        paths["python"] = tool_lookup("python")

    def detected(key: str) -> Capability:
        path = paths[key]
        if path is None:
            return Capability(CAPABILITY_NAMES[key], None, None)
        try:
            version = parse_version(version_output(path, *version_arguments[key]))
        except (OSError, subprocess.SubprocessError):
            version = None
        return Capability(CAPABILITY_NAMES[key], path, version)

    capabilities = {key: detected(key) for key in executables}
    node_path = paths["node"]
    if node_path is None:
        capabilities["node_api"] = Capability("Node-API", None, None)
    else:
        try:
            node_api_version = parse_version(
                version_output(node_path, "-p", "process.versions.napi")
            )
        except (OSError, subprocess.SubprocessError):
            node_api_version = None
        capabilities["node_api"] = Capability(
            "Node-API", node_path, node_api_version
        )
    return capabilities


def _minimum_label(minimum: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in minimum)


def require_ci_capabilities(capabilities: dict[str, Capability]) -> None:
    for key, minimum in MINIMUMS.items():
        capability = capabilities.get(
            key, Capability(CAPABILITY_NAMES[key], None, None)
        )
        if capability.path is None or capability.version is None:
            raise RunnerError(
                f"required capability: {capability.name} {_minimum_label(minimum)}+"
            )
        if capability.version < minimum:
            raise RunnerError(
                f"{capability.name} {_minimum_label(minimum)}+ is required"
            )
    for key, fallback_name in (("cc", "C compiler"), ("cxx", "C++ compiler")):
        capability = capabilities.get(key, Capability(fallback_name, None, None))
        if capability.path is None:
            raise RunnerError(f"required capability: {capability.name}")


def qualification_plan(
    target: Target,
    root: Path,
    artifact_directory: Path,
    capabilities: dict[str, Capability],
) -> list[PlannedCommand]:
    root = Path(root)
    artifact_directory = Path(artifact_directory)
    python = capabilities["python"].path
    if python is None:
        raise RunnerError("required capability: Python 3.11+")
    shared_library = artifact_directory / target.shared_name
    static_library = artifact_directory / target.static_name
    link_library = (
        artifact_directory / target.import_name
        if target.import_name is not None
        else shared_library
    )
    compiler_environment = (
        ("CC", capabilities["cc"].path or ""),
        ("CXX", capabilities["cxx"].path or ""),
    )
    return [
        PlannedCommand(("cargo", "fmt", "--check"), root),
        PlannedCommand(
            ("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"),
            root,
        ),
        PlannedCommand(("cargo", "test", "--workspace"), root),
        PlannedCommand(("cargo", "build", "-p", "agentgate-ffi", "--release"), root),
        PlannedCommand(
            (
                python,
                str(root / "scripts" / "test-phase5b.py"),
                "--library",
                str(link_library),
            ),
            root,
            compiler_environment,
        ),
        PlannedCommand(
            (
                python,
                str(root / "scripts" / "test-phase5b.py"),
                "--native-only",
                "--static",
                "--library",
                str(static_library),
            ),
            root,
            compiler_environment,
        ),
        PlannedCommand(
            (
                python,
                str(root / "scripts" / "test-phase5c.py"),
                "--runtime",
                "all",
                "--library",
                str(shared_library),
            ),
            root,
            compiler_environment,
        ),
    ]


def validate_artifacts(
    target: Target,
    artifact_directory: Path,
    path_is_file=None,
) -> None:
    path_is_file = (lambda path: path.is_file()) if path_is_file is None else path_is_file
    names = [target.shared_name, target.static_name]
    if target.import_name is not None:
        names.append(target.import_name)
    for name in names:
        path = Path(artifact_directory) / name
        if not path_is_file(path):
            raise RunnerError(f"native library not found: {path}")


def run_command(
    command: PlannedCommand,
    command_runner=subprocess.run,
    dry_run: bool = False,
    windows: bool | None = None,
) -> str:
    if windows is None:
        windows = platform.system() == "Windows"
    formatted = (
        subprocess.list2cmdline(list(command.argv))
        if windows
        else shlex.join(command.argv)
    )
    print("+ " + formatted)
    if dry_run:
        return "PLANNED"
    environment = os.environ.copy()
    environment.update(dict(command.env))
    try:
        completed = command_runner(
            list(command.argv),
            cwd=command.cwd,
            env=environment,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerError(f"unable to run {command.argv[0]}: {error}") from error
    if completed.returncode != 0:
        raise RunnerError(f"command failed with exit code {completed.returncode}")
    return "PASS"


def run_qualification(
    target: Target,
    root: Path,
    artifact_directory: Path,
    capabilities: dict[str, Capability],
    *,
    command_runner=subprocess.run,
    dry_run: bool = False,
    path_is_file=None,
) -> str:
    require_ci_capabilities(capabilities)
    plan = qualification_plan(target, root, artifact_directory, capabilities)
    for index, command in enumerate(plan):
        if index == 4 and not dry_run:
            validate_artifacts(target, artifact_directory, path_is_file)
        run_command(
            command,
            command_runner,
            dry_run=dry_run,
            windows=target.system == "Windows",
        )
    return "PLANNED" if dry_run else "PASS"


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
    root: Path = ROOT,
    tool_lookup=shutil.which,
    version_output=_version_output,
    command_runner=subprocess.run,
    path_is_file=None,
) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.self_test:
        return _run_self_tests()

    host_system = platform.system() if system is None else system
    host_arch = platform.machine() if arch is None else arch
    validation = validate_target(host_system, host_arch, arguments.ci)
    if not validation.qualified and arguments.stage is not None:
        raise RunnerError("Phase 5D qualification requires x86_64")
    if arguments.stage in {"sanitizers", "artifact"}:
        raise RunnerError(f"Phase 5D stage is not implemented: {arguments.stage}")
    if arguments.ci:
        if arguments.stage is None:
            raise RunnerError("Phase 5D CI requires an explicit stage")

    if arguments.stage in {"qualification", "all"}:
        target = Target.for_host(host_system, host_arch)
        capabilities = detect_capabilities(
            target.system, tool_lookup=tool_lookup, version_output=version_output
        )
        status = run_qualification(
            target,
            Path(root),
            Path(root) / "target" / "release",
            capabilities,
            command_runner=command_runner,
            dry_run=arguments.dry_run,
            path_is_file=path_is_file,
        )
        print(f"phase5d: qualification={status}")
        if arguments.stage == "all":
            raise RunnerError("Phase 5D stage is not implemented: sanitizers")
        return 0

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
