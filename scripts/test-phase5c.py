#!/usr/bin/env python3
"""Capability-aware orchestration for the Phase 5C runtime wrappers."""

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
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RunnerError(Exception):
    def __init__(self, message, status="FAIL"):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Capability:
    name: str
    path: str | None
    version: tuple[int, ...] | None


@dataclass(frozen=True)
class NativeLibrary:
    link_path: Path
    runtime_path: Path


@dataclass(frozen=True)
class PlannedCommand:
    argv: tuple[str, ...]
    cwd: Path | None = None
    env: tuple[tuple[str, str], ...] = ()


def parse_version(output):
    match = re.search(r"(?<!\d)(\d+(?:\.\d+)*)(?!\d)", output)
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def require_version(capability, minimum):
    if capability.path is None:
        return "MISSING"
    if capability.version is None or capability.version < minimum:
        raise RunnerError(f"{capability.name} version is below {minimum}")
    return "PASS"


def _version_output(path, *arguments):
    completed = subprocess.run(
        [path, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return completed.stdout


def detect_capabilities(tool_lookup=shutil.which, version_output=_version_output):
    paths = {name: tool_lookup(name) for name in ("go", "java", "javac", "node", "cmake", "ctest")}

    def capability(key, name, arguments):
        path = paths[key]
        if path is None:
            return Capability(name, None, None)
        try:
            version = parse_version(version_output(path, *arguments))
        except (OSError, subprocess.SubprocessError):
            version = None
        return Capability(name, path, version)

    node = capability("node", "Node", ("--version",))
    node_api = (
        Capability("Node-API", None, None)
        if node.path is None
        else capability("node", "Node-API", ("-p", "process.versions.napi"))
    )
    return {
        "go": capability("go", "Go", ("version",)),
        "java": capability("java", "Java", ("-version",)),
        "javac": capability("javac", "Java compiler", ("-version",)),
        "node": node,
        "node_api": node_api,
        "cmake": Capability("CMake", paths["cmake"], None),
        "ctest": Capability("CTest", paths["ctest"], None),
    }


def discover_library(root, explicit, system):
    root = Path(root)
    names = {
        "Linux": "libagentgate_ffi.so",
        "Darwin": "libagentgate_ffi.dylib",
        "Windows": "agentgate_ffi.dll.lib",
    }
    if system not in names:
        raise RunnerError("unsupported platform: %s" % system)
    candidate = Path(explicit) if explicit is not None else root / "target" / "release" / names[system]
    if explicit is not None and not candidate.is_absolute():
        candidate = root / candidate
    if candidate.suffix == ".a" or (
        candidate.suffix == ".lib" and not candidate.name.lower().endswith(".dll.lib")
    ):
        raise RunnerError("Phase 5C runtimes require a shared native library")

    if system != "Windows":
        expected_suffix = ".so" if system == "Linux" else ".dylib"
        if candidate.suffix != expected_suffix:
            raise RunnerError("Phase 5C runtimes require a shared native library")
        if not candidate.is_file():
            raise RunnerError(
                "native library not found: %s" % candidate, status="MISSING"
            )
        resolved = candidate.resolve()
        return NativeLibrary(resolved, resolved)

    lower_name = candidate.name.lower()
    if lower_name.endswith(".dll.lib"):
        link_path = candidate
        runtime_path = candidate.with_name(candidate.name[:-4])
    elif lower_name.endswith(".dll"):
        runtime_path = candidate
        candidates = (candidate.with_name(candidate.name + ".lib"), candidate.with_suffix(".lib"))
        link_path = next((path for path in candidates if path.is_file()), candidates[0])
    else:
        raise RunnerError("Windows shared library must be a .dll or .dll.lib")
    if not link_path.is_file():
        raise RunnerError(
            "Windows import library not found: %s" % link_path,
            status="MISSING",
        )
    if not runtime_path.is_file():
        raise RunnerError(
            "Windows runtime DLL not found: %s" % runtime_path,
            status="MISSING",
        )
    return NativeLibrary(link_path.resolve(), runtime_path.resolve())


def _missing_capabilities(runtime, capabilities):
    minimums = {
        "go": (("go", (1, 24)),),
        "java": (("java", (17,)), ("javac", (17,))),
        "node": (("node", (22,)), ("node_api", (9,))),
    }
    missing = [
        "missing capability: %s %s+"
        % (
            capabilities[key].name,
            ".".join(str(part) for part in minimum),
        )
        for key, minimum in minimums[runtime]
        if require_version(capabilities[key], minimum) == "MISSING"
    ]
    if runtime == "java":
        for key in ("cmake", "ctest"):
            if capabilities[key].path is None:
                missing.append("missing capability: %s" % capabilities[key].name)
    return missing


def build_plan(
    runtime,
    library,
    capabilities,
    system,
    root=ROOT,
    environment=None,
):
    if runtime not in {"go", "java", "node", "all"}:
        raise RunnerError("unsupported runtime: %s" % runtime)

    selected = ("go", "java", "node") if runtime == "all" else (runtime,)
    available = []
    missing_messages = []
    for selected_runtime in selected:
        missing = _missing_capabilities(selected_runtime, capabilities)
        if missing:
            missing_messages.extend(missing)
            if runtime != "all":
                raise RunnerError("; ".join(missing))
            continue
        available.append(selected_runtime)

    if not available:
        raise RunnerError("; ".join(missing_messages) or "no Phase 5C runtimes selected")

    root = Path(root)
    runtime_library = str(library.runtime_path)
    link_library = str(library.link_path)
    environment = os.environ if environment is None else environment
    commands = []
    if "go" in available:
        go_environment = ()
        if system in {"Linux", "Darwin"}:
            library_directory = str(library.runtime_path.parent)
            link_flag = shlex.join(["-L" + library_directory])
            existing_link_flags = environment.get("CGO_LDFLAGS")
            combined_link_flags = (
                link_flag + " " + existing_link_flags
                if existing_link_flags
                else link_flag
            )
            runtime_variable = (
                "LD_LIBRARY_PATH" if system == "Linux" else "DYLD_LIBRARY_PATH"
            )
            existing_runtime_path = environment.get(runtime_variable)
            combined_runtime_path = (
                library_directory + os.pathsep + existing_runtime_path
                if existing_runtime_path
                else library_directory
            )
            go_environment = (
                ("CGO_LDFLAGS", combined_link_flags),
                (runtime_variable, combined_runtime_path),
            )
        commands.append(
            PlannedCommand(
                (
                    capabilities["go"].path,
                    "test",
                    "./...",
                    "-args",
                    "--agentgate-library",
                    runtime_library,
                ),
                root / "bindings" / "go",
                go_environment,
            )
        )
    if "java" in available:
        build = root / "target" / "phase5c" / "java"
        commands.append(
            PlannedCommand(
                (
                    capabilities["cmake"].path,
                    "-S",
                    str(root / "bindings" / "java"),
                    "-B",
                    str(build),
                    "-DAGENTGATE_LIBRARY=" + link_library,
                    "-DAGENTGATE_RUNTIME_LIBRARY=" + runtime_library,
                    "-DJAVA_EXECUTABLE=" + capabilities["java"].path,
                    "-DJAVAC_EXECUTABLE=" + capabilities["javac"].path,
                ),
                root,
            )
        )
        build_argv = [capabilities["cmake"].path, "--build", str(build)]
        ctest_argv = [capabilities["ctest"].path, "--test-dir", str(build), "--output-on-failure"]
        if system == "Windows":
            build_argv.extend(("--config", "Release"))
            ctest_argv.extend(("-C", "Release"))
        commands.extend((PlannedCommand(tuple(build_argv), root), PlannedCommand(tuple(ctest_argv), root)))
    if "node" in available:
        commands.append(
            PlannedCommand(
                (
                    capabilities["node"].path,
                    "--test",
                    "bindings/node/tests",
                ),
                root,
                (("AGENTGATE_LIBRARY_PATH", runtime_library),),
            )
        )
    return commands


def run_command(command, command_runner, dry_run=False):
    print("+ " + shlex.join(command.argv))
    if dry_run:
        return "PLANNED"
    environment = os.environ.copy()
    environment.update(dict(command.env))
    try:
        completed = command_runner(
            list(command.argv), cwd=command.cwd, env=environment
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerError(
            "unable to run %s: %s" % (command.argv[0], error)
        ) from error
    if completed.returncode != 0:
        raise RunnerError("command failed with exit code %d" % completed.returncode)
    return "PASS"


def run_phase5c(args, **injections):
    root = Path(injections.get("root", ROOT))
    platform_name = injections.get("platform_name", platform.system)
    tool_lookup = injections.get("tool_lookup", shutil.which)
    version_output = injections.get("version_output", _version_output)
    command_runner = injections.get("command_runner", subprocess.run)
    reporter = injections.get("reporter", lambda message: print(message, file=sys.stderr))
    selected = (
        ("go", "java", "node") if args.runtime == "all" else (args.runtime,)
    )

    phase5b_library = args.phase5b_library
    library_argument = args.library if args.library is not None else phase5b_library
    try:
        system = platform_name()
        library = discover_library(root, library_argument, system)
    except RunnerError as error:
        for selected_runtime in selected:
            reporter(
                "phase5c: runtime=%s status=%s"
                % (selected_runtime, error.status)
            )
        reporter("phase5c: overall status=%s" % error.status)
        raise
    capabilities = detect_capabilities(tool_lookup, version_output)

    available = []
    missing_messages = []
    missing_by_runtime = {}
    for selected_runtime in selected:
        try:
            missing = _missing_capabilities(selected_runtime, capabilities)
        except RunnerError:
            reporter("phase5c: runtime=%s status=FAIL" % selected_runtime)
            reporter("phase5c: overall status=FAIL")
            raise
        missing_by_runtime[selected_runtime] = missing
        for message in missing:
            reporter(message)

    for selected_runtime in selected:
        missing = missing_by_runtime[selected_runtime]
        if missing:
            missing_messages.extend(missing)
            reporter("phase5c: runtime=%s status=MISSING" % selected_runtime)
        else:
            available.append(selected_runtime)

    if not available:
        reporter("phase5c: overall status=MISSING")
        raise RunnerError("; ".join(missing_messages))

    if phase5b_library is not None:
        phase5b = PlannedCommand(
            (
                sys.executable,
                str(root / "scripts" / "test-phase5b.py"),
                "--library",
                str(phase5b_library),
            ),
            root,
        )
        try:
            run_command(phase5b, command_runner, args.dry_run)
        except RunnerError:
            reporter("phase5c: overall status=FAIL")
            raise

    status = "PLANNED" if args.dry_run else "PASS"
    for selected_runtime in available:
        try:
            plan = build_plan(
                selected_runtime, library, capabilities, system, root
            )
            for command in plan:
                run_command(command, command_runner, args.dry_run)
        except RunnerError:
            reporter("phase5c: runtime=%s status=FAIL" % selected_runtime)
            reporter("phase5c: overall status=FAIL")
            raise
        reporter(
            "phase5c: runtime=%s status=%s" % (selected_runtime, status)
        )
    reporter("phase5c: overall status=%s" % status)
    return status


class RunnerSelfTests(unittest.TestCase):
    def test_exact_version_parsing(self):
        self.assertEqual(parse_version("go version go1.24.3 windows/amd64"), (1, 24, 3))
        self.assertEqual(parse_version('openjdk version "17.0.12" 2024-07-16'), (17, 0, 12))
        self.assertEqual(parse_version("javac 17.0.12"), (17, 0, 12))
        self.assertEqual(parse_version("v22.11.0"), (22, 11, 0))
        self.assertEqual(parse_version("9\n"), (9,))
        self.assertIsNone(parse_version("development build"))

    def test_capability_detection_and_missing_messages(self):
        paths = {
            "go": None,
            "java": "/tools/java",
            "javac": None,
            "node": "/tools/node",
            "cmake": None,
            "ctest": None,
        }
        outputs = {
            ("/tools/java", "-version"): 'openjdk version "17.0.12"',
            ("/tools/node", "--version"): "v22.5.0",
            ("/tools/node", "-p", "process.versions.napi"): "9",
        }
        capabilities = detect_capabilities(paths.get, lambda path, *args: outputs[(path, *args)])

        self.assertEqual(capabilities["go"], Capability("Go", None, None))
        self.assertEqual(capabilities["java"].version, (17, 0, 12))
        self.assertEqual(capabilities["node_api"].version, (9,))
        with self.assertRaisesRegex(RunnerError, "missing capability: Go 1.24\+"):
            build_plan("go", NativeLibrary(Path("lib.so"), Path("lib.so")), capabilities, "Linux")
        with self.assertRaisesRegex(RunnerError, "missing capability: Java compiler 17\+"):
            build_plan("java", NativeLibrary(Path("lib.so"), Path("lib.so")), capabilities, "Linux")

    def test_runtime_selection_only_plans_selected_available_runtime(self):
        capabilities = self._capabilities()
        plan = build_plan(
            "node",
            NativeLibrary(Path("/native/libagentgate_ffi.so"), Path("/native/libagentgate_ffi.so")),
            capabilities,
            "Linux",
            Path("/repo"),
        )

        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0].argv[0], "/tools/node")
        self.assertIn("bindings/node/tests", plan[0].argv)

    def test_all_selection_skips_missing_runtime_but_rejects_bad_available_version(self):
        capabilities = self._capabilities()
        capabilities["go"] = Capability("Go", None, None)
        plan = build_plan(
            "all",
            NativeLibrary(Path("/native/libagentgate_ffi.so"), Path("/native/libagentgate_ffi.so")),
            capabilities,
            "Linux",
            Path("/repo"),
        )
        self.assertFalse(any(command.argv[0] == "/tools/go" for command in plan))

        capabilities["node"] = Capability("Node", "/tools/node", (21, 9, 0))
        with self.assertRaisesRegex(RunnerError, "Node version is below \(22,\)"):
            build_plan("all", NativeLibrary(Path("lib.so"), Path("lib.so")), capabilities, "Linux")

    def test_shared_library_discovery_rejects_static_libraries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            static = root / "libagentgate_ffi.a"
            static.write_bytes(b"archive")
            with self.assertRaisesRegex(RunnerError, "shared native library"):
                discover_library(root, static, "Linux")

    def test_windows_library_keeps_import_and_runtime_artifacts_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dll = root / "native path" / "agentgate_ffi.dll"
            import_library = dll.with_name("agentgate_ffi.dll.lib")
            dll.parent.mkdir()
            dll.write_bytes(b"dll")
            import_library.write_bytes(b"import")

            library = discover_library(root, import_library, "Windows")

            self.assertEqual(library.link_path, import_library.resolve())
            self.assertEqual(library.runtime_path, dll.resolve())

    def test_windows_release_commands_and_spaced_loader_paths(self):
        capabilities = self._capabilities()
        dll = Path("C:/AgentGate native/agentgate_ffi.dll")
        library = NativeLibrary(Path("C:/AgentGate native/agentgate_ffi.dll.lib"), dll)
        plan = build_plan("all", library, capabilities, "Windows", Path("C:/source tree"))

        java_build = next(command for command in plan if command.argv[:2] == ("/tools/cmake", "--build"))
        java_ctest = next(command for command in plan if command.argv[0] == "/tools/ctest")
        go = next(command for command in plan if command.argv[0] == "/tools/go")
        node = next(command for command in plan if command.argv[0] == "/tools/node")
        self.assertIn(("--config", "Release"), tuple(zip(java_build.argv, java_build.argv[1:])))
        self.assertIn(("-C", "Release"), tuple(zip(java_ctest.argv, java_ctest.argv[1:])))
        self.assertIn("--agentgate-library", go.argv)
        self.assertEqual(go.argv[go.argv.index("--agentgate-library") + 1], str(dll))
        self.assertEqual(dict(node.env)["AGENTGATE_LIBRARY_PATH"], str(dll))

    def test_go_unix_plan_links_and_loads_from_discovered_spaced_unicode_parent(self):
        capabilities = self._capabilities()
        parent = Path("/native path/镜像 Ω")
        library = NativeLibrary(
            parent / "libagentgate_ffi.dylib",
            parent / "libagentgate_ffi.dylib",
        )
        existing = {
            "CGO_LDFLAGS": "-Wl,-dead_strip",
            "DYLD_LIBRARY_PATH": "/existing runtime",
        }

        command = build_plan(
            "go",
            library,
            capabilities,
            "Darwin",
            Path("/source tree"),
            environment=existing,
        )[0]
        planned_environment = dict(command.env)

        self.assertEqual(
            shlex.split(planned_environment["CGO_LDFLAGS"]),
            ["-L" + str(parent), "-Wl,-dead_strip"],
        )
        self.assertEqual(
            planned_environment["DYLD_LIBRARY_PATH"],
            str(parent) + os.pathsep + existing["DYLD_LIBRARY_PATH"],
        )
        self.assertNotIn("LD_LIBRARY_PATH", planned_environment)

        calls = []
        run_command(
            command,
            lambda argv, **kwargs: calls.append((argv, kwargs))
            or type("Completed", (), {"returncode": 0})(),
        )
        self.assertEqual(
            calls[0][1]["env"]["CGO_LDFLAGS"],
            planned_environment["CGO_LDFLAGS"],
        )
        self.assertEqual(
            calls[0][1]["env"]["DYLD_LIBRARY_PATH"],
            planned_environment["DYLD_LIBRARY_PATH"],
        )

    def test_go_linux_plan_uses_ld_library_path_and_preserves_existing_values(self):
        parent = Path("/opt/agent gate")
        command = build_plan(
            "go",
            NativeLibrary(
                parent / "libagentgate_ffi.so",
                parent / "libagentgate_ffi.so",
            ),
            self._capabilities(),
            "Linux",
            environment={
                "CGO_LDFLAGS": "-pthread",
                "LD_LIBRARY_PATH": "/already/here",
            },
        )[0]
        environment = dict(command.env)

        self.assertEqual(
            shlex.split(environment["CGO_LDFLAGS"]),
            ["-L" + str(parent), "-pthread"],
        )
        self.assertEqual(
            environment["LD_LIBRARY_PATH"],
            str(parent) + os.pathsep + "/already/here",
        )
        self.assertNotIn("DYLD_LIBRARY_PATH", environment)

    def test_go_windows_plan_remains_runtime_loader_only(self):
        dll = Path("C:/native path/agentgate_ffi.dll")
        command = build_plan(
            "go",
            NativeLibrary(Path("C:/native path/agentgate_ffi.dll.lib"), dll),
            self._capabilities(),
            "Windows",
            environment={
                "CGO_LDFLAGS": "existing",
                "LD_LIBRARY_PATH": "existing-linux",
                "DYLD_LIBRARY_PATH": "existing-macos",
            },
        )[0]

        self.assertEqual(command.env, ())
        self.assertEqual(
            command.argv[command.argv.index("--agentgate-library") + 1],
            str(dll),
        )

    def test_run_command_reports_selected_runtime_failure(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return type("Completed", (), {"returncode": 7})()

        command = PlannedCommand(("/tool path/go", "test"), Path("/source path"), (("A", "B"),))
        with self.assertRaisesRegex(RunnerError, "command failed with exit code 7"):
            run_command(command, runner)
        self.assertEqual(calls[0][0], ["/tool path/go", "test"])
        self.assertEqual(calls[0][1]["cwd"], Path("/source path"))
        self.assertEqual(calls[0][1]["env"]["A"], "B")

    def test_dry_run_reports_planned_without_invoking_command(self):
        command = PlannedCommand(("/tools/go", "test"))

        status = run_command(
            command,
            lambda *args, **kwargs: self.fail("dry-run invoked a command"),
            dry_run=True,
        )

        self.assertEqual(status, "PLANNED")

    def test_run_command_wraps_process_launch_errors(self):
        command = PlannedCommand(("/safe/tool", "test"))

        with self.assertRaisesRegex(
            RunnerError,
            r"unable to run /safe/tool: executable disappeared",
        ):
            run_command(
                command,
                lambda *args, **kwargs: (_ for _ in ()).throw(
                    FileNotFoundError("executable disappeared")
                ),
            )

    def test_visible_status_lines_cover_missing_pass_planned_and_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "libagentgate_ffi.so"
            library.write_bytes(b"shared")

            def invoke(path, dry_run, returncode=0):
                messages = []
                args = argparse.Namespace(
                    runtime="go",
                    library=library,
                    phase5b_library=None,
                    dry_run=dry_run,
                )
                paths = {
                    "go": path,
                    "java": None,
                    "javac": None,
                    "node": None,
                    "cmake": None,
                    "ctest": None,
                }
                try:
                    result = run_phase5c(
                        args,
                        root=root,
                        platform_name=lambda: "Linux",
                        tool_lookup=paths.get,
                        version_output=lambda *args: "go version go1.24.0 linux/amd64",
                        command_runner=lambda *args, **kwargs: type(
                            "Completed", (), {"returncode": returncode}
                        )(),
                        reporter=messages.append,
                    )
                except RunnerError:
                    result = None
                return result, messages

            missing_result, missing = invoke(None, False)
            pass_result, passed = invoke("/tools/go", False)
            planned_result, planned = invoke("/tools/go", True)
            fail_result, failed = invoke("/tools/go", False, returncode=7)

            self.assertIsNone(missing_result)
            self.assertIn("phase5c: runtime=go status=MISSING", missing)
            self.assertEqual(pass_result, "PASS")
            self.assertIn("phase5c: runtime=go status=PASS", passed)
            self.assertIn("phase5c: overall status=PASS", passed)
            self.assertEqual(planned_result, "PLANNED")
            self.assertIn("phase5c: runtime=go status=PLANNED", planned)
            self.assertIn("phase5c: overall status=PLANNED", planned)
            self.assertIsNone(fail_result)
            self.assertIn("phase5c: runtime=go status=FAIL", failed)
            self.assertIn("phase5c: overall status=FAIL", failed)

    def test_main_labels_missing_library_as_missing_before_safe_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                exit_code = main(
                    ["--runtime", "go", "--library", str(root / "missing.so")],
                    root=root,
                    platform_name=lambda: "Linux",
                )

            lines = output.getvalue().splitlines()
            self.assertEqual(exit_code, 1)
            self.assertEqual(lines[0], "phase5c: runtime=go status=MISSING")
            self.assertEqual(lines[1], "phase5c: overall status=MISSING")
            self.assertIn("phase5c: native library not found:", lines[2])

    def test_main_labels_invalid_and_unsupported_preflight_as_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            static = root / "libagentgate_ffi.a"
            static.write_bytes(b"archive")
            cases = (
                (["--runtime", "node", "--library", str(static)], lambda: "Linux"),
                (["--runtime", "node"], lambda: "Plan9"),
            )

            for argv, platform_name in cases:
                with self.subTest(argv=argv):
                    output = io.StringIO()
                    with contextlib.redirect_stderr(output):
                        exit_code = main(
                            argv,
                            root=root,
                            platform_name=platform_name,
                        )

                    lines = output.getvalue().splitlines()
                    self.assertEqual(exit_code, 1)
                    self.assertEqual(lines[0], "phase5c: runtime=node status=FAIL")
                    self.assertEqual(lines[1], "phase5c: overall status=FAIL")
                    self.assertTrue(lines[2].startswith("phase5c: "))

    def test_cli_orchestration_uses_injected_platform_tools_versions_and_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "libagentgate_ffi.so"
            library.write_bytes(b"shared")
            calls = []
            args = argparse.Namespace(
                runtime="go",
                library=library,
                phase5b_library=library,
                dry_run=False,
            )
            paths = {"go": "/tools/go", "java": None, "javac": None, "node": None, "cmake": None, "ctest": None}

            status = run_phase5c(
                args,
                root=root,
                platform_name=lambda: "Linux",
                tool_lookup=paths.get,
                version_output=lambda path, *arguments: "go version go1.24.0 linux/amd64",
                command_runner=lambda argv, **kwargs: calls.append((argv, kwargs)) or type("Completed", (), {"returncode": 0})(),
            )

            self.assertEqual(calls[0][0][:2], [sys.executable, str(root / "scripts" / "test-phase5b.py")])
            self.assertEqual(calls[0][0][-2:], ["--library", str(library)])
            self.assertEqual(calls[1][0][0], "/tools/go")
            self.assertEqual(status, "PASS")

    def test_all_orchestration_reports_each_absent_runtime_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "libagentgate_ffi.so"
            library.write_bytes(b"shared")
            messages = []
            args = argparse.Namespace(runtime="all", library=library, phase5b_library=None, dry_run=True)
            paths = {
                "go": None,
                "java": None,
                "javac": None,
                "node": "/tools/node",
                "cmake": None,
                "ctest": None,
            }

            status = run_phase5c(
                args,
                root=root,
                platform_name=lambda: "Linux",
                tool_lookup=paths.get,
                version_output=lambda path, *arguments: "v22.5.0" if arguments == ("--version",) else "9",
                command_runner=lambda *args, **kwargs: self.fail("dry-run invoked a command"),
                reporter=messages.append,
            )

            self.assertEqual(status, "PLANNED")
            self.assertEqual(
                messages,
                [
                    "missing capability: Go 1.24+",
                    "missing capability: Java 17+",
                    "missing capability: Java compiler 17+",
                    "missing capability: CMake",
                    "missing capability: CTest",
                    "phase5c: runtime=go status=MISSING",
                    "phase5c: runtime=java status=MISSING",
                    "phase5c: runtime=node status=PLANNED",
                    "phase5c: overall status=PLANNED",
                ],
            )

    @staticmethod
    def _capabilities():
        return {
            "go": Capability("Go", "/tools/go", (1, 24, 1)),
            "java": Capability("Java", "/tools/java", (17, 0, 12)),
            "javac": Capability("Java compiler", "/tools/javac", (17, 0, 12)),
            "node": Capability("Node", "/tools/node", (22, 5, 0)),
            "node_api": Capability("Node-API", "/tools/node", (9,)),
            "cmake": Capability("CMake", "/tools/cmake", None),
            "ctest": Capability("CTest", "/tools/ctest", None),
        }


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", choices=("go", "java", "node", "all"), default="all")
    parser.add_argument("--library", type=Path, help="Phase 5C shared native library")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--phase5b-library",
        type=Path,
        help="run the Phase 5B harness first with this native library",
    )
    return parser.parse_args(argv)


def main(argv=None, **injections):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerSelfTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        status = run_phase5c(args, **injections)
    except RunnerError as error:
        print("phase5c: %s" % error, file=sys.stderr)
        return 1
    return 0 if status in {"PASS", "PLANNED"} else 1


if __name__ == "__main__":
    sys.exit(main())
