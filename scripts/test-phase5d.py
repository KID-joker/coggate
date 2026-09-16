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
import tempfile
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
    def test_abi_probes_reference_every_frozen_export(self):
        for extension in ("c", "cpp"):
            source = (
                ROOT / "tests" / "qualification" / f"abi_probe.{extension}"
            ).read_text(encoding="utf-8")
            source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
            source = re.sub(r"//.*$", "", source, flags=re.MULTILINE)
            references = set(
                re.findall(r"=\s*&?(ag_[A-Za-z0-9_]+)\s*;", source)
            )
            self.assertEqual(references, EXPECTED_EXPORTS)

    def test_symbol_parsers_accept_only_the_frozen_exports(self):
        darwin = "000 T _ag_abi_version\n000 T _ag_buffer_free\n"
        windows = (
            "  1    0 00001000 ag_abi_version\n"
            "  2    1 00001010 ag_buffer_free\n"
        )
        self.assertEqual(
            parse_nm_exports(darwin, darwin=True),
            {"ag_abi_version", "ag_buffer_free"},
        )
        self.assertEqual(
            parse_dumpbin_exports(windows), {"ag_abi_version", "ag_buffer_free"}
        )

    def test_nm_parser_handles_linux_format_and_rejects_noise(self):
        output = """\
0000000000001100 T ag_abi_version
0000000000001110 W ag_buffer_free
                 U ag_service_issue
0000000000001120 T unrelated_export
0000000000001130 T runtime_helper
0000000000001140 T ag-core-version
nm: archive member noise
"""
        self.assertEqual(
            parse_nm_exports(output), {"ag_abi_version", "ag_buffer_free"}
        )

    def test_nm_parser_strips_exactly_one_leading_underscore(self):
        output = """\
0000000000001100 T _ag_abi_version
0000000000001110 T __ag_buffer_free
"""
        self.assertEqual(
            parse_nm_exports(output, darwin=True), {"ag_abi_version"}
        )

    def test_nm_parser_only_normalizes_darwin_symbol_prefixes(self):
        output = "0000000000001100 T _ag_abi_version\n"
        self.assertEqual(parse_nm_exports(output), set())
        self.assertEqual(parse_nm_exports(output, darwin=True), {"ag_abi_version"})

    def test_dumpbin_parser_ignores_headers_ordinals_and_decorations(self):
        output = """\
Microsoft (R) COFF/PE Dumper Version 14.40

Dump of file agentgate_ffi.dll

  Section contains the following exports for agentgate_ffi.dll

    ordinal hint RVA      name

          1    0 00001000 ag_abi_version
          2    1 00001010 ag_buffer_free
          3    2 00001020 _ag_service_issue@8
          4    3 00001030 ag_service_verify.extra
          5    4 00001040 ag_service_issue@8 = FORWARDER.issue

  Summary
        1000 .data
"""
        self.assertEqual(
            parse_dumpbin_exports(output),
            {
                "ag_abi_version",
                "ag_buffer_free",
                "ag_service_issue@8",
                "ag_service_verify.extra",
            },
        )

    def test_decorated_public_export_is_unexpected_and_cannot_satisfy_exact_name(self):
        decorated = "ag_abi_version@@AGENTGATE_1"
        self.assertEqual(
            parse_nm_exports(f"0000000000001100 T {decorated}\n"),
            {decorated},
        )
        actual = (EXPECTED_EXPORTS - {"ag_abi_version"}) | {decorated}
        with self.assertRaises(RunnerError) as raised:
            validate_exports(actual)
        self.assertIn(
            "missing exports (1 total): ag_abi_version", str(raised.exception)
        )
        self.assertIn(
            f"unexpected exports (1 total): {decorated}", str(raised.exception)
        )

    def test_export_difference_is_fail_closed(self):
        with self.assertRaisesRegex(RunnerError, "unexpected exports"):
            validate_exports(EXPECTED_EXPORTS | {"ag_secret_debug"})
        with self.assertRaisesRegex(RunnerError, "missing exports"):
            validate_exports(EXPECTED_EXPORTS - {"ag_service_verify"})

    def test_export_difference_reports_sorted_missing_and_unexpected_names(self):
        actual = (
            EXPECTED_EXPORTS
            - {"ag_service_verify", "ag_buffer_free"}
            | {"ag_zeta_debug", "ag_alpha_debug"}
        )
        with self.assertRaises(RunnerError) as raised:
            validate_exports(actual)
        self.assertEqual(
            str(raised.exception),
            "missing exports (2 total): ag_buffer_free, ag_service_verify; "
            "unexpected exports (2 total): ag_alpha_debug, ag_zeta_debug",
        )

    def test_export_difference_bounds_large_sorted_diagnostics(self):
        actual = {f"ag_extra_{index:04d}" for index in range(1000)}
        with self.assertRaises(RunnerError) as raised:
            validate_exports(actual)
        diagnostic = str(raised.exception)
        self.assertIn("missing exports (7 total)", diagnostic)
        self.assertIn("unexpected exports (1000 total)", diagnostic)
        self.assertIn("ag_extra_0000", diagnostic)
        self.assertIn("ag_extra_0004", diagnostic)
        self.assertNotIn("ag_extra_0005", diagnostic)
        self.assertLess(len(diagnostic), 700)

    def test_symbol_command_selection_is_platform_specific(self):
        shared = Path("/qualified artifacts/libagentgate_ffi.so")
        self.assertEqual(
            symbol_inspection_command(
                Target.for_host("Linux", "x86_64"), shared
            ).argv,
            ("nm", "-D", "--defined-only", str(shared)),
        )
        darwin_shared = Path("/qualified artifacts/libagentgate_ffi.dylib")
        self.assertEqual(
            symbol_inspection_command(
                Target.for_host("Darwin", "x86_64"), darwin_shared
            ).argv,
            ("nm", "-gU", str(darwin_shared)),
        )
        windows_shared = Path("C:/qualified artifacts/agentgate_ffi.dll")
        self.assertEqual(
            symbol_inspection_command(
                Target.for_host("Windows", "AMD64"), windows_shared
            ).argv,
            ("dumpbin", "/exports", str(windows_shared)),
        )

    def test_symbol_inspection_captures_output_and_validates_exact_exports(self):
        command = symbol_inspection_command(
            Target.for_host("Linux", "x86_64"),
            Path("/qualified artifacts/libagentgate_ffi.so"),
        )
        output = "\n".join(
            f"0000000000001000 T {name}" for name in sorted(EXPECTED_EXPORTS)
        )
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout=output))
        self.assertEqual(
            run_symbol_inspection(command, "Linux", runner, windows=False), "PASS"
        )
        _, kwargs = runner.call_args
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], subprocess.STDOUT)
        self.assertTrue(kwargs["text"])
        self.assertFalse(kwargs["check"])
        self.assertFalse(kwargs["shell"])

    def test_symbol_inspection_rejects_nonzero_exit_before_parsing(self):
        command = symbol_inspection_command(
            Target.for_host("Windows", "AMD64"),
            Path("C:/qualified/agentgate_ffi.dll"),
        )
        runner = mock.Mock(return_value=mock.Mock(returncode=3, stdout="noise"))
        with self.assertRaisesRegex(RunnerError, r"dumpbin.*exit code 3"):
            run_symbol_inspection(command, "Windows", runner, windows=True)

    def test_linux_probe_plan_covers_strict_c_and_cpp_shared_and_static(self):
        root = Path("/repo with spaces")
        artifacts = Path("/qualified artifacts")
        build_root = Path("/temporary probe builds/unique")
        plan = abi_probe_plan(
            Target.for_host("Linux", "x86_64"),
            root,
            artifacts,
            complete_capabilities(),
            build_root,
        )
        self.assertEqual(len(plan), 8)
        compile_commands = plan[::2]
        run_commands = plan[1::2]
        self.assertEqual(
            [command.argv[0] for command in compile_commands],
            ["/tools/cc", "/tools/cxx", "/tools/cc", "/tools/cxx"],
        )
        self.assertIn("-std=c11", compile_commands[0].argv)
        self.assertIn("-std=c++17", compile_commands[1].argv)
        for command in compile_commands:
            for flag in ("-Wall", "-Wextra", "-Wpedantic", "-Werror"):
                self.assertIn(flag, command.argv)
            self.assertIn(str(root / "packages" / "ffi" / "include"), command.argv)
        self.assertIn(str(artifacts / "libagentgate_ffi.so"), compile_commands[0].argv)
        self.assertIn(str(artifacts / "libagentgate_ffi.a"), compile_commands[2].argv)
        self.assertIn("-DAGENTGATE_STATIC", compile_commands[2].argv)
        self.assertTrue(
            all(Path(command.argv[0]).parent == build_root for command in run_commands)
        )
        self.assertTrue(
            all(
                any(str(build_root) in argument for argument in command.argv)
                for command in compile_commands
            )
        )
        self.assertTrue(
            all(
                str(artifacts / "agentgate_abi_c_shared") not in command.argv
                for command in compile_commands
            )
        )
        self.assertEqual(
            dict(run_commands[0].env)["LD_LIBRARY_PATH"], str(artifacts)
        )
        self.assertNotIn("LD_LIBRARY_PATH", dict(run_commands[2].env))
        self.assertTrue(all(command.cwd == build_root for command in run_commands))

    def test_darwin_shared_probe_uses_qualified_runtime_directory(self):
        artifacts = Path("/qualified artifacts")
        build_root = Path("/temporary probe builds/unique")
        plan = abi_probe_plan(
            Target.for_host("Darwin", "x86_64"),
            Path("/repo"),
            artifacts,
            complete_capabilities(),
            build_root,
        )
        self.assertEqual(
            dict(plan[1].env)["DYLD_LIBRARY_PATH"], str(artifacts)
        )

    def test_windows_probe_plan_distinguishes_import_dll_and_static_library(self):
        root = Path("C:/repo with spaces")
        artifacts = Path("C:/qualified artifacts")
        build_root = Path("C:/temporary probe builds/unique")
        plan = abi_probe_plan(
            Target.for_host("Windows", "AMD64"),
            root,
            artifacts,
            complete_capabilities(),
            build_root,
        )
        self.assertEqual(len(plan), 8)
        c_shared, run_c_shared, cpp_shared, _, c_static, run_c_static, cpp_static, _ = plan
        self.assertIn("/std:c11", c_shared.argv)
        self.assertIn("/std:c++17", cpp_shared.argv)
        self.assertIn("/EHsc", cpp_shared.argv)
        for command in (c_shared, cpp_shared, c_static, cpp_static):
            self.assertIn("/W4", command.argv)
            self.assertIn("/WX", command.argv)
        self.assertIn(str(artifacts / "agentgate_ffi.dll.lib"), c_shared.argv)
        self.assertNotIn("/DAGENTGATE_STATIC", c_shared.argv)
        self.assertIn(str(artifacts / "agentgate_ffi.lib"), c_static.argv)
        self.assertIn("/DAGENTGATE_STATIC", c_static.argv)
        for command in (c_shared, cpp_shared, c_static, cpp_static):
            self.assertTrue(any(arg.startswith("/Fo") for arg in command.argv))
            self.assertTrue(any(arg.startswith("/Fe") for arg in command.argv))
            self.assertTrue(any(str(build_root) in arg for arg in command.argv))
        self.assertEqual(run_c_shared.cwd, build_root)
        self.assertEqual(run_c_static.cwd, build_root)
        self.assertEqual(Path(run_c_shared.argv[0]).parent, build_root)

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

    def test_compiler_capabilities_require_presence_without_version_probe(self):
        version_output = mock.Mock(
            side_effect=AssertionError("compiler version probe is not required")
        )
        capabilities = detect_capabilities(
            "Windows",
            lambda name: "/tools/cl" if name == "cl" else None,
            version_output,
        )
        self.assertEqual(capabilities["cc"], Capability("C compiler", "/tools/cl", None))
        self.assertEqual(
            capabilities["cxx"], Capability("C++ compiler", "/tools/cl", None)
        )
        version_output.assert_not_called()

    def test_qualification_plan_is_complete_and_ordered(self):
        artifact_directory = Path(
            "/repo/target with spaces/phase5d/x86_64-unknown-linux-gnu/release"
        )
        plan = qualification_plan(
            Target.for_host("Linux", "x86_64"),
            Path("/repo"),
            artifact_directory,
            complete_capabilities(),
            Path("/temporary probe builds/unique"),
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
        for command in plan[:4]:
            self.assertEqual(
                dict(command.env)["CARGO_TARGET_DIR"],
                str(artifact_directory.parent),
            )

    def test_cargo_target_directory_overrides_conflicting_parent_environment(self):
        artifact_directory = Path("/controlled target/release")
        command = qualification_plan(
            Target.for_host("Linux", "x86_64"),
            Path("/repo"),
            artifact_directory,
            complete_capabilities(),
            Path("/temporary probe builds/unique"),
        )[3]
        runner = mock.Mock(return_value=mock.Mock(returncode=0))
        with mock.patch.dict(
            os.environ, {"CARGO_TARGET_DIR": "/redirected elsewhere"}, clear=True
        ):
            run_command(command, runner, windows=False)
        self.assertEqual(
            runner.call_args.kwargs["env"]["CARGO_TARGET_DIR"],
            "/controlled target",
        )

    def test_run_qualification_validates_artifacts_between_build_and_wrappers(self):
        events = []

        def runner(argv, **kwargs):
            events.append(("command", tuple(argv)))
            output = ""
            if argv[0] == "nm":
                output = "\n".join(
                    f"0000000000001000 T {name}"
                    for name in sorted(EXPECTED_EXPORTS)
                )
            return mock.Mock(returncode=0, stdout=output)

        def path_is_file(path):
            events.append(("artifact", path.name))
            return True

        self.assertEqual(
            run_qualification(
                Target.for_host("Linux", "x86_64"),
                Path("/repo with spaces"),
                Path("/controlled target/release"),
                complete_capabilities(),
                command_runner=runner,
                path_is_file=path_is_file,
            ),
            "PASS",
        )
        build_index = events.index(
            ("command", ("cargo", "build", "-p", "agentgate-ffi", "--release"))
        )
        first_artifact_index = next(
            index for index, event in enumerate(events) if event[0] == "artifact"
        )
        symbol_index = next(
            index for index, event in enumerate(events)
            if event[0] == "command" and event[1][:3] == ("nm", "-D", "--defined-only")
        )
        first_probe_index = next(
            index for index, event in enumerate(events)
            if event[0] == "command" and "abi_probe.c" in " ".join(event[1])
        )
        phase5b_index = next(
            index for index, event in enumerate(events)
            if event[0] == "command" and "test-phase5b.py" in " ".join(event[1])
        )
        self.assertLess(build_index, first_artifact_index)
        self.assertLess(first_artifact_index, symbol_index)
        self.assertLess(symbol_index, first_probe_index)
        self.assertLess(first_probe_index, phase5b_index)

    def test_windows_qualification_stages_dll_beside_temporary_probes(self):
        artifact_directory = Path("C:/qualified artifacts")
        temporary_roots = []
        staged = []
        calls = []

        def temporary_directory(**kwargs):
            context = tempfile.TemporaryDirectory(**kwargs)
            temporary_roots.append(Path(context.name))
            return context

        def runner(argv, **kwargs):
            calls.append((tuple(argv), kwargs))
            output = ""
            if argv[0] == "dumpbin":
                output = "\n".join(
                    f"{index} {index:X} 00001000 {name}"
                    for index, name in enumerate(sorted(EXPECTED_EXPORTS), 1)
                )
            return mock.Mock(returncode=0, stdout=output)

        with mock.patch.dict(os.environ, {"BASE": "yes"}, clear=True):
            self.assertEqual(
                run_qualification(
                    Target.for_host("Windows", "AMD64"),
                    Path("C:/repo with spaces"),
                    artifact_directory,
                    complete_capabilities(),
                    command_runner=runner,
                    path_is_file=lambda path: True,
                    temporary_directory=temporary_directory,
                    copy_file=lambda source, destination: staged.append(
                        (Path(source), Path(destination))
                    ),
                ),
                "PASS",
            )

        self.assertEqual(len(temporary_roots), 1)
        probe_root = temporary_roots[0]
        self.assertEqual(
            staged,
            [
                (
                    artifact_directory / "agentgate_ffi.dll",
                    probe_root / "agentgate_ffi.dll",
                )
            ],
        )
        shared_runs = [
            kwargs
            for argv, kwargs in calls
            if Path(argv[0]).name in {
                "agentgate_abi_c_shared.exe",
                "agentgate_abi_cpp_shared.exe",
            }
        ]
        self.assertEqual(len(shared_runs), 2)
        self.assertTrue(all(kwargs["cwd"] == probe_root for kwargs in shared_runs))
        self.assertTrue(all("PATH" not in kwargs["env"] for kwargs in shared_runs))
        self.assertFalse(probe_root.exists())

    def test_probe_build_directory_is_cleaned_after_command_failure(self):
        temporary_roots = []

        def temporary_directory(**kwargs):
            context = tempfile.TemporaryDirectory(**kwargs)
            temporary_roots.append(Path(context.name))
            return context

        def runner(argv, **kwargs):
            output = ""
            if argv[0] == "nm":
                output = "\n".join(
                    f"0000000000001000 T {name}"
                    for name in sorted(EXPECTED_EXPORTS)
                )
            returncode = 9 if any("abi_probe.c" in arg for arg in argv) else 0
            return mock.Mock(returncode=returncode, stdout=output)

        with self.assertRaisesRegex(RunnerError, "exit code 9"):
            run_qualification(
                Target.for_host("Linux", "x86_64"),
                Path("/repo"),
                Path("/qualified artifacts"),
                complete_capabilities(),
                command_runner=runner,
                path_is_file=lambda path: True,
                temporary_directory=temporary_directory,
            )
        self.assertEqual(len(temporary_roots), 1)
        self.assertFalse(temporary_roots[0].exists())

    def test_dry_run_cleans_temporary_probe_plan_without_staging(self):
        temporary_roots = []

        def temporary_directory(**kwargs):
            context = tempfile.TemporaryDirectory(**kwargs)
            temporary_roots.append(Path(context.name))
            return context

        runner = mock.Mock(side_effect=AssertionError("dry run executed a command"))
        copy_file = mock.Mock(side_effect=AssertionError("dry run staged a DLL"))
        path_is_file = mock.Mock(
            side_effect=AssertionError("dry run validated artifacts")
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                run_qualification(
                    Target.for_host("Windows", "AMD64"),
                    Path("C:/repo"),
                    Path("C:/qualified artifacts"),
                    complete_capabilities(),
                    command_runner=runner,
                    dry_run=True,
                    path_is_file=path_is_file,
                    temporary_directory=temporary_directory,
                    copy_file=copy_file,
                ),
                "PLANNED",
            )
        runner.assert_not_called()
        copy_file.assert_not_called()
        path_is_file.assert_not_called()
        self.assertEqual(len(temporary_roots), 1)
        self.assertFalse(temporary_roots[0].exists())

    def test_artifact_gate_tracks_phase5b_boundary_without_magic_index(self):
        events = []
        plan = [
            PlannedCommand(("cargo", "build"), Path("/repo")),
            PlannedCommand(("tool", "extra-check"), Path("/repo")),
            PlannedCommand(
                ("/tools/python", "/repo/scripts/test-phase5b.py", "--library", "lib"),
                Path("/repo"),
            ),
        ]

        def runner(argv, **kwargs):
            events.append(("command", tuple(argv)))
            return mock.Mock(returncode=0)

        def path_is_file(path):
            events.append(("artifact", path.name))
            return True

        with mock.patch.object(
            sys.modules[__name__], "qualification_plan", return_value=plan
        ):
            run_qualification(
                Target.for_host("Linux", "x86_64"),
                Path("/repo"),
                Path("/target/release"),
                complete_capabilities(),
                command_runner=runner,
                path_is_file=path_is_file,
            )
        phase5b_index = events.index(("command", plan[-1].argv))
        artifact_indexes = [
            index for index, event in enumerate(events) if event[0] == "artifact"
        ]
        self.assertTrue(artifact_indexes)
        self.assertLess(max(artifact_indexes), phase5b_index)

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
        expected["cc"] = Capability("C compiler", "/tools/cc", None)
        expected["cxx"] = Capability("C++ compiler", "/tools/cxx", None)
        self.assertEqual(
            {key: capability.version for key, capability in capabilities.items()},
            {key: capability.version for key, capability in expected.items()},
        )
        self.assertEqual(
            {key: capability.name for key, capability in capabilities.items()},
            {key: capability.name for key, capability in expected.items()},
        )

    def test_tool_version_parser_ignores_warning_prefix_numbers(self):
        self.assertEqual(
            parse_tool_version(
                "java",
                'JAVA_TOOL_OPTIONS: -Dbuild.year=2022\nopenjdk version "17.0.12"',
            ),
            (17, 0, 12),
        )
        self.assertEqual(
            parse_tool_version(
                "maven",
                "launcher warning: Java 8 selected\n  \x1b[1mApache Maven 3.9.9\x1b[0m",
            ),
            (3, 9, 9),
        )
        self.assertEqual(
            parse_tool_version(
                "java",
                'warning: launcher 8\n  \x1b[32mopenjdk version "17.0.12"\x1b[0m',
            ),
            (17, 0, 12),
        )

    def test_nonzero_version_probe_rejects_parseable_banner(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / "version probe.py"
            probe.write_text(
                "import sys\nprint('tool 99.0.0')\nprint('diagnostic ' + 'x' * 1000)\nsys.exit(7)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RunnerError, r"version probe.*exit code 7.*tool 99\.0\.0"
            ) as raised:
                _version_output(sys.executable, str(probe))
        self.assertLess(len(str(raised.exception)), 800)

    def test_windows_version_probe_error_uses_native_command_rendering(self):
        completed = mock.Mock(returncode=7, stdout="tool 99.0.0")
        with mock.patch.object(
            subprocess, "run", return_value=completed
        ), mock.patch.object(
            platform, "system", return_value="Windows"
        ), self.assertRaises(RunnerError) as raised:
            _version_output("C:\\Program Files\\tool.exe", "--version")
        self.assertIn(
            subprocess.list2cmdline(["C:\\Program Files\\tool.exe", "--version"]),
            str(raised.exception),
        )

    def test_windows_plan_uses_import_library_for_phase5b_and_dll_for_phase5c(self):
        root = Path("C:/repo")
        artifacts = Path("C:/artifacts")
        plan = qualification_plan(
            Target.for_host("Windows", "AMD64"), root, artifacts,
            complete_capabilities(),
            Path("C:/temporary probe builds/unique"),
        )
        phase5b_dynamic = next(
            command for command in plan
            if "test-phase5b.py" in " ".join(command.argv)
            and "--static" not in command.argv
        )
        phase5c = next(
            command for command in plan
            if "test-phase5c.py" in " ".join(command.argv)
        )
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

    def test_nonzero_command_error_names_command_and_exit_code(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
            RunnerError, r"tool.*exit code 9"
        ):
            run_command(
                PlannedCommand(("tool", "arg"), Path("/repo")),
                mock.Mock(return_value=mock.Mock(returncode=9)),
                windows=False,
            )

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
        for stage in ("all", "sanitizers", "artifact"):
            with self.subTest(stage=stage), self.assertRaisesRegex(
                RunnerError, f"Phase 5D stage is not implemented: {stage}"
            ):
                main(["--stage", stage], system="Linux", arch="x86_64")

    def test_all_fails_before_discovery_execution_or_success_output(self):
        tool_lookup = mock.Mock(side_effect=AssertionError("unexpected tool lookup"))
        version_output = mock.Mock(side_effect=AssertionError("unexpected probe"))
        command_runner = mock.Mock(side_effect=AssertionError("unexpected command"))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaisesRegex(
            RunnerError, "Phase 5D stage is not implemented: all"
        ):
            main(
                ["--stage", "all"],
                system="Linux",
                arch="x86_64",
                tool_lookup=tool_lookup,
                version_output=version_output,
                command_runner=command_runner,
            )
        tool_lookup.assert_not_called()
        version_output.assert_not_called()
        command_runner.assert_not_called()
        self.assertNotIn("PASS", stdout.getvalue())

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
    purpose: str = "command"


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

EXPECTED_EXPORTS = frozenset(
    {
        "ag_abi_version",
        "ag_buffer_free",
        "ag_core_version",
        "ag_service_create",
        "ag_service_destroy",
        "ag_service_issue",
        "ag_service_verify",
    }
)

PUBLIC_EXPORT_PREFIX = "ag_"
MAX_REPORTED_EXPORTS = 5
MAX_REPORTED_EXPORT_NAME_LENGTH = 48
NM_EXPORT_LINE = re.compile(
    r"^\s*[0-9A-Fa-f]+\s+([A-Za-z])\s+(\S+)\s*$"
)
DUMPBIN_EXPORT_LINE = re.compile(
    r"^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)(?:\s+.*)?$"
)


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


TOOL_VERSION_PATTERNS = {
    "cargo": r"^cargo\s+(\d+(?:\.\d+)*)",
    "rustc": r"^rustc\s+(\d+(?:\.\d+)*)",
    "python": r"^Python\s+(\d+(?:\.\d+)*)",
    "go": r"^go version go(\d+(?:\.\d+)*)",
    "java": r"^(?:openjdk|java) version\s+[\"']?(\d+(?:\.\d+)*)",
    "javac": r"^javac\s+(\d+(?:\.\d+)*)",
    "cmake": r"^cmake version\s+(\d+(?:\.\d+)*)",
    "ctest": r"^ctest version\s+(\d+(?:\.\d+)*)",
    "maven": r"^Apache Maven\s+(\d+(?:\.\d+)*)",
    "node": r"^v(\d+(?:\.\d+)*)",
    "node_api": r"^\s*(\d+(?:\.\d+)*)\s*$",
    "node_gyp": r"^v(\d+(?:\.\d+)*)",
}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def parse_tool_version(tool: str, output: str) -> tuple[int, ...] | None:
    pattern = TOOL_VERSION_PATTERNS[tool]
    normalized_output = "\n".join(
        line.lstrip() for line in ANSI_ESCAPE.sub("", output).splitlines()
    )
    match = re.search(
        pattern, normalized_output, flags=re.IGNORECASE | re.MULTILINE
    )
    if match is None:
        return None
    return parse_version(match.group(1))


def _bounded_diagnostic(output: str, limit: int = 512) -> str:
    diagnostic = " ".join(output.split())
    if not diagnostic:
        return "no output"
    if len(diagnostic) > limit:
        return diagnostic[:limit] + "..."
    return diagnostic


def _format_command(argv: tuple[str, ...] | list[str], windows: bool | None = None) -> str:
    if windows is None:
        windows = platform.system() == "Windows"
    return subprocess.list2cmdline(list(argv)) if windows else shlex.join(argv)


def _version_output(path: str, *arguments: str) -> str:
    completed = subprocess.run(
        [path, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        command = _format_command([path, *arguments])
        raise RunnerError(
            f"version probe failed for {command} with exit code "
            f"{completed.returncode}: {_bounded_diagnostic(completed.stdout)}"
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
    }
    paths = {key: tool_lookup(executable) for key, executable in executables.items()}
    if paths["python"] is None:
        paths["python"] = tool_lookup("python")

    def detected(key: str) -> Capability:
        path = paths[key]
        if path is None:
            return Capability(CAPABILITY_NAMES[key], None, None)
        if key in {"cc", "cxx"}:
            return Capability(CAPABILITY_NAMES[key], path, None)
        try:
            version = parse_tool_version(
                key, version_output(path, *version_arguments[key])
            )
        except (OSError, subprocess.SubprocessError):
            version = None
        return Capability(CAPABILITY_NAMES[key], path, version)

    capabilities = {key: detected(key) for key in executables}
    node_path = paths["node"]
    if node_path is None:
        capabilities["node_api"] = Capability("Node-API", None, None)
    else:
        try:
            node_api_version = parse_tool_version(
                "node_api",
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


def parse_nm_exports(output: str, *, darwin: bool = False) -> set[str]:
    exports = set()
    for line in output.splitlines():
        match = NM_EXPORT_LINE.fullmatch(line)
        if match is None or match.group(1).casefold() == "u":
            continue
        name = match.group(2)
        if darwin and name.startswith("_"):
            name = name[1:]
        if name.startswith(PUBLIC_EXPORT_PREFIX):
            exports.add(name)
    return exports


def parse_dumpbin_exports(output: str) -> set[str]:
    exports = set()
    for line in output.splitlines():
        match = DUMPBIN_EXPORT_LINE.fullmatch(line)
        if match is None:
            continue
        name = match.group(1)
        if name.startswith(PUBLIC_EXPORT_PREFIX):
            exports.add(name)
    return exports


def _format_export_difference(label: str, names: list[str]) -> str:
    displayed = []
    for name in names[:MAX_REPORTED_EXPORTS]:
        if len(name) > MAX_REPORTED_EXPORT_NAME_LENGTH:
            name = name[: MAX_REPORTED_EXPORT_NAME_LENGTH - 3] + "..."
        displayed.append(name)
    suffix = ", ..." if len(names) > MAX_REPORTED_EXPORTS else ""
    return f"{label} ({len(names)} total): {', '.join(displayed)}{suffix}"


def validate_exports(actual: set[str] | frozenset[str]) -> None:
    missing = sorted(EXPECTED_EXPORTS - set(actual))
    unexpected = sorted(set(actual) - EXPECTED_EXPORTS)
    differences = []
    if missing:
        differences.append(_format_export_difference("missing exports", missing))
    if unexpected:
        differences.append(_format_export_difference("unexpected exports", unexpected))
    if differences:
        raise RunnerError("; ".join(differences))


def symbol_inspection_command(
    target: Target, shared_library: Path
) -> PlannedCommand:
    shared_library = Path(shared_library)
    if target.system == "Darwin":
        argv = ("nm", "-gU", str(shared_library))
    elif target.system == "Linux":
        argv = ("nm", "-D", "--defined-only", str(shared_library))
    elif target.system == "Windows":
        argv = ("dumpbin", "/exports", str(shared_library))
    else:
        raise RunnerError(f"unsupported platform: {target.system}")
    return PlannedCommand(argv, shared_library.parent, purpose="symbol-inspection")


def _probe_output_path(
    target: Target, build_directory: Path, language: str, linkage: str
) -> Path:
    suffix = ".exe" if target.system == "Windows" else ""
    return build_directory / f"agentgate_abi_{language}_{linkage}{suffix}"


def _probe_compile_command(
    target: Target,
    root: Path,
    artifact_directory: Path,
    capabilities: dict[str, Capability],
    build_directory: Path,
    language: str,
    linkage: str,
) -> PlannedCommand:
    is_cpp = language == "cpp"
    compiler_key = "cxx" if is_cpp else "cc"
    compiler = capabilities[compiler_key].path
    if compiler is None:
        label = "C++" if is_cpp else "C"
        raise RunnerError(f"required capability: {label} compiler")
    source = root / "tests" / "qualification" / f"abi_probe.{language}"
    output = _probe_output_path(target, build_directory, language, linkage)
    library_name = target.shared_name if linkage == "shared" else target.static_name
    library = artifact_directory / library_name
    include_directory = root / "packages" / "ffi" / "include"

    if target.system == "Windows":
        link_library = (
            artifact_directory / target.import_name
            if linkage == "shared" and target.import_name is not None
            else library
        )
        arguments = [
            compiler,
            "/nologo",
            "/std:c++17" if is_cpp else "/std:c11",
        ]
        if is_cpp:
            arguments.append("/EHsc")
        arguments.extend(["/W4", "/WX", f"/I{include_directory}"])
        if linkage == "static":
            arguments.append("/DAGENTGATE_STATIC")
        object_path = build_directory / f"agentgate_abi_{language}_{linkage}.obj"
        arguments.extend(
            [str(source), f"/Fo{object_path}", f"/Fe{output}", str(link_library)]
        )
    else:
        arguments = [
            compiler,
            "-std=c++17" if is_cpp else "-std=c11",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
            str(include_directory),
        ]
        if linkage == "static":
            arguments.append("-DAGENTGATE_STATIC")
        arguments.extend([str(source), "-o", str(output), str(library)])
        if linkage == "shared":
            arguments.append("-Wl,-rpath," + str(artifact_directory))
        if target.system == "Linux":
            arguments.extend(["-ldl", "-lpthread", "-lm"])
    return PlannedCommand(
        tuple(arguments),
        build_directory,
        purpose=f"abi-probe-compile-{language}-{linkage}",
    )


def abi_probe_plan(
    target: Target,
    root: Path,
    artifact_directory: Path,
    capabilities: dict[str, Capability],
    build_directory: Path,
) -> list[PlannedCommand]:
    root = Path(root)
    artifact_directory = Path(artifact_directory)
    build_directory = Path(build_directory)
    commands = []
    for linkage in ("shared", "static"):
        for language in ("c", "cpp"):
            compile_command = _probe_compile_command(
                target,
                root,
                artifact_directory,
                capabilities,
                build_directory,
                language,
                linkage,
            )
            output = _probe_output_path(
                target, build_directory, language, linkage
            )
            runtime_environment = ()
            if linkage == "shared" and target.system == "Linux":
                runtime_environment = (("LD_LIBRARY_PATH", str(artifact_directory)),)
            elif linkage == "shared" and target.system == "Darwin":
                runtime_environment = (("DYLD_LIBRARY_PATH", str(artifact_directory)),)
            commands.extend(
                [
                    compile_command,
                    PlannedCommand(
                        (str(output),),
                        build_directory,
                        runtime_environment,
                        purpose=f"abi-probe-run-{language}-{linkage}",
                    ),
                ]
            )
    return commands


def qualification_plan(
    target: Target,
    root: Path,
    artifact_directory: Path,
    capabilities: dict[str, Capability],
    probe_build_directory: Path,
) -> list[PlannedCommand]:
    root = Path(root)
    artifact_directory = Path(artifact_directory)
    probe_build_directory = Path(probe_build_directory)
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
    cargo_environment = (("CARGO_TARGET_DIR", str(artifact_directory.parent)),)
    cargo_commands = [
        PlannedCommand(("cargo", "fmt", "--check"), root, cargo_environment),
        PlannedCommand(
            ("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"),
            root,
            cargo_environment,
        ),
        PlannedCommand(
            ("cargo", "test", "--workspace"), root, cargo_environment
        ),
        PlannedCommand(
            ("cargo", "build", "-p", "agentgate-ffi", "--release"),
            root,
            cargo_environment,
        ),
    ]
    native_qualification_commands = [
        symbol_inspection_command(target, shared_library),
        *abi_probe_plan(
            target,
            root,
            artifact_directory,
            capabilities,
            probe_build_directory,
        ),
    ]
    wrapper_commands = [
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
    return cargo_commands + native_qualification_commands + wrapper_commands


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
    formatted = _format_command(command.argv, windows)
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
        raise RunnerError(
            f"command failed: {formatted} (exit code {completed.returncode})"
        )
    return "PASS"


def run_symbol_inspection(
    command: PlannedCommand,
    system: str,
    command_runner=subprocess.run,
    dry_run: bool = False,
    windows: bool | None = None,
) -> str:
    if windows is None:
        windows = platform.system() == "Windows"
    formatted = _format_command(command.argv, windows)
    print("+ " + formatted)
    if dry_run:
        return "PLANNED"
    try:
        completed = command_runner(
            list(command.argv),
            cwd=command.cwd,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerError(f"unable to run {command.argv[0]}: {error}") from error
    if completed.returncode != 0:
        raise RunnerError(
            f"command failed: {formatted} (exit code {completed.returncode}): "
            f"{_bounded_diagnostic(completed.stdout)}"
        )
    if system == "Windows":
        exports = parse_dumpbin_exports(completed.stdout)
    else:
        exports = parse_nm_exports(completed.stdout, darwin=system == "Darwin")
    validate_exports(exports)
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
    temporary_directory=tempfile.TemporaryDirectory,
    copy_file=shutil.copy2,
) -> str:
    require_ci_capabilities(capabilities)
    with temporary_directory(prefix="agentgate-phase5d-abi-") as directory:
        probe_build_directory = Path(directory)
        plan = qualification_plan(
            target,
            root,
            artifact_directory,
            capabilities,
            probe_build_directory,
        )
        artifacts_validated = False
        runtime_staged = False
        for command in plan:
            starts_phase5b = any(
                argument.replace("\\", "/").endswith("/test-phase5b.py")
                for argument in command.argv
            )
            starts_native_qualification = command.purpose == "symbol-inspection"
            starts_abi_probe = command.purpose.startswith("abi-probe-")
            if (
                (starts_native_qualification or starts_phase5b)
                and not artifacts_validated
                and not dry_run
            ):
                validate_artifacts(target, artifact_directory, path_is_file)
                artifacts_validated = True
            if (
                target.system == "Windows"
                and starts_abi_probe
                and not runtime_staged
                and not dry_run
            ):
                source = Path(artifact_directory) / target.shared_name
                destination = probe_build_directory / target.shared_name
                try:
                    copy_file(source, destination)
                except OSError as error:
                    raise RunnerError(
                        f"unable to stage qualified DLL {source}: {error}"
                    ) from error
                runtime_staged = True
            if starts_native_qualification:
                run_symbol_inspection(
                    command,
                    target.system,
                    command_runner,
                    dry_run=dry_run,
                    windows=target.system == "Windows",
                )
            else:
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
    if arguments.stage in {"all", "sanitizers", "artifact"}:
        raise RunnerError(f"Phase 5D stage is not implemented: {arguments.stage}")
    if arguments.ci:
        if arguments.stage is None:
            raise RunnerError("Phase 5D CI requires an explicit stage")

    if arguments.stage == "qualification":
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
