#!/usr/bin/env python3
"""Build and run the Phase 5B direct-wrapper tests."""

import argparse
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIR = ROOT / "packages" / "ffi" / "include"
BINDINGS_DIR = ROOT / "bindings"
FIXTURE_PATH = (ROOT / "fixtures" / "bindings" / "v1.json").resolve()


class RunnerError(Exception):
    pass


def platform_library_name(system, static=False):
    names = (
        {
            "Linux": "libcoggate_ffi.a",
            "Darwin": "libcoggate_ffi.a",
            "Windows": "coggate_ffi.lib",
        }
        if static
        else {
            "Linux": "libcoggate_ffi.so",
            "Darwin": "libcoggate_ffi.dylib",
            "Windows": "coggate_ffi.dll.lib",
        }
    )
    try:
        return names[system]
    except KeyError:
        raise RunnerError("unsupported platform: %s" % system)


def discover_library(root, explicit, system, static=False):
    if explicit is not None:
        candidate = explicit if explicit.is_absolute() else root / explicit
    else:
        candidate = root / "target" / "release" / platform_library_name(system, static)
    if not candidate.is_file():
        raise RunnerError("native library not found: %s" % candidate)
    return candidate.resolve()


def capability_messages(tools, python_version):
    messages = []
    if not tools.get("cmake"):
        messages.append("missing capability: CMake")
    if not tools.get("cc"):
        messages.append("missing capability: C compiler")
    if not tools.get("cxx"):
        messages.append("missing capability: C++ compiler")
    if python_version < (3, 11):
        messages.append(
            "missing capability: Python 3.11+ (running %d.%d)" % python_version[:2]
        )
    return messages


def _find_tool(environment_name, fallback):
    configured = os.environ.get(environment_name)
    if configured:
        return shutil.which(configured)
    return shutil.which(fallback)


def detect_tools(system):
    msvc = system == "Windows"
    return {
        "cmake": shutil.which("cmake"),
        "cc": _find_tool("CC", "cl" if msvc else "cc"),
        "cxx": _find_tool("CXX", "cl" if msvc else "c++"),
    }


def partition_sources(sources):
    sources = list(sources)
    support_names = {"harness", "support"}
    support = sorted(
        source
        for source in sources
        if source.stem in support_names or source.stem.endswith("_support")
    )
    entries = sorted(source for source in sources if source not in support)
    return entries, support


def source_groups(directory, extension):
    tests, test_support = partition_sources((directory / "tests").glob("*" + extension))
    examples, example_support = partition_sources(
        (directory / "examples").glob("*" + extension)
    )
    return tests, examples, test_support, example_support


def _sources(language):
    extension = ".c" if language == "c" else ".cpp"
    return source_groups(BINDINGS_DIR / language, extension)


def _run(command, dry_run=False, cwd=None, env=None):
    print("+ " + shlex.join([str(part) for part in command]))
    if dry_run:
        return
    completed = subprocess.run(
        [str(part) for part in command], cwd=cwd, env=env, shell=False
    )
    if completed.returncode != 0:
        raise RunnerError("command failed with exit code %d" % completed.returncode)


def _warning(message):
    print(message, file=sys.stderr)


def windows_library_artifacts(library, static):
    if static:
        return library, None
    name = library.name.lower()
    if name.endswith(".dll.lib"):
        import_library = library
        runtime_library = library.with_name(library.name[:-4])
    elif name.endswith(".dll"):
        runtime_library = library
        candidates = [
            library.with_name(library.name + ".lib"),
            library.with_suffix(".lib"),
        ]
        import_library = next((path for path in candidates if path.is_file()), None)
        if import_library is None:
            raise RunnerError("Windows import library not found beside DLL")
    else:
        raise RunnerError("Windows shared library must be a .dll or .dll.lib")
    if not runtime_library.is_file():
        raise RunnerError("Windows runtime DLL not found: %s" % runtime_library)
    return import_library.resolve(), runtime_library.resolve()


def _cmake_build(library, runtime_library, static, dry_run, system):
    with tempfile.TemporaryDirectory(prefix="coggate-phase5b-cmake-") as directory:
        build = Path(directory)
        configure = [
            "cmake",
            "-S",
            BINDINGS_DIR,
            "-B",
            build,
            "-DCOGGATE_INCLUDE_DIR=" + str(INCLUDE_DIR),
            "-DCOGGATE_LIBRARY=" + str(library),
            "-DCOGGATE_STATIC=" + ("ON" if static else "OFF"),
        ]
        if runtime_library is not None:
            configure.append("-DCOGGATE_RUNTIME_LIBRARY=" + str(runtime_library))
        _run(configure, dry_run)
        build_command = ["cmake", "--build", build]
        ctest_command = ["ctest", "--output-on-failure"]
        if system == "Windows":
            build_command.extend(["--config", "Release"])
            ctest_command.extend(["-C", "Release"])
        _run(build_command, dry_run)
        if any(_sources(language)[0] for language in ("c", "cpp")):
            _run(ctest_command, dry_run, cwd=build)


def _nlohmann_include_dir():
    configured = os.environ.get("NLOHMANN_JSON_INCLUDE_DIR")
    if not configured:
        raise RunnerError(
            "NLOHMANN_JSON_INCLUDE_DIR is required for direct C++ builds"
        )
    include_dir = Path(configured)
    if not (include_dir / "nlohmann" / "json.hpp").is_file():
        raise RunnerError(
            "NLOHMANN_JSON_INCLUDE_DIR does not contain nlohmann/json.hpp: %s"
            % include_dir
        )
    return include_dir.resolve()


def _direct_flags(
    language, library, system, static, nlohmann_include=None
):
    flags = [
        "-std=c11" if language == "c" else "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-I",
        INCLUDE_DIR,
    ]
    if language == "cpp":
        flags.extend(["-I", BINDINGS_DIR / "cpp" / "include"])
        flags.extend(
            ["-I", nlohmann_include or _nlohmann_include_dir()]
        )
        fixture_path = str(FIXTURE_PATH).replace("\\", "/")
        flags.append('-DCOGGATE_BINDING_FIXTURE_PATH="' + fixture_path + '"')
    if static:
        flags.append("-DCOGGATE_STATIC")
    flags.append(library)
    if not static:
        flags.append("-Wl,-rpath," + str(library.parent))
    if system == "Linux":
        flags.extend(["-ldl", "-lpthread", "-lm"])
    return flags


def _environment_flags(name):
    value = os.environ.get(name, "")
    try:
        return shlex.split(value)
    except ValueError as error:
        raise RunnerError(f"invalid {name}: {error}") from error


def _direct_build(library, tools, system, static, dry_run):
    groups = {language: _sources(language) for language in ("c", "cpp")}
    language_flags = {
        "c": _environment_flags("CFLAGS"),
        "cpp": _environment_flags("CXXFLAGS"),
    }
    link_flags = _environment_flags("LDFLAGS")
    cpp_tests, cpp_examples, _, _ = groups["cpp"]
    nlohmann_include = (
        _nlohmann_include_dir() if cpp_tests or cpp_examples else None
    )
    with tempfile.TemporaryDirectory(prefix="coggate-phase5b-native-") as directory:
        build = Path(directory)
        for language, compiler_key in (("c", "cc"), ("cpp", "cxx")):
            tests, examples, test_support, example_support = groups[language]
            sources = tests + examples
            if sources and not tools[compiler_key]:
                label = "C" if language == "c" else "C++"
                raise RunnerError("missing capability: %s compiler" % label)
            for source in sources:
                output = build / (language + "-" + source.stem)
                command = [tools[compiler_key], source]
                command.extend(language_flags[language])
                command.extend(test_support if source in tests else example_support)
                command.extend(["-o", output])
                command.extend(
                    _direct_flags(
                        language,
                        library,
                        system,
                        static,
                        nlohmann_include,
                    )
                )
                command.extend(link_flags)
                _run(command, dry_run)
                if source in tests or source in examples:
                    _run([output], dry_run)


def run_phase5b(args):
    system = args.system or platform.system()
    direct_native = getattr(args, "direct_native", False)
    if direct_native and system == "Windows":
        raise RunnerError("--direct-native is not supported on Windows")
    tools = detect_tools(system)
    for message in capability_messages(tools, sys.version_info[:2]):
        _warning(message)
    library = discover_library(ROOT, args.library, system, args.static)
    static = args.static or (
        library.suffix in {".a", ".lib"}
        and not library.name.endswith(".dll.lib")
    )

    runtime_library = None
    if system == "Windows":
        if not tools["cmake"]:
            raise RunnerError("Windows native tests require CMake and MSVC")
        library, runtime_library = windows_library_artifacts(library, static)
        _cmake_build(library, runtime_library, static, args.dry_run, system)
    elif direct_native:
        _direct_build(library, tools, system, static, args.dry_run)
    elif tools["cmake"]:
        _cmake_build(library, None, static, args.dry_run, system)
    else:
        _warning("using direct compiler fallback because CMake is unavailable")
        _direct_build(library, tools, system, static, args.dry_run)

    if not args.native_only:
        if static:
            raise RunnerError(
                "Python ctypes tests require a shared native library; "
                "use --native-only with --static"
            )
        if sys.version_info < (3, 11):
            raise RunnerError("missing capability: Python 3.11+")
        python_environment = os.environ.copy()
        if not static:
            python_environment["COGGATE_LIBRARY_PATH"] = str(
                runtime_library or library
            )
        _run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                ROOT / "bindings" / "python" / "tests",
                "-v",
            ],
            args.dry_run,
            cwd=ROOT,
            env=python_environment,
        )
        _run(
            [
                sys.executable,
                ROOT / "bindings" / "python" / "examples" / "complete.py",
            ],
            args.dry_run,
            cwd=ROOT,
            env=python_environment,
        )


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--library", type=Path)
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--direct-native", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--system", choices=["Linux", "Darwin", "Windows"], help=argparse.SUPPRESS)
    return parser.parse_args(argv)

class RunnerSelfTests(unittest.TestCase):
    def test_windows_cmake_uses_release_configuration_for_build_and_ctest(self):
        commands = []
        with mock.patch.object(
            sys.modules[__name__],
            "_run",
            side_effect=lambda command, *args, **kwargs: commands.append(command),
        ):
            _cmake_build(
                Path("coggate_ffi.lib"),
                None,
                True,
                True,
                "Windows",
            )

        build = next(command for command in commands if command[:2] == ["cmake", "--build"])
        ctest = next(command for command in commands if command[0] == "ctest")
        self.assertEqual(build[-2:], ["--config", "Release"])
        self.assertEqual(ctest[-2:], ["-C", "Release"])

    def test_c_complete_example_is_registered_with_ctest(self):
        c_cmake = (BINDINGS_DIR / "c" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'coggate_configure_c_target("coggate_c_example_${stem}" "${source}" TRUE',
            c_cmake,
        )

    def test_non_native_run_executes_python_contract_and_complete_example(self):
        release_library = ROOT / "target" / "release" / "libcoggate_ffi.dylib"
        args = argparse.Namespace(
            system="Darwin",
            library=None,
            static=False,
            dry_run=True,
            native_only=False,
        )
        commands = []

        with mock.patch.object(
            sys.modules[__name__],
            "detect_tools",
            return_value={"cmake": "cmake", "cc": "cc", "cxx": "c++"},
        ), mock.patch.object(
            sys.modules[__name__],
            "discover_library",
            return_value=release_library,
        ), mock.patch.object(
            sys.modules[__name__],
            "_cmake_build",
        ), mock.patch.object(
            sys.modules[__name__],
            "_run",
            side_effect=lambda command, *positional, **keyword: commands.append(
                (command, positional, keyword)
            ),
        ), mock.patch.object(sys, "version_info", (3, 11)):
            run_phase5b(args)

        self.assertEqual(
            [command for command, _, _ in commands],
            [
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    ROOT / "bindings" / "python" / "tests",
                    "-v",
                ],
                [
                    sys.executable,
                    ROOT / "bindings" / "python" / "examples" / "complete.py",
                ],
            ],
        )
        self.assertTrue(all(keyword.get("cwd") == ROOT for _, _, keyword in commands))
        self.assertTrue(
            all(
                keyword["env"]["COGGATE_LIBRARY_PATH"]
                == str(release_library)
                for _, _, keyword in commands
            )
        )

    def test_windows_runtime_dll_is_forwarded_to_python_subprocesses(self):
        import_library = Path("C:/native dir/coggate_ffi.dll.lib")
        runtime_library = Path("C:/native dir/coggate_ffi.dll")
        args = argparse.Namespace(
            system="Windows",
            library=import_library,
            static=False,
            dry_run=True,
            native_only=False,
        )
        commands = []

        with mock.patch.object(
            sys.modules[__name__],
            "detect_tools",
            return_value={"cmake": "cmake", "cc": "cl", "cxx": "cl"},
        ), mock.patch.object(
            sys.modules[__name__],
            "discover_library",
            return_value=import_library,
        ), mock.patch.object(
            sys.modules[__name__],
            "windows_library_artifacts",
            return_value=(import_library, runtime_library),
        ), mock.patch.object(
            sys.modules[__name__],
            "_cmake_build",
        ), mock.patch.object(
            sys.modules[__name__],
            "_run",
            side_effect=lambda command, *args, **kwargs: commands.append(
                (command, kwargs)
            ),
        ), mock.patch.object(sys, "version_info", (3, 11)):
            run_phase5b(args)

        self.assertEqual(len(commands), 2)
        for _, kwargs in commands:
            self.assertEqual(
                kwargs["env"]["COGGATE_LIBRARY_PATH"], str(runtime_library)
            )

    def test_static_full_gate_is_rejected_after_native_build(self):
        static_library = Path("C:/native dir/coggate_ffi.lib")
        args = argparse.Namespace(
            system="Windows",
            library=static_library,
            static=True,
            dry_run=True,
            native_only=False,
        )
        with mock.patch.dict(
            os.environ, {"COGGATE_LIBRARY_PATH": str(static_library)}
        ), mock.patch.object(
            sys.modules[__name__],
            "detect_tools",
            return_value={"cmake": "cmake", "cc": "cl", "cxx": "cl"},
        ), mock.patch.object(
            sys.modules[__name__],
            "discover_library",
            return_value=static_library,
        ), mock.patch.object(
            sys.modules[__name__],
            "windows_library_artifacts",
            return_value=(static_library, None),
        ), mock.patch.object(
            sys.modules[__name__],
            "_cmake_build",
        ) as cmake_build, mock.patch.object(
            sys.modules[__name__],
            "_run",
        ) as run, mock.patch.object(sys, "version_info", (3, 11)):
            with self.assertRaisesRegex(
                RunnerError,
                "Python ctypes tests require a shared native library; "
                "use --native-only with --static",
            ):
                run_phase5b(args)

        cmake_build.assert_called_once()
        run.assert_not_called()

    def test_cpp_consumers_receive_the_shared_fixture_path_directly(self):
        cpp_cmake = (BINDINGS_DIR / "cpp" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        contract = (BINDINGS_DIR / "cpp" / "tests" / "contract.cpp").read_text(
            encoding="utf-8"
        )
        example = (BINDINGS_DIR / "cpp" / "examples" / "complete.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn("COGGATE_BINDING_FIXTURE_PATH", cpp_cmake)
        self.assertIn("add_test(NAME ${target} COMMAND ${target})", cpp_cmake)
        self.assertNotIn("generated_fixtures.h", contract)
        self.assertIn("fixture_by_id(\"accepted\")", example)
        flags = _direct_flags(
            "cpp",
            Path("library"),
            "Darwin",
            False,
            Path("nlohmann"),
        )
        expected = str(FIXTURE_PATH).replace("\\", "/")
        self.assertTrue(
            any(
                str(flag).startswith("-DCOGGATE_BINDING_FIXTURE_PATH=")
                and expected in str(flag)
                for flag in flags
            )
        )

    def test_direct_build_executes_examples_as_smoke_tests(self):
        c_test = Path("c/tests/contract.c")
        c_example = Path("c/examples/complete.c")
        cpp_test = Path("cpp/tests/contract.cpp")
        cpp_example = Path("cpp/examples/complete.cpp")
        groups = {
            "c": ([c_test], [c_example], [], []),
            "cpp": ([cpp_test], [cpp_example], [], []),
        }
        commands = []

        with mock.patch.object(
            sys.modules[__name__],
            "_sources",
            side_effect=lambda language: groups[language],
        ), mock.patch.object(
            sys.modules[__name__],
            "_nlohmann_include_dir",
            return_value=Path("json"),
        ), mock.patch.object(
            sys.modules[__name__],
            "_run",
            side_effect=lambda command, *args: commands.append(command),
        ):
            _direct_build(
                Path("library"),
                {"cc": "cc", "cxx": "c++"},
                "Darwin",
                False,
                False,
            )

        executed = [command[0] for command in commands if len(command) == 1]
        self.assertEqual(len(executed), 4)

    def test_direct_native_bypasses_cmake_even_when_available_on_linux(self):
        library = Path("/native/libcoggate_ffi.so")
        args = argparse.Namespace(
            system="Linux", library=library, static=False, dry_run=True,
            native_only=True, direct_native=True,
        )
        with mock.patch.object(
            sys.modules[__name__], "detect_tools",
            return_value={"cmake": "cmake", "cc": "cc", "cxx": "c++"},
        ), mock.patch.object(
            sys.modules[__name__], "discover_library", return_value=library
        ), mock.patch.object(sys.modules[__name__], "_cmake_build") as cmake_build, mock.patch.object(
            sys.modules[__name__], "_direct_build"
        ) as direct_build:
            run_phase5b(args)

        cmake_build.assert_not_called()
        direct_build.assert_called_once_with(
            library, {"cmake": "cmake", "cc": "cc", "cxx": "c++"},
            "Linux", False, True,
        )

    def test_direct_native_is_rejected_on_windows(self):
        args = argparse.Namespace(
            system="Windows", library=Path("C:/native/coggate_ffi.dll.lib"),
            static=False, dry_run=True, native_only=True, direct_native=True,
        )
        with self.assertRaisesRegex(RunnerError, "--direct-native.*Windows"), mock.patch.object(
            sys.modules[__name__], "detect_tools"
        ) as detect_tools:
            run_phase5b(args)
        detect_tools.assert_not_called()

    def test_default_native_path_remains_cmake_first(self):
        library = Path("/native/libcoggate_ffi.so")
        args = argparse.Namespace(
            system="Linux", library=library, static=False, dry_run=True,
            native_only=True, direct_native=False,
        )
        with mock.patch.object(
            sys.modules[__name__], "detect_tools",
            return_value={"cmake": "cmake", "cc": "cc", "cxx": "c++"},
        ), mock.patch.object(
            sys.modules[__name__], "discover_library", return_value=library
        ), mock.patch.object(sys.modules[__name__], "_cmake_build") as cmake_build, mock.patch.object(
            sys.modules[__name__], "_direct_build"
        ) as direct_build:
            run_phase5b(args)

        cmake_build.assert_called_once_with(library, None, False, True, "Linux")
        direct_build.assert_not_called()

    def test_direct_build_tokenizes_language_and_linker_flags_without_shell(self):
        c_source = Path("c/tests/contract.c")
        cpp_source = Path("cpp/tests/contract.cpp")
        commands = []
        environment = {
            "CFLAGS": '-DC_ONLY="two words" -fsanitize=address,undefined',
            "CXXFLAGS": '-DCXX_ONLY="two words" -fsanitize=address,undefined',
            "LDFLAGS": "-Wl,--as-needed -fsanitize=address,undefined",
        }
        groups = {"c": ([c_source], [], [], []), "cpp": ([cpp_source], [], [], [])}
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            sys.modules[__name__], "_sources", side_effect=lambda language: groups[language]
        ), mock.patch.object(
            sys.modules[__name__], "_nlohmann_include_dir", return_value=Path("json")
        ), mock.patch.object(
            sys.modules[__name__], "_run", side_effect=lambda command, *args, **kwargs: commands.append(command)
        ):
            _direct_build(
                Path("library"), {"cc": "cc", "cxx": "c++"}, "Linux", False, True
            )

        compile_commands = [command for command in commands if command[0] in {"cc", "c++"}]
        self.assertEqual(len(compile_commands), 2)
        c_command = next(command for command in compile_commands if command[0] == "cc")
        cpp_command = next(command for command in compile_commands if command[0] == "c++")
        self.assertIn("-DC_ONLY=two words", c_command)
        self.assertNotIn("-DCXX_ONLY=two words", c_command)
        self.assertIn("-DCXX_ONLY=two words", cpp_command)
        self.assertNotIn("-DC_ONLY=two words", cpp_command)
        for command in compile_commands:
            self.assertIn("-Wl,--as-needed", command)
            self.assertIn("-fsanitize=address,undefined", command)

    def test_direct_build_rejects_malformed_flag_quoting_without_execution(self):
        with mock.patch.dict(os.environ, {"CFLAGS": "'unterminated"}, clear=False), mock.patch.object(
            sys.modules[__name__], "_sources", return_value=([Path("c/tests/contract.c")], [], [], [])
        ), mock.patch.object(sys.modules[__name__], "_run") as run:
            with self.assertRaisesRegex(RunnerError, "invalid CFLAGS"):
                _direct_build(
                    Path("library"), {"cc": "cc", "cxx": "c++"}, "Linux", False, True
                )
        run.assert_not_called()

    def test_run_never_uses_a_shell(self):
        completed = mock.Mock(returncode=0)
        with mock.patch.object(subprocess, "run", return_value=completed) as runner:
            _run(["compiler", "input.c"])
        self.assertFalse(runner.call_args.kwargs["shell"])

    def test_cmake_requires_and_links_nlohmann_json_package(self):
        root_cmake = (BINDINGS_DIR / "CMakeLists.txt").read_text(encoding="utf-8")
        cpp_cmake = (BINDINGS_DIR / "cpp" / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )

        self.assertIn("find_package(nlohmann_json 3.11 REQUIRED)", root_cmake)
        self.assertNotIn("NLOHMANN_JSON_INCLUDE_DIR", root_cmake)
        self.assertIn("nlohmann_json::nlohmann_json", cpp_cmake)

    def test_platform_release_library_names_are_exact(self):
        self.assertEqual(platform_library_name("Linux"), "libcoggate_ffi.so")
        self.assertEqual(platform_library_name("Darwin"), "libcoggate_ffi.dylib")
        self.assertEqual(platform_library_name("Windows"), "coggate_ffi.dll.lib")
        self.assertEqual(platform_library_name("Linux", True), "libcoggate_ffi.a")
        self.assertEqual(platform_library_name("Darwin", True), "libcoggate_ffi.a")
        self.assertEqual(platform_library_name("Windows", True), "coggate_ffi.lib")

    def test_explicit_library_has_priority_over_release_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            explicit = root / "custom library.dylib"
            discovered = root / "target" / "release" / "libcoggate_ffi.dylib"
            explicit.write_bytes(b"explicit")
            discovered.parent.mkdir(parents=True)
            discovered.write_bytes(b"discovered")

            self.assertEqual(discover_library(root, explicit, "Darwin"), explicit.resolve())

    def test_missing_capabilities_are_reported_independently(self):
        messages = capability_messages(
            {"cmake": None, "cc": None, "cxx": None}, (3, 9)
        )

        self.assertEqual(
            messages,
            [
                "missing capability: CMake",
                "missing capability: C compiler",
                "missing capability: C++ compiler",
                "missing capability: Python 3.11+ (running 3.9)",
            ],
        )

    def test_harness_sources_are_linked_as_support_not_executed(self):
        contract = Path("tests/contract.c")
        harness = Path("tests/harness.c")

        entries, support = partition_sources([harness, contract])

        self.assertEqual(entries, [contract])
        self.assertEqual(support, [harness])

    def test_test_and_example_support_sources_remain_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            test_dir = root / "tests"
            example_dir = root / "examples"
            test_dir.mkdir()
            example_dir.mkdir()
            for path in (
                test_dir / "contract.c",
                test_dir / "harness.c",
                example_dir / "complete.c",
                example_dir / "example_support.c",
            ):
                path.write_text("", encoding="utf-8")

            tests, examples, test_support, example_support = source_groups(
                root, ".c"
            )

            self.assertEqual(tests, [test_dir / "contract.c"])
            self.assertEqual(examples, [example_dir / "complete.c"])
            self.assertEqual(test_support, [test_dir / "harness.c"])
            self.assertEqual(
                example_support, [example_dir / "example_support.c"]
            )

    def test_windows_import_and_runtime_libraries_are_paired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "coggate_ffi.dll"
            import_library = root / "coggate_ffi.dll.lib"
            runtime.write_bytes(b"runtime")
            import_library.write_bytes(b"import")

            self.assertEqual(
                windows_library_artifacts(import_library, False),
                (import_library.resolve(), runtime.resolve()),
            )
            self.assertEqual(
                windows_library_artifacts(runtime, False),
                (import_library.resolve(), runtime.resolve()),
            )

    def test_direct_cpp_build_requires_nlohmann_include_directory(self):
        previous = os.environ.pop("NLOHMANN_JSON_INCLUDE_DIR", None)
        try:
            with mock.patch.object(sys.modules[__name__], "_run") as run:
                with self.assertRaisesRegex(
                    RunnerError, "NLOHMANN_JSON_INCLUDE_DIR is required"
                ):
                    _direct_build(
                        Path("library"),
                        {"cc": "cc", "cxx": "c++"},
                        "Darwin",
                        False,
                        False,
                    )
                run.assert_not_called()
        finally:
            if previous is not None:
                os.environ["NLOHMANN_JSON_INCLUDE_DIR"] = previous

    def test_direct_cpp_build_rejects_invalid_nlohmann_include_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("NLOHMANN_JSON_INCLUDE_DIR")
            os.environ["NLOHMANN_JSON_INCLUDE_DIR"] = directory
            try:
                with mock.patch.object(sys.modules[__name__], "_run") as run:
                    with self.assertRaisesRegex(
                        RunnerError, "does not contain nlohmann/json.hpp"
                    ):
                        _direct_build(
                            Path("library"),
                            {"cc": "cc", "cxx": "c++"},
                            "Darwin",
                            False,
                            False,
                        )
                    run.assert_not_called()
            finally:
                if previous is None:
                    os.environ.pop("NLOHMANN_JSON_INCLUDE_DIR", None)
                else:
                    os.environ["NLOHMANN_JSON_INCLUDE_DIR"] = previous


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerSelfTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        run_phase5b(args)
    except RunnerError as error:
        print("phase5b: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
