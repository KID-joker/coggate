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
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIR = ROOT / "packages" / "ffi" / "include"
BINDINGS_DIR = ROOT / "bindings"


class RunnerError(Exception):
    pass


def platform_library_name(system, static=False):
    names = (
        {
            "Linux": "libagentgate_ffi.a",
            "Darwin": "libagentgate_ffi.a",
            "Windows": "agentgate_ffi.lib",
        }
        if static
        else {
            "Linux": "libagentgate_ffi.so",
            "Darwin": "libagentgate_ffi.dylib",
            "Windows": "agentgate_ffi.dll.lib",
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


def _run(command, dry_run=False, cwd=None):
    print("+ " + shlex.join([str(part) for part in command]))
    if dry_run:
        return
    completed = subprocess.run([str(part) for part in command], cwd=cwd)
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


def _cmake_build(library, runtime_library, static, dry_run):
    with tempfile.TemporaryDirectory(prefix="agentgate-phase5b-cmake-") as directory:
        build = Path(directory)
        configure = [
            "cmake",
            "-S",
            BINDINGS_DIR,
            "-B",
            build,
            "-DAGENTGATE_INCLUDE_DIR=" + str(INCLUDE_DIR),
            "-DAGENTGATE_LIBRARY=" + str(library),
            "-DAGENTGATE_STATIC=" + ("ON" if static else "OFF"),
        ]
        if runtime_library is not None:
            configure.append("-DAGENTGATE_RUNTIME_LIBRARY=" + str(runtime_library))
        _run(configure, dry_run)
        _run(["cmake", "--build", build], dry_run)
        if any(_sources(language)[0] for language in ("c", "cpp")):
            _run(["ctest", "--output-on-failure"], dry_run, cwd=build)


def _direct_flags(language, library, system, static):
    flags = [
        "-std=c11" if language == "c" else "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-I",
        INCLUDE_DIR,
    ]
    if static:
        flags.append("-DAGENTGATE_STATIC")
    flags.append(library)
    if not static:
        flags.append("-Wl,-rpath," + str(library.parent))
    if system == "Linux":
        flags.extend(["-ldl", "-lpthread", "-lm"])
    return flags


def _direct_build(library, tools, system, static, dry_run):
    with tempfile.TemporaryDirectory(prefix="agentgate-phase5b-native-") as directory:
        build = Path(directory)
        for language, compiler_key in (("c", "cc"), ("cpp", "cxx")):
            tests, examples, test_support, example_support = _sources(language)
            sources = tests + examples
            if sources and not tools[compiler_key]:
                label = "C" if language == "c" else "C++"
                raise RunnerError("missing capability: %s compiler" % label)
            for source in sources:
                output = build / (language + "-" + source.stem)
                command = [tools[compiler_key], source]
                command.extend(test_support if source in tests else example_support)
                command.extend(["-o", output])
                command.extend(_direct_flags(language, library, system, static))
                _run(command, dry_run)
                if source in tests:
                    _run([output], dry_run)


def run_phase5b(args):
    system = args.system or platform.system()
    tools = detect_tools(system)
    for message in capability_messages(tools, sys.version_info[:2]):
        _warning(message)
    library = discover_library(ROOT, args.library, system, args.static)
    static = args.static or (
        library.suffix in {".a", ".lib"}
        and not library.name.endswith(".dll.lib")
    )

    if system == "Windows":
        if not tools["cmake"]:
            raise RunnerError("Windows native tests require CMake and MSVC")
        library, runtime_library = windows_library_artifacts(library, static)
        _cmake_build(library, runtime_library, static, args.dry_run)
    elif tools["cmake"]:
        _cmake_build(library, None, static, args.dry_run)
    else:
        _warning("using direct compiler fallback because CMake is unavailable")
        _direct_build(library, tools, system, static, args.dry_run)

    if not args.native_only:
        if sys.version_info < (3, 11):
            raise RunnerError("missing capability: Python 3.11+")
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
        )


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--library", type=Path)
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--system", choices=["Linux", "Darwin", "Windows"], help=argparse.SUPPRESS)
    return parser.parse_args(argv)

class RunnerSelfTests(unittest.TestCase):
    def test_platform_release_library_names_are_exact(self):
        self.assertEqual(platform_library_name("Linux"), "libagentgate_ffi.so")
        self.assertEqual(platform_library_name("Darwin"), "libagentgate_ffi.dylib")
        self.assertEqual(platform_library_name("Windows"), "agentgate_ffi.dll.lib")
        self.assertEqual(platform_library_name("Linux", True), "libagentgate_ffi.a")
        self.assertEqual(platform_library_name("Darwin", True), "libagentgate_ffi.a")
        self.assertEqual(platform_library_name("Windows", True), "agentgate_ffi.lib")

    def test_explicit_library_has_priority_over_release_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            explicit = root / "custom library.dylib"
            discovered = root / "target" / "release" / "libagentgate_ffi.dylib"
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
            runtime = root / "agentgate_ffi.dll"
            import_library = root / "agentgate_ffi.dll.lib"
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
