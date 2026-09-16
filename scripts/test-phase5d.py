#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import io
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import stat
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


def target_fixture():
    return Target.for_host("Linux", "x86_64")


def tool_versions_fixture():
    return {key: ".".join(str(part) for part in capability.version)
            for key, capability in complete_capabilities().items()}


def build_fixture_artifact(parent: Path) -> Path:
    root = parent / "artifact"
    (root / "include").mkdir(parents=True)
    (root / "include/agentgate.h").write_text("fixture header\n", encoding="utf-8")
    manifest = build_manifest(root, target_fixture(), tool_versions_fixture())
    write_manifest(root, manifest)
    return root


class RunnerSelfTests(unittest.TestCase):
    def _reparse_stat(self, path):
        original = Path(path).lstat()
        value = mock.Mock()
        for attribute in (
            "st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
        ):
            setattr(value, attribute, getattr(original, attribute))
        value.st_file_attributes = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return value

    def _rewrite_manifest(self, root, manifest):
        write_manifest(root, manifest)
        write_checksums(root)

    def _source_fixture(self, parent, target):
        root = parent / "repo"
        paths = [
            "packages/ffi/include/agentgate.h",
            f"target/release/{target.shared_name}",
            f"target/release/{target.static_name}",
            "bindings/go/go.mod",
            "bindings/go/agentgate/service.go",
            "bindings/go/examples/complete/main.go",
            "bindings/java/target/agentgate-java-0.1.0-SNAPSHOT.jar",
            "bindings/java/examples/Complete.java",
            "bindings/node/package.json",
            "bindings/node/lib/index.js",
            "bindings/node/examples/complete.js",
            "bindings/node/build/Release/agentgate.node",
            f"bindings/node/build/Release/{target.shared_name}",
            "tests/qualification/abi_probe.c",
            "tests/qualification/abi_probe.cpp",
        ]
        shim = {
            "Linux": "target/phase5c/java/libagentgate_jni.so",
            "Darwin": "target/phase5c/java/libagentgate_jni.dylib",
            "Windows": "target/phase5c/java/Release/agentgate_jni.dll",
        }[target.system]
        paths.append(shim)
        if target.import_name is not None:
            paths.append(f"target/release/{target.import_name}")
        for relative in paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture {relative}\n", encoding="utf-8")
        return root

    def _assembled_fixture(self, parent, target=None):
        target = target_fixture() if target is None else target
        parent = Path(parent).resolve()
        source = self._source_fixture(parent / "source", target)
        return assemble_artifact(
            source, parent / "output", target, tool_versions_fixture()
        )

    def _remove_layout_path(self, root, relative):
        path = root / relative
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
        prefix = relative.rstrip("/") + "/"
        manifest["files"] = [
            entry for entry in manifest["files"]
            if entry["path"] != relative and not entry["path"].startswith(prefix)
        ]
        self._rewrite_manifest(root, manifest)

    def test_manifest_and_checksums_are_deterministic_sorted_and_relative(self):
        snapshots = []
        with tempfile.TemporaryDirectory() as directory:
            for name in ("one", "two"):
                root = Path(directory) / name / "artifact"
                (root / "zeta").mkdir(parents=True)
                (root / "alpha").mkdir()
                (root / "zeta/item.bin").write_bytes(b"zeta")
                (root / "alpha/item.bin").write_bytes(b"alpha")
                manifest = build_manifest(
                    root, target_fixture(), tool_versions_fixture()
                )
                write_manifest(root, manifest)
                write_checksums(root)
                snapshots.append(
                    (
                        (root / "manifest.json").read_bytes(),
                        (root / "SHA256SUMS").read_bytes(),
                    )
                )
                paths = [entry["path"] for entry in manifest["files"]]
                self.assertEqual(paths, sorted(paths))
                self.assertTrue(all(not path.startswith("/") for path in paths))
                self.assertTrue(all("\\" not in path for path in paths))
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertTrue(snapshots[0][0].endswith(b"\n"))
            self.assertTrue(snapshots[0][1].endswith(b"\n"))

    def test_verification_passes_then_rejects_payload_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._assembled_fixture(Path(directory))
            self.assertEqual(verify_artifact(root, target_fixture()), "PASS")
            (root / "include/agentgate.h").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(RunnerError, "size|sha256"):
                verify_artifact(root, target_fixture())

    def test_verification_rejects_consistent_minimal_artifact_without_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = build_fixture_artifact(Path(directory))
            write_checksums(root)
            with self.assertRaisesRegex(RunnerError, "layout"):
                verify_artifact(root, target_fixture())

    def test_verification_requires_every_singleton_and_recursive_group(self):
        target = target_fixture()
        singletons = {
            "include/agentgate.h",
            f"native/{target.shared_name}",
            f"native/{target.static_name}",
            "go/go.mod",
            "java/agentgate-java-0.1.0-SNAPSHOT.jar",
            "java/libagentgate_jni.so",
            f"java/{target.shared_name}",
            "java/examples/Complete.java",
            "node/package.json",
            "node/examples/complete.js",
            "node/build/Release/agentgate.node",
            f"node/build/Release/{target.shared_name}",
            "smoke/abi_probe.c",
            "smoke/abi_probe.cpp",
        }
        groups = {"go/agentgate", "go/examples/complete", "node/lib"}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            base = self._assembled_fixture(parent / "base", target)
            for index, relative in enumerate(sorted(singletons | groups)):
                with self.subTest(relative=relative):
                    root = parent / f"case-{index}" / "artifact"
                    shutil.copytree(base, root)
                    self._remove_layout_path(root, relative)
                    with self.assertRaisesRegex(RunnerError, "layout"):
                        verify_artifact(root, target)

    def test_verification_rejects_paths_outside_layout_and_nonwindows_import(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            for index, relative in enumerate(
                ("java/unexpected.txt", "native/agentgate_ffi.dll.lib")
            ):
                with self.subTest(relative=relative):
                    root = self._assembled_fixture(parent / str(index))
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("unexpected", encoding="utf-8")
                    manifest = build_manifest(
                        root, target_fixture(), tool_versions_fixture()
                    )
                    self._rewrite_manifest(root, manifest)
                    with self.assertRaisesRegex(RunnerError, "layout"):
                        verify_artifact(root, target_fixture())

    def test_windows_verification_requires_import_library(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Target.for_host("Windows", "AMD64")
            root = self._assembled_fixture(Path(directory), target)
            self.assertEqual(verify_artifact(root, target), "PASS")
            self._remove_layout_path(root, f"native/{target.import_name}")
            with self.assertRaisesRegex(RunnerError, "layout"):
                verify_artifact(root, target)

    def test_verification_rejects_forged_manifest_kind(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._assembled_fixture(Path(directory))
            manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
            manifest["files"][0]["kind"] = "forged-kind"
            self._rewrite_manifest(root, manifest)
            with self.assertRaisesRegex(RunnerError, "kind"):
                verify_artifact(root, target_fixture())

    def test_verification_rejects_extra_missing_symlink_and_nonregular_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for anomaly in ("extra", "missing", "symlink", "fifo"):
                with self.subTest(anomaly=anomaly):
                    case = parent / anomaly
                    case.mkdir()
                    root = self._assembled_fixture(case)
                    payload = root / "include/agentgate.h"
                    if anomaly == "extra":
                        (root / "extra.txt").write_text("extra", encoding="utf-8")
                    elif anomaly == "missing":
                        payload.unlink()
                    elif anomaly == "symlink":
                        payload.unlink()
                        payload.symlink_to(case / "outside")
                    else:
                        payload.unlink()
                        os.mkfifo(payload)
                    with self.assertRaises(RunnerError):
                        verify_artifact(root, target_fixture())

    def test_verification_rejects_symlink_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            real = build_fixture_artifact(parent / "real")
            write_checksums(real)
            linked = parent / "linked-artifact"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RunnerError, "symlink"):
                verify_artifact(linked, target_fixture())

    def test_hashing_rejects_file_replaced_by_symlink_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            payload = parent / "payload"
            outside = parent / "outside"
            payload.write_bytes(b"original")
            outside.write_bytes(b"outside")
            real_open = os.open

            def swap_before_open(path, flags, *args, **kwargs):
                if Path(path).name == payload.name and not payload.is_symlink():
                    payload.unlink()
                    payload.symlink_to(outside)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=swap_before_open
            ), self.assertRaises(RunnerError):
                sha256_file(payload, trusted_root=parent)

    def test_manifest_and_checksums_reject_replacement_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = build_fixture_artifact(Path(directory))
            write_checksums(root)
            outside = Path(directory) / "outside"
            outside.write_text("outside", encoding="utf-8")
            real_open = os.open
            for name, operation in (
                (MANIFEST_NAME, lambda: _load_manifest(root)),
                (CHECKSUM_NAME, lambda: parse_checksums(root / CHECKSUM_NAME, root)),
            ):
                with self.subTest(name=name):
                    path = root / name
                    original = path.read_bytes()

                    def swap_before_open(candidate, flags, *args, **kwargs):
                        if Path(candidate).name == path.name and not path.is_symlink():
                            path.unlink()
                            path.symlink_to(outside)
                        return real_open(candidate, flags, *args, **kwargs)

                    with mock.patch.object(
                        os, "open", side_effect=swap_before_open
                    ), self.assertRaises(RunnerError):
                        operation()
                    path.unlink()
                    path.write_bytes(original)

    def test_hashing_rejects_parent_directory_replaced_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifact"
            parent = root / "payload"
            outside = Path(directory) / "outside"
            parent.mkdir(parents=True)
            outside.mkdir()
            (parent / "file").write_bytes(b"inside")
            (outside / "file").write_bytes(b"outside")
            displaced = root / "payload-original"
            real_open = os.open

            def swap_parent(candidate, flags, *args, **kwargs):
                if Path(candidate).name == "file" and not parent.is_symlink():
                    parent.rename(displaced)
                    parent.symlink_to(outside, target_is_directory=True)
                return real_open(candidate, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=swap_parent
            ), self.assertRaises(RunnerError):
                sha256_file(parent / "file", trusted_root=root)

    def test_manifest_rejects_escaping_absolute_duplicate_and_reserved_paths(self):
        invalid_paths = (
            "../escape",
            "/absolute",
            "C:/absolute",
            r"C:\absolute",
            "manifest.json",
            "SHA256SUMS",
        )
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for index, invalid in enumerate(invalid_paths):
                with self.subTest(path=invalid):
                    root = build_fixture_artifact(parent / str(index))
                    manifest = json.loads((root / "manifest.json").read_text())
                    manifest["files"][0]["path"] = invalid
                    self._rewrite_manifest(root, manifest)
                    with self.assertRaises(RunnerError):
                        verify_artifact(root, target_fixture())
            root = build_fixture_artifact(parent / "duplicate")
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"].append(dict(manifest["files"][0]))
            self._rewrite_manifest(root, manifest)
            with self.assertRaisesRegex(RunnerError, "duplicate"):
                verify_artifact(root, target_fixture())

    def test_manifest_rejects_bad_hash_size_schema_json_and_target(self):
        mutations = {
            "malformed sha": lambda value: value["files"][0].update(sha256="A" * 64),
            "wrong size": lambda value: value["files"][0].update(size=999),
            "wrong hash": lambda value: value["files"][0].update(sha256="0" * 64),
            "schema": lambda value: value.update(schema_version=2),
            "target": lambda value: value["target"].update(triple="forged-target"),
        }
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    root = self._assembled_fixture(parent / name)
                    manifest = json.loads((root / "manifest.json").read_text())
                    mutate(manifest)
                    self._rewrite_manifest(root, manifest)
                    with self.assertRaises(RunnerError):
                        verify_artifact(root, target_fixture())
            root = build_fixture_artifact(parent / "json")
            (root / "manifest.json").write_text("{malformed", encoding="utf-8")
            write_checksums(root)
            with self.assertRaisesRegex(RunnerError, "JSON"):
                verify_artifact(root, target_fixture())

    def test_checksum_rejects_duplicate_mismatch_missing_and_extra_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for anomaly in ("duplicate", "mismatch", "missing", "extra"):
                with self.subTest(anomaly=anomaly):
                    root = self._assembled_fixture(parent / anomaly)
                    checksum = root / "SHA256SUMS"
                    lines = checksum.read_text(encoding="utf-8").splitlines()
                    if anomaly == "duplicate":
                        lines.append(lines[0])
                    elif anomaly == "mismatch":
                        lines[0] = "0" * 64 + lines[0][64:]
                    elif anomaly == "missing":
                        lines.pop()
                    else:
                        lines.append("0" * 64 + "  unlisted.txt")
                    checksum.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    with self.assertRaises(RunnerError):
                        verify_artifact(root, target_fixture())

    def test_safe_copy_rejects_symlink_sources_destinations_and_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            artifact = parent / "artifact"
            artifact.mkdir()
            source = parent / "source"
            source.write_text("payload", encoding="utf-8")
            linked_source = parent / "linked-source"
            linked_source.symlink_to(source)
            with self.assertRaisesRegex(RunnerError, "symlink"):
                safe_copy_file(linked_source, artifact, "file")
            destination = artifact / "file"
            destination.symlink_to(parent / "outside")
            with self.assertRaisesRegex(RunnerError, "symlink"):
                safe_copy_file(source, artifact, "file")
            with self.assertRaises(RunnerError):
                safe_copy_file(source, artifact, "../escape")

    def test_collection_requires_all_outputs_windows_import_and_exact_main_jar(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            linux_root = self._source_fixture(parent / "linux", target_fixture())
            sources = collect_artifact_sources(linux_root, target_fixture())
            self.assertIn("java/agentgate-java-0.1.0-SNAPSHOT.jar", sources)
            (linux_root / "bindings/java/target/agentgate-java-0.1.0-SNAPSHOT.jar").unlink()
            with self.assertRaisesRegex(RunnerError, "JAR"):
                collect_artifact_sources(linux_root, target_fixture())

            windows = Target.for_host("Windows", "AMD64")
            windows_root = self._source_fixture(parent / "windows", windows)
            (windows_root / f"target/release/{windows.import_name}").unlink()
            with self.assertRaisesRegex(RunnerError, "native library"):
                collect_artifact_sources(windows_root, windows)

            java_target = parent / "jars"
            java_target.mkdir()
            for name in (
                "agentgate-java-0.1.0-SNAPSHOT-sources.jar",
                "agentgate-java-0.1.0-SNAPSHOT-javadoc.jar",
                "original-agentgate-java-0.1.0-SNAPSHOT.jar",
                "agentgate-java-0.1.0-SNAPSHOT.jar",
            ):
                (java_target / name).write_text(name, encoding="utf-8")
            self.assertEqual(
                select_maven_main_jar(java_target).name,
                "agentgate-java-0.1.0-SNAPSHOT.jar",
            )
            (java_target / "agentgate-java-0.1.0.jar").write_text("other", encoding="utf-8")
            with self.assertRaisesRegex(RunnerError, "JAR"):
                select_maven_main_jar(java_target)

    def test_collection_layout_and_jni_mapping_are_exact_on_every_platform(self):
        expected_shims = {
            "Linux": "libagentgate_jni.so",
            "Darwin": "libagentgate_jni.dylib",
            "Windows": "agentgate_jni.dll",
        }
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for system, arch in (("Linux", "x86_64"), ("Darwin", "x86_64"), ("Windows", "AMD64")):
                with self.subTest(system=system):
                    target = Target.for_host(system, arch)
                    root = self._source_fixture(parent / system, target)
                    paths = set(collect_artifact_sources(root, target))
                    required = {
                        "include/agentgate.h",
                        f"native/{target.shared_name}",
                        f"native/{target.static_name}",
                        "go/go.mod",
                        "go/agentgate/service.go",
                        "go/examples/complete/main.go",
                        "java/agentgate-java-0.1.0-SNAPSHOT.jar",
                        f"java/{expected_shims[system]}",
                        f"java/{target.shared_name}",
                        "java/examples/Complete.java",
                        "node/package.json",
                        "node/lib/index.js",
                        "node/examples/complete.js",
                        "node/build/Release/agentgate.node",
                        f"node/build/Release/{target.shared_name}",
                        "smoke/abi_probe.c",
                        "smoke/abi_probe.cpp",
                    }
                    if target.import_name:
                        required.add(f"native/{target.import_name}")
                    self.assertEqual(paths, required)

    def test_assembled_manifest_contains_no_sensitive_or_host_material(self):
        sentinels = (
            "PRIVATE_MATERIAL_SENTINEL",
            "ANSWER_SENTINEL",
            "KEY_SENTINEL",
            "CALLBACK_SENTINEL",
            "ENVIRONMENT_SECRET_SENTINEL",
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, {"AGENTGATE_SECRET": sentinels[-1]}, clear=False
        ):
            parent = Path(directory).resolve()
            root = self._source_fixture(parent, target_fixture())
            header = root / "packages/ffi/include/agentgate.h"
            header.write_text("\n".join(sentinels[:-1]), encoding="utf-8")
            artifact = assemble_artifact(
                root, parent / "output", target_fixture(), tool_versions_fixture()
            )
            manifest_bytes = (artifact / "manifest.json").read_bytes()
            self.assertNotIn(str(root).encode(), manifest_bytes)
            for sentinel in sentinels:
                self.assertNotIn(sentinel.encode(), manifest_bytes)
            self.assertEqual(verify_artifact(artifact, target_fixture()), "PASS")

    def test_assembly_rejects_lexical_traversal_and_symlinked_output_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            traversal = parent / "safe" / ".." / "escaped-output"
            with self.assertRaisesRegex(RunnerError, "output.*traversal"):
                assemble_artifact(
                    root, traversal, target_fixture(), tool_versions_fixture()
                )
            self.assertFalse((parent / "escaped-output" / "artifact").exists())

            real = parent / "real-output"
            real.mkdir()
            linked = parent / "linked-output"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RunnerError, "symlink|reparse"):
                assemble_artifact(
                    root,
                    linked / "child",
                    target_fixture(),
                    tool_versions_fixture(),
                )
            self.assertFalse((real / "child" / "artifact").exists())

    def test_failed_post_publish_verification_rolls_back_only_new_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            output = parent / "output"
            output.mkdir()
            sibling = output / "unrelated.txt"
            sibling.write_text("preserve", encoding="utf-8")
            working_directory = Path.cwd()
            real_verify = _verify_artifact_at
            calls = 0

            def fail_after_publish(path, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RunnerError("injected post-publish verification failure")
                return real_verify(path, target)

            with mock.patch.object(
                sys.modules[__name__], "_verify_artifact_at", side_effect=fail_after_publish
            ), self.assertRaisesRegex(RunnerError, "post-publish"):
                assemble_artifact(
                    root, output, target_fixture(), tool_versions_fixture()
                )
            self.assertEqual(calls, 2)
            self.assertFalse((output / "artifact").exists())
            self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve")
            self.assertEqual(Path.cwd(), working_directory)

    def test_rollback_preserves_artifact_replaced_after_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            output = parent / "output"
            displaced = output / "displaced-published-artifact"
            calls = 0
            real_verify = _verify_artifact_at

            def replace_after_publish(descriptor, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    (output / "artifact").rename(displaced)
                    (output / "artifact").mkdir()
                    (output / "artifact/replacement.txt").write_text(
                        "preserve replacement", encoding="utf-8"
                    )
                    raise RunnerError("injected replacement race")
                return real_verify(descriptor, target)

            with mock.patch.object(
                sys.modules[__name__],
                "_verify_artifact_at",
                side_effect=replace_after_publish,
            ), self.assertRaisesRegex(RunnerError, "replacement race"):
                assemble_artifact(
                    root, output, target_fixture(), tool_versions_fixture()
                )
            self.assertEqual(calls, 2)
            self.assertEqual(
                (output / "artifact/replacement.txt").read_text(encoding="utf-8"),
                "preserve replacement",
            )
            self.assertFalse(displaced.exists())

    def test_descriptor_reads_reject_replacement_immediately_after_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._assembled_fixture(Path(directory))
            for relative in (
                "include/agentgate.h",
                MANIFEST_NAME,
                CHECKSUM_NAME,
            ):
                with self.subTest(relative=relative):
                    case = Path(directory) / f"case-{relative.replace('/', '-')}"
                    shutil.copytree(root, case)
                    root_descriptor = os.open(case, _directory_open_flags())
                    real_open = os.open
                    replaced = False

                    def replace_after_open(path, flags, *args, **kwargs):
                        nonlocal replaced
                        descriptor = real_open(path, flags, *args, **kwargs)
                        if path == relative.split("/")[-1] and not replaced:
                            replaced = True
                            target = case / relative
                            target.rename(target.with_name(target.name + ".displaced"))
                            target.write_bytes(b"replacement")
                        return descriptor

                    try:
                        with mock.patch.object(os, "open", side_effect=replace_after_open):
                            with self.assertRaisesRegex(RunnerError, "changed"):
                                if relative == "include/agentgate.h":
                                    _walk_files_at(root_descriptor)
                                else:
                                    _read_bytes_at(
                                        root_descriptor,
                                        relative,
                                        max_bytes=MAX_METADATA_BYTES,
                                    )
                    finally:
                        os.close(root_descriptor)

    def test_descriptor_read_rejects_parent_replacement_after_file_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._assembled_fixture(Path(directory))
            root_descriptor = os.open(root, _directory_open_flags())
            real_open = os.open
            replaced = False

            def replace_parent_after_open(path, flags, *args, **kwargs):
                nonlocal replaced
                descriptor = real_open(path, flags, *args, **kwargs)
                if path == "agentgate.h" and not replaced:
                    replaced = True
                    parent = root / "include"
                    parent.rename(root / "displaced-include")
                    parent.mkdir()
                    (parent / "agentgate.h").write_bytes(b"replacement")
                return descriptor

            try:
                with mock.patch.object(os, "open", side_effect=replace_parent_after_open):
                    with self.assertRaisesRegex(RunnerError, "changed"):
                        _hash_file_at(root_descriptor, "include/agentgate.h")
            finally:
                os.close(root_descriptor)

    def test_windows_reparse_points_are_rejected_at_every_path_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            source = self._source_fixture(parent / "source", target_fixture())
            artifact = self._assembled_fixture(parent / "assembled")
            real_lstat = Path.lstat

            cases = [
                (source, lambda: _require_directory(source, "root")),
                (
                    source / "packages/ffi/include/agentgate.h",
                    lambda: _require_regular_file(
                        source / "packages/ffi/include/agentgate.h", "source"
                    ),
                ),
                (
                    artifact / "include",
                    lambda: _walk_regular_files(artifact, exclude_metadata=True),
                ),
                (
                    source / "bindings/go/agentgate/service.go",
                    lambda: _collect_tree(
                        {}, source, "bindings/go/agentgate", "go/agentgate"
                    ),
                ),
                (
                    artifact / MANIFEST_NAME,
                    lambda: verify_artifact(artifact, target_fixture()),
                ),
                (
                    artifact / CHECKSUM_NAME,
                    lambda: verify_artifact(artifact, target_fixture()),
                ),
                (
                    parent / "output-ancestry",
                    lambda: _validate_output_path(parent / "output-ancestry/child"),
                ),
            ]
            (parent / "output-ancestry").mkdir()
            for reparse_path, operation in cases:
                with self.subTest(path=reparse_path):
                    reparse_value = self._reparse_stat(reparse_path)

                    def lstat(path, *args, **kwargs):
                        if Path(path) == reparse_path:
                            return reparse_value
                        return real_lstat(path, *args, **kwargs)

                    with mock.patch.object(
                        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True
                    ), mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat):
                        with self.assertRaisesRegex(RunnerError, "symlink|reparse|real"):
                            operation()

    def test_windows_no_dirfd_reader_rejects_reparse_root_parent_and_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / "parent"
            parent.mkdir()
            payload = parent / "payload"
            payload.write_bytes(b"payload")
            real_lstat = Path.lstat
            for reparse_path in (root, parent, payload):
                with self.subTest(path=reparse_path):
                    reparse_value = self._reparse_stat(reparse_path)

                    def lstat(path, *args, **kwargs):
                        if Path(path) == reparse_path:
                            return reparse_value
                        return real_lstat(path, *args, **kwargs)

                    with mock.patch.object(
                        Path, "lstat", autospec=True, side_effect=lstat
                    ), mock.patch.object(
                        sys.modules[__name__], "SECURE_DIR_FD_SUPPORTED", False
                    ), mock.patch.object(
                        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True
                    ), self.assertRaisesRegex(RunnerError, "real|regular"):
                        with _open_regular_file(
                            payload, trusted_root=root
                        ) as source_file:
                            source_file.read()

    def test_descriptor_verifier_uses_strict_canonical_manifest_and_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self._assembled_fixture(Path(directory) / "base")
            mutations = {
                "duplicate-manifest-key": (lambda root: (
                    root / MANIFEST_NAME
                ).write_bytes(
                    (root / MANIFEST_NAME).read_bytes().replace(
                        b'{\n  "abi_version"', b'{\n  "abi_version": 1,\n  "abi_version"', 1
                    )
                )),
                "noncanonical-manifest": (lambda root: (
                    root / MANIFEST_NAME
                ).write_bytes((root / MANIFEST_NAME).read_bytes().replace(b"  ", b" ", 1))),
                "noncanonical-checksums": (lambda root: (
                    root / CHECKSUM_NAME
                ).write_bytes((root / CHECKSUM_NAME).read_bytes().replace(b"  ", b"   ", 1))),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    root = Path(directory) / name
                    shutil.copytree(base, root)
                    mutate(root)
                    with self.assertRaises(RunnerError) as public_error:
                        verify_artifact(root, target_fixture())
                    descriptor = os.open(root, _directory_open_flags())
                    try:
                        with self.assertRaises(RunnerError) as descriptor_error:
                            _verify_artifact_at(descriptor, target_fixture())
                    finally:
                        os.close(descriptor)
                    self.assertEqual(
                        str(descriptor_error.exception), str(public_error.exception)
                    )

    def test_rollback_retries_quarantine_collisions_and_removes_exact_identity(self):
        for collision_count in (1, 8):
            with self.subTest(collision_count=collision_count), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve()
                root = self._source_fixture(parent / "source", target_fixture())
                output = parent / "output"
                output.mkdir()
                sibling = output / "unrelated.txt"
                sibling.write_text("preserve", encoding="utf-8")
                tokens = [f"collision-{index}" for index in range(collision_count)]
                tokens.append("success")
                for token in tokens[:-1]:
                    collision = output / f".artifact.rollback-{token}"
                    collision.mkdir()
                    (collision / "marker").write_text(token, encoding="utf-8")
                published_identity = None
                real_verify = _verify_artifact_at
                calls = 0

                def fail_final(descriptor, target):
                    nonlocal calls, published_identity
                    calls += 1
                    if calls == 2:
                        published_identity = _filesystem_identity(os.fstat(descriptor))
                        raise RunnerError("injected final verification failure")
                    return real_verify(descriptor, target)

                with mock.patch.object(
                    sys.modules[__name__], "_verify_artifact_at", side_effect=fail_final
                ), mock.patch.object(
                    secrets, "token_hex", side_effect=tokens
                ), self.assertRaisesRegex(RunnerError, "final verification"):
                    assemble_artifact(
                        root, output, target_fixture(), tool_versions_fixture()
                    )
                self.assertIsNotNone(published_identity)
                for child in output.iterdir():
                    self.assertNotEqual(
                        _filesystem_identity(child.lstat()), published_identity
                    )
                for token in tokens[:-1]:
                    self.assertEqual(
                        (output / f".artifact.rollback-{token}/marker").read_text(
                            encoding="utf-8"
                        ),
                        token,
                    )
                self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve")

    def test_prepublication_failures_remove_owned_staging_and_preserve_collisions(self):
        failure_points = ("copy", "write", "verify")
        for failure_point in failure_points:
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve()
                root = self._source_fixture(parent / "source", target_fixture())
                output = parent / "output"
                output.mkdir()
                sibling = output / "unrelated.txt"
                sibling.write_text("preserve", encoding="utf-8")
                collision = output / ".artifact.failed-collision"
                collision.mkdir()
                (collision / "marker").write_text("preserve", encoding="utf-8")
                patches = {
                    "copy": mock.patch.object(
                        sys.modules[__name__],
                        "_copy_file_at",
                        side_effect=RunnerError("injected copy failure"),
                    ),
                    "write": mock.patch.object(
                        sys.modules[__name__],
                        "_write_bytes_at",
                        side_effect=RunnerError("injected write failure"),
                    ),
                    "verify": mock.patch.object(
                        sys.modules[__name__],
                        "_verify_artifact_at",
                        side_effect=RunnerError("injected verify failure"),
                    ),
                }
                with patches[failure_point], mock.patch.object(
                    secrets, "token_hex", side_effect=("collision", "success")
                ), self.assertRaisesRegex(RunnerError, "injected"):
                    assemble_artifact(
                        root, output, target_fixture(), tool_versions_fixture()
                    )
                self.assertFalse((output / ".artifact.tmp").exists())
                self.assertEqual(
                    [path.name for path in output.glob(".artifact.failed-*")],
                    [".artifact.failed-collision"],
                )
                self.assertEqual(
                    (collision / "marker").read_text(encoding="utf-8"), "preserve"
                )
                self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve")

    def test_windows_fallback_prepublication_failure_removes_owned_staging(self):
        for failure_point, function_name in (
            ("copy", "safe_copy_file"),
            ("write", "write_manifest"),
            ("verify", "verify_artifact"),
        ):
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve()
                root = self._source_fixture(parent / "source", target_fixture())
                output = parent / "output"
                output.mkdir()
                identity = _filesystem_identity(output.lstat())
                collision = output / ".artifact.failed-collision"
                collision.mkdir()
                (collision / "marker").write_text("preserve", encoding="utf-8")
                with mock.patch.object(
                    sys.modules[__name__],
                    "_open_output_directory",
                    return_value=(output, None, identity),
                ), mock.patch.object(
                    sys.modules[__name__],
                    function_name,
                    side_effect=RunnerError(f"injected fallback {failure_point} failure"),
                ), mock.patch.object(
                    secrets, "token_hex", side_effect=("collision", "success")
                ), self.assertRaisesRegex(RunnerError, f"fallback {failure_point}"):
                    assemble_artifact(
                        root, output, target_fixture(), tool_versions_fixture()
                    )
                self.assertFalse((output / ".artifact.tmp").exists())
                self.assertEqual(
                    [path.name for path in output.glob(".artifact.failed-*")],
                    [".artifact.failed-collision"],
                )
                self.assertEqual(
                    (collision / "marker").read_text(encoding="utf-8"), "preserve"
                )

    def test_prepublication_cleanup_removes_displaced_owned_staging_only(self):
        for descriptor_mode in (True, False):
            with self.subTest(descriptor_mode=descriptor_mode), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve()
                root = self._source_fixture(parent / "source", target_fixture())
                output = parent / "output"
                output.mkdir()
                output_identity = _filesystem_identity(output.lstat())
                owned_identity = None

                def displace_then_fail(*args, **kwargs):
                    nonlocal owned_identity
                    staging = output / ".artifact.tmp"
                    owned_identity = _filesystem_identity(staging.lstat())
                    staging.rename(output / "displaced-staging")
                    replacement = output / ".artifact.tmp"
                    replacement.mkdir()
                    (replacement / "marker").write_text("preserve", encoding="utf-8")
                    raise RunnerError("injected displaced staging failure")

                open_output_patch = (
                    contextlib.nullcontext()
                    if descriptor_mode
                    else mock.patch.object(
                        sys.modules[__name__],
                        "_open_output_directory",
                        return_value=(output, None, output_identity),
                    )
                )
                copy_name = "_copy_file_at" if descriptor_mode else "safe_copy_file"
                with open_output_patch, mock.patch.object(
                    sys.modules[__name__], copy_name, side_effect=displace_then_fail
                ), self.assertRaisesRegex(RunnerError, "displaced staging"):
                    assemble_artifact(
                        root, output, target_fixture(), tool_versions_fixture()
                    )

                self.assertEqual(
                    (output / ".artifact.tmp/marker").read_text(encoding="utf-8"),
                    "preserve",
                )
                self.assertIsNotNone(owned_identity)
                self.assertFalse(
                    any(
                        _filesystem_identity(child.lstat()) == owned_identity
                        for child in output.iterdir()
                    )
                )
                self.assertEqual(list(output.glob(".artifact.failed-*")), [])

    def test_descriptor_walk_closes_queued_directories_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(16):
                child = root / f"dir-{index:02d}"
                child.mkdir()
                (child / "payload").write_text("payload", encoding="utf-8")
            root_descriptor = os.open(root, _directory_open_flags())
            real_open = os.open
            real_close = os.close
            opened = set()
            closed = set()

            def tracking_open(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                if kwargs.get("dir_fd") is not None and args[0] != "payload":
                    opened.add(descriptor)
                return descriptor

            def tracking_close(descriptor):
                if descriptor in opened:
                    closed.add(descriptor)
                return real_close(descriptor)

            try:
                with mock.patch.object(os, "open", side_effect=tracking_open), mock.patch.object(
                    os, "close", side_effect=tracking_close
                ), mock.patch.object(
                    sys.modules[__name__],
                    "_hash_file_at",
                    side_effect=RunnerError("injected hash failure"),
                ), self.assertRaisesRegex(RunnerError, "hash failure"):
                    _walk_files_at(root_descriptor)
            finally:
                real_close(root_descriptor)
            self.assertEqual(opened, closed)

    def test_publication_rejects_destination_created_during_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            output = parent / "output"
            real_rename = _rename_noreplace

            def create_destination(parent_descriptor, source, destination):
                if destination != "artifact":
                    return real_rename(parent_descriptor, source, destination)
                os.mkdir(destination, dir_fd=parent_descriptor)
                destination_descriptor = os.open(
                    destination,
                    _directory_open_flags(),
                    dir_fd=parent_descriptor,
                )
                try:
                    _write_bytes_at(destination_descriptor, "marker", b"preserve")
                finally:
                    os.close(destination_descriptor)
                real_rename(parent_descriptor, source, destination)

            with mock.patch.object(
                sys.modules[__name__],
                "_rename_noreplace",
                side_effect=create_destination,
            ), self.assertRaisesRegex(RunnerError, "already exists"):
                assemble_artifact(
                    root, output, target_fixture(), tool_versions_fixture()
                )
            self.assertEqual(
                (output / "artifact/marker").read_text(encoding="utf-8"),
                "preserve",
            )
            self.assertFalse((output / ".artifact.tmp").exists())

    def test_windows_path_fallback_avoids_dir_fd_and_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            output = parent / "output"
            output.mkdir()
            identity = _filesystem_identity(output.lstat())
            real_rename = Path.rename

            def destination_race(source, destination):
                if source.name == ".artifact.tmp":
                    destination.mkdir()
                    (destination / "marker").write_text("preserve", encoding="utf-8")
                    raise FileExistsError(destination)
                return real_rename(source, destination)

            with mock.patch.object(
                sys.modules[__name__],
                "_open_output_directory",
                return_value=(output, None, identity),
            ), mock.patch.object(
                Path, "rename", autospec=True, side_effect=destination_race
            ), mock.patch.object(
                sys.modules[__name__],
                "_copy_file_at",
                side_effect=AssertionError("dir_fd copy must not run"),
            ), self.assertRaisesRegex(RunnerError, "already exists"):
                assemble_artifact(
                    root, output, target_fixture(), tool_versions_fixture()
                )
            self.assertEqual(
                (output / "artifact/marker").read_text(encoding="utf-8"),
                "preserve",
            )

    def test_windows_path_fallback_rejects_replaced_output_and_preserves_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            output = parent / "output"
            output.mkdir()
            displaced = parent / "displaced-output"
            identity = _filesystem_identity(output.lstat())
            real_verify = verify_artifact
            calls = 0

            def replace_output(path, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    output.rename(displaced)
                    (output / "artifact").mkdir(parents=True)
                    (output / "artifact/replacement.txt").write_text(
                        "preserve", encoding="utf-8"
                    )
                    return "PASS"
                return real_verify(path, target)

            with mock.patch.object(
                sys.modules[__name__],
                "_open_output_directory",
                return_value=(output, None, identity),
            ), mock.patch.object(
                sys.modules[__name__], "verify_artifact", side_effect=replace_output
            ), self.assertRaisesRegex(RunnerError, "(?:output|ancestry) changed"):
                assemble_artifact(
                    root, output, target_fixture(), tool_versions_fixture()
                )
            self.assertEqual(
                (output / "artifact/replacement.txt").read_text(encoding="utf-8"),
                "preserve",
            )

    def test_windows_path_fallback_rejects_reparse_inserted_in_output_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = self._source_fixture(parent / "source", target_fixture())
            container = parent / "container"
            output = container / "output"
            output.mkdir(parents=True)
            displaced = parent / "displaced-container"
            identity = _filesystem_identity(output.lstat())
            real_copy = safe_copy_file
            calls = 0

            def replace_ancestor(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    container.rename(displaced)
                    container.symlink_to(displaced, target_is_directory=True)
                return real_copy(*args, **kwargs)

            with mock.patch.object(
                sys.modules[__name__],
                "_open_output_directory",
                return_value=(output, None, identity),
            ), mock.patch.object(
                sys.modules[__name__], "safe_copy_file", side_effect=replace_ancestor
            ), self.assertRaisesRegex(RunnerError, "ancestry changed"):
                assemble_artifact(
                    root, output, target_fixture(), tool_versions_fixture()
                )
            self.assertTrue(container.is_symlink())

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

    def test_smoke_plan_never_uses_source_build_outputs(self):
        artifact = Path("/isolated/镜像 Ω/agentgate")
        plan = smoke_plan(
            target_fixture(), artifact, Path("/tmp/smoke-build"),
            complete_capabilities(),
        )
        rendered = "\n".join(" ".join(command.argv) for command in plan)
        self.assertNotIn("/repo/target", rendered)
        self.assertNotIn("/repo/bindings", rendered)
        self.assertIn(str(artifact / "native/libagentgate_ffi.so"), rendered)

    def test_smoke_plan_orders_every_consumer_inside_extracted_artifact(self):
        artifact = Path("/isolated/路径 with spaces Ω/agentgate")
        build = Path("/fresh/smoke build")
        plan = smoke_plan(target_fixture(), artifact, build, complete_capabilities())
        self.assertEqual(len(plan), 14)
        self.assertEqual(
            [command.purpose for command in plan],
            [
                "abi-probe-compile-c-shared", "abi-probe-run-c-shared",
                "abi-probe-compile-cpp-shared", "abi-probe-run-cpp-shared",
                "abi-probe-compile-c-static", "abi-probe-run-c-static",
                "abi-probe-compile-cpp-static", "abi-probe-run-cpp-static",
                "smoke-python-ctypes", "smoke-go-test", "smoke-go-complete",
                "smoke-java-compile", "smoke-java-complete", "smoke-node-complete",
            ],
        )
        rendered = "\n".join(
            " ".join(command.argv) + " " + str(command.cwd) + " " +
            " ".join(f"{key}={value}" for key, value in command.env)
            for command in plan
        )
        for forbidden in ("/repo", "/source", "/target", "/bindings"):
            self.assertNotIn(forbidden, rendered)
        self.assertTrue(all(
            command.cwd == build or _is_within(command.cwd, artifact)
            for command in plan
        ))
        self.assertIn(str(artifact / "smoke/abi_probe.c"), plan[0].argv)
        self.assertIn(str(artifact / "include"), plan[0].argv)
        self.assertIn(str(artifact / "native/libagentgate_ffi.a"), plan[4].argv)
        self.assertIn("-DAGENTGATE_STATIC", plan[4].argv)
        self.assertEqual(plan[9].argv[-2:], ("--agentgate-library", str(artifact / "native/libagentgate_ffi.so")))
        self.assertEqual(plan[10].argv[-2:], ("--library", str(artifact / "native/libagentgate_ffi.so")))
        self.assertEqual(plan[-1].cwd, artifact / "node")

    def test_posix_go_smoke_uses_only_quoted_extracted_cgo_paths(self):
        artifact = Path("/isolated/路径 with spaces Ω/agentgate")
        plan = smoke_plan(
            target_fixture(), artifact, Path("/fresh/smoke build"),
            complete_capabilities(),
        )
        go_commands = [
            command for command in plan if command.purpose.startswith("smoke-go-")
        ]
        self.assertEqual(len(go_commands), 2)
        for command in go_commands:
            environment = dict(command.env)
            self.assertEqual(
                shlex.split(environment["CGO_CFLAGS"]),
                ["-I" + str(artifact / "include")],
            )
            self.assertEqual(
                shlex.split(environment["CGO_LDFLAGS"]),
                ["-L" + str(artifact / "native")],
            )
            self.assertNotIn("/repo", environment["CGO_CFLAGS"])
            self.assertNotIn("/repo", environment["CGO_LDFLAGS"])

    def test_windows_go_smoke_uses_only_quoted_extracted_include_path(self):
        artifact = Path("C:/isolated/路径 with spaces Ω/agentgate")
        plan = smoke_plan(
            Target.for_host("Windows", "AMD64"), artifact,
            Path("C:/fresh/smoke build"), complete_capabilities(),
        )
        go_commands = [
            command for command in plan if command.purpose.startswith("smoke-go-")
        ]
        self.assertEqual(len(go_commands), 2)
        for command in go_commands:
            environment = dict(command.env)
            self.assertEqual(
                shlex.split(environment["CGO_CFLAGS"]),
                ["-I" + str(artifact / "include")],
            )
            self.assertNotIn("CGO_LDFLAGS", environment)
            self.assertNotIn("/repo", environment["CGO_CFLAGS"])

    def test_windows_smoke_plan_links_import_library_and_stages_only_shared_dll(self):
        target = Target.for_host("Windows", "AMD64")
        artifact = Path("C:/isolated/路径 with spaces Ω/agentgate")
        build = Path("C:/fresh/smoke build")
        plan = smoke_plan(target, artifact, build, complete_capabilities())
        shared_compiles = (plan[0], plan[2])
        static_compiles = (plan[4], plan[6])
        for command in shared_compiles:
            self.assertIn(str(artifact / "native/agentgate_ffi.dll.lib"), command.argv)
            self.assertNotIn("/DAGENTGATE_STATIC", command.argv)
        for command in static_compiles:
            self.assertIn(str(artifact / "native/agentgate_ffi.lib"), command.argv)
            self.assertIn("/DAGENTGATE_STATIC", command.argv)
        self.assertEqual(plan[8].argv[0], "/tools/python")
        self.assertIn("WinDLL", plan[8].argv[-1])
        java = plan[12]
        self.assertIn(
            "-Dagentgate.core.path=" + str(artifact / "native/agentgate_ffi.dll"),
            java.argv,
        )

    def test_artifact_smoke_copies_to_unicode_child_and_verifies_before_and_after(self):
        temporary_roots = []
        copied_roots = []
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))

            def temporary_directory(**kwargs):
                context = tempfile.TemporaryDirectory(**kwargs)
                temporary_roots.append(Path(context.name))
                return context

            def copy_file(source, destination, relative, **kwargs):
                copied_roots.append(Path(destination))
                return safe_copy_file(source, destination, relative, **kwargs)

            calls = []
            with mock.patch.object(
                sys.modules[__name__], "verify_artifact", wraps=verify_artifact
            ) as verifier:
                self.assertEqual(
                    run_artifact_smoke(
                        target_fixture(), artifact, complete_capabilities(),
                        command_runner=lambda argv, **kwargs: (
                            calls.append((tuple(argv), kwargs)) or mock.Mock(returncode=0)
                        ),
                        temporary_directory=temporary_directory,
                        copy_file=copy_file,
                    ),
                    "PASS",
                )
            extracted = temporary_roots[0] / "路径 with spaces Ω"
            self.assertTrue(all(root == extracted for root in copied_roots))
            verified_paths = [call.args[0] for call in verifier.call_args_list]
            self.assertEqual(verified_paths[0], artifact)
            self.assertTrue(all(path == extracted for path in verified_paths[1:]))
            self.assertEqual(len(verified_paths), 17)
            self.assertTrue(all(
                str(artifact) not in argument
                for argv, _ in calls for argument in argv
            ))
            self.assertFalse(temporary_roots[0].exists())

    def test_artifact_smoke_creates_java_output_directory_before_javac(self):
        temporary_roots = []
        javac_outputs = []
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))

            def temporary_directory(**kwargs):
                context = tempfile.TemporaryDirectory(**kwargs)
                temporary_roots.append(Path(context.name))
                return context

            def runner(argv, **kwargs):
                if argv[0] == "/tools/javac":
                    output = Path(argv[argv.index("-d") + 1])
                    javac_outputs.append((output, output.is_dir(), output.is_symlink()))
                return mock.Mock(returncode=0)

            self.assertEqual(
                run_artifact_smoke(
                    target_fixture(), artifact, complete_capabilities(),
                    command_runner=runner, temporary_directory=temporary_directory,
                ),
                "PASS",
            )
        self.assertEqual(
            javac_outputs,
            [(temporary_roots[0] / "build/java-classes", True, False)],
        )
        self.assertFalse(temporary_roots[0].exists())

    def test_artifact_smoke_rejects_invalid_or_tampered_copy_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            invalid = build_fixture_artifact(parent / "invalid")
            write_checksums(invalid)
            runner = mock.Mock(side_effect=AssertionError("must not execute"))
            with self.assertRaises(RunnerError):
                run_artifact_smoke(target_fixture(), invalid, complete_capabilities(), command_runner=runner)
            runner.assert_not_called()

            artifact = self._assembled_fixture(parent / "valid")

            def tampering_copy(source, destination, relative, **kwargs):
                copied = safe_copy_file(source, destination, relative, **kwargs)
                if relative == CHECKSUM_NAME:
                    (Path(destination) / "include/agentgate.h").write_text("tampered", encoding="utf-8")
                return copied

            with self.assertRaises(RunnerError):
                run_artifact_smoke(
                    target_fixture(), artifact, complete_capabilities(),
                    command_runner=runner, copy_file=tampering_copy,
                )
            runner.assert_not_called()

    def test_artifact_smoke_rejects_regular_header_replacement_before_go(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))
            commands = []

            def runner(argv, **kwargs):
                commands.append(tuple(argv))
                if argv[:2] == ["/tools/python", "-c"]:
                    header = Path(kwargs["cwd"]) / "include/agentgate.h"
                    header.write_bytes(b"x" * len(header.read_bytes()))
                if argv[0] == "/tools/go":
                    raise AssertionError("Go ran after extracted header replacement")
                return mock.Mock(returncode=0)

            with self.assertRaisesRegex(RunnerError, "sha256"):
                run_artifact_smoke(
                    target_fixture(), artifact, complete_capabilities(),
                    command_runner=runner,
                )
            self.assertFalse(any(command[0] == "/tools/go" for command in commands))

    def test_artifact_smoke_rejects_regular_header_replacement_between_go_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))
            go_calls = []

            def runner(argv, **kwargs):
                if argv[0] == "/tools/go":
                    go_calls.append(tuple(argv))
                    if len(go_calls) == 1:
                        root = Path(kwargs["cwd"]).parent
                        header = root / "include/agentgate.h"
                        header.write_bytes(b"x" * len(header.read_bytes()))
                    else:
                        raise AssertionError("second Go command ran after header replacement")
                return mock.Mock(returncode=0)

            with self.assertRaisesRegex(RunnerError, "sha256"):
                run_artifact_smoke(
                    target_fixture(), artifact, complete_capabilities(),
                    command_runner=runner,
                )
            self.assertEqual(len(go_calls), 1)

    def test_artifact_smoke_rejects_jar_replacement_before_java_command(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))
            commands = []

            def runner(argv, **kwargs):
                commands.append(tuple(argv))
                if argv[:3] == ["/tools/go", "run", "./examples/complete"]:
                    root = Path(kwargs["cwd"]).parent
                    jar = root / "java/agentgate-java-0.1.0-SNAPSHOT.jar"
                    jar.write_bytes(b"x" * len(jar.read_bytes()))
                if argv[0] == "/tools/javac":
                    raise AssertionError("Java ran after extracted JAR replacement")
                return mock.Mock(returncode=0)

            with self.assertRaisesRegex(RunnerError, "sha256"):
                run_artifact_smoke(
                    target_fixture(), artifact, complete_capabilities(),
                    command_runner=runner,
                )
            self.assertFalse(any(command[0] == "/tools/javac" for command in commands))

    def test_artifact_smoke_reverifies_after_final_command(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))

            def runner(argv, **kwargs):
                if argv == ["/tools/node", "examples/complete.js"]:
                    script = Path(kwargs["cwd"]) / "examples/complete.js"
                    script.write_bytes(b"x" * len(script.read_bytes()))
                return mock.Mock(returncode=0)

            with self.assertRaisesRegex(RunnerError, "sha256"):
                run_artifact_smoke(
                    target_fixture(), artifact, complete_capabilities(),
                    command_runner=runner,
                )

    def test_artifact_smoke_clears_inherited_loader_and_agentgate_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = self._assembled_fixture(Path(directory))
            environments = []
            forbidden = {
                "LD_LIBRARY_PATH": "inherited-loader",
                "DYLD_LIBRARY_PATH": "inherited-loader",
                "AGENTGATE_LIBRARY_PATH": "inherited-agentgate",
                "AGENTGATE_LIBRARY": "inherited-agentgate",
                "AGENTGATE_RUNTIME_LIBRARY": "inherited-agentgate",
                "GOWORK": "/repo/go.work",
                "GOFLAGS": "-modfile=/repo/go.mod",
                "CGO_CFLAGS": "-I/repo/include",
                "CGO_CPPFLAGS": "-I/repo/include",
                "CGO_CXXFLAGS": "-I/repo/include",
                "CGO_LDFLAGS": "-L/repo/target/release",
            }
            with mock.patch.dict(os.environ, forbidden, clear=True):
                self.assertEqual(
                    run_artifact_smoke(
                        target_fixture(), artifact, complete_capabilities(),
                        command_runner=lambda argv, **kwargs: (
                            environments.append(kwargs["env"]) or mock.Mock(returncode=0)
                        ),
                    ),
                    "PASS",
                )
            for environment in environments:
                for key in forbidden:
                    if key == "GOWORK" and environment.get(key) == "off":
                        continue
                    if key in environment:
                        self.assertIn(
                            "路径 with spaces Ω",
                            environment[key],
                        )
                        self.assertNotIn(str(artifact), environment[key])
            self.assertFalse(any("GOFLAGS" in environment for environment in environments))
            self.assertEqual(
                sum(environment.get("GOWORK") == "off" for environment in environments),
                2,
            )

    def test_artifact_smoke_fails_closed_and_cleans_temporary_directory(self):
        for failure in (OSError("launch"), mock.Mock(returncode=9)):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                roots = []
                artifact = self._assembled_fixture(Path(directory))

                def temporary_directory(**kwargs):
                    context = tempfile.TemporaryDirectory(**kwargs)
                    roots.append(Path(context.name))
                    return context

                def runner(argv, **kwargs):
                    if isinstance(failure, BaseException):
                        raise failure
                    return failure

                with self.assertRaisesRegex(RunnerError, "unable to run|exit code 9"):
                    run_artifact_smoke(
                        target_fixture(), artifact, complete_capabilities(),
                        command_runner=runner, temporary_directory=temporary_directory,
                    )
                self.assertEqual(len(roots), 1)
                self.assertFalse(roots[0].exists())

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

    def test_compiler_capabilities_record_platform_specific_versions(self):
        version_output = mock.Mock(
            return_value="Microsoft (R) C/C++ Optimizing Compiler Version 19.42.34435"
        )
        capabilities = detect_capabilities(
            "Windows",
            lambda name: "/tools/cl" if name == "cl" else None,
            version_output,
        )
        self.assertEqual(
            capabilities["cc"],
            Capability("C compiler", "/tools/cl", (19, 42, 34435)),
        )
        self.assertEqual(
            capabilities["cxx"],
            Capability("C++ compiler", "/tools/cl", (19, 42, 34435)),
        )
        self.assertEqual(
            version_output.call_args_list,
            [mock.call("/tools/cl", "/?"), mock.call("/tools/cl", "/?")],
        )

    def test_tool_metadata_requires_every_numeric_bounded_version(self):
        versions = tool_versions_fixture()
        self.assertEqual(set(versions), set(CAPABILITY_NAMES))
        self.assertEqual(versions["cc"], "17.0.0")
        self.assertEqual(versions["cxx"], "17.0.0")
        capabilities = complete_capabilities()
        capabilities["cc"] = Capability("C compiler", "/tools/cc", None)
        with self.assertRaisesRegex(RunnerError, "C compiler version"):
            tool_versions_from_capabilities(capabilities)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifact"
            root.mkdir()
            (root / "payload").write_text("payload", encoding="utf-8")
            with self.assertRaisesRegex(RunnerError, "tool metadata"):
                build_manifest(root, target_fixture(), {})

    def test_verification_rejects_incomplete_tool_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = build_fixture_artifact(Path(directory))
            manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
            del manifest["tools"]["cxx"]
            self._rewrite_manifest(root, manifest)
            with self.assertRaisesRegex(RunnerError, "tools metadata"):
                verify_artifact(root, target_fixture())

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
        phase5c_index = next(
            index for index, command in enumerate(commands)
            if "test-phase5c.py" in " ".join(command)
        )
        maven_package_index = commands.index(
            (
                "/tools/maven",
                "-f",
                "/repo/bindings/java/pom.xml",
                "package",
            )
        )
        self.assertLess(phase5c_index, maven_package_index)

    def test_sanitizer_plan_is_linux_clang_only(self):
        target = Target.for_host("Linux", "x86_64")
        command = sanitizer_plan(target, Path("/repo"), complete_capabilities())[0]
        environment = dict(command.env)
        self.assertEqual(environment["CC"], "clang")
        self.assertEqual(environment["CXX"], "clang++")
        self.assertIn("-fsanitize=address,undefined", environment["CFLAGS"])
        self.assertEqual(environment["ASAN_OPTIONS"], "detect_leaks=1:halt_on_error=1")
        self.assertEqual(environment["UBSAN_OPTIONS"], "halt_on_error=1:print_stacktrace=1")
        with self.assertRaisesRegex(RunnerError, "Linux x86_64"):
            sanitizer_plan(Target.for_host("Darwin", "x86_64"), Path("/repo"), complete_capabilities())

    def test_sanitizer_plan_rejects_missing_compile_or_link_flags(self):
        command = sanitizer_plan(
            Target.for_host("Linux", "x86_64"), Path("/repo"), complete_capabilities()
        )[0]
        environment = tuple(
            pair for pair in command.env if pair[0] != "LDFLAGS"
        )
        with self.assertRaisesRegex(RunnerError, "compile or link flags"):
            _assert_sanitizer_plan([
                PlannedCommand(command.argv, command.cwd, environment, command.purpose)
            ])

    def test_sanitizer_run_builds_stable_ffi_before_direct_consumers(self):
        commands = []

        def runner(argv, **kwargs):
            commands.append((tuple(argv), kwargs))
            return mock.Mock(returncode=0)

        self.assertEqual(
            run_sanitizers(
                Target.for_host("Linux", "x86_64"), Path("/repo"),
                complete_capabilities(), command_runner=runner,
            ),
            "PASS",
        )
        self.assertEqual(
            commands[0][0], ("cargo", "build", "-p", "agentgate-ffi", "--release")
        )
        self.assertIn("--direct-native", commands[1][0])
        self.assertEqual(commands[1][1]["env"]["CC"], "clang")
        self.assertIn("-fsanitize=address,undefined", commands[1][1]["env"]["LDFLAGS"])
        self.assertFalse(commands[0][1]["shell"])
        self.assertFalse(commands[1][1]["shell"])

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

    def test_dry_run_plans_without_temporary_directory_or_staging(self):
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
        self.assertEqual(temporary_roots, [])

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
            parse_compiler_version(
                "warning: build year 2022\nApple clang version 17.0.0"
            ),
            (17, 0, 0),
        )
        self.assertIsNone(
            parse_compiler_version("warning: fallback compiler 99.0.0")
        )
        for banner, expected in (
            ("warning: build 2026\nUbuntu clang version 18.1.3", (18, 1, 3)),
            ("notice: runtime 99\nDebian clang version 16.0.6", (16, 0, 6)),
        ):
            with self.subTest(banner=banner):
                self.assertEqual(parse_compiler_version(banner), expected)
        self.assertIsNone(
            parse_compiler_version("Ubuntu toolchain warning 22.04 compiler 99.0.0")
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

    def test_x86_64_all_stage_fails_closed(self):
        with self.assertRaisesRegex(RunnerError, "Phase 5D stage is not implemented: all"):
            main(["--stage", "all"], system="Linux", arch="x86_64")

    def test_sanitizer_stage_requires_linux_x86_64(self):
        with self.assertRaisesRegex(RunnerError, "Linux x86_64"):
            main(["--stage", "sanitizers"], system="Darwin", arch="x86_64")

    def test_ci_sanitizer_stage_reports_pass_only_after_runner_success(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__], "detect_capabilities",
            return_value=complete_capabilities(),
        ), mock.patch.object(
            sys.modules[__name__], "run_sanitizers", return_value="PASS"
        ) as runner, contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    ["--ci", "--stage", "sanitizers"],
                    system="Linux", arch="x86_64", root=Path("/repo"),
                ),
                0,
            )
        runner.assert_called_once()
        self.assertIn("sanitizers=PASS", stdout.getvalue())

    def test_artifact_stage_assembles_then_verifies_before_pass_output(self):
        artifact = Path("/output/artifact")
        assembler = mock.Mock(return_value=artifact)
        verifier = mock.Mock(return_value="PASS")
        smoker = mock.Mock(return_value="PASS")
        stdout = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__], "detect_capabilities",
            return_value=complete_capabilities(),
        ), mock.patch.object(
            sys.modules[__name__], "assemble_artifact", assembler
        ), mock.patch.object(
            sys.modules[__name__], "verify_artifact", verifier
        ), mock.patch.object(
            sys.modules[__name__], "run_artifact_smoke", smoker
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    ["--stage", "artifact", "--output", "/output"],
                    system="Linux",
                    arch="x86_64",
                    root=Path("/repo"),
                ),
                0,
            )
        assembler.assert_called_once()
        verifier.assert_called_once_with(artifact, target_fixture())
        smoker.assert_called_once_with(
            target_fixture(), artifact, complete_capabilities(),
            command_runner=subprocess.run,
        )
        self.assertIn("qualification=NOT_RUN artifact=PASS", stdout.getvalue())

    def test_artifact_dry_run_plans_without_filesystem_writes(self):
        assembler = mock.Mock(side_effect=AssertionError("dry run assembled artifact"))
        stdout = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__], "detect_capabilities",
            return_value=complete_capabilities(),
        ), mock.patch.object(
            sys.modules[__name__], "assemble_artifact", assembler
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    ["--stage", "artifact", "--dry-run", "--output", "/output"],
                    system="Linux",
                    arch="x86_64",
                    root=Path("/repo"),
                ),
                0,
            )
        assembler.assert_not_called()
        self.assertIn("qualification=NOT_RUN artifact=PLANNED", stdout.getvalue())

    def test_qualification_assembles_and_verifies_before_reporting_pass(self):
        artifact = Path("/output/artifact")
        events = []

        def qualify(*args, **kwargs):
            events.append("qualification")
            return "PASS"

        def assemble(*args, **kwargs):
            events.append("assembly")
            return artifact

        def verify(*args, **kwargs):
            events.append("verification")
            return "PASS"

        def smoke(*args, **kwargs):
            events.append("smoke")
            return "PASS"

        stdout = io.StringIO()
        with mock.patch.object(
            sys.modules[__name__], "detect_capabilities",
            return_value=complete_capabilities(),
        ), mock.patch.object(
            sys.modules[__name__], "run_qualification", qualify
        ), mock.patch.object(
            sys.modules[__name__], "assemble_artifact", assemble
        ), mock.patch.object(
            sys.modules[__name__], "verify_artifact", verify
        ), mock.patch.object(
            sys.modules[__name__], "run_artifact_smoke", smoke
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    ["--stage", "qualification", "--output", "/output"],
                    system="Linux",
                    arch="x86_64",
                    root=Path("/repo"),
                ),
                0,
            )
        self.assertEqual(events, ["qualification", "assembly", "verification", "smoke"])
        self.assertIn("qualification=PASS artifact=PASS", stdout.getvalue())

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

AGENTGATE_VERSION = "0.1.0"
ABI_VERSION = 1
MANIFEST_NAME = "manifest.json"
CHECKSUM_NAME = "SHA256SUMS"
RESERVED_ARTIFACT_NAMES = frozenset({MANIFEST_NAME, CHECKSUM_NAME})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
WINDOWS_ABSOLUTE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")
JNI_SHIM_NAMES = MappingProxyType(
    {
        "Linux": "libagentgate_jni.so",
        "Darwin": "libagentgate_jni.dylib",
        "Windows": "agentgate_jni.dll",
    }
)
MAX_REPORTED_PATHS = 5
MAX_REPORTED_PATH_LENGTH = 96
MAX_TOOL_VERSION_LENGTH = 64
MAX_METADATA_BYTES = 8 * 1024 * 1024
REQUIRED_TOOL_KEYS = frozenset(CAPABILITY_NAMES)
SECURE_DIR_FD_SUPPORTED = (
    os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and getattr(os, "O_DIRECTORY", 0) != 0
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
COMPILER_VERSION_PATTERNS = (
    re.compile(
        r"^(?:(?:Apple|Ubuntu|Debian)\s+)?clang version\s+(\d+(?:\.\d+)*)",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^(?:gcc|g\+\+|cc|c\+\+)(?:\s+\([^\r\n]*\))?\s+(\d+(?:\.\d+)*)",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^Microsoft \(R\) C/C\+\+ Optimizing Compiler Version\s+"
        r"(\d+(?:\.\d+)*)",
        flags=re.IGNORECASE | re.MULTILINE,
    ),
)


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


def parse_compiler_version(output: str) -> tuple[int, ...] | None:
    normalized_output = "\n".join(
        line.lstrip() for line in ANSI_ESCAPE.sub("", output).splitlines()
    )
    for pattern in COMPILER_VERSION_PATTERNS:
        match = pattern.search(normalized_output)
        if match is not None:
            return tuple(int(part) for part in match.group(1).split("."))
    return None


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
        "cc": ("/?",) if normalized_system == "Windows" else ("--version",),
        "cxx": ("/?",) if normalized_system == "Windows" else ("--version",),
    }
    paths = {key: tool_lookup(executable) for key, executable in executables.items()}
    if paths["python"] is None:
        paths["python"] = tool_lookup("python")

    def detected(key: str) -> Capability:
        path = paths[key]
        if path is None:
            return Capability(CAPABILITY_NAMES[key], None, None)
        try:
            output = version_output(path, *version_arguments[key])
            version = (
                parse_compiler_version(output)
                if key in {"cc", "cxx"}
                else parse_tool_version(key, output)
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
    *,
    source_directory: Path | None = None,
    include_directory: Path | None = None,
) -> PlannedCommand:
    is_cpp = language == "cpp"
    compiler_key = "cxx" if is_cpp else "cc"
    compiler = capabilities[compiler_key].path
    if compiler is None:
        label = "C++" if is_cpp else "C"
        raise RunnerError(f"required capability: {label} compiler")
    source = (
        root / "tests" / "qualification" / f"abi_probe.{language}"
        if source_directory is None
        else Path(source_directory) / f"abi_probe.{language}"
    )
    output = _probe_output_path(target, build_directory, language, linkage)
    library_name = target.shared_name if linkage == "shared" else target.static_name
    library = artifact_directory / library_name
    include_directory = (
        root / "packages" / "ffi" / "include"
        if include_directory is None
        else Path(include_directory)
    )

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


SMOKE_CLEARED_ENVIRONMENT = frozenset(
    {
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "AGENTGATE_LIBRARY_PATH",
        "AGENTGATE_LIBRARY",
        "AGENTGATE_RUNTIME_LIBRARY",
        "GOWORK",
        "GOFLAGS",
        "CGO_CFLAGS",
        "CGO_CPPFLAGS",
        "CGO_CXXFLAGS",
        "CGO_LDFLAGS",
    }
)


def smoke_plan(
    target: Target,
    artifact: Path,
    build_directory: Path,
    capabilities: dict[str, Capability],
) -> list[PlannedCommand]:
    """Plan consumers against an extracted artifact and fresh smoke output only."""
    artifact = Path(artifact)
    build_directory = Path(build_directory)
    native = artifact / "native"
    shared_library = native / target.shared_name
    commands = []
    for linkage in ("shared", "static"):
        for language in ("c", "cpp"):
            compile_command = _probe_compile_command(
                target,
                artifact,
                native,
                capabilities,
                build_directory,
                language,
                linkage,
                source_directory=artifact / "smoke",
                include_directory=artifact / "include",
            )
            runtime_environment = ()
            if linkage == "shared" and target.system == "Linux":
                runtime_environment = (("LD_LIBRARY_PATH", str(native)),)
            elif linkage == "shared" and target.system == "Darwin":
                runtime_environment = (("DYLD_LIBRARY_PATH", str(native)),)
            commands.extend(
                (
                    compile_command,
                    PlannedCommand(
                        (str(_probe_output_path(target, build_directory, language, linkage)),),
                        build_directory,
                        runtime_environment,
                        purpose=f"abi-probe-run-{language}-{linkage}",
                    ),
                )
            )

    python = capabilities["python"].path
    go = capabilities["go"].path
    javac = capabilities["javac"].path
    java = capabilities["java"].path
    node = capabilities["node"].path
    if None in (python, go, javac, java, node):
        raise RunnerError("required capability missing for artifact smoke")
    loader = "ctypes.WinDLL" if target.system == "Windows" else "ctypes.CDLL"
    ctypes_script = (
        "import ctypes; library=" + loader + "(" + repr(str(shared_library)) + "); "
        "assert library.ag_abi_version() == 1"
    )
    commands.append(
        PlannedCommand(
            (python, "-c", ctypes_script), artifact,
            purpose="smoke-python-ctypes",
        )
    )

    go_environment = (
        ("CGO_CFLAGS", shlex.join(["-I" + str(artifact / "include")])),
        ("GOWORK", "off"),
    )
    if target.system in {"Linux", "Darwin"}:
        loader_variable = (
            "LD_LIBRARY_PATH" if target.system == "Linux" else "DYLD_LIBRARY_PATH"
        )
        go_environment += (
            ("CGO_LDFLAGS", shlex.join(["-L" + str(native)])),
            (loader_variable, str(native)),
        )
    commands.extend(
        (
            PlannedCommand(
                (go, "test", "./...", "-args", "--agentgate-library", str(shared_library)),
                artifact / "go", go_environment, purpose="smoke-go-test",
            ),
            PlannedCommand(
                (go, "run", "./examples/complete", "--library", str(shared_library)),
                artifact / "go", go_environment, purpose="smoke-go-complete",
            ),
        )
    )

    classes = build_directory / "java-classes"
    main_jar = artifact / "java" / "agentgate-java-0.1.0-SNAPSHOT.jar"
    shim = artifact / "java" / JNI_SHIM_NAMES[target.system]
    classpath_separator = ";" if target.system == "Windows" else ":"
    classpath = classpath_separator.join((str(classes), str(main_jar)))
    java_environment = ()
    if target.system in {"Linux", "Darwin"}:
        loader_variable = (
            "LD_LIBRARY_PATH" if target.system == "Linux" else "DYLD_LIBRARY_PATH"
        )
        java_environment = ((loader_variable, str(artifact / "java")),)
    commands.append(
        PlannedCommand(
            (javac, "-cp", classpath, "-d", str(classes), str(artifact / "java/examples/Complete.java")),
            artifact / "java", java_environment, purpose="smoke-java-compile",
        )
    )
    java_argv = [java, "-cp", classpath]
    if target.system == "Windows":
        java_argv.append("-Dagentgate.core.path=" + str(shared_library))
    java_argv.extend(("io.agentgate.examples.Complete", str(shim)))
    commands.append(
        PlannedCommand(
            tuple(java_argv), artifact / "java", java_environment,
            purpose="smoke-java-complete",
        )
    )

    node_environment = (
        ("AGENTGATE_LIBRARY", str(shared_library)),
        ("AGENTGATE_RUNTIME_LIBRARY", str(shared_library)),
    )
    if target.system in {"Linux", "Darwin"}:
        loader_variable = (
            "LD_LIBRARY_PATH" if target.system == "Linux" else "DYLD_LIBRARY_PATH"
        )
        node_environment += ((loader_variable, str(native)),)
    commands.append(
        PlannedCommand(
            (node, "examples/complete.js"), artifact / "node", node_environment,
            purpose="smoke-node-complete",
        )
    )
    return commands


SANITIZER_FLAG = "-fsanitize=address,undefined"
SANITIZER_ENVIRONMENT = (
    ("CC", "clang"),
    ("CXX", "clang++"),
    ("CFLAGS", "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"),
    ("CXXFLAGS", "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"),
    ("LDFLAGS", "-fsanitize=address,undefined"),
    ("ASAN_OPTIONS", "detect_leaks=1:halt_on_error=1"),
    ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
)


def _assert_sanitizer_plan(plan: list[PlannedCommand]) -> None:
    """Fail closed unless direct consumer builds carry compile and link sanitizers."""
    for command in plan:
        environment = dict(command.env)
        if "--direct-native" not in command.argv:
            raise RunnerError("sanitizer direct compile plan requires --direct-native")
        if (
            SANITIZER_FLAG not in environment.get("CFLAGS", "")
            or SANITIZER_FLAG not in environment.get("CXXFLAGS", "")
            or SANITIZER_FLAG not in environment.get("LDFLAGS", "")
        ):
            raise RunnerError(
                "sanitizer direct compile plan is missing sanitizer compile or link flags"
            )


def sanitizer_plan(
    target: Target, root: Path, capabilities: dict[str, Capability]
) -> list[PlannedCommand]:
    if target.system != "Linux" or target.arch != "x86_64":
        raise RunnerError("sanitizer stage requires Linux x86_64")
    python = capabilities["python"].path
    if python is None:
        raise RunnerError("required capability: Python 3.11+")
    root = Path(root)
    plan = [
        PlannedCommand(
            (
                python,
                str(root / "scripts" / "test-phase5b.py"),
                "--native-only",
                "--direct-native",
                "--library",
                str(root / "target" / "release" / target.shared_name),
            ),
            root,
            SANITIZER_ENVIRONMENT,
            purpose="sanitizer-direct-native",
        )
    ]
    _assert_sanitizer_plan(plan)
    return plan


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
        PlannedCommand(
            (
                capabilities["maven"].path or "mvn",
                "-f",
                str(root / "bindings" / "java" / "pom.xml"),
                "package",
            ),
            root,
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


def _format_paths(paths) -> str:
    values = sorted(str(path) for path in paths)
    shown = []
    for value in values[:MAX_REPORTED_PATHS]:
        if len(value) > MAX_REPORTED_PATH_LENGTH:
            value = value[: MAX_REPORTED_PATH_LENGTH - 3] + "..."
        shown.append(value)
    suffix = ", ..." if len(values) > MAX_REPORTED_PATHS else ""
    return f"{', '.join(shown)}{suffix} ({len(values)} total)"


def normalize_artifact_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RunnerError("artifact path must be a non-empty string")
    if (
        value.startswith(("/", "\\"))
        or WINDOWS_ABSOLUTE_PATTERN.match(value)
        or "\\" in value
    ):
        raise RunnerError(f"artifact path must be relative POSIX: {_bounded_diagnostic(value)}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RunnerError(f"artifact path is not normalized: {_bounded_diagnostic(value)}")
    if any(part in RESERVED_ARTIFACT_NAMES for part in parts):
        raise RunnerError(f"manifest cannot name reserved artifact file: {value}")
    normalized = Path(*parts).as_posix()
    if normalized != value:
        raise RunnerError(f"artifact path is not normalized: {_bounded_diagnostic(value)}")
    return normalized


def _path_lstat(path: Path):
    try:
        return path.lstat()
    except OSError as error:
        raise RunnerError(f"artifact path is missing or inaccessible: {path}") from error


def _require_directory(path: Path, label: str) -> None:
    value = _path_lstat(path)
    if _is_link_or_reparse(value):
        raise RunnerError(f"{label} is a symlink or reparse point: {path}")
    if not stat.S_ISDIR(value.st_mode):
        raise RunnerError(f"{label} is not a directory: {path}")


def _require_regular_file(path: Path, label: str = "artifact file") -> None:
    value = _path_lstat(path)
    if _is_link_or_reparse(value):
        raise RunnerError(f"{label} is a symlink or reparse point: {path}")
    if not stat.S_ISREG(value.st_mode):
        raise RunnerError(f"{label} is not a regular file: {path}")


@contextlib.contextmanager
def _open_regular_file(
    path: Path,
    label: str = "artifact file",
    *,
    trusted_root: Path | None = None,
    max_bytes: int | None = None,
):
    path = Path(path)
    root = path.parent if trusted_root is None else Path(trusted_root)
    absolute_path = path.absolute()
    absolute_root = root.absolute()
    try:
        relative = absolute_path.relative_to(absolute_root)
    except ValueError as error:
        raise RunnerError(f"{label} escapes its trusted root: {path}") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RunnerError(f"{label} path is not normalized: {path}")

    read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    supports_descriptor_walk = SECURE_DIR_FD_SUPPORTED
    descriptors = []
    source = None

    def directory_identity(value):
        return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode))

    def file_identity(value):
        return (
            value.st_dev,
            value.st_ino,
            stat.S_IFMT(value.st_mode),
            value.st_size,
            value.st_mtime_ns,
        )

    try:
        if supports_descriptor_walk:
            root_before = absolute_root.lstat()
            if _is_link_or_reparse(root_before) or not stat.S_ISDIR(root_before.st_mode):
                raise RunnerError(f"trusted root is not a real directory: {root}")
            root_descriptor = os.open(
                absolute_root,
                read_flags | directory_flag | nofollow,
            )
            descriptors.append(root_descriptor)
            if directory_identity(os.fstat(root_descriptor)) != directory_identity(root_before):
                raise RunnerError(f"trusted root changed during validation: {root}")
            directory_links = []
            parent_descriptor = root_descriptor
            for component in relative.parts[:-1]:
                before = os.stat(
                    component, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if _is_link_or_reparse(before) or not stat.S_ISDIR(before.st_mode):
                    raise RunnerError(f"{label} parent is not a real directory: {path}")
                child_descriptor = os.open(
                    component,
                    read_flags | directory_flag | nofollow,
                    dir_fd=parent_descriptor,
                )
                descriptors.append(child_descriptor)
                if directory_identity(os.fstat(child_descriptor)) != directory_identity(before):
                    raise RunnerError(f"{label} parent changed during validation: {path}")
                directory_links.append((parent_descriptor, component, before))
                parent_descriptor = child_descriptor
            filename = relative.parts[-1]
            before = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
            if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
                raise RunnerError(f"{label} is not a regular file: {path}")
            file_descriptor = os.open(
                filename,
                read_flags | nofollow,
                dir_fd=parent_descriptor,
            )
            descriptors.append(file_descriptor)
            opened = os.fstat(file_descriptor)
            if not stat.S_ISREG(opened.st_mode) or file_identity(opened) != file_identity(before):
                raise RunnerError(f"{label} changed during validation: {path}")
            if max_bytes is not None and opened.st_size > max_bytes:
                raise RunnerError(f"{label} exceeds the size limit")
            source = os.fdopen(file_descriptor, "rb", closefd=False)
            yield source
            after_open = os.fstat(file_descriptor)
            after_path = os.stat(
                filename, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                _is_link_or_reparse(after_path)
                or file_identity(after_open) != file_identity(opened)
                or file_identity(after_path) != file_identity(before)
            ):
                raise RunnerError(f"{label} changed while being read: {path}")
            for parent_fd, component, expected in directory_links:
                current = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
                if (
                    _is_link_or_reparse(current)
                    or directory_identity(current) != directory_identity(expected)
                ):
                    raise RunnerError(f"{label} parent changed while being read: {path}")
            root_after = absolute_root.lstat()
            if (
                _is_link_or_reparse(root_after)
                or directory_identity(root_after) != directory_identity(root_before)
            ):
                raise RunnerError(f"trusted root changed while reading {label}: {root}")
        else:
            parents = []
            current = absolute_root
            root_before = current.lstat()
            if _is_link_or_reparse(root_before) or not stat.S_ISDIR(root_before.st_mode):
                raise RunnerError(f"trusted root is not a real directory: {root}")
            parents.append((current, root_before))
            for component in relative.parts[:-1]:
                current = current / component
                before_parent = current.lstat()
                if _is_link_or_reparse(before_parent) or not stat.S_ISDIR(before_parent.st_mode):
                    raise RunnerError(f"{label} parent is not a real directory: {path}")
                parents.append((current, before_parent))
            before = absolute_path.lstat()
            if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
                raise RunnerError(f"{label} is not a regular file: {path}")
            file_descriptor = os.open(absolute_path, read_flags | nofollow)
            descriptors.append(file_descriptor)
            opened = os.fstat(file_descriptor)
            current_file = absolute_path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_link_or_reparse(current_file)
                or file_identity(opened) != file_identity(before)
                or file_identity(current_file) != file_identity(before)
            ):
                raise RunnerError(f"{label} changed during validation: {path}")
            for parent_path, expected in parents:
                current_parent = parent_path.lstat()
                if (
                    _is_link_or_reparse(current_parent)
                    or directory_identity(current_parent) != directory_identity(expected)
                ):
                    raise RunnerError(f"{label} parent changed during validation: {path}")
            if max_bytes is not None and opened.st_size > max_bytes:
                raise RunnerError(f"{label} exceeds the size limit")
            source = os.fdopen(file_descriptor, "rb", closefd=False)
            yield source
            current_file = absolute_path.lstat()
            if (
                file_identity(os.fstat(file_descriptor)) != file_identity(opened)
                or _is_link_or_reparse(current_file)
                or file_identity(current_file) != file_identity(before)
            ):
                raise RunnerError(f"{label} changed while being read: {path}")
            for parent_path, expected in parents:
                current_parent = parent_path.lstat()
                if (
                    _is_link_or_reparse(current_parent)
                    or directory_identity(current_parent) != directory_identity(expected)
                ):
                    raise RunnerError(f"{label} parent changed while being read: {path}")
    except RunnerError:
        raise
    except OSError as error:
        raise RunnerError(
            f"unable to open {label} without following symlinks: {path}"
        ) from error
    finally:
        if source is not None:
            source.close()
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_regular_bytes(path: Path, label: str, trusted_root: Path) -> bytes:
    try:
        with _open_regular_file(
            path, label, trusted_root=trusted_root, max_bytes=MAX_METADATA_BYTES
        ) as source:
            data = source.read(MAX_METADATA_BYTES + 1)
            if len(data) > MAX_METADATA_BYTES:
                raise RunnerError(f"{label} exceeds the size limit")
            return data
    except OSError as error:
        raise RunnerError(f"unable to read {label}: {path}") from error


def _walk_regular_files(root: Path, *, exclude_metadata: bool) -> list[tuple[str, Path]]:
    root = Path(root)
    _require_directory(root, "artifact root")
    files = []
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda child: child.name)
        except OSError as error:
            raise RunnerError(f"unable to inspect artifact directory: {directory}") from error
        for child in children:
            relative = f"{prefix}/{child.name}" if prefix else child.name
            value = _path_lstat(child)
            if _is_link_or_reparse(value):
                raise RunnerError(f"artifact contains symlink or reparse point: {relative}")
            if stat.S_ISDIR(value.st_mode):
                pending.append((child, relative))
            elif stat.S_ISREG(value.st_mode):
                if exclude_metadata and relative in RESERVED_ARTIFACT_NAMES:
                    continue
                normalized = (
                    relative
                    if relative in RESERVED_ARTIFACT_NAMES
                    else normalize_artifact_path(relative)
                )
                files.append((normalized, child))
            else:
                raise RunnerError(f"artifact contains non-regular file: {relative}")
    return sorted(files, key=lambda item: item[0])


def sha256_file(path: Path, *, trusted_root: Path | None = None) -> str:
    digest = hashlib.sha256()
    try:
        with _open_regular_file(
            Path(path), trusted_root=trusted_root
        ) as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as error:
        raise RunnerError(f"unable to hash artifact file: {path}") from error
    return digest.hexdigest()


def _artifact_kind(path: str) -> str:
    if path == "include/agentgate.h":
        return "header"
    if path.startswith("native/"):
        return "native-library"
    if path.endswith(".jar"):
        return "java-archive"
    if path.endswith((".so", ".dylib", ".dll", ".node", ".lib", ".a")):
        return "runtime-binary"
    if path.endswith((".c", ".cpp")) and path.startswith("smoke/"):
        return "smoke-source"
    if path.endswith((".go", ".java", ".js")):
        return "source"
    return "metadata"


def _required_artifact_singletons(target: Target) -> set[str]:
    required = {
        "include/agentgate.h",
        f"native/{target.shared_name}",
        f"native/{target.static_name}",
        "go/go.mod",
        "java/agentgate-java-0.1.0-SNAPSHOT.jar",
        f"java/{JNI_SHIM_NAMES[target.system]}",
        f"java/{target.shared_name}",
        "java/examples/Complete.java",
        "node/package.json",
        "node/examples/complete.js",
        "node/build/Release/agentgate.node",
        f"node/build/Release/{target.shared_name}",
        "smoke/abi_probe.c",
        "smoke/abi_probe.cpp",
    }
    if target.import_name is not None:
        required.add(f"native/{target.import_name}")
    return required


REQUIRED_ARTIFACT_GROUPS = (
    "go/agentgate/",
    "go/examples/complete/",
    "node/lib/",
)


def _validate_artifact_layout(entries: list[dict], target: Target) -> None:
    paths = {entry["path"] for entry in entries}
    required = _required_artifact_singletons(target)
    missing = required - paths
    empty_groups = [
        prefix.rstrip("/")
        for prefix in REQUIRED_ARTIFACT_GROUPS
        if not any(path.startswith(prefix) for path in paths)
    ]
    unexpected = {
        path for path in paths
        if path not in required
        and not any(path.startswith(prefix) for prefix in REQUIRED_ARTIFACT_GROUPS)
    }
    if missing or empty_groups or unexpected:
        differences = []
        if missing:
            differences.append(f"missing layout paths: {_format_paths(missing)}")
        if empty_groups:
            differences.append(
                f"empty layout groups: {_format_paths(empty_groups)}"
            )
        if unexpected:
            differences.append(
                f"unexpected layout paths: {_format_paths(unexpected)}"
            )
        raise RunnerError("artifact layout mismatch: " + "; ".join(differences))


def _validate_tool_versions(tool_versions: dict[str, str]) -> dict[str, str]:
    if not isinstance(tool_versions, dict) or set(tool_versions) != REQUIRED_TOOL_KEYS:
        raise RunnerError("artifact tool metadata must contain every required tool")
    normalized = {}
    for key in sorted(REQUIRED_TOOL_KEYS):
        version = tool_versions[key]
        if (
            not isinstance(version, str)
            or not version
            or len(version) > MAX_TOOL_VERSION_LENGTH
            or re.fullmatch(r"\d+(?:\.\d+)*", version) is None
        ):
            raise RunnerError(f"artifact tool metadata is malformed: {key}")
        normalized[key] = version
    return normalized


def build_manifest(
    artifact_root: Path,
    target: Target,
    tool_versions: dict[str, str],
) -> dict:
    artifact_root = Path(artifact_root)
    tools = _validate_tool_versions(tool_versions)
    files = []
    for relative, path in _walk_regular_files(
        artifact_root, exclude_metadata=True
    ):
        files.append(
            {
                "path": relative,
                "kind": _artifact_kind(relative),
                "size": path.lstat().st_size,
                "sha256": sha256_file(path, trusted_root=artifact_root),
            }
        )
    return {
        "schema_version": 1,
        "agentgate_version": AGENTGATE_VERSION,
        "abi_version": ABI_VERSION,
        "target": {
            "os": target.system,
            "arch": target.arch,
            "triple": target.triple,
        },
        "tools": tools,
        "files": files,
    }


def _canonical_json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def write_manifest(artifact_root: Path, manifest: dict) -> Path:
    root = Path(artifact_root)
    _require_directory(root, "artifact root")
    destination = root / MANIFEST_NAME
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink():
            raise RunnerError(f"manifest destination is a symlink: {destination}")
        _require_regular_file(destination, "manifest destination")
    try:
        destination.write_bytes(_canonical_json(manifest))
    except (OSError, TypeError, ValueError) as error:
        raise RunnerError(f"unable to write manifest: {destination}") from error
    return destination


def write_checksums(artifact_root: Path) -> Path:
    root = Path(artifact_root)
    files = _walk_regular_files(root, exclude_metadata=False)
    entries = []
    for relative, path in files:
        if relative == CHECKSUM_NAME:
            continue
        entries.append(f"{sha256_file(path, trusted_root=root)}  {relative}\n")
    destination = root / CHECKSUM_NAME
    if destination.is_symlink():
        raise RunnerError(f"checksum destination is a symlink: {destination}")
    if destination.exists():
        _require_regular_file(destination, "checksum destination")
    try:
        destination.write_bytes("".join(entries).encode("utf-8"))
    except OSError as error:
        raise RunnerError(f"unable to write checksums: {destination}") from error
    return destination


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RunnerError(f"duplicate JSON key: {_bounded_diagnostic(str(key))}")
        result[key] = value
    return result


def _load_manifest(root: Path) -> tuple[dict, bytes]:
    path = root / MANIFEST_NAME
    data = _read_regular_bytes(path, "manifest", root)
    return _parse_manifest_bytes(data)


def _parse_manifest_bytes(data: bytes) -> tuple[dict, bytes]:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except RunnerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError("manifest JSON is malformed") from error
    if not isinstance(value, dict):
        raise RunnerError("manifest JSON must be an object")
    if data != _canonical_json(value):
        raise RunnerError("manifest JSON is not canonical")
    return value, data


def _validate_manifest_schema(manifest: dict, expected_target: Target | None) -> list[dict]:
    expected_keys = {
        "schema_version", "agentgate_version", "abi_version", "target", "tools", "files"
    }
    if set(manifest) != expected_keys:
        raise RunnerError("manifest schema has missing or unknown fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise RunnerError("unsupported manifest schema_version")
    if manifest["agentgate_version"] != AGENTGATE_VERSION:
        raise RunnerError("unexpected manifest agentgate_version")
    if type(manifest["abi_version"]) is not int or manifest["abi_version"] != ABI_VERSION:
        raise RunnerError("unexpected manifest abi_version")
    target_value = manifest["target"]
    if not isinstance(target_value, dict) or set(target_value) != {"os", "arch", "triple"}:
        raise RunnerError("manifest target metadata is malformed")
    if not all(isinstance(target_value[key], str) for key in target_value):
        raise RunnerError("manifest target metadata is malformed")
    try:
        recorded_target = Target.for_host(target_value["os"], target_value["arch"])
    except RunnerError as error:
        raise RunnerError("manifest target metadata is unsupported") from error
    if target_value != {
        "os": recorded_target.system,
        "arch": recorded_target.arch,
        "triple": recorded_target.triple,
    }:
        raise RunnerError("manifest target metadata is inconsistent")
    if expected_target is not None and recorded_target != expected_target:
        raise RunnerError("manifest target does not match expected target")
    tools = manifest["tools"]
    try:
        _validate_tool_versions(tools)
    except RunnerError as error:
        raise RunnerError("manifest tools metadata is malformed") from error
    files = manifest["files"]
    if not isinstance(files, list):
        raise RunnerError("manifest files must be an array")
    seen = set()
    previous = None
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "kind", "size", "sha256"}:
            raise RunnerError("manifest file entry is malformed")
        relative = normalize_artifact_path(entry["path"])
        if relative in seen:
            raise RunnerError(f"duplicate manifest path: {relative}")
        if previous is not None and relative <= previous:
            raise RunnerError("manifest file paths are not sorted")
        seen.add(relative)
        previous = relative
        if not isinstance(entry["kind"], str) or not entry["kind"]:
            raise RunnerError(f"manifest kind is malformed: {relative}")
        if entry["kind"] != _artifact_kind(relative):
            raise RunnerError(f"manifest kind is not canonical: {relative}")
        if type(entry["size"]) is not int or entry["size"] < 0:
            raise RunnerError(f"manifest size is malformed: {relative}")
        if not isinstance(entry["sha256"], str) or not SHA256_PATTERN.fullmatch(entry["sha256"]):
            raise RunnerError(f"manifest sha256 is malformed: {relative}")
    _validate_artifact_layout(files, recorded_target)
    return files


def parse_checksums(
    path: Path, trusted_root: Path | None = None
) -> dict[str, str]:
    data = _read_regular_bytes(
        Path(path),
        "checksum file",
        Path(path).parent if trusted_root is None else Path(trusted_root),
    )
    return _parse_checksums_bytes(data)


def _parse_checksums_bytes(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RunnerError("unable to read SHA256SUMS as UTF-8") from error
    if not text or not text.endswith("\n"):
        raise RunnerError("SHA256SUMS must end with a newline")
    entries = {}
    previous = None
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise RunnerError("SHA256SUMS line is malformed")
        digest, raw_path = match.groups()
        if raw_path == CHECKSUM_NAME:
            raise RunnerError("SHA256SUMS cannot hash itself")
        relative = (
            MANIFEST_NAME
            if raw_path == MANIFEST_NAME
            else normalize_artifact_path(raw_path)
        )
        if relative in entries:
            raise RunnerError(f"duplicate SHA256SUMS path: {relative}")
        if previous is not None and relative <= previous:
            raise RunnerError("SHA256SUMS entries are not sorted")
        entries[relative] = digest
        previous = relative
    canonical = "".join(
        f"{digest}  {relative}\n"
        for relative, digest in sorted(entries.items())
    ).encode("utf-8")
    if data != canonical:
        raise RunnerError("SHA256SUMS is not canonical")
    return entries


def verify_artifact(artifact_root: Path, expected_target: Target | None = None) -> str:
    root = Path(artifact_root)
    _require_directory(root, "artifact root")
    manifest, _ = _load_manifest(root)
    entries = _validate_manifest_schema(manifest, expected_target)
    actual_payload = dict(_walk_regular_files(root, exclude_metadata=True))
    expected_payload = {entry["path"]: entry for entry in entries}
    missing = set(expected_payload) - set(actual_payload)
    extra = set(actual_payload) - set(expected_payload)
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing payload files: {_format_paths(missing)}")
        if extra:
            parts.append(f"extra payload files: {_format_paths(extra)}")
        raise RunnerError("; ".join(parts))
    for relative, entry in expected_payload.items():
        path = actual_payload[relative]
        size = path.lstat().st_size
        if size != entry["size"]:
            raise RunnerError(f"payload size mismatch: {relative}")
        if sha256_file(path, trusted_root=root) != entry["sha256"]:
            raise RunnerError(f"payload sha256 mismatch: {relative}")
    checksums = parse_checksums(root / CHECKSUM_NAME, root)
    checksum_paths = set(actual_payload) | {MANIFEST_NAME}
    missing_checksums = checksum_paths - set(checksums)
    extra_checksums = set(checksums) - checksum_paths
    if missing_checksums or extra_checksums:
        parts = []
        if missing_checksums:
            parts.append(f"missing checksum entries: {_format_paths(missing_checksums)}")
        if extra_checksums:
            parts.append(f"extra checksum entries: {_format_paths(extra_checksums)}")
        raise RunnerError("; ".join(parts))
    for relative in sorted(checksum_paths):
        if sha256_file(
            root / Path(*relative.split("/")), trusted_root=root
        ) != checksums[relative]:
            raise RunnerError(f"SHA256SUMS mismatch: {relative}")
    return "PASS"


def _ensure_source_tree(root: Path, source: Path) -> None:
    try:
        relative = source.relative_to(root)
    except ValueError as error:
        raise RunnerError(f"artifact source escapes repository root: {source}") from error
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        _require_directory(current, "artifact source directory")


def _source_file(root: Path, relative: str, label: str = "artifact source") -> Path:
    source = root / Path(*relative.split("/"))
    _ensure_source_tree(root, source)
    try:
        _require_regular_file(source, label)
    except RunnerError as error:
        if label == "native library":
            raise RunnerError(f"native library not found: {source}") from error
        raise
    return source


def select_maven_main_jar(java_target: Path) -> Path:
    java_target = Path(java_target)
    _require_directory(java_target, "Maven target directory")
    candidates = []
    observed = []
    for path in sorted(java_target.iterdir(), key=lambda item: item.name):
        if not path.name.endswith(".jar"):
            continue
        _require_regular_file(path, "Maven JAR")
        observed.append(path.name)
        if (
            path.name.startswith("agentgate-java-")
            and not path.name.endswith(("-sources.jar", "-javadoc.jar"))
            and not path.name.startswith("original-")
        ):
            candidates.append(path)
    expected = "agentgate-java-0.1.0-SNAPSHOT.jar"
    if len(candidates) != 1 or candidates[0].name != expected:
        raise RunnerError(
            "expected exactly one Maven main JAR named "
            f"{expected}; found {_format_paths(observed)}"
        )
    return candidates[0]


def _collect_tree(
    sources: dict[str, Path], root: Path, source_directory: str, destination: str
) -> None:
    directory = root / Path(*source_directory.split("/"))
    _require_directory(directory, "artifact source directory")
    pending = [(directory, destination)]
    found = False
    while pending:
        current, prefix = pending.pop()
        for child in sorted(current.iterdir(), key=lambda item: item.name):
            value = _path_lstat(child)
            relative = f"{prefix}/{child.name}"
            if _is_link_or_reparse(value):
                raise RunnerError(f"artifact source is a symlink or reparse point: {child}")
            if stat.S_ISDIR(value.st_mode):
                pending.append((child, relative))
            elif stat.S_ISREG(value.st_mode):
                normalized = normalize_artifact_path(relative)
                sources[normalized] = child
                found = True
            else:
                raise RunnerError(f"artifact source is not regular: {child}")
    if not found:
        raise RunnerError(f"artifact source directory is empty: {directory}")


def collect_artifact_sources(root: Path, target: Target) -> dict[str, Path]:
    root = Path(root)
    _require_directory(root, "repository root")
    sources = {
        "include/agentgate.h": _source_file(
            root, "packages/ffi/include/agentgate.h"
        ),
        f"native/{target.shared_name}": _source_file(
            root, f"target/release/{target.shared_name}", "native library"
        ),
        f"native/{target.static_name}": _source_file(
            root, f"target/release/{target.static_name}", "native library"
        ),
        "go/go.mod": _source_file(root, "bindings/go/go.mod"),
        "java/agentgate-java-0.1.0-SNAPSHOT.jar": select_maven_main_jar(
            root / "bindings/java/target"
        ),
        f"java/{target.shared_name}": _source_file(
            root, f"target/release/{target.shared_name}", "native library"
        ),
        "java/examples/Complete.java": _source_file(
            root, "bindings/java/examples/Complete.java"
        ),
        "node/package.json": _source_file(root, "bindings/node/package.json"),
        "node/examples/complete.js": _source_file(
            root, "bindings/node/examples/complete.js"
        ),
        "node/build/Release/agentgate.node": _source_file(
            root, "bindings/node/build/Release/agentgate.node"
        ),
        f"node/build/Release/{target.shared_name}": _source_file(
            root,
            f"bindings/node/build/Release/{target.shared_name}",
            "native library",
        ),
        "smoke/abi_probe.c": _source_file(root, "tests/qualification/abi_probe.c"),
        "smoke/abi_probe.cpp": _source_file(root, "tests/qualification/abi_probe.cpp"),
    }
    if target.import_name is not None:
        sources[f"native/{target.import_name}"] = _source_file(
            root, f"target/release/{target.import_name}", "native library"
        )
    jni_source = (
        f"target/phase5c/java/Release/{JNI_SHIM_NAMES[target.system]}"
        if target.system == "Windows"
        else f"target/phase5c/java/{JNI_SHIM_NAMES[target.system]}"
    )
    sources[f"java/{JNI_SHIM_NAMES[target.system]}"] = _source_file(
        root, jni_source, "JNI shim"
    )
    _collect_tree(sources, root, "bindings/go/agentgate", "go/agentgate")
    _collect_tree(
        sources, root, "bindings/go/examples/complete", "go/examples/complete"
    )
    _collect_tree(sources, root, "bindings/node/lib", "node/lib")
    return dict(sorted(sources.items()))


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _filesystem_identity(value) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode))


def _is_link_or_reparse(value) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(value, "st_file_attributes", 0)
    return stat.S_ISLNK(value.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _validate_output_path(output: Path) -> Path:
    output = Path(output)
    if ".." in output.parts:
        raise RunnerError(f"artifact output traversal is not allowed: {output}")
    absolute = output.absolute()
    current = Path(absolute.anchor)
    components = absolute.parts[1:] if absolute.anchor else absolute.parts
    for component in components:
        current = current / component
        try:
            value = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RunnerError(f"unable to validate artifact output: {current}") from error
        if _is_link_or_reparse(value):
            raise RunnerError(f"artifact output contains symlink or reparse point: {current}")
        if not stat.S_ISDIR(value.st_mode):
            raise RunnerError(f"artifact output component is not a directory: {current}")
    return absolute


def _snapshot_output_ancestry(output: Path) -> list[tuple[Path, tuple[int, int, int]]]:
    snapshot = []
    current = Path(output.anchor)
    for component in output.parts[1:]:
        current = current / component
        value = current.lstat()
        if _is_link_or_reparse(value) or not stat.S_ISDIR(value.st_mode):
            raise RunnerError(f"artifact output ancestry is not a real directory: {current}")
        snapshot.append((current, _filesystem_identity(value)))
    return snapshot


def _validate_output_ancestry(
    snapshot: list[tuple[Path, tuple[int, int, int]]]
) -> None:
    for path, expected in snapshot:
        try:
            value = path.lstat()
        except OSError as error:
            raise RunnerError(f"artifact output ancestry changed: {path}") from error
        if _is_link_or_reparse(value) or _filesystem_identity(value) != expected:
            raise RunnerError(f"artifact output ancestry changed: {path}")


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_output_directory(output: Path):
    output = _validate_output_path(output)
    if getattr(os, "O_DIRECTORY", 0) and os.open in os.supports_dir_fd:
        descriptor = os.open(output.anchor, _directory_open_flags())
        try:
            for component in output.parts[1:]:
                try:
                    value = os.stat(
                        component, dir_fd=descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    try:
                        os.mkdir(component, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    value = os.stat(
                        component, dir_fd=descriptor, follow_symlinks=False
                    )
                if _is_link_or_reparse(value) or not stat.S_ISDIR(value.st_mode):
                    raise RunnerError(
                        f"artifact output component is not a real directory: {component}"
                    )
                child = os.open(component, _directory_open_flags(), dir_fd=descriptor)
                if _filesystem_identity(os.fstat(child)) != _filesystem_identity(value):
                    os.close(child)
                    raise RunnerError("artifact output changed while opening")
                os.close(descriptor)
                descriptor = child
            return output, descriptor, _filesystem_identity(os.fstat(descriptor))
        except Exception:
            os.close(descriptor)
            raise
    if not output.exists():
        output.mkdir(parents=True)
    before = output.lstat()
    if _is_link_or_reparse(before) or not stat.S_ISDIR(before.st_mode):
        raise RunnerError(f"artifact output is not a real directory: {output}")
    return output, None, _filesystem_identity(before)


def _rename_noreplace(parent_descriptor: int, source: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        if rename is None:
            raise RunnerError("exclusive artifact publication is unavailable")
        result = rename(
            parent_descriptor,
            ctypes.c_char_p(source_bytes),
            parent_descriptor,
            ctypes.c_char_p(destination_bytes),
            1,
        )
    elif sys.platform == "darwin":
        rename = getattr(library, "renameatx_np", None)
        if rename is None:
            raise RunnerError("exclusive artifact publication is unavailable")
        result = rename(
            parent_descriptor,
            ctypes.c_char_p(source_bytes),
            parent_descriptor,
            ctypes.c_char_p(destination_bytes),
            4,
        )
    else:
        raise RunnerError("exclusive descriptor-relative publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (errno.EEXIST, errno.ENOTEMPTY):
        raise RunnerError(f"artifact destination already exists: {destination}")
    raise RunnerError(
        f"unable to publish artifact exclusively: {os.strerror(error_number)}"
    )


def _open_tree_directory(root_descriptor: int, parts, *, create: bool = False) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for component in parts:
            if create:
                try:
                    os.mkdir(component, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, _directory_open_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _write_bytes_at(root_descriptor: int, relative: str, data: bytes) -> None:
    parts = relative.split("/")
    parent = _open_tree_directory(root_descriptor, parts[:-1], create=True)
    descriptor = None
    try:
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(data)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _descriptor_file_identity(value) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


@contextlib.contextmanager
def _open_regular_file_at(
    root_descriptor: int,
    relative: str,
    *,
    max_bytes: int | None = None,
):
    parts = relative.split("/")
    parent = _open_tree_directory(root_descriptor, parts[:-1])
    descriptor = None
    parent_identity = _filesystem_identity(os.fstat(parent))
    try:
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        pathname = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_or_reparse(pathname)
            or _descriptor_file_identity(opened) != _descriptor_file_identity(pathname)
        ):
            raise RunnerError(f"artifact file changed while opening: {relative}")
        if max_bytes is not None and opened.st_size > max_bytes:
            raise RunnerError(f"artifact file exceeds the size limit: {relative}")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            yield source, opened
        after = os.fstat(descriptor)
        pathname_after = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        anchored_parent = _open_tree_directory(root_descriptor, parts[:-1])
        try:
            anchored_parent_identity = _filesystem_identity(
                os.fstat(anchored_parent)
            )
        finally:
            os.close(anchored_parent)
        if (
            _descriptor_file_identity(after) != _descriptor_file_identity(opened)
            or _descriptor_file_identity(pathname_after)
            != _descriptor_file_identity(opened)
            or _filesystem_identity(os.fstat(parent)) != parent_identity
            or anchored_parent_identity != parent_identity
        ):
            raise RunnerError(f"artifact file changed while reading: {relative}")
    except RunnerError:
        raise
    except OSError as error:
        raise RunnerError(f"artifact file changed or is inaccessible: {relative}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _read_bytes_at(
    root_descriptor: int, relative: str, *, max_bytes: int | None = None
) -> bytes:
    with _open_regular_file_at(
        root_descriptor, relative, max_bytes=max_bytes
    ) as (source, _):
        data = source.read() if max_bytes is None else source.read(max_bytes + 1)
        if max_bytes is not None and len(data) > max_bytes:
            raise RunnerError(f"artifact file exceeds the size limit: {relative}")
        return data


def _hash_file_at(root_descriptor: int, relative: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with _open_regular_file_at(root_descriptor, relative) as (source, _):
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _copy_file_at(
    source: Path, source_root: Path, root_descriptor: int, relative: str
) -> tuple[int, str]:
    parts = normalize_artifact_path(relative).split("/")
    parent = _open_tree_directory(root_descriptor, parts[:-1], create=True)
    destination_descriptor = None
    digest = hashlib.sha256()
    size = 0
    try:
        destination_descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
            dir_fd=parent,
        )
        with _open_regular_file(source, trusted_root=source_root) as input_file, os.fdopen(
            destination_descriptor, "wb", closefd=False
        ) as output_file:
            while True:
                chunk = input_file.read(1024 * 1024)
                if not chunk:
                    break
                output_file.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(parent)
    return size, digest.hexdigest()


def _walk_files_at(root_descriptor: int) -> dict[str, tuple[int, str]]:
    files = {}
    pending = [(os.dup(root_descriptor), "")]
    try:
        while pending:
            descriptor, prefix = pending.pop()
            try:
                for name in sorted(os.listdir(descriptor)):
                    relative = f"{prefix}/{name}" if prefix else name
                    value = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if _is_link_or_reparse(value):
                        raise RunnerError(f"artifact contains symlink: {relative}")
                    if stat.S_ISDIR(value.st_mode):
                        child = os.open(
                            name, _directory_open_flags(), dir_fd=descriptor
                        )
                        if _filesystem_identity(os.fstat(child)) != _filesystem_identity(value):
                            os.close(child)
                            raise RunnerError(f"artifact directory changed: {relative}")
                        pending.append((child, relative))
                    elif stat.S_ISREG(value.st_mode):
                        files[relative] = _hash_file_at(root_descriptor, relative)
                    else:
                        raise RunnerError(f"artifact contains non-regular file: {relative}")
            finally:
                os.close(descriptor)
    finally:
        for descriptor, _ in pending:
            os.close(descriptor)
    return files


def _verify_artifact_at(root_descriptor: int, target: Target) -> str:
    manifest, _ = _parse_manifest_bytes(
        _read_bytes_at(
            root_descriptor, MANIFEST_NAME, max_bytes=MAX_METADATA_BYTES
        )
    )
    entries = _validate_manifest_schema(manifest, target)
    actual = _walk_files_at(root_descriptor)
    manifest_bytes = actual.pop(MANIFEST_NAME, None)
    checksum_bytes = _read_bytes_at(
        root_descriptor, CHECKSUM_NAME, max_bytes=MAX_METADATA_BYTES
    )
    actual.pop(CHECKSUM_NAME, None)
    expected = {entry["path"]: (entry["size"], entry["sha256"]) for entry in entries}
    if actual != expected:
        raise RunnerError("artifact payload does not match manifest")
    checksums = _parse_checksums_bytes(checksum_bytes)
    if manifest_bytes is None:
        raise RunnerError("artifact manifest is missing")
    checksum_paths = set(actual) | {MANIFEST_NAME}
    missing_checksums = checksum_paths - set(checksums)
    extra_checksums = set(checksums) - checksum_paths
    if missing_checksums or extra_checksums:
        parts = []
        if missing_checksums:
            parts.append(
                f"missing checksum entries: {_format_paths(missing_checksums)}"
            )
        if extra_checksums:
            parts.append(f"extra checksum entries: {_format_paths(extra_checksums)}")
        raise RunnerError("; ".join(parts))
    actual_checksums = {path: digest for path, (_, digest) in actual.items()}
    actual_checksums[MANIFEST_NAME] = manifest_bytes[1]
    for relative in sorted(checksum_paths):
        if actual_checksums[relative] != checksums[relative]:
            raise RunnerError(f"SHA256SUMS mismatch: {relative}")
    return "PASS"


def _relative_lstat(parent: Path, descriptor, name: str):
    if descriptor is not None and os.stat in os.supports_dir_fd:
        return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    return (parent / name).lstat()


def _find_owned_directory_name(
    output: Path,
    output_descriptor,
    expected_identity: tuple[int, int, int],
) -> str | None:
    names = (
        os.listdir(output_descriptor)
        if output_descriptor is not None
        else [child.name for child in output.iterdir()]
    )
    for name in names:
        try:
            value = _relative_lstat(output, output_descriptor, name)
        except FileNotFoundError:
            continue
        if (
            not _is_link_or_reparse(value)
            and stat.S_ISDIR(value.st_mode)
            and _filesystem_identity(value) == expected_identity
        ):
            return name
    return None


def _remove_directory_contents_at(descriptor: int) -> None:
    for name in os.listdir(descriptor):
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode) and not _is_link_or_reparse(before):
            child = os.open(name, _directory_open_flags(), dir_fd=descriptor)
            try:
                if _filesystem_identity(os.fstat(child)) != _filesystem_identity(before):
                    raise RunnerError(f"rollback child changed: {name}")
                _remove_directory_contents_at(child)
            finally:
                os.close(child)
            after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _filesystem_identity(after) != _filesystem_identity(before):
                raise RunnerError(f"rollback child changed: {name}")
            os.rmdir(name, dir_fd=descriptor)
        else:
            child = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    _descriptor_file_identity(opened)
                    != _descriptor_file_identity(before)
                    or _descriptor_file_identity(after)
                    != _descriptor_file_identity(before)
                ):
                    raise RunnerError(f"rollback child changed: {name}")
                os.unlink(name, dir_fd=descriptor)
            finally:
                os.close(child)


def _remove_published_artifact(
    output: Path,
    output_descriptor,
    published_identity: tuple[int, int, int],
    published_descriptor=None,
) -> None:
    owned_name = _find_owned_directory_name(
        output, output_descriptor, published_identity
    )
    if owned_name is None:
        return
    quarantine_name = None
    for _ in range(32):
        candidate = f".artifact.rollback-{secrets.token_hex(12)}"
        try:
            if output_descriptor is not None:
                _rename_noreplace(output_descriptor, owned_name, candidate)
            else:
                (output / owned_name).rename(output / candidate)
            quarantine_name = candidate
            break
        except (FileExistsError, RunnerError) as error:
            if isinstance(error, RunnerError) and "already exists" not in str(error):
                break
            continue
        except OSError:
            break
    if quarantine_name is None:
        return
    moved = _relative_lstat(output, output_descriptor, quarantine_name)
    if _filesystem_identity(moved) != published_identity:
        return
    if output_descriptor is not None:
        descriptor = (
            os.dup(published_descriptor)
            if published_descriptor is not None
            else os.open(quarantine_name, _directory_open_flags(), dir_fd=output_descriptor)
        )
        try:
            if _filesystem_identity(os.fstat(descriptor)) != published_identity:
                return
            _remove_directory_contents_at(descriptor)
        finally:
            os.close(descriptor)
        current = _relative_lstat(output, output_descriptor, quarantine_name)
        if _filesystem_identity(current) == published_identity:
            os.rmdir(quarantine_name, dir_fd=output_descriptor)
        return
    shutil.rmtree(output / quarantine_name)


def _remove_staging_artifact(
    output: Path,
    output_descriptor,
    staging_identity: tuple[int, int, int],
    staging_descriptor=None,
) -> None:
    owned_name = _find_owned_directory_name(
        output, output_descriptor, staging_identity
    )
    if owned_name is None:
        return
    quarantine_name = None
    for _ in range(32):
        candidate = f".artifact.failed-{secrets.token_hex(12)}"
        try:
            if output_descriptor is not None:
                _rename_noreplace(output_descriptor, owned_name, candidate)
            else:
                destination = output / candidate
                try:
                    destination.lstat()
                except FileNotFoundError:
                    pass
                else:
                    continue
                (output / owned_name).rename(destination)
            quarantine_name = candidate
            break
        except (FileExistsError, RunnerError) as error:
            if isinstance(error, RunnerError) and "already exists" not in str(error):
                return
            continue
        except OSError:
            return
    if quarantine_name is None:
        return
    moved = _relative_lstat(output, output_descriptor, quarantine_name)
    if _filesystem_identity(moved) != staging_identity:
        return
    if output_descriptor is not None:
        descriptor = (
            os.dup(staging_descriptor)
            if staging_descriptor is not None
            else os.open(quarantine_name, _directory_open_flags(), dir_fd=output_descriptor)
        )
        try:
            if _filesystem_identity(os.fstat(descriptor)) != staging_identity:
                return
            _remove_directory_contents_at(descriptor)
        finally:
            os.close(descriptor)
        current = _relative_lstat(output, output_descriptor, quarantine_name)
        if _filesystem_identity(current) == staging_identity:
            os.rmdir(quarantine_name, dir_fd=output_descriptor)
        return
    shutil.rmtree(output / quarantine_name)


def safe_copy_file(
    source: Path,
    artifact_root: Path,
    relative: str,
    *,
    source_root: Path | None = None,
    allow_reserved: bool = False,
) -> Path:
    source = Path(source)
    root = Path(artifact_root)
    _require_regular_file(source, "artifact source")
    _require_directory(root, "artifact root")
    if allow_reserved:
        if relative not in RESERVED_ARTIFACT_NAMES:
            raise RunnerError(f"unexpected reserved artifact file: {relative}")
        normalized = relative
    else:
        normalized = normalize_artifact_path(relative)
    root_resolved = root.resolve(strict=True)
    destination = root / Path(*normalized.split("/"))
    current = root
    for part in Path(*normalized.split("/")).parts[:-1]:
        current = current / part
        if current.exists() or current.is_symlink():
            _require_directory(current, "artifact destination directory")
        else:
            try:
                current.mkdir()
            except OSError as error:
                raise RunnerError(f"unable to create artifact directory: {current}") from error
        if not _is_within(current.resolve(strict=True), root_resolved):
            raise RunnerError(f"artifact destination escapes root: {relative}")
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink():
            raise RunnerError(f"artifact destination is a symlink: {destination}")
        _require_regular_file(destination, "artifact destination")
        raise RunnerError(f"artifact destination already exists: {destination}")
    if not _is_within(destination.parent.resolve(strict=True), root_resolved):
        raise RunnerError(f"artifact destination escapes root: {relative}")
    try:
        with _open_regular_file(
            source,
            "artifact source",
            trusted_root=source.parent if source_root is None else source_root,
        ) as source_file:
            with destination.open("xb") as destination_file:
                shutil.copyfileobj(source_file, destination_file)
    except (OSError, RunnerError) as error:
        if destination.exists() or destination.is_symlink():
            destination.unlink()
        if isinstance(error, RunnerError):
            raise
        raise RunnerError(f"unable to copy artifact source: {source}") from error
    _require_regular_file(destination, "artifact destination")
    return destination


def tool_versions_from_capabilities(
    capabilities: dict[str, Capability],
) -> dict[str, str]:
    versions = {}
    for key in sorted(REQUIRED_TOOL_KEYS):
        capability = capabilities.get(
            key, Capability(CAPABILITY_NAMES[key], None, None)
        )
        if capability.version is None:
            raise RunnerError(
                f"{capability.name} version is required for artifact metadata"
            )
        versions[key] = ".".join(str(part) for part in capability.version)
    return _validate_tool_versions(versions)


def _assemble_artifact_path_fallback(
    root: Path,
    output: Path,
    output_identity: tuple[int, int, int],
    sources: dict[str, Path],
    target: Target,
    tool_versions: dict[str, str],
) -> Path:
    ancestry = _snapshot_output_ancestry(output)
    artifact = output / "artifact"
    staging = output / ".artifact.tmp"
    for destination in (artifact, staging):
        if destination.exists() or destination.is_symlink():
            raise RunnerError(f"artifact destination already exists: {destination}")
    staging_identity = None
    published_identity = None
    try:
        staging.mkdir()
        staging_identity = _filesystem_identity(staging.lstat())
        for relative, source in sources.items():
            _validate_output_ancestry(ancestry)
            safe_copy_file(source, staging, relative, source_root=root)
            _validate_output_ancestry(ancestry)
        _validate_output_ancestry(ancestry)
        manifest = build_manifest(staging, target, tool_versions)
        write_manifest(staging, manifest)
        write_checksums(staging)
        verify_artifact(staging, target)
        _validate_output_ancestry(ancestry)
        before_publish = output.lstat()
        if (
            _is_link_or_reparse(before_publish)
            or _filesystem_identity(before_publish) != output_identity
            or _filesystem_identity(staging.lstat()) != staging_identity
        ):
            raise RunnerError("artifact output changed during publication")
        try:
            staging.rename(artifact)
        except FileExistsError as error:
            raise RunnerError(f"artifact destination already exists: {artifact}") from error
        published = artifact.lstat()
        if _filesystem_identity(published) != staging_identity:
            raise RunnerError("published artifact identity changed")
        published_identity = staging_identity
        staging_identity = None
        verify_artifact(artifact, target)
        _validate_output_ancestry(ancestry)
        after_publish = output.lstat()
        if (
            _is_link_or_reparse(after_publish)
            or _filesystem_identity(after_publish) != output_identity
            or _filesystem_identity(artifact.lstat()) != published_identity
        ):
            raise RunnerError("artifact output changed during publication")
        return artifact
    except Exception:
        if published_identity is not None:
            _remove_published_artifact(output, None, published_identity)
        elif staging_identity is not None:
            _remove_staging_artifact(output, None, staging_identity)
        raise


def assemble_artifact(
    root: Path,
    output: Path,
    target: Target,
    tool_versions: dict[str, str],
) -> Path:
    root = Path(root).absolute()
    output = _validate_output_path(Path(output))
    sources = collect_artifact_sources(root, target)
    artifact = output / "artifact"
    output_descriptor = None
    staging_descriptor = None
    published_descriptor = None
    published_identity = None
    staging_identity = None
    try:
        output, output_descriptor, output_identity = _open_output_directory(output)
        if output_descriptor is None:
            return _assemble_artifact_path_fallback(
                root,
                output,
                output_identity,
                sources,
                target,
                tool_versions,
            )
        for name in ("artifact", ".artifact.tmp"):
            try:
                value = _relative_lstat(output, output_descriptor, name)
            except FileNotFoundError:
                continue
            if _is_link_or_reparse(value):
                raise RunnerError(f"artifact destination is a symlink: {output / name}")
            raise RunnerError(f"artifact destination already exists: {output / name}")
        os.mkdir(".artifact.tmp", dir_fd=output_descriptor)
        staging_identity = _filesystem_identity(
            _relative_lstat(output, output_descriptor, ".artifact.tmp")
        )
        staging_descriptor = os.open(
            ".artifact.tmp", _directory_open_flags(), dir_fd=output_descriptor
        )
        file_entries = []
        for relative, source in sources.items():
            size, digest = _copy_file_at(
                source, root, staging_descriptor, relative
            )
            file_entries.append(
                {
                    "path": relative,
                    "kind": _artifact_kind(relative),
                    "size": size,
                    "sha256": digest,
                }
            )
        manifest = {
            "schema_version": 1,
            "agentgate_version": AGENTGATE_VERSION,
            "abi_version": ABI_VERSION,
            "target": {
                "os": target.system,
                "arch": target.arch,
                "triple": target.triple,
            },
            "tools": _validate_tool_versions(tool_versions),
            "files": file_entries,
        }
        manifest_data = _canonical_json(manifest)
        _write_bytes_at(staging_descriptor, MANIFEST_NAME, manifest_data)
        checksums = {entry["path"]: entry["sha256"] for entry in file_entries}
        checksums[MANIFEST_NAME] = hashlib.sha256(manifest_data).hexdigest()
        checksum_data = "".join(
            f"{digest}  {relative}\n"
            for relative, digest in sorted(checksums.items())
        ).encode("utf-8")
        _write_bytes_at(staging_descriptor, CHECKSUM_NAME, checksum_data)
        _verify_artifact_at(staging_descriptor, target)
        os.close(staging_descriptor)
        staging_descriptor = None
        _rename_noreplace(output_descriptor, ".artifact.tmp", "artifact")
        published_value = _relative_lstat(output, output_descriptor, "artifact")
        if _is_link_or_reparse(published_value) or not stat.S_ISDIR(published_value.st_mode):
            raise RunnerError("published artifact is not a real directory")
        if _filesystem_identity(published_value) != staging_identity:
            raise RunnerError("published artifact identity changed")
        published_identity = staging_identity
        staging_identity = None
        published_descriptor = os.open(
            "artifact", _directory_open_flags(), dir_fd=output_descriptor
        )
        _verify_artifact_at(published_descriptor, target)
        current_output = output.lstat()
        if (
            _is_link_or_reparse(current_output)
            or _filesystem_identity(current_output) != output_identity
        ):
            raise RunnerError("artifact output changed during publication")
    except Exception:
        if published_identity is not None:
            _remove_published_artifact(
                output,
                output_descriptor,
                published_identity,
                published_descriptor,
            )
        elif staging_identity is not None and output_descriptor is not None:
            _remove_staging_artifact(
                output,
                output_descriptor,
                staging_identity,
                staging_descriptor,
            )
        raise
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if published_descriptor is not None:
            os.close(published_descriptor)
        if output_descriptor is not None:
            os.close(output_descriptor)
    return artifact


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


def run_sanitizer_command(
    command: PlannedCommand,
    command_runner=subprocess.run,
    *,
    dry_run: bool = False,
) -> str:
    """Run a sanitizer plan command while rendering its required flags."""
    formatted = shlex.join(
        [f"{key}={value}" for key, value in command.env] + list(command.argv)
    )
    print("+ " + formatted)
    if dry_run:
        return "PLANNED"
    environment = os.environ.copy()
    environment.update(dict(command.env))
    try:
        completed = command_runner(
            list(command.argv), cwd=command.cwd, env=environment, shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerError(f"unable to run {command.argv[0]}: {error}") from error
    if completed.returncode != 0:
        raise RunnerError(
            f"command failed: {formatted} (exit code {completed.returncode})"
        )
    return "PASS"


def run_sanitizers(
    target: Target,
    root: Path,
    capabilities: dict[str, Capability],
    *,
    command_runner=subprocess.run,
    dry_run: bool = False,
) -> str:
    """Exercise sanitized C/C++ consumers against the stable Rust FFI release."""
    require_ci_capabilities(capabilities)
    root = Path(root)
    plan = sanitizer_plan(target, root, capabilities)
    _assert_sanitizer_plan(plan)
    stable_ffi_build = PlannedCommand(
        ("cargo", "build", "-p", "agentgate-ffi", "--release"),
        root,
        purpose="sanitizer-stable-ffi-build",
    )
    run_command(stable_ffi_build, command_runner, dry_run=dry_run)
    for command in plan:
        run_sanitizer_command(command, command_runner, dry_run=dry_run)
    return "PLANNED" if dry_run else "PASS"


def _copy_verified_artifact(
    source: Path,
    destination: Path,
    target: Target,
    *,
    copy_file=safe_copy_file,
) -> Path:
    """Copy a verified artifact without following links or copying unlisted files."""
    source = Path(source)
    destination = Path(destination)
    verify_artifact(source, target)
    if destination.exists() or destination.is_symlink():
        raise RunnerError(f"smoke extraction destination already exists: {destination}")
    destination.mkdir()
    _require_directory(destination, "smoke extraction destination")
    files = _walk_regular_files(source, exclude_metadata=True)
    for relative, file_path in files:
        copy_file(file_path, destination, relative, source_root=source)
    for relative in (MANIFEST_NAME, CHECKSUM_NAME):
        copy_file(
            source / relative,
            destination,
            relative,
            source_root=source,
            allow_reserved=True,
        )
    verify_artifact(destination, target)
    return destination


def run_smoke_command(
    command: PlannedCommand,
    command_runner=subprocess.run,
    *,
    dry_run: bool = False,
    windows: bool = False,
) -> str:
    """Launch a smoke command with inherited loader and AgentGate paths removed."""
    formatted = _format_command(command.argv, windows)
    print("+ " + formatted)
    if dry_run:
        return "PLANNED"
    environment = os.environ.copy()
    for name in SMOKE_CLEARED_ENVIRONMENT:
        environment.pop(name, None)
    environment.update(dict(command.env))
    try:
        completed = command_runner(
            list(command.argv), cwd=command.cwd, env=environment, shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerError(f"unable to run {command.argv[0]}: {error}") from error
    if completed.returncode != 0:
        raise RunnerError(
            f"command failed: {formatted} (exit code {completed.returncode})"
        )
    return "PASS"


def _validate_extracted_go_header(artifact: Path) -> Path:
    artifact = Path(artifact)
    header = artifact / "include" / "agentgate.h"
    try:
        _require_regular_file(header, "extracted Go header")
        artifact_root = artifact.resolve(strict=True)
        resolved = header.resolve(strict=True)
    except (OSError, RunnerError) as error:
        raise RunnerError(f"extracted Go header is unavailable: {header}") from error
    if not _is_within(resolved, artifact_root):
        raise RunnerError(f"extracted Go header escapes artifact: {header}")
    return resolved


def run_artifact_smoke(
    target: Target,
    artifact: Path,
    capabilities: dict[str, Capability],
    *,
    command_runner=subprocess.run,
    dry_run: bool = False,
    temporary_directory=tempfile.TemporaryDirectory,
    copy_file=safe_copy_file,
) -> str:
    """Reverify, extract, and exercise a package without accessing build outputs."""
    artifact = Path(artifact)
    if dry_run:
        plan = smoke_plan(
            target,
            artifact,
            Path("/tmp/agentgate-phase5d-smoke-plan/build"),
            capabilities,
        )
        for command in plan:
            run_smoke_command(
                command, command_runner, dry_run=True,
                windows=target.system == "Windows",
            )
        return "PLANNED"
    with temporary_directory(prefix="agentgate-phase5d-smoke-") as temporary_root:
        temporary_root = Path(temporary_root)
        extracted = _copy_verified_artifact(
            artifact, temporary_root / "路径 with spaces Ω", target, copy_file=copy_file,
        )
        build_directory = temporary_root / "build"
        build_directory.mkdir()
        (build_directory / "java-classes").mkdir()
        if target.system == "Windows":
            safe_copy_file(
                extracted / "native" / target.shared_name,
                build_directory,
                target.shared_name,
                source_root=extracted,
            )
        for command in smoke_plan(target, extracted, build_directory, capabilities):
            if command.purpose.startswith("smoke-go-"):
                _validate_extracted_go_header(extracted)
            verify_artifact(extracted, target)
            run_smoke_command(
                command, command_runner, windows=target.system == "Windows",
            )
        verify_artifact(extracted, target)
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
    directory_context = (
        contextlib.nullcontext(Path(root) / "target" / "phase5d" / ".abi-plan")
        if dry_run
        else temporary_directory(prefix="agentgate-phase5d-abi-")
    )
    with directory_context as directory:
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
    if arguments.stage == "all":
        raise RunnerError(f"Phase 5D stage is not implemented: {arguments.stage}")
    if arguments.ci:
        if arguments.stage is None:
            raise RunnerError("Phase 5D CI requires an explicit stage")

    if arguments.stage in {"qualification", "artifact", "sanitizers"}:
        target = Target.for_host(host_system, host_arch)
        if arguments.stage == "sanitizers" and target.system != "Linux":
            raise RunnerError("sanitizer stage requires Linux x86_64")
        capabilities = detect_capabilities(
            target.system, tool_lookup=tool_lookup, version_output=version_output
        )
        require_ci_capabilities(capabilities)

    if arguments.stage == "sanitizers":
        status = run_sanitizers(
            target,
            Path(root),
            capabilities,
            command_runner=command_runner,
            dry_run=arguments.dry_run,
        )
        print(f"phase5d: qualification=NOT_RUN sanitizers={status}")
        return 0

    if arguments.stage == "artifact":
        if arguments.dry_run:
            print(f"+ assemble verified artifact {arguments.output / 'artifact'}")
            run_artifact_smoke(
                target,
                arguments.output / "artifact",
                capabilities,
                command_runner=command_runner,
                dry_run=True,
            )
            print("phase5d: qualification=NOT_RUN artifact=PLANNED")
            return 0
        artifact = assemble_artifact(
            Path(root),
            arguments.output,
            target,
            tool_versions_from_capabilities(capabilities),
        )
        verify_artifact(artifact, target)
        run_artifact_smoke(
            target, artifact, capabilities, command_runner=command_runner,
        )
        print("phase5d: qualification=NOT_RUN artifact=PASS")
        return 0

    if arguments.stage == "qualification":
        status = run_qualification(
            target,
            Path(root),
            Path(root) / "target" / "release",
            capabilities,
            command_runner=command_runner,
            dry_run=arguments.dry_run,
            path_is_file=path_is_file,
        )
        if arguments.dry_run:
            print(f"+ assemble verified artifact {arguments.output / 'artifact'}")
            run_artifact_smoke(
                target,
                arguments.output / "artifact",
                capabilities,
                command_runner=command_runner,
                dry_run=True,
            )
            print(f"phase5d: qualification={status} artifact=PLANNED")
            return 0
        artifact = assemble_artifact(
            Path(root),
            arguments.output,
            target,
            tool_versions_from_capabilities(capabilities),
        )
        verify_artifact(artifact, target)
        run_artifact_smoke(
            target, artifact, capabilities, command_runner=command_runner,
        )
        print(f"phase5d: qualification={status} artifact=PASS")
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
        print(f"phase5d: status=FAIL reason={error}", file=sys.stderr)
        raise SystemExit(1)
