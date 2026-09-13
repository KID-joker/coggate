import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "bindings" / "python" / "src"
sys.path.insert(0, str(SRC))


class AbiLayoutTests(unittest.TestCase):
    def test_ctypes_layouts_and_constants_match_c_header(self):
        from agentgate import _ffi

        structures = {
            "AgByteSlice": _ffi.AgByteSlice,
            "AgOwnedBuffer": _ffi.AgOwnedBuffer,
            "AgHostBuffer": _ffi.AgHostBuffer,
            "AgCallbackHeader": _ffi.AgCallbackHeader,
            "AgLifecycleCallbacks": _ffi.AgLifecycleCallbacks,
            "AgKeyCallbacks": _ffi.AgKeyCallbacks,
            "AgObserverCallbacks": _ffi.AgObserverCallbacks,
        }
        constants = [
            "AG_ABI_VERSION_1",
            "AG_STATUS_OK", "AG_STATUS_INVALID_CONFIGURATION",
            "AG_STATUS_GENERATION_FAILED", "AG_STATUS_INVALID_CHALLENGE_MATERIAL",
            "AG_STATUS_INVALID_ANSWER_ENCODING", "AG_STATUS_ANSWER_MISMATCH",
            "AG_STATUS_UNSUPPORTED_GENERATOR_VERSION", "AG_STATUS_INTERNAL_ERROR",
            "AG_STATUS_INVALID_ARGUMENT", "AG_STATUS_CALLBACK_FAILED",
            "AG_STATUS_PANIC_CAUGHT", "AG_LIFECYCLE_STATUS_OK",
            "AG_LIFECYCLE_STATUS_UNAVAILABLE", "AG_LIFECYCLE_STATUS_CONFLICT",
            "AG_LIFECYCLE_STATUS_INTERNAL", "AG_BEGIN_STATUS_OK",
            "AG_BEGIN_STATUS_UNAVAILABLE", "AG_BEGIN_STATUS_CONFLICT",
            "AG_BEGIN_STATUS_INTERNAL", "AG_BEGIN_STATUS_NOT_FOUND",
            "AG_BEGIN_STATUS_EXPIRED", "AG_BEGIN_STATUS_ALREADY_CONSUMED",
            "AG_BEGIN_STATUS_BINDING_MISMATCH", "AG_BEGIN_STATUS_NONCE_MISMATCH",
            "AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED", "AG_KEY_STATUS_OK",
            "AG_KEY_STATUS_UNAVAILABLE", "AG_KEY_STATUS_NOT_FOUND",
            "AG_KEY_STATUS_INVALID_MATERIAL", "AG_ATTEMPT_OUTCOME_ACCEPTED",
            "AG_ATTEMPT_OUTCOME_REJECTED", "AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE",
            "AG_ATTEMPT_LIMIT_ONE", "AG_ATTEMPT_LIMIT_TWO",
        ]
        c_names = {
            "AgByteSlice": "ag_byte_slice",
            "AgOwnedBuffer": "ag_owned_buffer",
            "AgHostBuffer": "ag_host_buffer",
            "AgCallbackHeader": "ag_callback_header",
            "AgLifecycleCallbacks": "ag_lifecycle_callbacks",
            "AgKeyCallbacks": "ag_key_callbacks",
            "AgObserverCallbacks": "ag_observer_callbacks",
        }
        lines = [
            '#include "agentgate.h"', "#include <stddef.h>", "#include <stdio.h>",
            "int main(void) {",
        ]
        for python_name, structure in structures.items():
            c_name = c_names[python_name]
            lines.append(
                'printf("S %s %zu\\n", "{}", sizeof({}));'.format(
                    python_name, c_name
                )
            )
            for field_name, _ in structure._fields_:
                lines.append(
                    'printf("F %s %s %zu\\n", "{}", "{}", offsetof({}, {}));'.format(
                        python_name, field_name, c_name, field_name
                    )
                )
        for name in constants:
            lines.append(
                'printf("C %s %lld\\n", "{}", (long long){});'.format(
                    name, name
                )
            )
        lines.extend(["return 0;", "}"])

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "layout.c"
            executable = Path(directory) / "layout"
            source.write_text("\n".join(lines), encoding="utf-8")
            compiler = os.environ.get("CC", "cc")
            built = subprocess.run(
                [compiler, "-std=c11", "-I", str(ROOT / "packages" / "ffi" / "include"), str(source), "-o", str(executable)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            output = subprocess.check_output([str(executable)], text=True)

        expected = {}
        for line in output.splitlines():
            kind, *parts = line.split()
            expected[(kind, *parts[:-1])] = int(parts[-1])
        for python_name, structure in structures.items():
            self.assertEqual(ctypes.sizeof(structure), expected[("S", python_name)])
            for field_name, _ in structure._fields_:
                self.assertEqual(getattr(structure, field_name).offset, expected[("F", python_name, field_name)])
        for name in constants:
            self.assertEqual(getattr(_ffi, name), expected[("C", name)])

    def test_all_callback_prototypes_use_cdecl_and_exact_types(self):
        from agentgate import _ffi

        self.assertIs(_ffi.AgHostRelease._restype_, None)
        self.assertEqual(_ffi.AgHostRelease._argtypes_, (
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
        ))
        self.assertEqual(_ffi.AgStoreIssuedCallback._restype_, ctypes.c_int32)
        self.assertEqual(_ffi.AgStoreIssuedCallback._argtypes_, (
            ctypes.c_void_p,
            _ffi.AgByteSlice,
            _ffi.AgByteSlice,
            ctypes.c_uint32,
        ))
        self.assertEqual(_ffi.AgBeginAttemptCallback._restype_, ctypes.c_int32)
        self.assertEqual(_ffi.AgBeginAttemptCallback._argtypes_, (
            ctypes.c_void_p,
            _ffi.AgByteSlice,
            _ffi.AgByteSlice,
            ctypes.c_int64,
            ctypes.POINTER(_ffi.AgHostBuffer),
            ctypes.POINTER(_ffi.AgHostBuffer),
        ))
        self.assertEqual(_ffi.AgFinishAttemptCallback._restype_, ctypes.c_int32)
        self.assertEqual(_ffi.AgFinishAttemptCallback._argtypes_, (
            ctypes.c_void_p,
            _ffi.AgByteSlice,
            ctypes.c_int32,
        ))
        self.assertEqual(_ffi.AgActiveKeyCallback._restype_, ctypes.c_int32)
        self.assertEqual(_ffi.AgActiveKeyCallback._argtypes_, (
            ctypes.c_void_p,
            ctypes.POINTER(_ffi.AgHostBuffer),
            ctypes.POINTER(_ffi.AgHostBuffer),
        ))
        self.assertEqual(_ffi.AgKeyByIdCallback._restype_, ctypes.c_int32)
        self.assertEqual(_ffi.AgKeyByIdCallback._argtypes_, (
            ctypes.c_void_p,
            _ffi.AgByteSlice,
            ctypes.POINTER(_ffi.AgHostBuffer),
        ))
        self.assertIs(_ffi.AgObserveCallback._restype_, None)
        self.assertEqual(_ffi.AgObserveCallback._argtypes_, (
            ctypes.c_void_p,
            _ffi.AgByteSlice,
        ))


class _FakeFunction:
    def __init__(self, result=0):
        self.result = result

    def __call__(self, *args):
        return self.result


class _FakeLibrary:
    def __init__(self, abi_version=1):
        self.ag_abi_version = _FakeFunction(abi_version)
        self.ag_core_version = _FakeFunction()
        self.ag_service_create = _FakeFunction()
        self.ag_service_destroy = _FakeFunction()
        self.ag_service_issue = _FakeFunction()
        self.ag_service_verify = _FakeFunction()
        self.ag_buffer_free = _FakeFunction()


class LibraryLoaderTests(unittest.TestCase):
    def test_explicit_path_precedes_environment_and_uses_cdecl_loader(self):
        from agentgate import _ffi

        library = _FakeLibrary()
        with mock.patch.dict(os.environ, {"AGENTGATE_LIBRARY_PATH": "env-secret.dll"}), mock.patch.object(
            _ffi.ctypes, "CDLL", return_value=library
        ) as loader, mock.patch.object(_ffi.ctypes.util, "find_library") as find:
            loaded = _ffi.load_library(Path("explicit") / "agentgate_ffi.dll")

        self.assertIs(loaded, library)
        loader.assert_called_once_with(os.fspath(Path("explicit") / "agentgate_ffi.dll"))
        find.assert_not_called()
        self.assertIs(_ffi._library_class("win32"), ctypes.CDLL)
        self.assertIs(_ffi._callback_factory("win32"), ctypes.CFUNCTYPE)

    def test_environment_precedes_find_library_and_platform_names(self):
        from agentgate import _ffi

        library = _FakeLibrary()
        with mock.patch.dict(os.environ, {"AGENTGATE_LIBRARY_PATH": "configured-native"}), mock.patch.object(
            _ffi.ctypes, "CDLL", return_value=library
        ) as loader, mock.patch.object(_ffi.ctypes.util, "find_library") as find:
            self.assertIs(_ffi.load_library(), library)

        loader.assert_called_once_with("configured-native")
        find.assert_not_called()

    def test_defaults_try_find_library_then_platform_filename(self):
        from agentgate import _ffi

        for platform, filename in (
            ("linux", "libagentgate_ffi.so"),
            ("darwin", "libagentgate_ffi.dylib"),
            ("win32", "agentgate_ffi.dll"),
        ):
            with self.subTest(platform=platform):
                library = _FakeLibrary()
                attempts = []

                def load(candidate):
                    attempts.append(candidate)
                    if candidate == filename:
                        return library
                    raise OSError("not found")

                with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                    _ffi.sys, "platform", platform
                ), mock.patch.object(
                    _ffi.ctypes.util, "find_library", return_value="discovered-name"
                ), mock.patch.object(_ffi.ctypes, "CDLL", side_effect=load):
                    self.assertIs(_ffi.load_library(), library)
                self.assertEqual(attempts, ["discovered-name", filename])

    def test_loader_declares_every_exported_function_exactly(self):
        from agentgate import _ffi

        library = _FakeLibrary()
        with mock.patch.object(_ffi.ctypes, "CDLL", return_value=library):
            _ffi.load_library("native")

        self.assertEqual(library.ag_abi_version.argtypes, [])
        self.assertIs(library.ag_abi_version.restype, ctypes.c_uint32)
        self.assertEqual(library.ag_core_version.argtypes, [])
        self.assertIs(library.ag_core_version.restype, _ffi.AgByteSlice)
        self.assertEqual(library.ag_service_create.argtypes, [
            ctypes.POINTER(_ffi.AgLifecycleCallbacks),
            ctypes.POINTER(_ffi.AgKeyCallbacks),
            ctypes.POINTER(_ffi.AgObserverCallbacks),
            ctypes.POINTER(ctypes.c_void_p),
        ])
        self.assertIs(library.ag_service_create.restype, ctypes.c_int32)
        self.assertEqual(library.ag_service_destroy.argtypes, [ctypes.c_void_p])
        self.assertIs(library.ag_service_destroy.restype, ctypes.c_int32)
        for function in (library.ag_service_issue, library.ag_service_verify):
            self.assertEqual(function.argtypes, [
                ctypes.c_void_p, _ffi.AgByteSlice, _ffi.AgByteSlice,
                ctypes.c_uint32 if function is library.ag_service_issue else ctypes.POINTER(_ffi.AgOwnedBuffer),
                ctypes.POINTER(_ffi.AgOwnedBuffer),
            ] if function is library.ag_service_issue else [
                ctypes.c_void_p, _ffi.AgByteSlice, _ffi.AgByteSlice,
                ctypes.POINTER(_ffi.AgOwnedBuffer),
            ])
            self.assertIs(function.restype, ctypes.c_int32)
        self.assertEqual(library.ag_buffer_free.argtypes, [ctypes.POINTER(_ffi.AgOwnedBuffer)])
        self.assertIs(library.ag_buffer_free.restype, ctypes.c_int32)

    def test_loader_rejects_unsupported_abi_and_hides_candidate_names(self):
        from agentgate import _ffi

        with mock.patch.object(_ffi.ctypes, "CDLL", return_value=_FakeLibrary(2)):
            with self.assertRaisesRegex(RuntimeError, "unsupported AgentGate ABI version"):
                _ffi.load_library("SECRET_LIBRARY_PATH")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            _ffi.ctypes.util, "find_library", return_value=None
        ), mock.patch.object(_ffi.ctypes, "CDLL", side_effect=OSError("SECRET_LIBRARY_PATH")):
            with self.assertRaises(RuntimeError) as raised:
                _ffi.load_library()
        self.assertEqual(str(raised.exception), "AgentGate native library not found")
        self.assertNotIn("SECRET_LIBRARY_PATH", repr(raised.exception))


class ModelTests(unittest.TestCase):
    def test_models_round_trip_exact_canonical_json(self):
        from agentgate.models import (
            AnswerEncoding, PublicChallenge, RejectionReason, Submission,
            VerificationOutcome, VerificationStatus,
        )

        submission_json = '{"challenge_id":"id","nonce":"nonce","answer":"answer"}'
        self.assertEqual(Submission.from_json(submission_json).to_json(), submission_json)
        challenge_json = (
            '{"challenge_id":"id","generator_version":"1.0","nonce":"nonce",'
            '"issued_at":-9223372036854775808,"expires_at":9223372036854775807,'
            '"question":"question","answer_encoding":"base64url"}'
        )
        challenge = PublicChallenge.from_json(challenge_json)
        self.assertEqual(challenge.answer_encoding, AnswerEncoding.BASE64URL)
        self.assertEqual(challenge.to_json(), challenge_json)
        accepted = VerificationOutcome.from_json('{"status":"accepted"}')
        self.assertEqual(accepted.status, VerificationStatus.ACCEPTED)
        self.assertIsNone(accepted.reason)
        self.assertEqual(accepted.to_json(), '{"status":"accepted"}')
        rejected = VerificationOutcome.rejected(RejectionReason.NONCE_MISMATCH)
        self.assertEqual(rejected.to_json(), '{"status":"rejected","reason":"nonce_mismatch"}')

    def test_json_parsing_rejects_unknown_duplicate_and_noncanonical_types(self):
        from agentgate.models import PublicChallenge, Submission, VerificationOutcome

        invalid = [
            (Submission, '{"challenge_id":"id","nonce":"n","answer":"a","extra":1}'),
            (Submission, '{"challenge_id":"id","challenge_id":"other","nonce":"n","answer":"a"}'),
            (Submission, '{"challenge_id":1,"nonce":"n","answer":"a"}'),
            (PublicChallenge, '{"challenge_id":"id","generator_version":"1.0","nonce":"n","issued_at":true,"expires_at":1,"question":"q","answer_encoding":"base64url"}'),
            (PublicChallenge, '{"challenge_id":"id","generator_version":"1.0","nonce":"n","issued_at":-9223372036854775809,"expires_at":1,"question":"q","answer_encoding":"base64url"}'),
            (PublicChallenge, '{"challenge_id":"id","generator_version":"1.0","nonce":"n","issued_at":1,"expires_at":9223372036854775808,"question":"q","answer_encoding":"base64url"}'),
            (PublicChallenge, '{"challenge_id":"id","generator_version":"1.0","nonce":"n","issued_at":1,"expires_at":2,"question":"q","answer_encoding":"padded"}'),
            (VerificationOutcome, '{"status":"accepted","reason":"expired"}'),
            (VerificationOutcome, '{"status":"rejected"}'),
            (VerificationOutcome, '{"status":"rejected","reason":"unknown"}'),
            (VerificationOutcome, '[]'),
            (Submission, '{"challenge_id":"\\ud800","nonce":"n","answer":"a"}'),
        ]
        for model, payload in invalid:
            with self.subTest(model=model.__name__, payload=payload):
                with self.assertRaisesRegex(ValueError, "invalid AgentGate JSON"):
                    model.from_json(payload)

    def test_models_are_frozen_validate_wrapper_inputs_and_hide_sensitive_values(self):
        from dataclasses import FrozenInstanceError
        from agentgate.models import AttemptLimit, IssueRequest, Submission

        request = IssueRequest.v1(b"BINDING_SENTINEL", AttemptLimit.TWO)
        self.assertEqual(request.version, "1.0")
        self.assertEqual(request.binding, b"BINDING_SENTINEL")
        with self.assertRaises(FrozenInstanceError):
            request.version = "2.0"
        for binding in (b"", b"x" * 257, bytearray(b"x"), "x"):
            with self.subTest(binding_type=type(binding).__name__, length=len(binding)):
                with self.assertRaisesRegex(ValueError, "invalid AgentGate binding"):
                    IssueRequest.v1(binding)
        with self.assertRaisesRegex(ValueError, "invalid AgentGate attempt limit"):
            IssueRequest("1.0", b"x", 1)

        submission = Submission("ID_SENTINEL", "NONCE_SENTINEL", "ANSWER_SENTINEL")
        with self.assertRaisesRegex(ValueError, "invalid AgentGate JSON"):
            Submission("\ud800", "nonce", "answer")
        request_text = str(request) + repr(request)
        submission_text = str(submission) + repr(submission)
        for sentinel in ("BINDING_SENTINEL", "ID_SENTINEL", "NONCE_SENTINEL", "ANSWER_SENTINEL"):
            self.assertNotIn(sentinel, request_text + submission_text)


class ErrorTests(unittest.TestCase):
    def test_status_mapping_is_closed_stable_and_secret_free(self):
        from agentgate.errors import AgentGateError, code_for_status

        expected = {
            0: "ok", 1: "invalid_configuration", 2: "generation_failed",
            3: "invalid_challenge_material", 4: "invalid_answer_encoding",
            5: "answer_mismatch", 6: "unsupported_generator_version",
            7: "internal_error", 100: "invalid_argument",
            101: "callback_failed", 102: "panic_caught",
        }
        self.assertEqual({status: code_for_status(status) for status in expected}, expected)
        for status in (-1, 8, 99, 103):
            with self.assertRaisesRegex(ValueError, "invalid AgentGate status"):
                code_for_status(status)
        error = AgentGateError(7)
        self.assertEqual(error.status, 7)
        self.assertEqual(error.code, "internal_error")
        self.assertEqual(str(error), "internal_error")
        self.assertEqual(repr(error), "AgentGateError(code='internal_error')")
        self.assertNotIn("SECRET_SENTINEL", str(error) + repr(error))


if __name__ == "__main__":
    unittest.main()
