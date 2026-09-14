import ctypes
import gc
import json
import sys
import threading
import time
import types
import unittest
import weakref
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "bindings" / "python" / "src"
FIXTURE_PATH = ROOT / "fixtures" / "bindings" / "v1.json"
LIBRARY_PATH = ROOT / "target" / "release" / (
    "agentgate_ffi.dll" if sys.platform == "win32" else
    "libagentgate_ffi.dylib" if sys.platform == "darwin" else
    "libagentgate_ffi.so"
)
sys.path.insert(0, str(SRC))

from agentgate import (  # noqa: E402
    ActiveKeyResult,
    AgentGateError,
    AttemptLimit,
    BeginAttemptResult,
    IssueRequest,
    KeyResult,
    Service,
    Submission,
)
from agentgate import _ffi  # noqa: E402


MANIFEST = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
VECTORS = MANIFEST["vectors"]
CASES = MANIFEST["cases"]


def _hex(field):
    return bytes.fromhex(VECTORS[field])


def _begin_status(name):
    return {
        "ok": _ffi.AG_BEGIN_STATUS_OK,
        "unavailable": _ffi.AG_BEGIN_STATUS_UNAVAILABLE,
        "conflict": _ffi.AG_BEGIN_STATUS_CONFLICT,
        "internal": _ffi.AG_BEGIN_STATUS_INTERNAL,
        "not_found": _ffi.AG_BEGIN_STATUS_NOT_FOUND,
        "expired": _ffi.AG_BEGIN_STATUS_EXPIRED,
        "already_consumed": _ffi.AG_BEGIN_STATUS_ALREADY_CONSUMED,
        "binding_mismatch": _ffi.AG_BEGIN_STATUS_BINDING_MISMATCH,
        "nonce_mismatch": _ffi.AG_BEGIN_STATUS_NONCE_MISMATCH,
        "attempts_exhausted": _ffi.AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED,
    }[name]


class CallbackSentinel(BaseException):
    pass


class FixtureState:
    def __init__(self, fixture):
        self.fixture = fixture
        self.trace = []
        self.observed = []
        self.requested_key_id = None
        self.observer_raises = False
        self.stored = None


class FixtureLifecycle:
    def __init__(self, state):
        self.state = state
        self.reenter = None
        self.block_entered = None
        self.block_release = None
        self.raise_store = False
        self.raise_finish = False

    def store_issued(self, private_json, binding, attempt_limit):
        self.state.trace.append("store_issued")
        self.state.stored = (private_json, binding, attempt_limit)
        if self.raise_store:
            raise CallbackSentinel("STORE_SECRET_SENTINEL")
        if self.reenter:
            self.reenter()
        return _ffi.AG_LIFECYCLE_STATUS_OK

    def begin_attempt(self, identity_json, binding, server_time):
        del identity_json, binding, server_time
        script = self.state.fixture["lifecycle"]
        if script["callback_exception"]:
            self.state.trace.append("begin_attempt:exception")
            raise CallbackSentinel("CALLBACK_EXCEPTION_SENTINEL")
        self.state.trace.append("begin_attempt")
        if self.reenter:
            self.reenter()
        if self.block_entered:
            self.block_entered.set()
            self.block_release.wait(5)
        status = _begin_status(script["begin_status"])
        if status != _ffi.AG_BEGIN_STATUS_OK:
            return BeginAttemptResult(status, b"MATERIAL_SENTINEL", b"TOKEN_SENTINEL")
        material = json.dumps(
            VECTORS["private_material"], separators=(",", ":")
        ).encode("utf-8")
        return BeginAttemptResult(status, material, _hex("token_hex"))

    def finish_attempt(self, token, outcome):
        names = {
            _ffi.AG_ATTEMPT_OUTCOME_ACCEPTED: "accepted",
            _ffi.AG_ATTEMPT_OUTCOME_REJECTED: "rejected",
            _ffi.AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE: "system_failure",
        }
        self.state.trace.append("finish_attempt:" + names[outcome])
        if self.raise_finish:
            raise CallbackSentinel("FINISH_SECRET_SENTINEL")
        if self.reenter:
            self.reenter()
        return (
            _ffi.AG_LIFECYCLE_STATUS_INTERNAL
            if self.state.fixture["lifecycle"]["finish_status"] == "internal"
            else _ffi.AG_LIFECYCLE_STATUS_OK
        )


class FixtureKeys:
    def __init__(self, state):
        self.state = state
        self.reenter = None
        self.raise_lookup = False
        self.raise_active = False

    def active_key(self):
        self.state.trace.append("active_key")
        if self.raise_active:
            raise CallbackSentinel("ACTIVE_KEY_SECRET_SENTINEL")
        if self.reenter:
            self.reenter()
        return ActiveKeyResult(
            _ffi.AG_KEY_STATUS_OK,
            VECTORS["active_key_id"],
            _hex("active_key_hex"),
        )

    def key_by_id(self, key_id):
        self.state.requested_key_id = key_id
        self.state.trace.append("key_by_id:old")
        if self.reenter:
            self.reenter()
        if self.raise_lookup:
            raise CallbackSentinel("KEY_LOOKUP_SECRET_SENTINEL")
        return KeyResult(_ffi.AG_KEY_STATUS_OK, _hex("old_key_hex"))


class FixtureObserver:
    def __init__(self, state):
        self.state = state
        self.reenter = None

    def observe(self, event_json):
        event = json.loads(event_json)
        self.state.observed.append(event_json)
        self.state.trace.append("observe:" + event["event"])
        if self.reenter:
            self.reenter()
        if self.state.observer_raises:
            raise CallbackSentinel("OBSERVER_EXCEPTION_SENTINEL")


def _make_service(fixture, observer=True):
    state = FixtureState(fixture)
    lifecycle = FixtureLifecycle(state)
    keys = FixtureKeys(state)
    observing = FixtureObserver(state) if observer else None
    service = Service(
        lifecycle,
        keys,
        observing,
        library_path=LIBRARY_PATH,
    )
    service._bridge.release_hook = lambda label: state.trace.append("release:" + label)
    return service, state, lifecycle, keys, observing


class FixtureIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not LIBRARY_PATH.is_file():
            raise RuntimeError("release AgentGate library required: {}".format(LIBRARY_PATH))

    def test_all_fifteen_shared_fixture_cases(self):
        self.assertEqual(len(CASES), 15)
        for fixture in CASES:
            with self.subTest(case=fixture["id"]):
                observer = fixture["operation"] != "release"
                service, state, _, _, _ = _make_service(fixture, observer)
                if fixture["operation"] == "close":
                    service.close()
                    service.close()
                    state.trace.append("service_destroy")
                    self.assertEqual(service._destroy_count, 1)
                else:
                    submission = Submission.from_json(
                        json.dumps(fixture["submission"], separators=(",", ":"))
                    )
                    try:
                        outcome = service.verify(
                            submission, bytes.fromhex(fixture["binding_hex"])
                        )
                    except AgentGateError as error:
                        self.assertNotEqual(fixture["expected_status"], 0)
                        self.assertEqual(error.status, fixture["expected_status"])
                        self.assertEqual(error.code, fixture["expected_code"])
                        public = str(error) + repr(error)
                    else:
                        self.assertEqual(fixture["expected_status"], 0)
                        self.assertEqual(
                            json.loads(outcome.to_json()), fixture["expected_outcome"]
                        )
                        public = outcome.to_json() + repr(outcome)
                    self.assertEqual(service._bridge.outstanding_count, 0)
                    self.assertEqual(
                        service._bridge.release_count,
                        fixture["expected_release_count"],
                    )
                    service.close()
                    public += "".join(state.observed)
                    for sentinel in fixture["forbidden_sentinels"]:
                        self.assertNotIn(sentinel, public)
                self.assertEqual(state.trace, fixture["expected_trace"])
                if state.requested_key_id is not None:
                    self.assertEqual(state.requested_key_id, VECTORS["old_key_id"])
                for raw in state.observed:
                    event = json.loads(raw)
                    allowlist = (
                        {"event", "challenge_id", "generator_version", "stage", "error", "attempts", "duration_us"}
                        if event["event"] == "service_failed"
                        else set(VECTORS["observer_allowlist"])
                    )
                    self.assertLessEqual(set(event), allowlist)
                    self.assertNotIn(VECTORS["answer"], raw)
                    self.assertNotIn(VECTORS["nonce"], raw)
                    self.assertNotIn(VECTORS["old_key_id"], raw)

    def test_issue_strong_lifetimes_context_manager_and_owned_free(self):
        accepted = next(case for case in CASES if case["id"] == "accepted")
        service, state, lifecycle, keys, observer = _make_service(accepted)
        refs = [weakref.ref(value) for value in (lifecycle, keys, observer)]
        del lifecycle, keys, observer
        gc.collect()
        self.assertTrue(all(reference() is not None for reference in refs))
        before = service._owned_free_count
        challenge = service.issue(IssueRequest.v1(_hex("binding_hex"), AttemptLimit.TWO))
        self.assertTrue(challenge.challenge_id)
        self.assertEqual(service._owned_free_count, before + 1)
        self.assertEqual(state.stored[1], _hex("binding_hex"))
        self.assertIs(state.stored[2], AttemptLimit.TWO)
        self.assertEqual(service._bridge.outstanding_count, 0)
        with service:
            self.assertTrue(service.is_open)
        self.assertFalse(service.is_open)
        with self.assertRaisesRegex(AgentGateError, "^invalid_argument$"):
            service.issue(IssueRequest.v1(b"x"))
        with self.assertRaisesRegex(AgentGateError, "^invalid_argument$"):
            service.verify(Submission("id", "nonce", "answer"), b"x")

    def test_top_level_output_is_freed_before_parse_failure(self):
        accepted = next(case for case in CASES if case["id"] == "accepted")
        service, _, _, _, _ = _make_service(accepted)
        before = service._owned_free_count
        with mock.patch(
            "agentgate.service.PublicChallenge.from_json",
            side_effect=ValueError("PARSE_SENTINEL"),
        ), self.assertRaisesRegex(ValueError, "PARSE_SENTINEL"):
            service.issue(IssueRequest.v1(_hex("binding_hex")))
        self.assertEqual(service._owned_free_count, before + 1)
        service.close()

    def test_callback_exceptions_are_closed_and_observer_is_best_effort(self):
        accepted = next(case for case in CASES if case["id"] == "accepted")
        service, state, _, keys, observer = _make_service(accepted)
        keys.raise_lookup = True
        with self.assertRaisesRegex(AgentGateError, "^internal_error$") as caught:
            service.verify(
                Submission.from_json(json.dumps(accepted["submission"])),
                _hex("binding_hex"),
            )
        self.assertNotIn("KEY_LOOKUP_SECRET_SENTINEL", repr(caught.exception))
        self.assertEqual(state.trace.count("finish_attempt:system_failure"), 1)
        self.assertEqual(service._bridge.outstanding_count, 0)
        service.close()

        service, _, lifecycle, _, _ = _make_service(accepted)
        lifecycle.raise_store = True
        with self.assertRaisesRegex(AgentGateError, "^internal_error$") as caught:
            service.issue(IssueRequest.v1(b"x"))
        self.assertNotIn("STORE_SECRET_SENTINEL", repr(caught.exception))
        service.close()

        service, _, lifecycle, _, _ = _make_service(accepted)
        lifecycle.raise_finish = True
        with self.assertRaisesRegex(AgentGateError, "^internal_error$") as caught:
            service.verify(
                Submission.from_json(json.dumps(accepted["submission"])),
                _hex("binding_hex"),
            )
        self.assertNotIn("FINISH_SECRET_SENTINEL", repr(caught.exception))
        service.close()

        service, _, _, keys, _ = _make_service(accepted)
        keys.raise_active = True
        with self.assertRaisesRegex(AgentGateError, "^internal_error$") as caught:
            service.issue(IssueRequest.v1(b"x"))
        self.assertNotIn("ACTIVE_KEY_SECRET_SENTINEL", repr(caught.exception))
        service.close()

        service, state, _, _, observer = _make_service(accepted)
        state.observer_raises = True
        outcome = service.verify(
            Submission.from_json(json.dumps(accepted["submission"])),
            _hex("binding_hex"),
        )
        self.assertEqual(json.loads(outcome.to_json()), {"status": "accepted"})
        service.close()

    def test_same_service_reentry_fails_fast_but_cross_service_nesting_works(self):
        rejected = next(case for case in CASES if case["id"] == "lifecycle_not_found")
        service_a, _, lifecycle_a, keys_a, observer_a = _make_service(rejected)
        seen = []

        def same_issue():
            try:
                service_a.issue(IssueRequest.v1(b"x"))
            except AgentGateError as error:
                seen.append(error.code)

        lifecycle_a.reenter = same_issue
        outcome = service_a.verify(
            Submission.from_json(json.dumps(rejected["submission"])), b"x"
        )
        self.assertEqual(outcome.reason.value, "not_found")
        self.assertEqual(seen, ["invalid_argument"])
        lifecycle_a.reenter = None

        service_b, _, lifecycle_b, _, _ = _make_service(rejected)
        nested = []

        def enter_b():
            nested.append(service_b.verify(
                Submission.from_json(json.dumps(rejected["submission"])), b"x"
            ).reason.value)

        lifecycle_a.reenter = enter_b
        service_a.verify(Submission.from_json(json.dumps(rejected["submission"])), b"x")
        self.assertEqual(nested, ["not_found"])

        cycle = []
        lifecycle_b.reenter = lambda: cycle.append(self._capture_code(
            lambda: service_a.close()
        ))
        service_a.verify(Submission.from_json(json.dumps(rejected["submission"])), b"x")
        self.assertEqual(cycle, ["invalid_argument"])
        service_a.close()
        service_b.close()

    @staticmethod
    def _capture_code(action):
        try:
            action()
        except AgentGateError as error:
            return error.code
        return "not_rejected"

    def test_key_and_observer_callback_reentry_are_rejected(self):
        accepted = next(case for case in CASES if case["id"] == "accepted")
        service, _, _, keys, observer = _make_service(accepted)
        seen = []
        keys.reenter = lambda: seen.append(self._capture_code(
            lambda: service.issue(IssueRequest.v1(b"x"))
        ))
        service.issue(IssueRequest.v1(b"x"))
        keys.reenter = None
        observer.reenter = lambda: seen.append(self._capture_code(service.close))
        service.issue(IssueRequest.v1(b"x"))
        self.assertEqual(seen, ["invalid_argument", "invalid_argument"])
        service.close()

    def test_close_waits_for_in_flight_call_and_destroys_once(self):
        rejected = next(case for case in CASES if case["id"] == "lifecycle_not_found")
        service, _, lifecycle, _, _ = _make_service(rejected)
        lifecycle.block_entered = threading.Event()
        lifecycle.block_release = threading.Event()
        errors = []

        def verify():
            try:
                service.verify(Submission.from_json(json.dumps(rejected["submission"])), b"x")
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=verify)
        worker.start()
        self.assertTrue(lifecycle.block_entered.wait(2))
        closed = threading.Event()
        closer = threading.Thread(target=lambda: (service.close(), closed.set()))
        closer.start()
        self.assertFalse(closed.wait(0.05))
        lifecycle.block_release.set()
        worker.join(2)
        closer.join(2)
        self.assertFalse(errors)
        self.assertTrue(closed.is_set())
        self.assertEqual(service._destroy_count, 1)
        service.close()
        self.assertEqual(service._destroy_count, 1)

    def test_finalizer_is_only_a_fallback(self):
        accepted = next(case for case in CASES if case["id"] == "accepted")
        service, _, _, _, _ = _make_service(accepted)
        finalizer = service._finalizer
        self.assertTrue(finalizer.alive)
        self.assertIsNotNone(service._control.native.abi_lifetime)
        service.close()
        self.assertFalse(finalizer.alive)
        self.assertIsNone(service._control.native.abi_lifetime)

    def test_finalizer_does_not_root_a_provider_service_cycle(self):
        accepted = next(case for case in CASES if case["id"] == "accepted")
        service, _, lifecycle, _, _ = _make_service(accepted)
        lifecycle.service = service
        reference = weakref.ref(service)
        del service, lifecycle
        gc.collect()
        self.assertIsNone(reference())

    def test_callback_registry_requires_exact_tuple_and_releases_once(self):
        from agentgate.service import _AllocationRegistry

        registry = _AllocationRegistry()
        release = _ffi.AgHostRelease(registry.release)
        registry.release_callback = release
        out = _ffi.AgHostBuffer()
        pending = registry.pending(b"secret", "key")
        registry.transfer(((ctypes.pointer(out), pending),))
        self.assertEqual(registry.outstanding_count, 1)
        release(out.release_data, out.data, out.len + 1)
        self.assertEqual(registry.outstanding_count, 1)
        self.assertEqual(registry.release_count, 0)
        release(out.release_data, out.data, out.len)
        release(out.release_data, out.data, out.len)
        self.assertEqual(registry.outstanding_count, 0)
        self.assertEqual(registry.release_count, 1)

    def test_double_output_allocation_failures_are_closed_without_transfer(self):
        from agentgate import service as service_module

        accepted = next(case for case in CASES if case["id"] == "accepted")
        state = FixtureState(accepted)
        lifecycle = FixtureLifecycle(state)
        keys = FixtureKeys(state)
        factories = (
            (
                "begin-first",
                lambda bridge, first, second: bridge._begin_attempt(
                    None,
                    _ffi.AgByteSlice(),
                    _ffi.AgByteSlice(),
                    0,
                    first,
                    second,
                ),
                _ffi.AG_BEGIN_STATUS_INTERNAL,
                1,
            ),
            (
                "begin-second",
                lambda bridge, first, second: bridge._begin_attempt(
                    None,
                    _ffi.AgByteSlice(),
                    _ffi.AgByteSlice(),
                    0,
                    first,
                    second,
                ),
                _ffi.AG_BEGIN_STATUS_INTERNAL,
                2,
            ),
            (
                "active-first",
                lambda bridge, first, second: bridge._active_key(None, first, second),
                _ffi.AG_KEY_STATUS_UNAVAILABLE,
                1,
            ),
            (
                "active-second",
                lambda bridge, first, second: bridge._active_key(None, first, second),
                _ffi.AG_KEY_STATUS_UNAVAILABLE,
                2,
            ),
        )
        original = ctypes.create_string_buffer
        for name, invoke, expected, failure_call in factories:
            with self.subTest(case=name):
                bridge = service_module._CallbackBridge(lifecycle, keys, None)
                first = _ffi.AgHostBuffer()
                second = _ffi.AgHostBuffer()
                calls = 0

                def allocate(value, length):
                    nonlocal calls
                    calls += 1
                    if calls == failure_call:
                        raise MemoryError("ALLOCATION_SECRET")
                    return original(value, length)

                with mock.patch.object(
                    service_module.ctypes,
                    "create_string_buffer",
                    side_effect=allocate,
                ):
                    status = invoke(bridge, ctypes.pointer(first), ctypes.pointer(second))
                self.assertEqual(status, expected)
                self.assertEqual(
                    (bool(first.data), first.len, first.release_data, bool(first.release)),
                    (False, 0, None, False),
                )
                self.assertEqual(
                    (bool(second.data), second.len, second.release_data, bool(second.release)),
                    (False, 0, None, False),
                )
                self.assertEqual(bridge.outstanding_count, 0)

    def test_transfer_rolls_back_first_registration_when_second_conflicts(self):
        from agentgate.service import _AllocationRegistry

        registry = _AllocationRegistry()
        release = _ffi.AgHostRelease(registry.release)
        registry.release_callback = release
        pending = registry.pending(b"one", "material")
        first = _ffi.AgHostBuffer()
        second = _ffi.AgHostBuffer()
        with self.assertRaisesRegex(RuntimeError, "invalid AgentGate callback allocation"):
            registry.transfer(
                ((ctypes.pointer(first), pending), (ctypes.pointer(second), pending))
            )
        self.assertEqual(registry.outstanding_count, 0)
        for output in (first, second):
            self.assertEqual(
                (bool(output.data), output.len, output.release_data, bool(output.release)),
                (False, 0, None, False),
            )

    def test_required_zero_length_is_owned_but_optional_empty_is_canonical(self):
        from agentgate.service import _AllocationRegistry

        registry = _AllocationRegistry()
        release = _ffi.AgHostRelease(registry.release)
        registry.release_callback = release
        required = _ffi.AgHostBuffer()
        optional = _ffi.AgHostBuffer()
        registry.transfer((
            (ctypes.pointer(required), registry.pending(b"", "required")),
            (ctypes.pointer(optional), registry.pending(b"", "optional", optional=True)),
        ))
        self.assertTrue(required.data)
        self.assertEqual(required.len, 0)
        self.assertTrue(required.release_data)
        self.assertTrue(required.release)
        self.assertEqual(
            (bool(optional.data), optional.len, optional.release_data, bool(optional.release)),
            (False, 0, None, False),
        )
        self.assertEqual(registry.outstanding_count, 1)
        release(required.release_data, required.data, required.len)
        self.assertEqual(registry.outstanding_count, 0)
        self.assertEqual(registry.release_count, 1)

    def test_destroy_non_ok_closes_once_and_never_retries(self):
        from agentgate import service as service_module

        class FakeLibrary:
            def __init__(self):
                self.calls = 0

            def ag_service_destroy(self, handle):
                self.calls += 1
                return _ffi.AG_STATUS_INTERNAL_ERROR

        library = FakeLibrary()
        native = service_module._NativeState(library, (object(),))
        native.handle = ctypes.c_void_p(123)
        native.open = True
        service = Service.__new__(Service)
        service._control = types.SimpleNamespace(native=native)
        service._bridge = object()
        service._finalizer = service_module._Finalizer(service._control)
        with self.assertRaisesRegex(AgentGateError, "^internal_error$") as caught:
            service.close()
        self.assertNotIn("SECRET", repr(caught.exception))
        self.assertFalse(native.open)
        self.assertEqual(native.destroy_count, 1)
        self.assertIsNone(native.abi_lifetime)
        service._finalizer()
        service.close()
        self.assertEqual(library.calls, 1)
        self.assertEqual(native.destroy_count, 1)

    def test_destroy_base_exception_is_mapped_and_finalizer_swallows(self):
        from agentgate import service as service_module

        class RaisingLibrary:
            def __init__(self):
                self.calls = 0

            def ag_service_destroy(self, handle):
                self.calls += 1
                raise CallbackSentinel("DESTROY_SECRET_SECRET")

        library = RaisingLibrary()
        native = service_module._NativeState(library, (object(),))
        native.handle = ctypes.c_void_p(123)
        native.open = True
        control = types.SimpleNamespace(native=native)
        service = Service.__new__(Service)
        service._control = control
        service._bridge = object()
        service._finalizer = service_module._Finalizer(control)
        with self.assertRaisesRegex(AgentGateError, "^internal_error$") as caught:
            service.close()
        self.assertNotIn("DESTROY_SECRET", str(caught.exception) + repr(caught.exception))
        self.assertFalse(native.open)
        self.assertEqual(native.destroy_count, 1)
        calls = library.calls
        service._finalizer()
        self.assertEqual(library.calls, calls)
        self.assertIsNone(native.abi_lifetime)


if __name__ == "__main__":
    unittest.main()
