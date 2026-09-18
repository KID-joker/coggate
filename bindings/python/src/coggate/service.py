import ctypes
import threading
import weakref
from dataclasses import dataclass

from . import _ffi
from .errors import CogGateError
from .models import AttemptLimit, IssueRequest, PublicChallenge, Submission, VerificationOutcome


class _SafeResult:
    def __repr__(self):
        return "{}()".format(type(self).__name__)

    __str__ = __repr__


@dataclass(frozen=True, repr=False)
class BeginAttemptResult(_SafeResult):
    status: int
    material: bytes = b""
    token: bytes = b""

    def __post_init__(self):
        if type(self.status) is not int or type(self.material) is not bytes or type(self.token) is not bytes:
            raise ValueError("invalid CogGate callback result")


@dataclass(frozen=True, repr=False)
class ActiveKeyResult(_SafeResult):
    status: int
    key_id: str = ""
    key: bytes = b""

    def __post_init__(self):
        if type(self.status) is not int or type(self.key_id) is not str or type(self.key) is not bytes:
            raise ValueError("invalid CogGate callback result")


@dataclass(frozen=True, repr=False)
class KeyResult(_SafeResult):
    status: int
    key: bytes = b""

    def __post_init__(self):
        if type(self.status) is not int or type(self.key) is not bytes:
            raise ValueError("invalid CogGate callback result")


def _slice_bytes(value):
    if value.len == 0:
        return b""
    return ctypes.string_at(value.data, value.len)


def _slice_text(value):
    return _slice_bytes(value).decode("utf-8", errors="strict")


def _borrow_bytes(value):
    if not value:
        return _ffi.AgByteSlice(), None
    keeper = (ctypes.c_uint8 * len(value)).from_buffer_copy(value)
    return _ffi.AgByteSlice(ctypes.cast(keeper, _ffi.UInt8Pointer), len(value)), keeper


class _AllocationRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._allocations = {}
        self.release_count = 0
        self.release_hook = None

    @property
    def outstanding_count(self):
        with self._lock:
            return len(self._allocations)

    def pending(self, value, label, optional=False):
        if optional and not value:
            return None
        buffer = ctypes.create_string_buffer(value, len(value))
        address = ctypes.addressof(buffer)
        return address, len(value), buffer, label

    def transfer(self, pending_outputs):
        registered = []
        try:
            with self._lock:
                for out, pending in pending_outputs:
                    if pending is None:
                        out[0] = _ffi.AgHostBuffer()
                        continue
                    address, length, buffer, label = pending
                    key = (address, length)
                    if key in self._allocations:
                        raise RuntimeError("invalid CogGate callback allocation")
                    self._allocations[key] = (buffer, label)
                    registered.append(key)
                    out[0] = _ffi.AgHostBuffer(
                        ctypes.cast(buffer, _ffi.UInt8Pointer),
                        length,
                        ctypes.c_void_p(address),
                        self.release_callback,
                    )
        except BaseException:
            with self._lock:
                for key in registered:
                    self._allocations.pop(key, None)
            for out, _ in pending_outputs:
                out[0] = _ffi.AgHostBuffer()
            raise

    def release(self, release_data, data, length):
        address = ctypes.cast(data, ctypes.c_void_p).value or 0
        owner = ctypes.cast(release_data, ctypes.c_void_p).value or 0
        if owner != address:
            return
        with self._lock:
            entry = self._allocations.pop((address, int(length)), None)
            if entry is None:
                return
            self.release_count += 1
            hook = self.release_hook
            label = entry[1]
        if hook is not None:
            try:
                hook(label)
            except BaseException:
                pass


class _CallbackBridge:
    def __init__(self, lifecycle, keys, observer):
        self.lifecycle = lifecycle
        self.keys = keys
        self.observer = observer
        self._registry = _AllocationRegistry()
        # The C callback never dereferences user_data; this stable token lets the
        # finalizer retain the ABI pointer without indirectly rooting providers.
        self._user_data_object = ctypes.py_object(object())
        self._user_data_pointer = ctypes.cast(
            ctypes.pointer(self._user_data_object), ctypes.c_void_p
        )
        bridge = weakref.ref(self)

        def release(release_data, data, length):
            try:
                current = bridge()
                if current is not None:
                    current._registry.release(release_data, data, length)
            except BaseException:
                pass

        self._release = _ffi.AgHostRelease(release)
        self._registry.release_callback = self._release

        def store_issued(user_data, private_json, binding, attempt_limit):
            del user_data
            try:
                current = bridge()
                status = current.lifecycle.store_issued(
                    _slice_text(private_json),
                    _slice_bytes(binding),
                    AttemptLimit(attempt_limit),
                )
                if type(status) is not int:
                    raise ValueError("invalid CogGate callback result")
                return status
            except BaseException:
                return _ffi.AG_LIFECYCLE_STATUS_INTERNAL

        def begin_attempt(user_data, identity_json, binding, server_time, material_out, token_out):
            del user_data
            try:
                current = bridge()
                result = current.lifecycle.begin_attempt(
                    _slice_text(identity_json), _slice_bytes(binding), int(server_time)
                )
                if type(result) is not BeginAttemptResult:
                    raise ValueError("invalid CogGate callback result")
                if result.status != _ffi.AG_BEGIN_STATUS_OK:
                    return result.status
                material = current._registry.pending(result.material, "material")
                token = current._registry.pending(result.token, "token", optional=True)
                current._registry.transfer(((material_out, material), (token_out, token)))
                return _ffi.AG_BEGIN_STATUS_OK
            except BaseException:
                return _ffi.AG_BEGIN_STATUS_INTERNAL

        def finish_attempt(user_data, token, outcome):
            del user_data
            try:
                current = bridge()
                status = current.lifecycle.finish_attempt(_slice_bytes(token), int(outcome))
                if type(status) is not int:
                    raise ValueError("invalid CogGate callback result")
                return status
            except BaseException:
                return _ffi.AG_LIFECYCLE_STATUS_INTERNAL

        def active_key(user_data, key_id_out, key_out):
            del user_data
            try:
                current = bridge()
                result = current.keys.active_key()
                if type(result) is not ActiveKeyResult:
                    raise ValueError("invalid CogGate callback result")
                if result.status != _ffi.AG_KEY_STATUS_OK:
                    return result.status
                key_id = current._registry.pending(result.key_id.encode("utf-8", errors="strict"), "active_key_id")
                key = current._registry.pending(result.key, "active_key")
                current._registry.transfer(((key_id_out, key_id), (key_out, key)))
                return _ffi.AG_KEY_STATUS_OK
            except BaseException:
                return _ffi.AG_KEY_STATUS_UNAVAILABLE

        def key_by_id(user_data, key_id, key_out):
            del user_data
            try:
                current = bridge()
                result = current.keys.key_by_id(_slice_text(key_id))
                if type(result) is not KeyResult:
                    raise ValueError("invalid CogGate callback result")
                if result.status != _ffi.AG_KEY_STATUS_OK:
                    return result.status
                key = current._registry.pending(result.key, "key")
                current._registry.transfer(((key_out, key),))
                return _ffi.AG_KEY_STATUS_OK
            except BaseException:
                return _ffi.AG_KEY_STATUS_UNAVAILABLE

        def observe(user_data, event_json):
            del user_data
            try:
                current = bridge()
                if current is not None and current.observer is not None:
                    current.observer.observe(_slice_text(event_json))
            except BaseException:
                pass

        self._store_issued = _ffi.AgStoreIssuedCallback(store_issued)
        self._begin_attempt = _ffi.AgBeginAttemptCallback(begin_attempt)
        self._finish_attempt = _ffi.AgFinishAttemptCallback(finish_attempt)
        self._active_key = _ffi.AgActiveKeyCallback(active_key)
        self._key_by_id = _ffi.AgKeyByIdCallback(key_by_id)
        self._observe = _ffi.AgObserveCallback(observe)
        self.lifecycle_callbacks = _ffi.AgLifecycleCallbacks(
            ctypes.sizeof(_ffi.AgLifecycleCallbacks),
            _ffi.AG_ABI_VERSION_1,
            self._user_data_pointer,
            self._store_issued,
            self._begin_attempt,
            self._finish_attempt,
        )
        self.key_callbacks = _ffi.AgKeyCallbacks(
            ctypes.sizeof(_ffi.AgKeyCallbacks),
            _ffi.AG_ABI_VERSION_1,
            self._user_data_pointer,
            self._active_key,
            self._key_by_id,
        )
        self.observer_callbacks = _ffi.AgObserverCallbacks(
            ctypes.sizeof(_ffi.AgObserverCallbacks),
            _ffi.AG_ABI_VERSION_1,
            self._user_data_pointer,
            self._observe,
        )
        self.abi_lifetime = (
            self._user_data_object,
            self._user_data_pointer,
            self._release,
            self._store_issued,
            self._begin_attempt,
            self._finish_attempt,
            self._active_key,
            self._key_by_id,
            self._observe,
            self.lifecycle_callbacks,
            self.key_callbacks,
            self.observer_callbacks,
        )

    @property
    def release_hook(self):
        return self._registry.release_hook

    @release_hook.setter
    def release_hook(self, value):
        self._registry.release_hook = value

    @property
    def release_count(self):
        return self._registry.release_count

    @property
    def outstanding_count(self):
        return self._registry.outstanding_count


class _NativeState:
    def __init__(self, library, abi_lifetime):
        self.library = library
        self.abi_lifetime = abi_lifetime
        self.lock = threading.RLock()
        self.handle = ctypes.c_void_p()
        self.open = False
        self.destroy_count = 0
        self.owned_free_count = 0


class _Control:
    def __init__(self, library, bridge):
        self.native = _NativeState(library, bridge.abi_lifetime)
        self.bridge = bridge


_ACTIVE = threading.local()


def _active_stack():
    stack = getattr(_ACTIVE, "stack", None)
    if stack is None:
        stack = []
        _ACTIVE.stack = stack
    return stack


def _reject_reentry(native):
    if native in _active_stack():
        raise CogGateError(_ffi.AG_STATUS_INVALID_ARGUMENT)


def _destroy(native, raise_errors):
    _reject_reentry(native)
    with native.lock:
        if not native.open:
            return
        handle = native.handle
        native.handle = ctypes.c_void_p()
        native.open = False
        native.destroy_count += 1
        try:
            status = int(native.library.ag_service_destroy(handle))
        except BaseException:
            status = _ffi.AG_STATUS_INTERNAL_ERROR
        finally:
            # Callback functions and user_data must remain valid through the
            # complete native destroy call, but are no longer needed afterward.
            native.abi_lifetime = None
    if raise_errors and status != _ffi.AG_STATUS_OK:
        raise CogGateError(status)


class _Finalizer:
    """A cycle-safe fallback invoked from Service.__del__."""

    def __init__(self, control):
        self._control = control
        self.alive = True

    def __call__(self):
        if not self.alive:
            return
        try:
            _destroy(self._control.native, False)
        except BaseException:
            pass
        self.alive = False

    def detach(self):
        self.alive = False


class Service:
    def __init__(self, lifecycle, keys, observer=None, library_path=None):
        if lifecycle is None or keys is None:
            raise CogGateError(_ffi.AG_STATUS_INVALID_ARGUMENT)
        library = _ffi.load_library(library_path)
        bridge = _CallbackBridge(lifecycle, keys, observer)
        control = _Control(library, bridge)
        native = control.native
        observer_pointer = (
            ctypes.byref(bridge.observer_callbacks) if observer is not None else None
        )
        status = int(library.ag_service_create(
            ctypes.byref(bridge.lifecycle_callbacks),
            ctypes.byref(bridge.key_callbacks),
            observer_pointer,
            ctypes.byref(native.handle),
        ))
        if status != _ffi.AG_STATUS_OK:
            raise CogGateError(status)
        native.open = True
        self._control = control
        self._bridge = bridge
        self._finalizer = _Finalizer(control)

    def __del__(self):
        finalizer = getattr(self, "_finalizer", None)
        if finalizer is not None:
            finalizer()

    @property
    def is_open(self):
        return self._control.native.open

    @property
    def _destroy_count(self):
        return self._control.native.destroy_count

    @property
    def _owned_free_count(self):
        return self._control.native.owned_free_count

    def __enter__(self):
        if not self.is_open:
            raise CogGateError(_ffi.AG_STATUS_INVALID_ARGUMENT)
        return self

    def __exit__(self, exception_type, exception, traceback):
        del exception_type, exception, traceback
        self.close()
        return False

    def close(self):
        _destroy(self._control.native, True)
        self._finalizer.detach()

    def _invoke(self, function, arguments, keepers):
        native = self._control.native
        _reject_reentry(native)
        with native.lock:
            if not native.open or not native.handle.value:
                raise CogGateError(_ffi.AG_STATUS_INVALID_ARGUMENT)
            output = _ffi.AgOwnedBuffer()
            stack = _active_stack()
            stack.append(native)
            try:
                status = int(function(native.handle, *arguments, ctypes.byref(output)))
            finally:
                popped = stack.pop()
                if popped is not native:
                    raise RuntimeError("invalid CogGate call stack")
            del keepers
            payload = b""
            free_status = _ffi.AG_STATUS_OK
            if output.data:
                payload = ctypes.string_at(output.data, output.len)
                free_status = int(native.library.ag_buffer_free(ctypes.byref(output)))
                native.owned_free_count += 1
            if status != _ffi.AG_STATUS_OK:
                raise CogGateError(status)
            if free_status != _ffi.AG_STATUS_OK:
                raise CogGateError(free_status)
            return payload.decode("utf-8", errors="strict")

    def issue(self, request):
        if type(request) is not IssueRequest:
            raise CogGateError(_ffi.AG_STATUS_INVALID_ARGUMENT)
        version, version_keeper = _borrow_bytes(request.version.encode("utf-8"))
        binding, binding_keeper = _borrow_bytes(request.binding)
        payload = self._invoke(
            self._control.native.library.ag_service_issue,
            (version, binding, int(request.attempt_limit)),
            (version_keeper, binding_keeper),
        )
        return PublicChallenge.from_json(payload)

    def verify(self, submission, binding):
        if type(submission) is not Submission or type(binding) is not bytes or not 1 <= len(binding) <= 256:
            raise CogGateError(_ffi.AG_STATUS_INVALID_ARGUMENT)
        submission_slice, submission_keeper = _borrow_bytes(submission.to_json().encode("utf-8"))
        binding_slice, binding_keeper = _borrow_bytes(binding)
        payload = self._invoke(
            self._control.native.library.ag_service_verify,
            (submission_slice, binding_slice),
            (submission_keeper, binding_keeper),
        )
        return VerificationOutcome.from_json(payload)


__all__ = ["ActiveKeyResult", "BeginAttemptResult", "KeyResult", "Service"]
