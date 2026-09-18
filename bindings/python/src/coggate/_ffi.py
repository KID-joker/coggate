import ctypes
import ctypes.util
import os
import sys


AG_ABI_VERSION_1 = 1

AG_STATUS_OK = 0
AG_STATUS_INVALID_CONFIGURATION = 1
AG_STATUS_GENERATION_FAILED = 2
AG_STATUS_INVALID_CHALLENGE_MATERIAL = 3
AG_STATUS_INVALID_ANSWER_ENCODING = 4
AG_STATUS_ANSWER_MISMATCH = 5
AG_STATUS_UNSUPPORTED_GENERATOR_VERSION = 6
AG_STATUS_INTERNAL_ERROR = 7
AG_STATUS_INVALID_ARGUMENT = 100
AG_STATUS_CALLBACK_FAILED = 101
AG_STATUS_PANIC_CAUGHT = 102

AG_LIFECYCLE_STATUS_OK = 0
AG_LIFECYCLE_STATUS_UNAVAILABLE = 1
AG_LIFECYCLE_STATUS_CONFLICT = 2
AG_LIFECYCLE_STATUS_INTERNAL = 3

AG_BEGIN_STATUS_OK = 0
AG_BEGIN_STATUS_UNAVAILABLE = 1
AG_BEGIN_STATUS_CONFLICT = 2
AG_BEGIN_STATUS_INTERNAL = 3
AG_BEGIN_STATUS_NOT_FOUND = 10
AG_BEGIN_STATUS_EXPIRED = 11
AG_BEGIN_STATUS_ALREADY_CONSUMED = 12
AG_BEGIN_STATUS_BINDING_MISMATCH = 13
AG_BEGIN_STATUS_NONCE_MISMATCH = 14
AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED = 15

AG_KEY_STATUS_OK = 0
AG_KEY_STATUS_UNAVAILABLE = 1
AG_KEY_STATUS_NOT_FOUND = 2
AG_KEY_STATUS_INVALID_MATERIAL = 3

AG_ATTEMPT_OUTCOME_ACCEPTED = 1
AG_ATTEMPT_OUTCOME_REJECTED = 2
AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE = 3

AG_ATTEMPT_LIMIT_ONE = 1
AG_ATTEMPT_LIMIT_TWO = 2


UInt8Pointer = ctypes.POINTER(ctypes.c_uint8)


class AgByteSlice(ctypes.Structure):
    _fields_ = [("data", UInt8Pointer), ("len", ctypes.c_size_t)]


class AgOwnedBuffer(ctypes.Structure):
    _fields_ = [
        ("data", UInt8Pointer),
        ("len", ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]


# AG_CALL is __cdecl on Windows, so callbacks deliberately use CFUNCTYPE.
AgHostRelease = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, UInt8Pointer, ctypes.c_size_t
)


class AgHostBuffer(ctypes.Structure):
    _fields_ = [
        ("data", UInt8Pointer),
        ("len", ctypes.c_size_t),
        ("release_data", ctypes.c_void_p),
        ("release", AgHostRelease),
    ]


AgStoreIssuedCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    AgByteSlice,
    AgByteSlice,
    ctypes.c_uint32,
)
AgBeginAttemptCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    AgByteSlice,
    AgByteSlice,
    ctypes.c_int64,
    ctypes.POINTER(AgHostBuffer),
    ctypes.POINTER(AgHostBuffer),
)
AgFinishAttemptCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32, ctypes.c_void_p, AgByteSlice, ctypes.c_int32
)
AgActiveKeyCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(AgHostBuffer),
    ctypes.POINTER(AgHostBuffer),
)
AgKeyByIdCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    AgByteSlice,
    ctypes.POINTER(AgHostBuffer),
)
AgObserveCallback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, AgByteSlice)


class AgCallbackHeader(ctypes.Structure):
    _fields_ = [("struct_size", ctypes.c_uint32), ("abi_version", ctypes.c_uint32)]


class AgLifecycleCallbacks(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("user_data", ctypes.c_void_p),
        ("store_issued", AgStoreIssuedCallback),
        ("begin_attempt", AgBeginAttemptCallback),
        ("finish_attempt", AgFinishAttemptCallback),
    ]


class AgKeyCallbacks(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("user_data", ctypes.c_void_p),
        ("active_key", AgActiveKeyCallback),
        ("key_by_id", AgKeyByIdCallback),
    ]


class AgObserverCallbacks(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("user_data", ctypes.c_void_p),
        ("observe", AgObserveCallback),
    ]


def _callback_factory(platform=None):
    # coggate.h defines AG_CALL as __cdecl, including on Windows.
    return ctypes.CFUNCTYPE


def _library_class(platform=None):
    # CDLL is ctypes' cdecl loader. WinDLL would incorrectly select stdcall.
    return ctypes.CDLL


def _platform_library_name(platform=None):
    platform = sys.platform if platform is None else platform
    if platform == "darwin":
        return "libcoggate_ffi.dylib"
    if platform == "win32":
        return "coggate_ffi.dll"
    return "libcoggate_ffi.so"


def _configure_library(library):
    library.ag_abi_version.argtypes = []
    library.ag_abi_version.restype = ctypes.c_uint32
    library.ag_core_version.argtypes = []
    library.ag_core_version.restype = AgByteSlice
    library.ag_service_create.argtypes = [
        ctypes.POINTER(AgLifecycleCallbacks),
        ctypes.POINTER(AgKeyCallbacks),
        ctypes.POINTER(AgObserverCallbacks),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.ag_service_create.restype = ctypes.c_int32
    library.ag_service_destroy.argtypes = [ctypes.c_void_p]
    library.ag_service_destroy.restype = ctypes.c_int32
    library.ag_service_issue.argtypes = [
        ctypes.c_void_p,
        AgByteSlice,
        AgByteSlice,
        ctypes.c_uint32,
        ctypes.POINTER(AgOwnedBuffer),
    ]
    library.ag_service_issue.restype = ctypes.c_int32
    library.ag_service_verify.argtypes = [
        ctypes.c_void_p,
        AgByteSlice,
        AgByteSlice,
        ctypes.POINTER(AgOwnedBuffer),
    ]
    library.ag_service_verify.restype = ctypes.c_int32
    library.ag_buffer_free.argtypes = [ctypes.POINTER(AgOwnedBuffer)]
    library.ag_buffer_free.restype = ctypes.c_int32


def _load_candidate(candidate):
    try:
        library = _library_class()(os.fspath(candidate))
        _configure_library(library)
    except (OSError, AttributeError):
        raise RuntimeError("CogGate native library not found") from None
    if library.ag_abi_version() != AG_ABI_VERSION_1:
        raise RuntimeError("unsupported CogGate ABI version")
    return library


def load_library(path=None):
    if path is not None:
        return _load_candidate(path)

    configured = os.environ.get("COGGATE_LIBRARY_PATH")
    if configured:
        return _load_candidate(configured)

    candidates = []
    discovered = ctypes.util.find_library("coggate_ffi")
    if discovered:
        candidates.append(discovered)
    platform_name = _platform_library_name()
    if platform_name not in candidates:
        candidates.append(platform_name)
    for candidate in candidates:
        try:
            return _load_candidate(candidate)
        except RuntimeError as error:
            if str(error) != "CogGate native library not found":
                raise
    raise RuntimeError("CogGate native library not found")
