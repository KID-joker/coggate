use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use crate::{AG_ABI_VERSION_1, AgByteSlice, AgHostBuffer, AgStatus};

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Status returned by lifecycle store and finish callbacks.
pub enum AgLifecycleStatus {
    Ok = 0,
    Unavailable = 1,
    Conflict = 2,
    Internal = 3,
}

impl TryFrom<i32> for AgLifecycleStatus {
    type Error = AgStatus;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::Conflict),
            3 => Ok(Self::Internal),
            _ => Err(AgStatus::CallbackFailed),
        }
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Status returned by the lifecycle begin callback.
pub enum AgBeginStatus {
    Ok = 0,
    Unavailable = 1,
    Conflict = 2,
    Internal = 3,
    NotFound = 10,
    Expired = 11,
    AlreadyConsumed = 12,
    BindingMismatch = 13,
    NonceMismatch = 14,
    AttemptsExhausted = 15,
}

impl TryFrom<i32> for AgBeginStatus {
    type Error = AgStatus;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::Conflict),
            3 => Ok(Self::Internal),
            10 => Ok(Self::NotFound),
            11 => Ok(Self::Expired),
            12 => Ok(Self::AlreadyConsumed),
            13 => Ok(Self::BindingMismatch),
            14 => Ok(Self::NonceMismatch),
            15 => Ok(Self::AttemptsExhausted),
            _ => Err(AgStatus::CallbackFailed),
        }
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Status returned by key-provider callbacks.
pub enum AgKeyStatus {
    Ok = 0,
    Unavailable = 1,
    NotFound = 2,
    InvalidMaterial = 3,
}

impl TryFrom<i32> for AgKeyStatus {
    type Error = AgStatus;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::NotFound),
            3 => Ok(Self::InvalidMaterial),
            _ => Err(AgStatus::CallbackFailed),
        }
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Outcome passed to the lifecycle finish callback.
pub enum AgAttemptOutcome {
    Accepted = 1,
    Rejected = 2,
    SystemFailure = 3,
}

/// Persists newly issued private material.
///
/// `private_json` and `binding` are borrowed only for the synchronous call and
/// must not be retained. The callback must not unwind, throw, or longjmp across
/// the ABI boundary, and must not reenter the same service handle.
pub type AgStoreIssuedCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    private_json: AgByteSlice,
    binding: AgByteSlice,
    attempt_limit: u32,
) -> i32;

/// Begins an attempt and returns required private material plus an optional token.
///
/// `identity_json` and `binding` are borrowed only for the synchronous call and
/// must not be retained. Both out pointers are valid and writable only during
/// the call and must not be retained. Output ownership transfers to Rust only
/// when the callback returns [`AgBeginStatus::Ok`]; on every other status the
/// outputs remain host-owned and require host cleanup.
///
/// On success, `material_out` must be nonempty. `token_out` may use canonical
/// empty form (null `data`, zero `len`, and no release). Every non-null output
/// `data` pointer must be readable for `len` bytes and provide a release
/// callback, including at `len == 0`. Rust calls that release exactly once with
/// the unchanged `release_data`, `data`, and `len` tuple. The callback and all
/// release functions must not unwind, throw, or longjmp across the ABI boundary
/// and must not reenter the same service handle.
pub type AgBeginAttemptCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    identity_json: AgByteSlice,
    binding: AgByteSlice,
    server_time: i64,
    material_out: *mut AgHostBuffer,
    token_out: *mut AgHostBuffer,
) -> i32;

/// Finishes an attempt with the exact opaque token returned by begin.
///
/// `token` is borrowed only for the synchronous call and must not be retained.
/// The callback must not unwind, throw, or longjmp across the ABI boundary, and
/// must not reenter the same service handle.
pub type AgFinishAttemptCallback =
    unsafe extern "C" fn(user_data: *mut c_void, token: AgByteSlice, outcome: i32) -> i32;

/// Returns the required active key identifier and key material.
///
/// Both out pointers are valid and writable only during the call and must not
/// be retained. Ownership transfers to Rust only when the callback returns
/// [`AgKeyStatus::Ok`]; otherwise both outputs remain host-owned and require
/// host cleanup. On success both outputs must be nonempty. Every non-null data
/// pointer must be readable for its `len` and provide a release callback. Rust
/// calls each release exactly once with the unchanged `release_data`, `data`,
/// and `len` tuple. The callback and releases must not unwind, throw, or longjmp
/// across the ABI boundary and must not reenter the same service handle.
pub type AgActiveKeyCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    key_id_out: *mut AgHostBuffer,
    key_out: *mut AgHostBuffer,
) -> i32;

/// Returns required key material for an exact key identifier.
///
/// `key_id` is borrowed only for the synchronous call and must not be retained;
/// `key_out` is valid and writable only during that call and must not be
/// retained. Ownership transfers to Rust only on [`AgKeyStatus::Ok`]. On every
/// other status the output remains host-owned and requires host cleanup. On
/// success the key must be nonempty, its data must be readable for `len`, and
/// every non-null data pointer must provide a release callback. Rust calls the
/// release exactly once with the unchanged tuple. The callback and release must
/// not unwind, throw, or longjmp across the ABI boundary and must not reenter
/// the same service handle.
pub type AgKeyByIdCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    key_id: AgByteSlice,
    key_out: *mut AgHostBuffer,
) -> i32;

/// Observes a serialized service event.
///
/// `event_json` is borrowed only for this synchronous call and must not be
/// retained. The callback must not unwind, throw, or longjmp across the ABI
/// boundary, and must not reenter the same service handle.
pub type AgObserveCallback = unsafe extern "C" fn(user_data: *mut c_void, event_json: AgByteSlice);

/// Common prefix for every versioned callback table.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgCallbackHeader {
    pub struct_size: u32,
    pub abi_version: u32,
}

/// Host lifecycle callback table copied into a service handle.
///
/// After construction, the table and function pointers are immutable for the
/// service lifetime. `user_data` must remain valid until handle destruction and
/// must support serialized callback invocations from arbitrary host threads.
/// Its pointee remains host-owned and must be synchronized by the host. No
/// callback may reenter the same handle because future handle-level locking may
/// deadlock, and handle destruction must not run concurrently with callbacks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgLifecycleCallbacks {
    pub struct_size: u32,
    pub abi_version: u32,
    pub user_data: *mut c_void,
    pub store_issued: Option<AgStoreIssuedCallback>,
    pub begin_attempt: Option<AgBeginAttemptCallback>,
    pub finish_attempt: Option<AgFinishAttemptCallback>,
}

/// Host key-provider callback table copied into a service handle.
///
/// After construction, the table and function pointers are immutable for the
/// service lifetime. `user_data` must remain valid until handle destruction and
/// must support serialized callback invocations from arbitrary host threads.
/// Its pointee remains host-owned and must be synchronized by the host. No
/// callback may reenter the same handle because future handle-level locking may
/// deadlock, and handle destruction must not run concurrently with callbacks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgKeyCallbacks {
    pub struct_size: u32,
    pub abi_version: u32,
    pub user_data: *mut c_void,
    pub active_key: Option<AgActiveKeyCallback>,
    pub key_by_id: Option<AgKeyByIdCallback>,
}

/// Optional host observer callback table copied into a service handle.
///
/// After construction, the table and function pointer are immutable for the
/// service lifetime. `user_data` must remain valid until handle destruction and
/// must support serialized callback invocations from arbitrary host threads.
/// Its pointee remains host-owned and must be synchronized by the host. The
/// callback must not reenter the same handle, and handle destruction must not
/// run concurrently with callbacks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgObserverCallbacks {
    pub struct_size: u32,
    pub abi_version: u32,
    pub user_data: *mut c_void,
    pub observe: Option<AgObserveCallback>,
}

#[allow(dead_code)]
unsafe fn validate_header<T>(table: *const T) -> Result<(), AgStatus> {
    if table.is_null() {
        return Err(AgStatus::CallbackFailed);
    }

    let header = unsafe { ptr::read(table.cast::<AgCallbackHeader>()) };
    if header.abi_version != AG_ABI_VERSION_1 || header.struct_size < size_of::<T>() as u32 {
        return Err(AgStatus::CallbackFailed);
    }

    Ok(())
}

/// Validates and copies a lifecycle callback table supplied by the host.
///
/// # Safety
///
/// `table` may be null. Otherwise it must be aligned for
/// [`AgCallbackHeader`], point to an initialized header valid to read, and not
/// be mutated concurrently during either read performed here. If the header
/// advertises the current ABI version and a sufficient `struct_size`, `table`
/// must also be aligned for and valid to read one complete, initialized
/// [`AgLifecycleCallbacks`]. Its `Option<extern "C" fn>` fields must contain
/// valid nullable function-pointer representations.
#[allow(dead_code)]
pub(crate) unsafe fn read_lifecycle_callbacks(
    table: *const AgLifecycleCallbacks,
) -> Result<AgLifecycleCallbacks, AgStatus> {
    unsafe { validate_header(table)? };
    let callbacks = unsafe { ptr::read(table) };
    if callbacks.store_issued.is_none()
        || callbacks.begin_attempt.is_none()
        || callbacks.finish_attempt.is_none()
    {
        return Err(AgStatus::CallbackFailed);
    }
    Ok(callbacks)
}

/// Validates and copies a key callback table supplied by the host.
///
/// # Safety
///
/// `table` may be null. Otherwise it must be aligned for
/// [`AgCallbackHeader`], point to an initialized header valid to read, and not
/// be mutated concurrently during either read performed here. If the header
/// advertises the current ABI version and a sufficient `struct_size`, `table`
/// must also be aligned for and valid to read one complete, initialized
/// [`AgKeyCallbacks`]. Its `Option<extern "C" fn>` fields must contain valid
/// nullable function-pointer representations.
#[allow(dead_code)]
pub(crate) unsafe fn read_key_callbacks(
    table: *const AgKeyCallbacks,
) -> Result<AgKeyCallbacks, AgStatus> {
    unsafe { validate_header(table)? };
    let callbacks = unsafe { ptr::read(table) };
    if callbacks.active_key.is_none() || callbacks.key_by_id.is_none() {
        return Err(AgStatus::CallbackFailed);
    }
    Ok(callbacks)
}

/// Validates and copies an optional observer callback table supplied by the host.
///
/// # Safety
///
/// `table` may be null. Otherwise it must be aligned for
/// [`AgCallbackHeader`], point to an initialized header valid to read, and not
/// be mutated concurrently during either read performed here. If the header
/// advertises the current ABI version and a sufficient `struct_size`, `table`
/// must also be aligned for and valid to read one complete, initialized
/// [`AgObserverCallbacks`]. Its `Option<extern "C" fn>` field must contain a
/// valid nullable function-pointer representation.
#[allow(dead_code)]
pub(crate) unsafe fn read_observer_callbacks(
    table: *const AgObserverCallbacks,
) -> Result<Option<AgObserverCallbacks>, AgStatus> {
    if table.is_null() {
        return Ok(None);
    }

    unsafe { validate_header(table)? };
    let callbacks = unsafe { ptr::read(table) };
    if callbacks.observe.is_none() {
        return Err(AgStatus::CallbackFailed);
    }
    Ok(Some(callbacks))
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr;

    use super::{
        AgAttemptOutcome, AgBeginStatus, AgCallbackHeader, AgKeyCallbacks, AgKeyStatus,
        AgLifecycleCallbacks, AgLifecycleStatus, AgObserverCallbacks, read_key_callbacks,
        read_lifecycle_callbacks, read_observer_callbacks,
    };
    use crate::{AG_ABI_VERSION_1, AgByteSlice, AgHostBuffer, AgStatus};

    unsafe extern "C" fn store_issued(
        _: *mut c_void,
        _: AgByteSlice,
        _: AgByteSlice,
        _: u32,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn begin_attempt(
        _: *mut c_void,
        _: AgByteSlice,
        _: AgByteSlice,
        _: i64,
        _: *mut AgHostBuffer,
        _: *mut AgHostBuffer,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn finish_attempt(_: *mut c_void, _: AgByteSlice, _: i32) -> i32 {
        0
    }

    unsafe extern "C" fn active_key(
        _: *mut c_void,
        _: *mut AgHostBuffer,
        _: *mut AgHostBuffer,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn key_by_id(_: *mut c_void, _: AgByteSlice, _: *mut AgHostBuffer) -> i32 {
        0
    }

    unsafe extern "C" fn observe(_: *mut c_void, _: AgByteSlice) {}

    fn lifecycle_callbacks() -> AgLifecycleCallbacks {
        let mut callbacks: AgLifecycleCallbacks = unsafe { zeroed() };
        callbacks.struct_size = size_of::<AgLifecycleCallbacks>() as u32;
        callbacks.abi_version = AG_ABI_VERSION_1;
        callbacks.store_issued = Some(store_issued);
        callbacks.begin_attempt = Some(begin_attempt);
        callbacks.finish_attempt = Some(finish_attempt);
        callbacks
    }

    fn key_callbacks() -> AgKeyCallbacks {
        let mut callbacks: AgKeyCallbacks = unsafe { zeroed() };
        callbacks.struct_size = size_of::<AgKeyCallbacks>() as u32;
        callbacks.abi_version = AG_ABI_VERSION_1;
        callbacks.active_key = Some(active_key);
        callbacks.key_by_id = Some(key_by_id);
        callbacks
    }

    fn observer_callbacks() -> AgObserverCallbacks {
        let mut callbacks: AgObserverCallbacks = unsafe { zeroed() };
        callbacks.struct_size = size_of::<AgObserverCallbacks>() as u32;
        callbacks.abi_version = AG_ABI_VERSION_1;
        callbacks.observe = Some(observe);
        callbacks
    }

    #[test]
    fn callback_header_has_stable_layout_fields() {
        let header = AgCallbackHeader {
            struct_size: 24,
            abi_version: AG_ABI_VERSION_1,
        };
        assert_eq!(header.struct_size, 24);
        assert_eq!(header.abi_version, 1);
    }

    #[test]
    fn required_callback_pointers_reject_null() {
        assert_eq!(
            unsafe { read_lifecycle_callbacks(ptr::null()) }.err(),
            Some(AgStatus::CallbackFailed)
        );
        assert_eq!(
            unsafe { read_key_callbacks(ptr::null()) }.err(),
            Some(AgStatus::CallbackFailed)
        );
    }

    #[test]
    fn null_observer_is_accepted_as_absent() {
        assert!(
            unsafe { read_observer_callbacks(ptr::null()) }
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn lifecycle_reader_rejects_short_size() {
        let mut callbacks = lifecycle_callbacks();
        callbacks.struct_size = size_of::<AgCallbackHeader>() as u32;
        assert_eq!(
            unsafe { read_lifecycle_callbacks(&callbacks) }.err(),
            Some(AgStatus::CallbackFailed)
        );
    }

    #[test]
    fn key_reader_rejects_wrong_version() {
        let mut callbacks = key_callbacks();
        callbacks.abi_version = AG_ABI_VERSION_1 + 1;
        assert_eq!(
            unsafe { read_key_callbacks(&callbacks) }.err(),
            Some(AgStatus::CallbackFailed)
        );
    }

    #[test]
    fn readers_reject_missing_mandatory_callbacks() {
        let mut lifecycle = lifecycle_callbacks();
        lifecycle.finish_attempt = None;
        assert_eq!(
            unsafe { read_lifecycle_callbacks(&lifecycle) }.err(),
            Some(AgStatus::CallbackFailed)
        );

        let mut keys = key_callbacks();
        keys.key_by_id = None;
        assert_eq!(
            unsafe { read_key_callbacks(&keys) }.err(),
            Some(AgStatus::CallbackFailed)
        );

        let mut observer = observer_callbacks();
        observer.observe = None;
        assert_eq!(
            unsafe { read_observer_callbacks(&observer) }.err(),
            Some(AgStatus::CallbackFailed)
        );
    }

    #[test]
    fn oversized_compatible_tables_are_accepted() {
        let mut lifecycle = lifecycle_callbacks();
        lifecycle.struct_size += 64;
        assert!(unsafe { read_lifecycle_callbacks(&lifecycle) }.is_ok());

        let mut keys = key_callbacks();
        keys.struct_size += 64;
        assert!(unsafe { read_key_callbacks(&keys) }.is_ok());

        let mut observer = observer_callbacks();
        observer.struct_size += 64;
        assert!(
            unsafe { read_observer_callbacks(&observer) }
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn callback_status_discriminants_are_stable() {
        assert_eq!(AgLifecycleStatus::Ok as i32, 0);
        assert_eq!(AgLifecycleStatus::Unavailable as i32, 1);
        assert_eq!(AgLifecycleStatus::Conflict as i32, 2);
        assert_eq!(AgLifecycleStatus::Internal as i32, 3);
        assert_eq!(AgBeginStatus::Ok as i32, 0);
        assert_eq!(AgBeginStatus::Unavailable as i32, 1);
        assert_eq!(AgBeginStatus::Conflict as i32, 2);
        assert_eq!(AgBeginStatus::Internal as i32, 3);
        assert_eq!(AgBeginStatus::NotFound as i32, 10);
        assert_eq!(AgBeginStatus::Expired as i32, 11);
        assert_eq!(AgBeginStatus::AlreadyConsumed as i32, 12);
        assert_eq!(AgBeginStatus::BindingMismatch as i32, 13);
        assert_eq!(AgBeginStatus::NonceMismatch as i32, 14);
        assert_eq!(AgBeginStatus::AttemptsExhausted as i32, 15);
        assert_eq!(AgKeyStatus::Ok as i32, 0);
        assert_eq!(AgKeyStatus::Unavailable as i32, 1);
        assert_eq!(AgKeyStatus::NotFound as i32, 2);
        assert_eq!(AgKeyStatus::InvalidMaterial as i32, 3);
        assert_eq!(AgAttemptOutcome::Accepted as i32, 1);
        assert_eq!(AgAttemptOutcome::Rejected as i32, 2);
        assert_eq!(AgAttemptOutcome::SystemFailure as i32, 3);
    }

    #[test]
    fn every_valid_raw_status_converts() {
        for (raw, expected) in [
            (0, AgLifecycleStatus::Ok),
            (1, AgLifecycleStatus::Unavailable),
            (2, AgLifecycleStatus::Conflict),
            (3, AgLifecycleStatus::Internal),
        ] {
            assert_eq!(AgLifecycleStatus::try_from(raw), Ok(expected));
        }

        for (raw, expected) in [
            (0, AgBeginStatus::Ok),
            (1, AgBeginStatus::Unavailable),
            (2, AgBeginStatus::Conflict),
            (3, AgBeginStatus::Internal),
            (10, AgBeginStatus::NotFound),
            (11, AgBeginStatus::Expired),
            (12, AgBeginStatus::AlreadyConsumed),
            (13, AgBeginStatus::BindingMismatch),
            (14, AgBeginStatus::NonceMismatch),
            (15, AgBeginStatus::AttemptsExhausted),
        ] {
            assert_eq!(AgBeginStatus::try_from(raw), Ok(expected));
        }

        for (raw, expected) in [
            (0, AgKeyStatus::Ok),
            (1, AgKeyStatus::Unavailable),
            (2, AgKeyStatus::NotFound),
            (3, AgKeyStatus::InvalidMaterial),
        ] {
            assert_eq!(AgKeyStatus::try_from(raw), Ok(expected));
        }
    }

    #[test]
    fn unknown_raw_statuses_are_rejected() {
        assert_eq!(
            AgLifecycleStatus::try_from(99),
            Err(AgStatus::CallbackFailed)
        );
        assert_eq!(AgBeginStatus::try_from(4), Err(AgStatus::CallbackFailed));
        assert_eq!(AgKeyStatus::try_from(-1), Err(AgStatus::CallbackFailed));
    }
}
