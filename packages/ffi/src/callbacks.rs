use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use crate::{AG_ABI_VERSION_1, AgByteSlice, AgHostBuffer, AgStatus};

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
pub enum AgAttemptOutcome {
    Accepted = 1,
    Rejected = 2,
    SystemFailure = 3,
}

pub type AgStoreIssuedCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    private_json: AgByteSlice,
    binding: AgByteSlice,
    attempt_limit: u32,
) -> i32;

pub type AgBeginAttemptCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    identity_json: AgByteSlice,
    binding: AgByteSlice,
    server_time: i64,
    material_out: *mut AgHostBuffer,
    token_out: *mut AgHostBuffer,
) -> i32;

pub type AgFinishAttemptCallback =
    unsafe extern "C" fn(user_data: *mut c_void, token: AgByteSlice, outcome: i32) -> i32;

pub type AgActiveKeyCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    key_id_out: *mut AgHostBuffer,
    key_out: *mut AgHostBuffer,
) -> i32;

pub type AgKeyByIdCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    key_id: AgByteSlice,
    key_out: *mut AgHostBuffer,
) -> i32;

pub type AgObserveCallback = unsafe extern "C" fn(user_data: *mut c_void, event_json: AgByteSlice);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgCallbackHeader {
    pub struct_size: u32,
    pub abi_version: u32,
}

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AgKeyCallbacks {
    pub struct_size: u32,
    pub abi_version: u32,
    pub user_data: *mut c_void,
    pub active_key: Option<AgActiveKeyCallback>,
    pub key_by_id: Option<AgKeyByIdCallback>,
}

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
/// `table` must be null or point to a properly aligned, initialized
/// [`AgCallbackHeader`] that is valid to read. If that header advertises the
/// current ABI version and a sufficient `struct_size`, the pointer must also be
/// valid to read a complete [`AgLifecycleCallbacks`] value.
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
/// `table` must be null or point to a properly aligned, initialized
/// [`AgCallbackHeader`] that is valid to read. If that header advertises the
/// current ABI version and a sufficient `struct_size`, the pointer must also be
/// valid to read a complete [`AgKeyCallbacks`] value.
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
/// `table` may be null. Otherwise it must point to a properly aligned,
/// initialized [`AgCallbackHeader`] that is valid to read. If that header
/// advertises the current ABI version and a sufficient `struct_size`, the
/// pointer must also be valid to read a complete [`AgObserverCallbacks`] value.
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
