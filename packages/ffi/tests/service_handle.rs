use std::{ffi::c_void, mem::size_of, ptr};

use agentgate_ffi::{
    AG_ABI_VERSION_1, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks, AgKeyStatus,
    AgLifecycleCallbacks, AgLifecycleStatus, AgObserverCallbacks, AgService, AgStatus,
    ag_service_create, ag_service_destroy,
};

unsafe extern "C" fn store_issued(_: *mut c_void, _: AgByteSlice, _: AgByteSlice, _: u32) -> i32 {
    AgLifecycleStatus::Ok as i32
}

unsafe extern "C" fn begin_attempt(
    _: *mut c_void,
    _: AgByteSlice,
    _: AgByteSlice,
    _: i64,
    _: *mut AgHostBuffer,
    _: *mut AgHostBuffer,
) -> i32 {
    AgBeginStatus::Unavailable as i32
}

unsafe extern "C" fn finish_attempt(_: *mut c_void, _: AgByteSlice, _: i32) -> i32 {
    AgLifecycleStatus::Ok as i32
}

unsafe extern "C" fn active_key(_: *mut c_void, _: *mut AgHostBuffer, _: *mut AgHostBuffer) -> i32 {
    AgKeyStatus::Unavailable as i32
}

unsafe extern "C" fn key_by_id(_: *mut c_void, _: AgByteSlice, _: *mut AgHostBuffer) -> i32 {
    AgKeyStatus::NotFound as i32
}

unsafe extern "C" fn observe(_: *mut c_void, _: AgByteSlice) {}

fn lifecycle_callbacks() -> AgLifecycleCallbacks {
    AgLifecycleCallbacks {
        struct_size: size_of::<AgLifecycleCallbacks>() as u32,
        abi_version: AG_ABI_VERSION_1,
        user_data: ptr::null_mut(),
        store_issued: Some(store_issued),
        begin_attempt: Some(begin_attempt),
        finish_attempt: Some(finish_attempt),
    }
}

fn key_callbacks() -> AgKeyCallbacks {
    AgKeyCallbacks {
        struct_size: size_of::<AgKeyCallbacks>() as u32,
        abi_version: AG_ABI_VERSION_1,
        user_data: ptr::null_mut(),
        active_key: Some(active_key),
        key_by_id: Some(key_by_id),
    }
}

fn observer_callbacks() -> AgObserverCallbacks {
    AgObserverCallbacks {
        struct_size: size_of::<AgObserverCallbacks>() as u32,
        abi_version: AG_ABI_VERSION_1,
        user_data: ptr::null_mut(),
        observe: Some(observe),
    }
}

fn sentinel() -> *mut AgService {
    ptr::dangling_mut::<AgService>()
}

#[test]
fn service_handle_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AgService>();
}

#[test]
fn valid_required_callbacks_create_and_destroy_a_handle() {
    let lifecycle = lifecycle_callbacks();
    let keys = key_callbacks();
    let mut service = ptr::null_mut();

    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
        AgStatus::Ok
    );
    assert!(!service.is_null());
    assert_eq!(unsafe { ag_service_destroy(service) }, AgStatus::Ok);
}

#[test]
fn valid_observer_is_accepted() {
    let lifecycle = lifecycle_callbacks();
    let keys = key_callbacks();
    let observer = observer_callbacks();
    let mut service = ptr::null_mut();

    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, &observer, &mut service) },
        AgStatus::Ok
    );
    assert!(!service.is_null());
    assert_eq!(unsafe { ag_service_destroy(service) }, AgStatus::Ok);
}

#[test]
fn null_output_is_invalid_argument() {
    let lifecycle = lifecycle_callbacks();
    let keys = key_callbacks();

    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), ptr::null_mut()) },
        AgStatus::InvalidArgument
    );
}

#[test]
fn missing_required_tables_fail_and_clear_output() {
    let lifecycle = lifecycle_callbacks();
    let keys = key_callbacks();

    let mut service = sentinel();
    assert_eq!(
        unsafe { ag_service_create(ptr::null(), &keys, ptr::null(), &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());

    service = sentinel();
    assert_eq!(
        unsafe { ag_service_create(&lifecycle, ptr::null(), ptr::null(), &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());
}

#[test]
fn missing_required_callbacks_fail_and_clear_output() {
    let mut lifecycle = lifecycle_callbacks();
    lifecycle.finish_attempt = None;
    let keys = key_callbacks();
    let mut service = sentinel();

    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());

    let lifecycle = lifecycle_callbacks();
    let mut keys = key_callbacks();
    keys.active_key = None;
    service = sentinel();
    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());
}

#[test]
fn wrong_version_and_short_table_fail_and_clear_output() {
    let mut lifecycle = lifecycle_callbacks();
    lifecycle.abi_version += 1;
    let keys = key_callbacks();
    let mut service = sentinel();

    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());

    let lifecycle = lifecycle_callbacks();
    let mut keys = key_callbacks();
    keys.struct_size -= 1;
    service = sentinel();
    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());
}

#[test]
fn invalid_nonnull_observer_fails_and_clears_output() {
    let lifecycle = lifecycle_callbacks();
    let keys = key_callbacks();
    let mut observer = observer_callbacks();
    observer.observe = None;
    let mut service = sentinel();

    assert_eq!(
        unsafe { ag_service_create(&lifecycle, &keys, &observer, &mut service) },
        AgStatus::CallbackFailed
    );
    assert!(service.is_null());
}

#[test]
fn null_destroy_is_invalid_argument() {
    assert_eq!(
        unsafe { ag_service_destroy(ptr::null_mut()) },
        AgStatus::InvalidArgument
    );
}
