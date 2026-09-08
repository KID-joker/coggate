use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use agentgate_core::{ChallengeService, ServiceError};

use crate::{
    AgKeyCallbacks, AgLifecycleCallbacks, AgObserverCallbacks, AgStatus,
    adapters::{CallbackKeys, CallbackLifecycle, CallbackObserver},
    callbacks::{read_key_callbacks, read_lifecycle_callbacks, read_observer_callbacks},
    catch_status,
};

type CoreService = ChallengeService<CallbackLifecycle, CallbackKeys, CallbackObserver>;

/// Opaque, synchronized challenge-service handle for the C ABI.
#[repr(C)]
pub struct AgService {
    service: Mutex<CoreService>,
    protocol_violation: Arc<AtomicBool>,
}

impl AgService {
    /// Runs one serialized core operation and resolves callback ABI violations.
    #[allow(dead_code)]
    pub(crate) fn call(
        &self,
        operation: impl FnOnce(&mut CoreService) -> Result<(), ServiceError>,
    ) -> AgStatus {
        let mut service = match self.service.lock() {
            Ok(service) => service,
            Err(_) => return AgStatus::InternalError,
        };

        self.protocol_violation.store(false, Ordering::SeqCst);
        let result = operation(&mut service);
        let violated = self.protocol_violation.swap(false, Ordering::SeqCst);
        let status = if violated {
            AgStatus::CallbackFailed
        } else {
            result.map_or_else(AgStatus::from, |()| AgStatus::Ok)
        };
        drop(service);
        status
    }
}

/// Creates a synchronized challenge-service handle from host callback tables.
///
/// The callback tables are copied during this call and may be released after it
/// returns. Their function pointers must remain callable, and each non-null
/// `user_data` pointee must remain valid, host-owned, and host-synchronized for
/// serialized callback calls from arbitrary threads until destruction finishes.
/// Callbacks and release functions must obey their documented borrowing and
/// ownership contracts; they must not unwind, throw, or longjmp across the ABI
/// boundary, or reenter the same service handle.
///
/// On every return after `out` is validated, `*out` is null unless creation
/// succeeds, in which case ownership of exactly one opaque handle is transferred
/// to the caller.
///
/// # Safety
///
/// `out` may be null. Otherwise it must be aligned, valid, and writable for one
/// `*mut AgService` for the duration of this call, and not concurrently accessed.
/// Each callback-table pointer may be null. A non-null pointer must satisfy the
/// complete two-stage read requirements documented by its corresponding table
/// reader: an aligned, initialized, stable readable header, followed—when that
/// header advertises the supported version and size—by one complete aligned,
/// initialized, stable readable callback table containing valid nullable
/// function-pointer representations. Callback and `user_data` lifetime,
/// synchronization, unwind, ownership, and reentrancy requirements are as
/// described above and on the callback-table types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ag_service_create(
    lifecycle: *const AgLifecycleCallbacks,
    keys: *const AgKeyCallbacks,
    observer: *const AgObserverCallbacks,
    out: *mut *mut AgService,
) -> AgStatus {
    catch_status(|| {
        if out.is_null() {
            return AgStatus::InvalidArgument;
        }

        unsafe { out.write(std::ptr::null_mut()) };

        let lifecycle = match unsafe { read_lifecycle_callbacks(lifecycle) } {
            Ok(callbacks) => callbacks,
            Err(status) => return status,
        };
        let keys = match unsafe { read_key_callbacks(keys) } {
            Ok(callbacks) => callbacks,
            Err(status) => return status,
        };
        let observer = match unsafe { read_observer_callbacks(observer) } {
            Ok(callbacks) => callbacks,
            Err(status) => return status,
        };

        let protocol_violation = Arc::new(AtomicBool::new(false));
        // SAFETY: the readers above validated and copied each table. The caller
        // inherits the constructors' documented callback/user_data lifetime,
        // thread-synchronization, unwind, ownership, and reentrancy invariants.
        let lifecycle =
            unsafe { CallbackLifecycle::new(lifecycle, Arc::clone(&protocol_violation)) };
        let keys = unsafe { CallbackKeys::new(keys, Arc::clone(&protocol_violation)) };
        let observer = unsafe { CallbackObserver::new(observer, Arc::clone(&protocol_violation)) };
        let service = Box::new(AgService {
            service: Mutex::new(ChallengeService::with_observer(lifecycle, keys, observer)),
            protocol_violation,
        });

        unsafe { out.write(Box::into_raw(service)) };
        AgStatus::Ok
    })
}

/// Destroys one challenge-service handle.
///
/// # Safety
///
/// `service` must be the exact pointer returned by one successful
/// [`ag_service_create`] call. It must not have been destroyed previously.
/// There must be no concurrent access to the handle or its callbacks, and no
/// access or call may occur through the pointer after this function begins.
/// All callback function pointers and `user_data` pointees must remain valid and
/// host-synchronized until destruction completes. Host destructors, callbacks,
/// and release functions must not unwind, throw, or longjmp across the ABI
/// boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ag_service_destroy(service: *mut AgService) -> AgStatus {
    catch_status(|| {
        if service.is_null() {
            return AgStatus::InvalidArgument;
        }

        drop(unsafe { Box::from_raw(service) });
        AgStatus::Ok
    })
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::c_void,
        mem::size_of,
        panic::{AssertUnwindSafe, catch_unwind},
        ptr,
        sync::atomic::Ordering,
    };

    use agentgate_core::ServiceError;

    use super::{AgService, ag_service_create};
    use crate::{
        AG_ABI_VERSION_1, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks, AgKeyStatus,
        AgLifecycleCallbacks, AgLifecycleStatus, AgStatus,
    };

    unsafe extern "C" fn store(_: *mut c_void, _: AgByteSlice, _: AgByteSlice, _: u32) -> i32 {
        AgLifecycleStatus::Ok as i32
    }

    unsafe extern "C" fn begin(
        _: *mut c_void,
        _: AgByteSlice,
        _: AgByteSlice,
        _: i64,
        _: *mut AgHostBuffer,
        _: *mut AgHostBuffer,
    ) -> i32 {
        AgBeginStatus::Unavailable as i32
    }

    unsafe extern "C" fn finish(_: *mut c_void, _: AgByteSlice, _: i32) -> i32 {
        AgLifecycleStatus::Ok as i32
    }

    unsafe extern "C" fn active(_: *mut c_void, _: *mut AgHostBuffer, _: *mut AgHostBuffer) -> i32 {
        AgKeyStatus::Unavailable as i32
    }

    unsafe extern "C" fn by_id(_: *mut c_void, _: AgByteSlice, _: *mut AgHostBuffer) -> i32 {
        AgKeyStatus::NotFound as i32
    }

    fn service() -> Box<AgService> {
        let lifecycle = AgLifecycleCallbacks {
            struct_size: size_of::<AgLifecycleCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data: ptr::null_mut(),
            store_issued: Some(store),
            begin_attempt: Some(begin),
            finish_attempt: Some(finish),
        };
        let keys = AgKeyCallbacks {
            struct_size: size_of::<AgKeyCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data: ptr::null_mut(),
            active_key: Some(active),
            key_by_id: Some(by_id),
        };
        let mut service = ptr::null_mut();
        assert_eq!(
            unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
            AgStatus::Ok
        );
        unsafe { Box::from_raw(service) }
    }

    #[test]
    fn mutex_poison_maps_to_internal_error_without_invoking_operation() {
        let service = service();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = service.service.lock().expect("initial lock");
            panic!("poison service mutex");
        }));
        assert!(poisoned.is_err());

        let mut invoked = false;
        assert_eq!(
            service.call(|_| {
                invoked = true;
                Ok(())
            }),
            AgStatus::InternalError
        );
        assert!(!invoked);
    }

    #[test]
    fn protocol_violation_is_scoped_to_each_serialized_call() {
        let service = service();

        service.protocol_violation.store(true, Ordering::SeqCst);
        assert_eq!(service.call(|_| Ok(())), AgStatus::Ok);

        let flag = service.protocol_violation.clone();
        assert_eq!(
            service.call(|_| {
                flag.store(true, Ordering::SeqCst);
                Err(ServiceError::InvalidConfiguration)
            }),
            AgStatus::CallbackFailed
        );

        assert_eq!(
            service.call(|_| Err(ServiceError::GenerationFailed)),
            AgStatus::GenerationFailed
        );
        assert_eq!(service.call(|_| Ok(())), AgStatus::Ok);
    }
}
