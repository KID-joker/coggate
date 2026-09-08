use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use agentgate_core::{AttemptLimit, ChallengeService, IssueRequest, ServiceError, VerifyRequest};

use crate::{
    AgByteSlice, AgKeyCallbacks, AgLifecycleCallbacks, AgObserverCallbacks, AgOwnedBuffer,
    AgStatus,
    adapters::{CallbackKeys, CallbackLifecycle, CallbackObserver},
    callbacks::{read_key_callbacks, read_lifecycle_callbacks, read_observer_callbacks},
    catch_status,
    json::{parse_submission, serialize_outcome},
};

type CoreService = ChallengeService<CallbackLifecycle, CallbackKeys, CallbackObserver>;

/// Closed challenge verification-attempt budgets exposed as ABI constants.
///
/// Functions accept the underlying `u32` rather than this enum so that foreign
/// callers cannot create an invalid Rust enum value.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgAttemptLimit {
    One = 1,
    Two = 2,
}

/// Opaque, synchronized challenge-service handle for the C ABI.
#[repr(C)]
pub struct AgService {
    service: Mutex<CoreService>,
    protocol_violation: Arc<AtomicBool>,
}

impl AgService {
    /// Runs one serialized core operation and resolves callback ABI violations.
    pub(crate) fn call<T>(
        &self,
        operation: impl FnOnce(&mut CoreService) -> Result<T, ServiceError>,
    ) -> Result<T, AgStatus> {
        let mut service = match self.service.lock() {
            Ok(service) => service,
            Err(_) => return Err(AgStatus::InternalError),
        };

        self.protocol_violation.store(false, Ordering::SeqCst);
        let result = operation(&mut service);
        let violated = self.protocol_violation.swap(false, Ordering::SeqCst);
        let result = if violated {
            Err(AgStatus::CallbackFailed)
        } else {
            result.map_err(AgStatus::from)
        };
        drop(service);
        result
    }
}

/// Issues and durably stores one challenge, returning its public JSON form.
///
/// Calls through the same service handle are serialized. Host callbacks must
/// not reenter that handle. `version` and `binding` are copied synchronously;
/// their pointers are not retained. `version` must be strict UTF-8, `binding`
/// must contain 1 through 256 bytes, and `attempt_limit` must be `1` or `2`.
///
/// `out` must contain the canonical empty buffer at entry. This prevents an
/// existing allocation from being overwritten or leaked. Once `out` has been
/// validated, it remains canonical empty on every failure. On success ownership
/// of its allocation transfers to the caller for exactly one [`crate::ag_buffer_free`]
/// call. The public result is not published until durable storage reports
/// success.
///
/// # Safety
///
/// `service` may be null. Otherwise it must be the exact live pointer returned
/// by [`ag_service_create`], with no concurrent destruction. Calls may be made
/// concurrently through that handle subject to serialization above. Each
/// non-null slice pointer must be readable for its declared length and not
/// concurrently mutated during this call; null is valid only with length zero.
/// `out` may be null. Otherwise it must be aligned, valid, and writable for one
/// [`AgOwnedBuffer`] and must not be concurrently accessed.
/// The caller must also uphold all callback lifetime, synchronization,
/// ownership, unwind, and reentrancy requirements from service creation.
/// Runtime checks cannot establish pointer provenance, allocation ownership,
/// exact handle identity, or the absence of concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ag_service_issue(
    service: *mut AgService,
    version: AgByteSlice,
    binding: AgByteSlice,
    attempt_limit: u32,
    out: *mut AgOwnedBuffer,
) -> AgStatus {
    catch_status(|| {
        let Some(out) = (unsafe { out.as_mut() }) else {
            return AgStatus::InvalidArgument;
        };
        if !out.data.is_null() || out.len != 0 || out.capacity != 0 {
            return AgStatus::InvalidArgument;
        }
        let Some(service) = (unsafe { service.as_ref() }) else {
            return AgStatus::InvalidArgument;
        };

        let version = match unsafe { version.copy_bytes() } {
            Ok(version) => version,
            Err(status) => return status,
        };
        let binding = match unsafe { binding.copy_bytes() } {
            Ok(binding) => binding,
            Err(status) => return status,
        };
        let version = match String::from_utf8(version) {
            Ok(version) => version,
            Err(_) => return AgStatus::InvalidArgument,
        };
        let attempt_limit = match attempt_limit {
            x if x == AgAttemptLimit::One as u32 => AttemptLimit::One,
            x if x == AgAttemptLimit::Two as u32 => AttemptLimit::Two,
            _ => return AgStatus::InvalidArgument,
        };
        let request = match IssueRequest::new(&version, &binding, attempt_limit) {
            Ok(request) => request,
            Err(error) => return AgStatus::from(error),
        };
        let public = match service.call(|service| service.issue_challenge(request)) {
            Ok(public) => public,
            Err(status) => return status,
        };
        let json = match serde_json::to_vec(&public) {
            Ok(json) => json,
            Err(_) => return AgStatus::InternalError,
        };

        *out = AgOwnedBuffer::from_vec(json);
        AgStatus::Ok
    })
}

/// Verifies one submission through the fail-closed lifecycle protocol.
///
/// Calls through the same service handle are serialized. Host callbacks must
/// not reenter that handle. `submission_json` and `binding` are copied
/// synchronously and their pointers are not retained. `submission_json` must be
/// strict submission JSON with no unknown fields; `binding` must contain 1
/// through 256 bytes.
///
/// `out` must contain the canonical empty buffer at entry. This prevents an
/// existing allocation from being overwritten or leaked. Once `out` has been
/// validated, it remains canonical empty on every failure. Only successful
/// verification outcomes are serialized and published. On success ownership
/// of the allocation transfers to the caller for exactly one
/// [`crate::ag_buffer_free`] call.
///
/// # Safety
///
/// `service` may be null. Otherwise it must be the exact live pointer returned
/// by [`ag_service_create`], with no concurrent destruction. Calls may be made
/// concurrently through that handle subject to serialization above. Each
/// non-null slice pointer must be readable for its declared length and not
/// concurrently mutated during this call; null is valid only with length zero.
/// `out` may be null. Otherwise it must be aligned, valid, and writable for one
/// [`AgOwnedBuffer`] and must not be concurrently accessed.
/// The caller must also uphold all callback lifetime, synchronization,
/// ownership, unwind, and reentrancy requirements from service creation.
/// Runtime checks cannot establish pointer provenance, allocation ownership,
/// exact handle identity, or the absence of concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ag_service_verify(
    service: *mut AgService,
    submission_json: AgByteSlice,
    binding: AgByteSlice,
    out: *mut AgOwnedBuffer,
) -> AgStatus {
    catch_status(|| {
        let Some(out) = (unsafe { out.as_mut() }) else {
            return AgStatus::InvalidArgument;
        };
        if !out.data.is_null() || out.len != 0 || out.capacity != 0 {
            return AgStatus::InvalidArgument;
        }
        let Some(service) = (unsafe { service.as_ref() }) else {
            return AgStatus::InvalidArgument;
        };

        let submission_json = match unsafe { submission_json.copy_bytes() } {
            Ok(submission_json) => submission_json,
            Err(status) => return status,
        };
        let binding = match unsafe { binding.copy_bytes() } {
            Ok(binding) => binding,
            Err(status) => return status,
        };
        let submission = match parse_submission(&submission_json) {
            Ok(submission) => submission,
            Err(()) => return AgStatus::InvalidArgument,
        };
        let request = match VerifyRequest::new(&submission, &binding) {
            Ok(request) => request,
            Err(error) => return AgStatus::from(error),
        };
        let outcome = match service.call(|service| service.verify_submission(request)) {
            Ok(outcome) => outcome,
            Err(status) => return status,
        };
        let json = match serialize_outcome(outcome) {
            Ok(json) => json,
            Err(()) => return AgStatus::InternalError,
        };

        *out = AgOwnedBuffer::from_vec(json);
        AgStatus::Ok
    })
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
            Err(AgStatus::InternalError)
        );
        assert!(!invoked);
    }

    #[test]
    fn protocol_violation_is_scoped_to_each_serialized_call() {
        let service = service();

        service.protocol_violation.store(true, Ordering::SeqCst);
        assert_eq!(service.call(|_| Ok(())), Ok(()));

        let flag = service.protocol_violation.clone();
        assert_eq!(
            service.call(|_| {
                flag.store(true, Ordering::SeqCst);
                Err::<(), _>(ServiceError::InvalidConfiguration)
            }),
            Err(AgStatus::CallbackFailed)
        );

        assert_eq!(
            service.call(|_| Err::<(), _>(ServiceError::GenerationFailed)),
            Err(AgStatus::GenerationFailed)
        );
        assert_eq!(service.call(|_| Ok(())), Ok(()));
    }

    #[test]
    fn successful_value_is_discarded_when_callback_protocol_was_violated() {
        let service = service();
        let flag = service.protocol_violation.clone();

        assert_eq!(
            service.call(|_| {
                flag.store(true, Ordering::SeqCst);
                Ok(42_u32)
            }),
            Err(AgStatus::CallbackFailed)
        );
    }
}
