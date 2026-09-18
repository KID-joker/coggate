use std::{
    ffi::c_void,
    mem::{align_of, offset_of, size_of},
    ptr, slice,
};

use coggate_ffi::{
    AG_ABI_VERSION_1, AgAttemptLimit, AgAttemptOutcome, AgBeginStatus, AgByteSlice,
    AgCallbackHeader, AgHostBuffer, AgKeyCallbacks, AgKeyStatus, AgLifecycleCallbacks,
    AgLifecycleStatus, AgObserverCallbacks, AgOwnedBuffer, AgStatus, ag_abi_version,
    ag_core_version,
};

// Keep the Rust ABI contract pinned to the public C header shipped to consumers.
const HEADER: &str = include_str!("../include/coggate.h");

unsafe extern "C" {
    #[link_name = "ag_abi_version"]
    fn linked_ag_abi_version() -> u32;
    #[link_name = "ag_core_version"]
    fn linked_ag_core_version() -> AgByteSlice;
    #[link_name = "ag_service_create"]
    fn linked_ag_service_create(
        lifecycle: *const AgLifecycleCallbacks,
        keys: *const AgKeyCallbacks,
        observer: *const AgObserverCallbacks,
        out: *mut *mut c_void,
    ) -> AgStatus;
    #[link_name = "ag_service_destroy"]
    fn linked_ag_service_destroy(service: *mut c_void) -> AgStatus;
    #[link_name = "ag_service_issue"]
    fn linked_ag_service_issue(
        service: *mut c_void,
        version: AgByteSlice,
        binding: AgByteSlice,
        attempt_limit: u32,
        out: *mut AgOwnedBuffer,
    ) -> AgStatus;
    #[link_name = "ag_service_verify"]
    fn linked_ag_service_verify(
        service: *mut c_void,
        submission_json: AgByteSlice,
        binding: AgByteSlice,
        out: *mut AgOwnedBuffer,
    ) -> AgStatus;
    #[link_name = "ag_buffer_free"]
    fn linked_ag_buffer_free(buffer: *mut AgOwnedBuffer) -> AgStatus;
}

fn header_integer(name: &str) -> i64 {
    let prefix = format!("#define {name} ");
    let value = HEADER
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing {name} in coggate.h"));
    let value = value
        .strip_prefix("INT32_C(")
        .or_else(|| value.strip_prefix("UINT32_C("))
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(value);
    value
        .parse()
        .unwrap_or_else(|_| panic!("invalid {name} value"))
}

#[test]
fn header_constants_match_every_rust_discriminant() {
    let expected = [
        ("AG_ABI_VERSION_1", i64::from(AG_ABI_VERSION_1)),
        ("AG_STATUS_OK", AgStatus::Ok as i64),
        (
            "AG_STATUS_INVALID_CONFIGURATION",
            AgStatus::InvalidConfiguration as i64,
        ),
        (
            "AG_STATUS_GENERATION_FAILED",
            AgStatus::GenerationFailed as i64,
        ),
        (
            "AG_STATUS_INVALID_CHALLENGE_MATERIAL",
            AgStatus::InvalidChallengeMaterial as i64,
        ),
        (
            "AG_STATUS_INVALID_ANSWER_ENCODING",
            AgStatus::InvalidAnswerEncoding as i64,
        ),
        ("AG_STATUS_ANSWER_MISMATCH", AgStatus::AnswerMismatch as i64),
        (
            "AG_STATUS_UNSUPPORTED_GENERATOR_VERSION",
            AgStatus::UnsupportedGeneratorVersion as i64,
        ),
        ("AG_STATUS_INTERNAL_ERROR", AgStatus::InternalError as i64),
        (
            "AG_STATUS_INVALID_ARGUMENT",
            AgStatus::InvalidArgument as i64,
        ),
        ("AG_STATUS_CALLBACK_FAILED", AgStatus::CallbackFailed as i64),
        ("AG_STATUS_PANIC_CAUGHT", AgStatus::PanicCaught as i64),
        ("AG_LIFECYCLE_STATUS_OK", AgLifecycleStatus::Ok as i64),
        (
            "AG_LIFECYCLE_STATUS_UNAVAILABLE",
            AgLifecycleStatus::Unavailable as i64,
        ),
        (
            "AG_LIFECYCLE_STATUS_CONFLICT",
            AgLifecycleStatus::Conflict as i64,
        ),
        (
            "AG_LIFECYCLE_STATUS_INTERNAL",
            AgLifecycleStatus::Internal as i64,
        ),
        ("AG_BEGIN_STATUS_OK", AgBeginStatus::Ok as i64),
        (
            "AG_BEGIN_STATUS_UNAVAILABLE",
            AgBeginStatus::Unavailable as i64,
        ),
        ("AG_BEGIN_STATUS_CONFLICT", AgBeginStatus::Conflict as i64),
        ("AG_BEGIN_STATUS_INTERNAL", AgBeginStatus::Internal as i64),
        ("AG_BEGIN_STATUS_NOT_FOUND", AgBeginStatus::NotFound as i64),
        ("AG_BEGIN_STATUS_EXPIRED", AgBeginStatus::Expired as i64),
        (
            "AG_BEGIN_STATUS_ALREADY_CONSUMED",
            AgBeginStatus::AlreadyConsumed as i64,
        ),
        (
            "AG_BEGIN_STATUS_BINDING_MISMATCH",
            AgBeginStatus::BindingMismatch as i64,
        ),
        (
            "AG_BEGIN_STATUS_NONCE_MISMATCH",
            AgBeginStatus::NonceMismatch as i64,
        ),
        (
            "AG_BEGIN_STATUS_ATTEMPTS_EXHAUSTED",
            AgBeginStatus::AttemptsExhausted as i64,
        ),
        ("AG_KEY_STATUS_OK", AgKeyStatus::Ok as i64),
        ("AG_KEY_STATUS_UNAVAILABLE", AgKeyStatus::Unavailable as i64),
        ("AG_KEY_STATUS_NOT_FOUND", AgKeyStatus::NotFound as i64),
        (
            "AG_KEY_STATUS_INVALID_MATERIAL",
            AgKeyStatus::InvalidMaterial as i64,
        ),
        (
            "AG_ATTEMPT_OUTCOME_ACCEPTED",
            AgAttemptOutcome::Accepted as i64,
        ),
        (
            "AG_ATTEMPT_OUTCOME_REJECTED",
            AgAttemptOutcome::Rejected as i64,
        ),
        (
            "AG_ATTEMPT_OUTCOME_SYSTEM_FAILURE",
            AgAttemptOutcome::SystemFailure as i64,
        ),
        ("AG_ATTEMPT_LIMIT_ONE", AgAttemptLimit::One as i64),
        ("AG_ATTEMPT_LIMIT_TWO", AgAttemptLimit::Two as i64),
    ];

    for (name, rust_value) in expected {
        assert_eq!(header_integer(name), rust_value, "{name}");
    }
}

#[test]
fn version_exports_are_stable_and_core_version_is_static_utf8() {
    assert_eq!(ag_abi_version(), AG_ABI_VERSION_1);
    let first = ag_core_version();
    let second = ag_core_version();
    assert_eq!((first.data, first.len), (second.data, second.len));
    assert!(!first.data.is_null());
    let bytes = unsafe { slice::from_raw_parts(first.data, first.len) };
    assert_eq!(bytes, env!("CARGO_PKG_VERSION").as_bytes());
    assert!(std::str::from_utf8(bytes).is_ok());
}

#[test]
fn exact_exported_symbol_names_resolve_and_are_safely_callable() {
    let empty_slice = AgByteSlice {
        data: ptr::null(),
        len: 0,
    };
    let mut output = AgOwnedBuffer::empty();
    let mut service = ptr::null_mut();

    // SAFETY: Every call uses the exact public ABI signature. Null service and
    // callback-table pointers are documented, checked invalid inputs; output
    // pointers refer to initialized, aligned, writable local storage.
    unsafe {
        assert_eq!(linked_ag_abi_version(), AG_ABI_VERSION_1);
        let version = linked_ag_core_version();
        assert!(!version.data.is_null());
        assert_eq!(
            slice::from_raw_parts(version.data, version.len),
            env!("CARGO_PKG_VERSION").as_bytes()
        );
        assert_eq!(
            linked_ag_service_create(ptr::null(), ptr::null(), ptr::null(), &mut service),
            AgStatus::CallbackFailed
        );
        assert!(service.is_null());
        assert_eq!(
            linked_ag_service_issue(
                ptr::null_mut(),
                empty_slice,
                empty_slice,
                AgAttemptLimit::One as u32,
                &mut output,
            ),
            AgStatus::InvalidArgument
        );
        assert_eq!(
            linked_ag_service_verify(ptr::null_mut(), empty_slice, empty_slice, &mut output,),
            AgStatus::InvalidArgument
        );
        assert_eq!(
            linked_ag_service_destroy(ptr::null_mut()),
            AgStatus::InvalidArgument
        );
        assert_eq!(linked_ag_buffer_free(&mut output), AgStatus::Ok);
    }
}

#[test]
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn public_c_struct_layouts_are_exact_on_supported_64_bit_targets() {
    assert_eq!(
        (size_of::<AgByteSlice>(), align_of::<AgByteSlice>()),
        (16, 8)
    );
    assert_eq!(offset_of!(AgByteSlice, data), 0);
    assert_eq!(offset_of!(AgByteSlice, len), 8);

    assert_eq!(
        (size_of::<AgOwnedBuffer>(), align_of::<AgOwnedBuffer>()),
        (24, 8)
    );
    assert_eq!(offset_of!(AgOwnedBuffer, data), 0);
    assert_eq!(offset_of!(AgOwnedBuffer, len), 8);
    assert_eq!(offset_of!(AgOwnedBuffer, capacity), 16);

    assert_eq!(
        (size_of::<AgHostBuffer>(), align_of::<AgHostBuffer>()),
        (32, 8)
    );
    assert_eq!(offset_of!(AgHostBuffer, data), 0);
    assert_eq!(offset_of!(AgHostBuffer, len), 8);
    assert_eq!(offset_of!(AgHostBuffer, release_data), 16);
    assert_eq!(offset_of!(AgHostBuffer, release), 24);

    assert_eq!(
        (
            size_of::<AgCallbackHeader>(),
            align_of::<AgCallbackHeader>()
        ),
        (8, 4)
    );
    assert_eq!(offset_of!(AgCallbackHeader, struct_size), 0);
    assert_eq!(offset_of!(AgCallbackHeader, abi_version), 4);

    assert_eq!(
        (
            size_of::<AgLifecycleCallbacks>(),
            align_of::<AgLifecycleCallbacks>()
        ),
        (40, 8)
    );
    assert_eq!(offset_of!(AgLifecycleCallbacks, struct_size), 0);
    assert_eq!(offset_of!(AgLifecycleCallbacks, abi_version), 4);
    assert_eq!(offset_of!(AgLifecycleCallbacks, user_data), 8);
    assert_eq!(offset_of!(AgLifecycleCallbacks, store_issued), 16);
    assert_eq!(offset_of!(AgLifecycleCallbacks, begin_attempt), 24);
    assert_eq!(offset_of!(AgLifecycleCallbacks, finish_attempt), 32);

    assert_eq!(
        (size_of::<AgKeyCallbacks>(), align_of::<AgKeyCallbacks>()),
        (32, 8)
    );
    assert_eq!(offset_of!(AgKeyCallbacks, struct_size), 0);
    assert_eq!(offset_of!(AgKeyCallbacks, abi_version), 4);
    assert_eq!(offset_of!(AgKeyCallbacks, user_data), 8);
    assert_eq!(offset_of!(AgKeyCallbacks, active_key), 16);
    assert_eq!(offset_of!(AgKeyCallbacks, key_by_id), 24);

    assert_eq!(
        (
            size_of::<AgObserverCallbacks>(),
            align_of::<AgObserverCallbacks>()
        ),
        (24, 8)
    );
    assert_eq!(offset_of!(AgObserverCallbacks, struct_size), 0);
    assert_eq!(offset_of!(AgObserverCallbacks, abi_version), 4);
    assert_eq!(offset_of!(AgObserverCallbacks, user_data), 8);
    assert_eq!(offset_of!(AgObserverCallbacks, observe), 16);
}
