use std::{
    ffi::c_void,
    mem::size_of,
    ptr, slice,
    sync::{
        Mutex,
        atomic::{AtomicI32, AtomicUsize, Ordering},
    },
};

use agentgate_contracts::{PrivateChallengeMaterial, PublicChallenge};
use agentgate_ffi::{
    AG_ABI_VERSION_1, AgAttemptLimit, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks,
    AgKeyStatus, AgLifecycleCallbacks, AgLifecycleStatus, AgOwnedBuffer, AgService, AgStatus,
    ag_buffer_free, ag_service_create, ag_service_destroy, ag_service_issue,
};

#[derive(Clone, Copy)]
#[repr(i32)]
enum ActiveBehavior {
    Valid = 0,
    EmptyId = 1,
    InvalidUtf8Id = 2,
    ShortKey = 3,
}

struct StoreRecord {
    private: PrivateChallengeMaterial,
    binding: Vec<u8>,
    attempt_limit: u32,
}

struct Fixture {
    active_status: AtomicI32,
    active_behavior: AtomicI32,
    store_status: AtomicI32,
    store_calls: AtomicUsize,
    stores: Mutex<Vec<StoreRecord>>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            active_status: AtomicI32::new(AgKeyStatus::Ok as i32),
            active_behavior: AtomicI32::new(ActiveBehavior::Valid as i32),
            store_status: AtomicI32::new(AgLifecycleStatus::Ok as i32),
            store_calls: AtomicUsize::new(0),
            stores: Mutex::new(Vec::new()),
        }
    }
}

struct Harness {
    service: *mut AgService,
    fixture: Box<Fixture>,
}

impl Harness {
    fn new() -> Self {
        let mut fixture = Box::new(Fixture::new());
        let user_data = (&mut *fixture as *mut Fixture).cast::<c_void>();
        let lifecycle = AgLifecycleCallbacks {
            struct_size: size_of::<AgLifecycleCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data,
            store_issued: Some(store_issued),
            begin_attempt: Some(begin_attempt),
            finish_attempt: Some(finish_attempt),
        };
        let keys = AgKeyCallbacks {
            struct_size: size_of::<AgKeyCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data,
            active_key: Some(active_key),
            key_by_id: Some(key_by_id),
        };
        let mut service = ptr::null_mut();
        assert_eq!(
            unsafe { ag_service_create(&lifecycle, &keys, ptr::null(), &mut service) },
            AgStatus::Ok
        );
        Self { service, fixture }
    }

    fn issue(
        &self,
        version: &[u8],
        binding: &[u8],
        limit: u32,
        out: &mut AgOwnedBuffer,
    ) -> AgStatus {
        unsafe {
            ag_service_issue(
                self.service,
                borrowed(version),
                borrowed(binding),
                limit,
                out,
            )
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        assert_eq!(unsafe { ag_service_destroy(self.service) }, AgStatus::Ok);
    }
}

unsafe extern "C" fn release_boxed(_: *mut c_void, data: *mut u8, len: usize) {
    let raw = ptr::slice_from_raw_parts_mut(data, len);
    drop(unsafe { Box::from_raw(raw) });
}

unsafe fn write_host_buffer(out: *mut AgHostBuffer, bytes: Vec<u8>) {
    let mut bytes = bytes.into_boxed_slice();
    let buffer = AgHostBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
        release_data: ptr::null_mut(),
        release: Some(release_boxed),
    };
    std::mem::forget(bytes);
    unsafe { out.write(buffer) };
}

unsafe fn copied(value: AgByteSlice) -> Vec<u8> {
    unsafe { slice::from_raw_parts(value.data, value.len) }.to_vec()
}

unsafe extern "C" fn store_issued(
    user_data: *mut c_void,
    private_json: AgByteSlice,
    binding: AgByteSlice,
    attempt_limit: u32,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    fixture.store_calls.fetch_add(1, Ordering::SeqCst);
    let private =
        serde_json::from_slice(&unsafe { copied(private_json) }).expect("valid private JSON");
    fixture
        .stores
        .lock()
        .expect("stores lock")
        .push(StoreRecord {
            private,
            binding: unsafe { copied(binding) },
            attempt_limit,
        });
    fixture.store_status.load(Ordering::SeqCst)
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

unsafe extern "C" fn active_key(
    user_data: *mut c_void,
    key_id_out: *mut AgHostBuffer,
    key_out: *mut AgHostBuffer,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    let status = fixture.active_status.load(Ordering::SeqCst);
    if status != AgKeyStatus::Ok as i32 {
        return status;
    }

    let behavior = fixture.active_behavior.load(Ordering::SeqCst);
    let key_id = match behavior {
        x if x == ActiveBehavior::EmptyId as i32 => Vec::new(),
        x if x == ActiveBehavior::InvalidUtf8Id as i32 => vec![0xff],
        _ => b"active-key".to_vec(),
    };
    let key = if behavior == ActiveBehavior::ShortKey as i32 {
        vec![7; 31]
    } else {
        vec![7; 32]
    };
    unsafe {
        write_host_buffer(key_id_out, key_id);
        write_host_buffer(key_out, key);
    }
    AgKeyStatus::Ok as i32
}

unsafe extern "C" fn key_by_id(_: *mut c_void, _: AgByteSlice, _: *mut AgHostBuffer) -> i32 {
    AgKeyStatus::NotFound as i32
}

fn borrowed(bytes: &[u8]) -> AgByteSlice {
    AgByteSlice {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}

fn canonical_empty(buffer: &AgOwnedBuffer) -> bool {
    buffer.data.is_null() && buffer.len == 0 && buffer.capacity == 0
}

fn parse_and_free(out: &mut AgOwnedBuffer) -> PublicChallenge {
    let public = serde_json::from_slice(unsafe { slice::from_raw_parts(out.data, out.len) })
        .expect("valid public challenge JSON");
    assert_eq!(unsafe { ag_buffer_free(out) }, AgStatus::Ok);
    public
}

#[test]
fn successful_issue_returns_public_json_only_after_private_storage() {
    let harness = Harness::new();
    let mut out = AgOwnedBuffer::empty();

    assert_eq!(
        harness.issue(
            b"1.0",
            b"tenant-binding",
            AgAttemptLimit::Two as u32,
            &mut out
        ),
        AgStatus::Ok
    );
    assert_eq!(harness.fixture.store_calls.load(Ordering::SeqCst), 1);
    let public = parse_and_free(&mut out);
    assert_eq!(public.generator_version, "1.0");

    let stores = harness.fixture.stores.lock().expect("stores lock");
    assert_eq!(stores.len(), 1);
    assert_eq!(stores[0].binding, b"tenant-binding");
    assert_eq!(stores[0].attempt_limit, 2);
    assert_eq!(stores[0].private.challenge_id, public.challenge_id);
    assert_eq!(stores[0].private.nonce, public.nonce);
    assert_eq!(
        stores[0].private.generator_version,
        public.generator_version
    );
}

#[test]
fn attempt_limit_discriminants_and_callback_values_are_pinned() {
    assert_eq!(AgAttemptLimit::One as u32, 1);
    assert_eq!(AgAttemptLimit::Two as u32, 2);

    for (limit, expected) in [(AgAttemptLimit::One, 1), (AgAttemptLimit::Two, 2)] {
        let harness = Harness::new();
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            harness.issue(b"1.0", b"b", limit as u32, &mut out),
            AgStatus::Ok
        );
        assert_eq!(
            harness.fixture.stores.lock().expect("stores lock")[0].attempt_limit,
            expected
        );
        assert_eq!(unsafe { ag_buffer_free(&mut out) }, AgStatus::Ok);
    }
}

#[test]
fn null_pointers_and_nonempty_output_are_rejected_without_overwrite() {
    let harness = Harness::new();
    let mut empty = AgOwnedBuffer::empty();
    assert_eq!(
        unsafe {
            ag_service_issue(
                ptr::null_mut(),
                borrowed(b"1.0"),
                borrowed(b"b"),
                1,
                &mut empty,
            )
        },
        AgStatus::InvalidArgument
    );
    assert!(canonical_empty(&empty));
    assert_eq!(
        unsafe {
            ag_service_issue(
                harness.service,
                borrowed(b"1.0"),
                borrowed(b"b"),
                1,
                ptr::null_mut(),
            )
        },
        AgStatus::InvalidArgument
    );

    let mut occupied = AgOwnedBuffer::from_vec(b"caller-owned".to_vec());
    let before = (occupied.data, occupied.len, occupied.capacity);
    assert_eq!(
        harness.issue(b"1.0", b"b", 1, &mut occupied),
        AgStatus::InvalidArgument
    );
    assert_eq!((occupied.data, occupied.len, occupied.capacity), before);
    assert_eq!(unsafe { ag_buffer_free(&mut occupied) }, AgStatus::Ok);
}

#[test]
fn invalid_slices_utf8_limits_bindings_and_versions_map_exactly() {
    let harness = Harness::new();
    let cases = [
        (
            AgByteSlice {
                data: ptr::null(),
                len: 1,
            },
            borrowed(b"b"),
            1,
            AgStatus::InvalidArgument,
        ),
        (
            borrowed(b"1.0"),
            AgByteSlice {
                data: ptr::null(),
                len: 1,
            },
            1,
            AgStatus::InvalidArgument,
        ),
        (
            borrowed(&[0xff]),
            borrowed(b"b"),
            1,
            AgStatus::InvalidArgument,
        ),
        (
            borrowed(b"1.0"),
            borrowed(b""),
            1,
            AgStatus::InvalidConfiguration,
        ),
        (
            borrowed(b"1.0"),
            borrowed(&[b'x'; 257]),
            1,
            AgStatus::InvalidConfiguration,
        ),
        (
            borrowed(b"1.0"),
            borrowed(b"b"),
            0,
            AgStatus::InvalidArgument,
        ),
        (
            borrowed(b"1.0"),
            borrowed(b"b"),
            3,
            AgStatus::InvalidArgument,
        ),
        (
            borrowed(b"2.0"),
            borrowed(b"b"),
            1,
            AgStatus::UnsupportedGeneratorVersion,
        ),
        (
            borrowed(b"1.00"),
            borrowed(b"b"),
            1,
            AgStatus::UnsupportedGeneratorVersion,
        ),
    ];

    for (version, binding, limit, expected) in cases {
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            unsafe { ag_service_issue(harness.service, version, binding, limit, &mut out) },
            expected
        );
        assert!(canonical_empty(&out));
    }
    assert_eq!(harness.fixture.store_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn active_key_known_errors_and_protocol_violations_map_exactly() {
    for (raw, expected) in [
        (AgKeyStatus::Unavailable as i32, AgStatus::InternalError),
        (AgKeyStatus::NotFound as i32, AgStatus::InternalError),
        (
            AgKeyStatus::InvalidMaterial as i32,
            AgStatus::InvalidConfiguration,
        ),
        (77, AgStatus::CallbackFailed),
    ] {
        let harness = Harness::new();
        harness.fixture.active_status.store(raw, Ordering::SeqCst);
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(harness.issue(b"1.0", b"b", 1, &mut out), expected);
        assert!(canonical_empty(&out));
    }

    for behavior in [
        ActiveBehavior::EmptyId,
        ActiveBehavior::InvalidUtf8Id,
        ActiveBehavior::ShortKey,
    ] {
        let harness = Harness::new();
        harness
            .fixture
            .active_behavior
            .store(behavior as i32, Ordering::SeqCst);
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            harness.issue(b"1.0", b"b", 1, &mut out),
            AgStatus::CallbackFailed
        );
        assert!(canonical_empty(&out));
    }
}

#[test]
fn store_failures_are_single_shot_and_publish_no_output() {
    for raw in [
        AgLifecycleStatus::Unavailable as i32,
        AgLifecycleStatus::Conflict as i32,
        AgLifecycleStatus::Internal as i32,
    ] {
        let harness = Harness::new();
        harness.fixture.store_status.store(raw, Ordering::SeqCst);
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            harness.issue(b"1.0", b"b", 1, &mut out),
            AgStatus::InternalError
        );
        assert_eq!(harness.fixture.store_calls.load(Ordering::SeqCst), 1);
        assert!(canonical_empty(&out));
    }

    let harness = Harness::new();
    harness.fixture.store_status.store(99, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();
    assert_eq!(
        harness.issue(b"1.0", b"b", 1, &mut out),
        AgStatus::CallbackFailed
    );
    assert_eq!(harness.fixture.store_calls.load(Ordering::SeqCst), 1);
    assert!(canonical_empty(&out));
}

#[test]
fn failure_surfaces_do_not_expose_input_sentinels() {
    let harness = Harness::new();
    harness
        .fixture
        .active_status
        .store(AgKeyStatus::Unavailable as i32, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();
    let status = harness.issue(
        b"unsupported-version-sentinel",
        b"binding-secret-sentinel",
        1,
        &mut out,
    );
    assert_eq!(status, AgStatus::UnsupportedGeneratorVersion);
    assert!(canonical_empty(&out));
    let debug = format!("{status:?}");
    assert!(!debug.contains("unsupported-version-sentinel"));
    assert!(!debug.contains("binding-secret-sentinel"));
}
