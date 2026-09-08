use std::{
    ffi::c_void,
    mem::size_of,
    ptr, slice,
    sync::{
        Mutex,
        atomic::{AtomicI32, AtomicUsize, Ordering},
    },
};

use agentgate_contracts::{AnswerEncoding, PrivateChallengeMaterial};
use agentgate_core::{MacContext, compute_answer_mac};
use agentgate_ffi::{
    AG_ABI_VERSION_1, AgAttemptOutcome, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks,
    AgKeyStatus, AgLifecycleCallbacks, AgLifecycleStatus, AgOwnedBuffer, AgService, AgStatus,
    ag_buffer_free, ag_service_create, ag_service_destroy, ag_service_verify,
};

const CHALLENGE_ID: &str = "Y2hhbGxlbmdlLTEyMzQ1Ng";
const NONCE: &str = "bm9uY2UtMTIzNDU2Nzg5MA";
const ANSWER: &str = "YQ";
const KEY_ID: &str = "key-old";
const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const BINDING: &[u8] = b"tenant-binding";

struct Fixture {
    begin_status: AtomicI32,
    begin_calls: AtomicUsize,
    finish_status: AtomicI32,
    finish_calls: AtomicUsize,
    finish_outcomes: Mutex<Vec<i32>>,
    key_status: AtomicI32,
    key_calls: AtomicUsize,
    material_json: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let context = MacContext {
            challenge_id: CHALLENGE_ID.to_owned(),
            generator_version: "1.0".to_owned(),
            nonce: NONCE.to_owned(),
            issued_at: 1_788_062_400,
            expires_at: 1_788_062_408,
            mac_key_id: KEY_ID.to_owned(),
            answer_encoding: AnswerEncoding::Base64Url,
        };
        let material = PrivateChallengeMaterial {
            challenge_id: context.challenge_id.clone(),
            generator_version: context.generator_version.clone(),
            nonce: context.nonce.clone(),
            issued_at: context.issued_at,
            expires_at: context.expires_at,
            mac_key_id: context.mac_key_id.clone(),
            answer_mac: encode_hex(&compute_answer_mac(KEY, &context, ANSWER).unwrap()),
            answer_encoding: context.answer_encoding,
        };
        Self {
            begin_status: AtomicI32::new(AgBeginStatus::Ok as i32),
            begin_calls: AtomicUsize::new(0),
            finish_status: AtomicI32::new(AgLifecycleStatus::Ok as i32),
            finish_calls: AtomicUsize::new(0),
            finish_outcomes: Mutex::new(Vec::new()),
            key_status: AtomicI32::new(AgKeyStatus::Ok as i32),
            key_calls: AtomicUsize::new(0),
            material_json: serde_json::to_vec(&material).unwrap(),
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
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

    fn verify(&self, submission: &[u8], binding: AgByteSlice, out: &mut AgOwnedBuffer) -> AgStatus {
        unsafe { ag_service_verify(self.service, borrowed(submission), binding, out) }
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

unsafe extern "C" fn store_issued(_: *mut c_void, _: AgByteSlice, _: AgByteSlice, _: u32) -> i32 {
    unreachable!("verification does not store")
}

unsafe extern "C" fn begin_attempt(
    user_data: *mut c_void,
    identity_json: AgByteSlice,
    binding: AgByteSlice,
    _: i64,
    material_out: *mut AgHostBuffer,
    token_out: *mut AgHostBuffer,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    fixture.begin_calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        unsafe { copied(identity_json) },
        format!(r#"{{"challenge_id":"{CHALLENGE_ID}","nonce":"{NONCE}"}}"#).as_bytes()
    );
    assert_eq!(unsafe { copied(binding) }, BINDING);
    let status = fixture.begin_status.load(Ordering::SeqCst);
    if status == AgBeginStatus::Ok as i32 {
        unsafe {
            write_host_buffer(material_out, fixture.material_json.clone());
            write_host_buffer(token_out, b"attempt-token".to_vec());
        }
    }
    status
}

unsafe extern "C" fn finish_attempt(
    user_data: *mut c_void,
    token: AgByteSlice,
    outcome: i32,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    assert_eq!(unsafe { copied(token) }, b"attempt-token");
    fixture.finish_calls.fetch_add(1, Ordering::SeqCst);
    fixture.finish_outcomes.lock().unwrap().push(outcome);
    fixture.finish_status.load(Ordering::SeqCst)
}

unsafe extern "C" fn active_key(_: *mut c_void, _: *mut AgHostBuffer, _: *mut AgHostBuffer) -> i32 {
    unreachable!("verification does not request active key")
}

unsafe extern "C" fn key_by_id(
    user_data: *mut c_void,
    key_id: AgByteSlice,
    key_out: *mut AgHostBuffer,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    fixture.key_calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(unsafe { copied(key_id) }, KEY_ID.as_bytes());
    let status = fixture.key_status.load(Ordering::SeqCst);
    if status == AgKeyStatus::Ok as i32 {
        unsafe { write_host_buffer(key_out, KEY.to_vec()) };
    }
    status
}

fn borrowed(bytes: &[u8]) -> AgByteSlice {
    AgByteSlice {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}

fn submission(answer: &str) -> Vec<u8> {
    format!(r#"{{"challenge_id":"{CHALLENGE_ID}","nonce":"{NONCE}","answer":"{answer}"}}"#)
        .into_bytes()
}

fn canonical_empty(buffer: &AgOwnedBuffer) -> bool {
    buffer.data.is_null() && buffer.len == 0 && buffer.capacity == 0
}

fn copy_and_free(out: &mut AgOwnedBuffer) -> Vec<u8> {
    let json = unsafe { slice::from_raw_parts(out.data, out.len) }.to_vec();
    assert_eq!(unsafe { ag_buffer_free(out) }, AgStatus::Ok);
    json
}

#[test]
fn accepted_returns_exact_json_after_durable_finish() {
    let harness = Harness::new();
    let mut out = AgOwnedBuffer::empty();

    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::Ok
    );
    assert_eq!(copy_and_free(&mut out), br#"{"status":"accepted"}"#);
    assert_eq!(harness.fixture.begin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.fixture.finish_outcomes.lock().unwrap().as_slice(),
        [AgAttemptOutcome::Accepted as i32]
    );
}

#[test]
fn lifecycle_rejection_returns_exact_json_without_key_or_finish() {
    let harness = Harness::new();
    harness
        .fixture
        .begin_status
        .store(AgBeginStatus::Expired as i32, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();

    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::Ok
    );
    assert_eq!(
        copy_and_free(&mut out),
        br#"{"status":"rejected","reason":"expired"}"#
    );
    assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_unknown_field_and_invalid_slices_are_rejected_before_callbacks() {
    let harness = Harness::new();
    let unknown_field = format!(
        r#"{{"challenge_id":"{CHALLENGE_ID}","nonce":"{NONCE}","answer":"{ANSWER}","extra":true}}"#
    );
    let submitted = submission(ANSWER);
    let cases = [
        (borrowed(b"{"), borrowed(BINDING)),
        (borrowed(unknown_field.as_bytes()), borrowed(BINDING)),
        (
            AgByteSlice {
                data: ptr::null(),
                len: 1,
            },
            borrowed(BINDING),
        ),
        (
            borrowed(&submitted),
            AgByteSlice {
                data: ptr::null(),
                len: 1,
            },
        ),
    ];

    for (submission_json, binding) in cases {
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            unsafe { ag_service_verify(harness.service, submission_json, binding, &mut out) },
            AgStatus::InvalidArgument
        );
        assert!(canonical_empty(&out));
    }
    assert_eq!(harness.fixture.begin_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_binding_maps_exactly_and_keeps_output_empty() {
    let harness = Harness::new();
    for binding in [borrowed(b""), borrowed(&[b'x'; 257])] {
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            harness.verify(&submission(ANSWER), binding, &mut out),
            AgStatus::InvalidConfiguration
        );
        assert!(canonical_empty(&out));
    }
    assert_eq!(harness.fixture.begin_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn null_handle_null_output_and_nonempty_output_are_rejected_without_overwrite() {
    let harness = Harness::new();
    let submitted = submission(ANSWER);
    let mut empty = AgOwnedBuffer::empty();
    assert_eq!(
        unsafe {
            ag_service_verify(
                ptr::null_mut(),
                borrowed(&submitted),
                borrowed(BINDING),
                &mut empty,
            )
        },
        AgStatus::InvalidArgument
    );
    assert!(canonical_empty(&empty));
    assert_eq!(
        unsafe {
            ag_service_verify(
                harness.service,
                borrowed(&submitted),
                borrowed(BINDING),
                ptr::null_mut(),
            )
        },
        AgStatus::InvalidArgument
    );

    let mut occupied = AgOwnedBuffer::from_vec(b"caller-owned".to_vec());
    let before = (occupied.data, occupied.len, occupied.capacity);
    assert_eq!(
        harness.verify(&submitted, borrowed(BINDING), &mut occupied),
        AgStatus::InvalidArgument
    );
    assert_eq!((occupied.data, occupied.len, occupied.capacity), before);
    assert_eq!(unsafe { ag_buffer_free(&mut occupied) }, AgStatus::Ok);
}

#[test]
fn verification_errors_never_publish_partial_output() {
    let harness = Harness::new();
    for (answer, expected) in [
        ("not base64url!", AgStatus::InvalidAnswerEncoding),
        ("Yg", AgStatus::AnswerMismatch),
    ] {
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            harness.verify(&submission(answer), borrowed(BINDING), &mut out),
            expected
        );
        assert!(canonical_empty(&out));
    }

    let harness = Harness::new();
    harness
        .fixture
        .finish_status
        .store(AgLifecycleStatus::Internal as i32, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();
    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::InternalError
    );
    assert!(canonical_empty(&out));

    let harness = Harness::new();
    harness.fixture.key_status.store(77, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();
    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::CallbackFailed
    );
    assert!(canonical_empty(&out));
}
