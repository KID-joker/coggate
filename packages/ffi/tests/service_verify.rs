use std::{
    ffi::c_void,
    mem::size_of,
    ptr, slice,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
    },
};

use agentgate_contracts::{AnswerEncoding, PrivateChallengeMaterial};
use agentgate_core::{MacContext, compute_answer_mac};
use agentgate_ffi::{
    AG_ABI_VERSION_1, AgAttemptOutcome, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks,
    AgKeyStatus, AgLifecycleCallbacks, AgLifecycleStatus, AgObserverCallbacks, AgOwnedBuffer,
    AgService, AgStatus, ag_buffer_free, ag_service_create, ag_service_destroy, ag_service_verify,
};

const CHALLENGE_ID: &str = "Y2hhbGxlbmdlLTEyMzQ1Ng";
const NONCE: &str = "bm9uY2UtMTIzNDU2Nzg5MA";
const ANSWER: &str = "YQ";
const ANSWER_SENTINEL: &str = "QU5TV0VSX1NFTlRJTkVMX3ByaXZhdGVfYW5zd2Vy";
const KEY_ID: &str = "KEY_ID_SENTINEL_private_identifier";
const KEY: &[u8] = b"KEY_SENTINEL_private_material_0123456789";
const BINDING: &[u8] = b"BINDING_SENTINEL_private_binding";
const TOKEN: &[u8] = b"TOKEN_SENTINEL_private_attempt_token";

#[derive(Clone, Copy)]
#[repr(i32)]
enum BeginOutputBehavior {
    Normal = 0,
    WriteOnFailure = 1,
    MalformedToken = 2,
    NoncanonicalEmptyToken = 3,
}

struct Fixture {
    begin_status: AtomicI32,
    begin_calls: AtomicUsize,
    finish_status: AtomicI32,
    finish_calls: AtomicUsize,
    allow_empty_finish_token: AtomicBool,
    finish_outcomes: Mutex<Vec<i32>>,
    key_status: AtomicI32,
    key_calls: AtomicUsize,
    active_key_status: AtomicI32,
    active_key_calls: AtomicUsize,
    material_json: Mutex<Vec<u8>>,
    begin_output_behavior: AtomicI32,
    release_calls: AtomicUsize,
    host_owned_outputs: Mutex<Vec<(usize, usize)>>,
    replay_after_accept: AtomicBool,
    consumed: AtomicBool,
    observer_events: Mutex<Vec<Vec<u8>>>,
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
            allow_empty_finish_token: AtomicBool::new(false),
            finish_outcomes: Mutex::new(Vec::new()),
            key_status: AtomicI32::new(AgKeyStatus::Ok as i32),
            key_calls: AtomicUsize::new(0),
            active_key_status: AtomicI32::new(AgKeyStatus::Unavailable as i32),
            active_key_calls: AtomicUsize::new(0),
            material_json: Mutex::new(serde_json::to_vec(&material).unwrap()),
            begin_output_behavior: AtomicI32::new(BeginOutputBehavior::Normal as i32),
            release_calls: AtomicUsize::new(0),
            host_owned_outputs: Mutex::new(Vec::new()),
            replay_after_accept: AtomicBool::new(false),
            consumed: AtomicBool::new(false),
            observer_events: Mutex::new(Vec::new()),
        }
    }

    fn material(&self) -> PrivateChallengeMaterial {
        serde_json::from_slice(&self.material_json.lock().unwrap()).unwrap()
    }

    fn update_material(&self, update: impl FnOnce(&mut PrivateChallengeMaterial)) {
        let mut material = self.material();
        update(&mut material);
        *self.material_json.lock().unwrap() = serde_json::to_vec(&material).unwrap();
    }

    fn use_answer(&self, answer: &str) {
        self.update_material(|material| {
            let context = MacContext {
                challenge_id: material.challenge_id.clone(),
                generator_version: material.generator_version.clone(),
                nonce: material.nonce.clone(),
                issued_at: material.issued_at,
                expires_at: material.expires_at,
                mac_key_id: material.mac_key_id.clone(),
                answer_encoding: material.answer_encoding,
            };
            material.answer_mac = encode_hex(&compute_answer_mac(KEY, &context, answer).unwrap());
        });
    }

    unsafe fn clean_host_owned_outputs(&self) {
        for (data, len) in self.host_owned_outputs.lock().unwrap().drain(..) {
            let raw = ptr::slice_from_raw_parts_mut(data as *mut u8, len);
            drop(unsafe { Box::from_raw(raw) });
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
        Self::with_observer(false)
    }

    fn observed() -> Self {
        Self::with_observer(true)
    }

    fn with_observer(observed: bool) -> Self {
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
        let observer = AgObserverCallbacks {
            struct_size: size_of::<AgObserverCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data,
            observe: Some(observe),
        };
        let observer = if observed { &observer } else { ptr::null() };
        let mut service = ptr::null_mut();
        assert_eq!(
            unsafe { ag_service_create(&lifecycle, &keys, observer, &mut service) },
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
        assert_eq!(self.fixture.active_key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { ag_service_destroy(self.service) }, AgStatus::Ok);
    }
}

unsafe extern "C" fn release_boxed(user_data: *mut c_void, data: *mut u8, len: usize) {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    fixture.release_calls.fetch_add(1, Ordering::SeqCst);
    if !data.is_null() {
        let raw = ptr::slice_from_raw_parts_mut(data, len);
        drop(unsafe { Box::from_raw(raw) });
    }
}

unsafe fn write_host_buffer(user_data: *mut c_void, out: *mut AgHostBuffer, bytes: Vec<u8>) {
    let mut bytes = bytes.into_boxed_slice();
    let buffer = AgHostBuffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
        release_data: user_data,
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
    let status = if fixture.replay_after_accept.load(Ordering::SeqCst)
        && fixture.consumed.load(Ordering::SeqCst)
    {
        AgBeginStatus::AlreadyConsumed as i32
    } else {
        fixture.begin_status.load(Ordering::SeqCst)
    };
    let output_behavior = fixture.begin_output_behavior.load(Ordering::SeqCst);
    if status == AgBeginStatus::Ok as i32 {
        unsafe {
            write_host_buffer(
                user_data,
                material_out,
                fixture.material_json.lock().unwrap().clone(),
            );
            if output_behavior == BeginOutputBehavior::MalformedToken as i32 {
                token_out.write(AgHostBuffer {
                    data: ptr::null_mut(),
                    len: 1,
                    release_data: ptr::null_mut(),
                    release: None,
                });
            } else if output_behavior == BeginOutputBehavior::NoncanonicalEmptyToken as i32 {
                token_out.write(AgHostBuffer {
                    data: ptr::null_mut(),
                    len: 0,
                    release_data: user_data,
                    release: Some(release_boxed),
                });
            } else {
                write_host_buffer(user_data, token_out, TOKEN.to_vec());
            }
        }
    } else if output_behavior == BeginOutputBehavior::WriteOnFailure as i32 {
        let material = fixture.material_json.lock().unwrap().clone();
        let token = TOKEN.to_vec();
        unsafe {
            write_host_buffer(user_data, material_out, material);
            write_host_buffer(user_data, token_out, token);
        }
        let material = unsafe { &*material_out };
        let token = unsafe { &*token_out };
        fixture.host_owned_outputs.lock().unwrap().extend([
            (material.data as usize, material.len),
            (token.data as usize, token.len),
        ]);
    }
    status
}

unsafe extern "C" fn finish_attempt(
    user_data: *mut c_void,
    token: AgByteSlice,
    outcome: i32,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    let token = unsafe { copied(token) };
    if !fixture.allow_empty_finish_token.load(Ordering::SeqCst) {
        assert_eq!(token, TOKEN);
    }
    fixture.finish_calls.fetch_add(1, Ordering::SeqCst);
    fixture.finish_outcomes.lock().unwrap().push(outcome);
    if outcome == AgAttemptOutcome::Accepted as i32 {
        fixture.consumed.store(true, Ordering::SeqCst);
    }
    fixture.finish_status.load(Ordering::SeqCst)
}

unsafe extern "C" fn active_key(
    user_data: *mut c_void,
    _: *mut AgHostBuffer,
    _: *mut AgHostBuffer,
) -> i32 {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    fixture.active_key_calls.fetch_add(1, Ordering::SeqCst);
    fixture.active_key_status.load(Ordering::SeqCst)
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
        unsafe { write_host_buffer(user_data, key_out, KEY.to_vec()) };
    }
    status
}

unsafe extern "C" fn observe(user_data: *mut c_void, event_json: AgByteSlice) {
    let fixture = unsafe { &*user_data.cast::<Fixture>() };
    fixture
        .observer_events
        .lock()
        .unwrap()
        .push(unsafe { copied(event_json) });
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

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
}

fn assert_absent(haystack: &[u8], needle: &[u8]) {
    assert!(!needle.is_empty());
    assert!(!contains_bytes(haystack, needle));
}

fn assert_finish(harness: &Harness, expected: AgAttemptOutcome) {
    assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.fixture.finish_outcomes.lock().unwrap().as_slice(),
        [expected as i32]
    );
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
    assert_finish(&harness, AgAttemptOutcome::Accepted);
}

#[test]
fn every_lifecycle_rejection_returns_exact_json_without_key_or_finish() {
    for (begin_status, reason) in [
        (AgBeginStatus::NotFound, "not_found"),
        (AgBeginStatus::Expired, "expired"),
        (AgBeginStatus::AlreadyConsumed, "already_consumed"),
        (AgBeginStatus::BindingMismatch, "binding_mismatch"),
        (AgBeginStatus::NonceMismatch, "nonce_mismatch"),
        (AgBeginStatus::AttemptsExhausted, "attempts_exhausted"),
    ] {
        let harness = Harness::new();
        harness
            .fixture
            .begin_status
            .store(begin_status as i32, Ordering::SeqCst);
        let mut out = AgOwnedBuffer::empty();

        assert_eq!(
            harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
            AgStatus::Ok
        );
        assert_eq!(
            copy_and_free(&mut out),
            format!(r#"{{"status":"rejected","reason":"{reason}"}}"#).as_bytes()
        );
        assert_eq!(harness.fixture.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 0);
    }
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
fn invalid_encoding_and_mismatch_finish_rejected_without_output() {
    for (answer, expected) in [
        ("not base64url!", AgStatus::InvalidAnswerEncoding),
        ("Yg", AgStatus::AnswerMismatch),
    ] {
        let harness = Harness::new();
        let mut out = AgOwnedBuffer::empty();
        assert_eq!(
            harness.verify(&submission(answer), borrowed(BINDING), &mut out),
            expected
        );
        assert!(canonical_empty(&out));
        assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 1);
        assert_finish(&harness, AgAttemptOutcome::Rejected);
    }
}

#[test]
fn invalid_material_and_unsupported_version_finish_system_failure() {
    enum Scenario {
        InvalidMaterial,
        UnsupportedVersion,
    }

    for (scenario, expected) in [
        (
            Scenario::InvalidMaterial,
            AgStatus::InvalidChallengeMaterial,
        ),
        (
            Scenario::UnsupportedVersion,
            AgStatus::UnsupportedGeneratorVersion,
        ),
    ] {
        let harness = Harness::new();
        harness.fixture.update_material(|material| match scenario {
            Scenario::InvalidMaterial => {
                material.challenge_id = "not-a-canonical-challenge-id".to_owned();
            }
            Scenario::UnsupportedVersion => {
                material.generator_version = "2.0".to_owned();
            }
        });
        let mut out = AgOwnedBuffer::empty();

        assert_eq!(
            harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
            expected
        );
        assert!(canonical_empty(&out));
        assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 0);
        assert_finish(&harness, AgAttemptOutcome::SystemFailure);
    }
}

#[test]
fn every_key_failure_finishes_system_failure_and_maps_exactly() {
    for (raw, expected) in [
        (AgKeyStatus::Unavailable as i32, AgStatus::InternalError),
        (AgKeyStatus::NotFound as i32, AgStatus::InternalError),
        (AgKeyStatus::InvalidMaterial as i32, AgStatus::InternalError),
        (77, AgStatus::CallbackFailed),
    ] {
        let harness = Harness::new();
        harness.fixture.key_status.store(raw, Ordering::SeqCst);
        let mut out = AgOwnedBuffer::empty();

        assert_eq!(
            harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
            expected
        );
        assert!(canonical_empty(&out));
        assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 1);
        assert_finish(&harness, AgAttemptOutcome::SystemFailure);
    }
}

#[test]
fn finish_failure_prevents_publication_and_overrides_every_core_result() {
    enum Scenario {
        Accepted,
        Rejected,
        System,
    }

    for scenario in [Scenario::Accepted, Scenario::Rejected, Scenario::System] {
        let harness = Harness::new();
        harness
            .fixture
            .finish_status
            .store(AgLifecycleStatus::Internal as i32, Ordering::SeqCst);
        let answer = match scenario {
            Scenario::Accepted => ANSWER,
            Scenario::Rejected => "Yg",
            Scenario::System => {
                harness.fixture.update_material(|material| {
                    material.answer_mac = "invalid".to_owned();
                });
                ANSWER
            }
        };
        let expected_outcome = match scenario {
            Scenario::Accepted => AgAttemptOutcome::Accepted,
            Scenario::Rejected => AgAttemptOutcome::Rejected,
            Scenario::System => AgAttemptOutcome::SystemFailure,
        };
        let mut out = AgOwnedBuffer::empty();

        assert_eq!(
            harness.verify(&submission(answer), borrowed(BINDING), &mut out),
            AgStatus::InternalError
        );
        assert!(canonical_empty(&out));
        assert_finish(&harness, expected_outcome);
    }
}

#[test]
fn replay_after_accept_is_rejected_as_already_consumed() {
    let harness = Harness::new();
    harness
        .fixture
        .replay_after_accept
        .store(true, Ordering::SeqCst);

    let mut first = AgOwnedBuffer::empty();
    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut first),
        AgStatus::Ok
    );
    assert_eq!(copy_and_free(&mut first), br#"{"status":"accepted"}"#);

    let mut replay = AgOwnedBuffer::empty();
    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut replay),
        AgStatus::Ok
    );
    assert_eq!(
        copy_and_free(&mut replay),
        br#"{"status":"rejected","reason":"already_consumed"}"#
    );
    assert_eq!(harness.fixture.begin_calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn non_ok_begin_outputs_remain_host_owned_and_are_not_released() {
    let harness = Harness::new();
    harness
        .fixture
        .begin_status
        .store(AgBeginStatus::Expired as i32, Ordering::SeqCst);
    harness
        .fixture
        .begin_output_behavior
        .store(BeginOutputBehavior::WriteOnFailure as i32, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();

    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::Ok
    );
    assert_eq!(
        copy_and_free(&mut out),
        br#"{"status":"rejected","reason":"expired"}"#
    );
    assert_eq!(harness.fixture.release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.fixture.host_owned_outputs.lock().unwrap().len(), 2);
    unsafe { harness.fixture.clean_host_owned_outputs() };
}

#[test]
fn malformed_successful_begin_output_is_closed_and_releases_transferred_buffers() {
    let harness = Harness::new();
    harness
        .fixture
        .begin_output_behavior
        .store(BeginOutputBehavior::MalformedToken as i32, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();

    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::CallbackFailed
    );
    assert!(canonical_empty(&out));
    assert_eq!(harness.fixture.release_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn noncanonical_empty_optional_token_is_closed_and_released_exactly_once() {
    let harness = Harness::new();
    harness.fixture.begin_output_behavior.store(
        BeginOutputBehavior::NoncanonicalEmptyToken as i32,
        Ordering::SeqCst,
    );
    harness
        .fixture
        .allow_empty_finish_token
        .store(true, Ordering::SeqCst);
    harness
        .fixture
        .finish_status
        .store(AgLifecycleStatus::Internal as i32, Ordering::SeqCst);
    let mut out = AgOwnedBuffer::empty();

    assert_eq!(
        harness.verify(&submission(ANSWER), borrowed(BINDING), &mut out),
        AgStatus::CallbackFailed
    );
    assert!(canonical_empty(&out));
    assert_eq!(harness.fixture.release_calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.fixture.key_calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.fixture.finish_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn public_status_and_observer_json_do_not_expose_verification_secrets() {
    assert!(KEY.len() >= 32);
    let harness = Harness::observed();
    harness.fixture.use_answer(ANSWER_SENTINEL);
    let private_json = harness.fixture.material_json.lock().unwrap().clone();
    let private = harness.fixture.material();
    let mut out = AgOwnedBuffer::empty();
    let status = harness.verify(&submission(ANSWER_SENTINEL), borrowed(BINDING), &mut out);

    assert_eq!(status, AgStatus::Ok);
    let public_json = copy_and_free(&mut out);
    assert_eq!(public_json, br#"{"status":"accepted"}"#);
    let events = harness.fixture.observer_events.lock().unwrap();
    assert_eq!(events.len(), 1);
    let event: serde_json::Value = serde_json::from_slice(&events[0]).unwrap();
    assert_eq!(event["event"], "verification_completed");
    assert_eq!(event["disposition"], "accepted");
    assert!(event.as_object().unwrap().keys().all(|key| matches!(
        key.as_str(),
        "event"
            | "challenge_id"
            | "generator_version"
            | "disposition"
            | "elapsed_since_issue_us"
            | "duration_us"
    )));

    let debug = format!("{status:?}");
    for surface in [&public_json[..], &events[0], debug.as_bytes()] {
        for secret in [
            ANSWER_SENTINEL.as_bytes(),
            NONCE.as_bytes(),
            KEY_ID.as_bytes(),
            KEY,
            TOKEN,
            BINDING,
            private.answer_mac.as_bytes(),
            private_json.as_slice(),
        ] {
            assert_absent(surface, secret);
        }
    }
}
