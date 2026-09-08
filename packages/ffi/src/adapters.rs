use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use agentgate_core::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, BeginAttemptError, KeyProviderError,
    LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MacKey, MacKeyProvider, Observer,
    PendingAttempt, SubmissionIdentity, service::ServiceEvent,
};

use crate::{
    AgAttemptOutcome, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks, AgKeyStatus,
    AgLifecycleCallbacks, AgLifecycleStatus, AgObserverCallbacks,
    json::{parse_private_material, serialize_event, serialize_identity},
    memory::HostBufferGuard,
};

pub(crate) struct CallbackLifecycle {
    callbacks: AgLifecycleCallbacks,
    protocol_violation: Arc<AtomicBool>,
}

impl CallbackLifecycle {
    #[allow(dead_code)]
    pub(crate) fn new(
        callbacks: AgLifecycleCallbacks,
        protocol_violation: Arc<AtomicBool>,
    ) -> Self {
        Self {
            callbacks,
            protocol_violation,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn protocol_violation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.protocol_violation)
    }

    fn mark_violation(&self) {
        self.protocol_violation.store(true, Ordering::SeqCst);
    }
}

// SAFETY: service handles serialize calls to this adapter. The ABI contract
// requires the host to keep user_data and callbacks alive and thread-safe for
// the entire handle lifetime.
unsafe impl Send for CallbackLifecycle {}

impl LifecycleAdapter for CallbackLifecycle {
    type AttemptToken = Vec<u8>;

    fn store_issued(
        &mut self,
        material: agentgate_contracts::PrivateChallengeMaterial,
        binding: &[u8],
        attempt_limit: AttemptLimit,
    ) -> Result<(), LifecycleAdapterError> {
        let private_json =
            serde_json::to_vec(&material).map_err(|_| LifecycleAdapterError::Internal)?;
        let Some(callback) = self.callbacks.store_issued else {
            self.mark_violation();
            return Err(LifecycleAdapterError::Internal);
        };
        let raw = unsafe {
            callback(
                self.callbacks.user_data,
                byte_slice(&private_json),
                byte_slice(binding),
                match attempt_limit {
                    AttemptLimit::One => 1,
                    AttemptLimit::Two => 2,
                },
            )
        };
        map_lifecycle_status(raw).map_err(|()| {
            self.mark_violation();
            LifecycleAdapterError::Internal
        })?
    }

    fn begin_attempt(
        &mut self,
        identity: SubmissionIdentity<'_>,
        binding: &[u8],
        server_time: i64,
    ) -> Result<PendingAttempt<Self::AttemptToken>, BeginAttemptError> {
        let identity_json = serialize_identity(identity)
            .map_err(|()| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?;
        let Some(callback) = self.callbacks.begin_attempt else {
            self.mark_violation();
            return Err(BeginAttemptError::Adapter(LifecycleAdapterError::Internal));
        };
        let mut material_out = AgHostBuffer::empty();
        let mut token_out = AgHostBuffer::empty();
        let raw = unsafe {
            callback(
                self.callbacks.user_data,
                byte_slice(&identity_json),
                byte_slice(binding),
                server_time,
                &mut material_out,
                &mut token_out,
            )
        };
        match map_begin_status(raw) {
            Ok(()) => {}
            Err(Some(error)) => return Err(error),
            Err(None) => {
                self.mark_violation();
                return Err(BeginAttemptError::Adapter(LifecycleAdapterError::Internal));
            }
        }

        let material_guard =
            HostBufferGuard::take(material_out, Arc::clone(&self.protocol_violation));
        let token_guard = HostBufferGuard::take(token_out, Arc::clone(&self.protocol_violation));
        let material_bytes = material_guard
            .copy_bytes()
            .map_err(|()| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?;
        let token = token_guard
            .copy_bytes()
            .map_err(|()| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?;
        if material_bytes.is_empty() {
            self.mark_violation();
            return Err(BeginAttemptError::Adapter(LifecycleAdapterError::Internal));
        }
        let material = parse_private_material(&material_bytes).map_err(|()| {
            self.mark_violation();
            BeginAttemptError::Adapter(LifecycleAdapterError::Internal)
        })?;
        Ok(PendingAttempt::new(token, material))
    }

    fn finish_attempt(
        &mut self,
        token: Self::AttemptToken,
        outcome: AttemptOutcome,
    ) -> Result<(), LifecycleAdapterError> {
        let Some(callback) = self.callbacks.finish_attempt else {
            self.mark_violation();
            return Err(LifecycleAdapterError::Internal);
        };
        let raw = unsafe {
            callback(
                self.callbacks.user_data,
                byte_slice(&token),
                attempt_outcome_raw(outcome),
            )
        };
        map_lifecycle_status(raw).map_err(|()| {
            self.mark_violation();
            LifecycleAdapterError::Internal
        })?
    }
}

pub(crate) struct CallbackKeys {
    callbacks: AgKeyCallbacks,
    protocol_violation: Arc<AtomicBool>,
}

impl CallbackKeys {
    #[allow(dead_code)]
    pub(crate) fn new(callbacks: AgKeyCallbacks, protocol_violation: Arc<AtomicBool>) -> Self {
        Self {
            callbacks,
            protocol_violation,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn protocol_violation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.protocol_violation)
    }

    fn mark_violation(&self) {
        self.protocol_violation.store(true, Ordering::SeqCst);
    }
}

// SAFETY: service handles serialize calls to this adapter. The ABI contract
// requires the host to keep user_data and callbacks alive and thread-safe for
// the entire handle lifetime.
unsafe impl Send for CallbackKeys {}

impl MacKeyProvider for CallbackKeys {
    fn active_key(&mut self) -> Result<ActiveMacKey, KeyProviderError> {
        let Some(callback) = self.callbacks.active_key else {
            self.mark_violation();
            return Err(KeyProviderError::InvalidMaterial);
        };
        let mut key_id_out = AgHostBuffer::empty();
        let mut key_out = AgHostBuffer::empty();
        let raw = unsafe { callback(self.callbacks.user_data, &mut key_id_out, &mut key_out) };
        map_key_status(raw).map_err(|status| {
            if status.is_none() {
                self.mark_violation();
            }
            status.unwrap_or(KeyProviderError::InvalidMaterial)
        })?;
        let key_id_guard = HostBufferGuard::take(key_id_out, Arc::clone(&self.protocol_violation));
        let key_guard = HostBufferGuard::take(key_out, Arc::clone(&self.protocol_violation));
        let key_id_bytes = key_id_guard
            .copy_bytes()
            .map_err(|()| KeyProviderError::InvalidMaterial)?;
        let key_bytes = key_guard
            .copy_bytes()
            .map_err(|()| KeyProviderError::InvalidMaterial)?;
        if key_id_bytes.is_empty() || key_bytes.is_empty() {
            self.mark_violation();
            return Err(KeyProviderError::InvalidMaterial);
        }
        let key_id = String::from_utf8(key_id_bytes).map_err(|_| {
            self.mark_violation();
            KeyProviderError::InvalidMaterial
        })?;
        let key = MacKey::new(key_bytes).inspect_err(|_| {
            self.mark_violation();
        })?;
        ActiveMacKey::new(key_id, key).inspect_err(|_| {
            self.mark_violation();
        })
    }

    fn key_by_id(&mut self, key_id: &str) -> Result<MacKey, KeyProviderError> {
        let Some(callback) = self.callbacks.key_by_id else {
            self.mark_violation();
            return Err(KeyProviderError::InvalidMaterial);
        };
        let mut key_out = AgHostBuffer::empty();
        let raw = unsafe {
            callback(
                self.callbacks.user_data,
                byte_slice(key_id.as_bytes()),
                &mut key_out,
            )
        };
        map_key_status(raw).map_err(|status| {
            if status.is_none() {
                self.mark_violation();
            }
            status.unwrap_or(KeyProviderError::InvalidMaterial)
        })?;
        let key_guard = HostBufferGuard::take(key_out, Arc::clone(&self.protocol_violation));
        let key_bytes = key_guard
            .copy_bytes()
            .map_err(|()| KeyProviderError::InvalidMaterial)?;
        if key_bytes.is_empty() {
            self.mark_violation();
            return Err(KeyProviderError::InvalidMaterial);
        }
        MacKey::new(key_bytes).inspect_err(|_| {
            self.mark_violation();
        })
    }
}

pub(crate) struct CallbackObserver {
    callbacks: Option<AgObserverCallbacks>,
    protocol_violation: Arc<AtomicBool>,
}

impl CallbackObserver {
    #[allow(dead_code)]
    pub(crate) fn new(
        callbacks: Option<AgObserverCallbacks>,
        protocol_violation: Arc<AtomicBool>,
    ) -> Self {
        Self {
            callbacks,
            protocol_violation,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn protocol_violation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.protocol_violation)
    }
}

// SAFETY: service handles serialize calls to this adapter. The ABI contract
// requires the host to keep user_data and callbacks alive and thread-safe for
// the entire handle lifetime.
unsafe impl Send for CallbackObserver {}

impl Observer for CallbackObserver {
    fn observe(&mut self, event: &ServiceEvent) {
        let Some(callbacks) = self.callbacks else {
            return;
        };
        let Some(callback) = callbacks.observe else {
            return;
        };
        let Ok(event_json) = serialize_event(event) else {
            return;
        };
        unsafe { callback(callbacks.user_data, byte_slice(&event_json)) };
    }
}

fn byte_slice(bytes: &[u8]) -> AgByteSlice {
    AgByteSlice {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}

fn map_lifecycle_status(raw: i32) -> Result<Result<(), LifecycleAdapterError>, ()> {
    match raw {
        x if x == AgLifecycleStatus::Ok as i32 => Ok(Ok(())),
        x if x == AgLifecycleStatus::Unavailable as i32 => {
            Ok(Err(LifecycleAdapterError::Unavailable))
        }
        x if x == AgLifecycleStatus::Conflict as i32 => Ok(Err(LifecycleAdapterError::Conflict)),
        x if x == AgLifecycleStatus::Internal as i32 => Ok(Err(LifecycleAdapterError::Internal)),
        _ => Err(()),
    }
}

fn map_begin_status(raw: i32) -> Result<(), Option<BeginAttemptError>> {
    let error = match raw {
        x if x == AgBeginStatus::Ok as i32 => return Ok(()),
        x if x == AgBeginStatus::Unavailable as i32 => {
            BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable)
        }
        x if x == AgBeginStatus::Conflict as i32 => {
            BeginAttemptError::Adapter(LifecycleAdapterError::Conflict)
        }
        x if x == AgBeginStatus::Internal as i32 => {
            BeginAttemptError::Adapter(LifecycleAdapterError::Internal)
        }
        x if x == AgBeginStatus::NotFound as i32 => {
            BeginAttemptError::Rejected(LifecycleRejection::NotFound)
        }
        x if x == AgBeginStatus::Expired as i32 => {
            BeginAttemptError::Rejected(LifecycleRejection::Expired)
        }
        x if x == AgBeginStatus::AlreadyConsumed as i32 => {
            BeginAttemptError::Rejected(LifecycleRejection::AlreadyConsumed)
        }
        x if x == AgBeginStatus::BindingMismatch as i32 => {
            BeginAttemptError::Rejected(LifecycleRejection::BindingMismatch)
        }
        x if x == AgBeginStatus::NonceMismatch as i32 => {
            BeginAttemptError::Rejected(LifecycleRejection::NonceMismatch)
        }
        x if x == AgBeginStatus::AttemptsExhausted as i32 => {
            BeginAttemptError::Rejected(LifecycleRejection::AttemptsExhausted)
        }
        _ => return Err(None),
    };
    Err(Some(error))
}

fn map_key_status(raw: i32) -> Result<(), Option<KeyProviderError>> {
    match raw {
        x if x == AgKeyStatus::Ok as i32 => Ok(()),
        x if x == AgKeyStatus::Unavailable as i32 => Err(Some(KeyProviderError::Unavailable)),
        x if x == AgKeyStatus::NotFound as i32 => Err(Some(KeyProviderError::NotFound)),
        x if x == AgKeyStatus::InvalidMaterial as i32 => {
            Err(Some(KeyProviderError::InvalidMaterial))
        }
        _ => Err(None),
    }
}

fn attempt_outcome_raw(outcome: AttemptOutcome) -> i32 {
    match outcome {
        AttemptOutcome::Accepted => AgAttemptOutcome::Accepted as i32,
        AttemptOutcome::Rejected => AgAttemptOutcome::Rejected as i32,
        AttemptOutcome::SystemFailure => AgAttemptOutcome::SystemFailure as i32,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
    };

    use agentgate_contracts::{AnswerEncoding, PrivateChallengeMaterial, Submission};
    use agentgate_core::{
        AttemptLimit, AttemptOutcome, BeginAttemptError, ChallengeService, KeyProviderError,
        LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MacKeyProvider, Observer,
        ServiceError, ServiceEvent, ServiceFailureEvent, ServiceStage, SubmissionIdentity,
        VerifyRequest,
    };

    use crate::{
        AG_ABI_VERSION_1, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks,
        AgLifecycleCallbacks, AgObserverCallbacks,
    };

    use super::{CallbackKeys, CallbackLifecycle, CallbackObserver};

    struct Fixture {
        releases: AtomicUsize,
    }

    unsafe extern "C" fn release(data: *mut c_void, bytes: *mut u8, len: usize) {
        let fixture = unsafe { &*(data.cast::<Fixture>()) };
        fixture.releases.fetch_add(1, Ordering::SeqCst);
        if !bytes.is_null() {
            drop(unsafe { Vec::from_raw_parts(bytes, len, len) });
        }
    }

    unsafe fn output(data: *mut c_void, out: *mut AgHostBuffer, bytes: Vec<u8>) {
        let mut bytes = bytes.into_boxed_slice();
        let len = bytes.len();
        let ptr = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        unsafe {
            *out = AgHostBuffer {
                data: ptr,
                len,
                release_data: data,
                release: Some(release),
            }
        };
    }

    unsafe extern "C" fn store(_: *mut c_void, _: AgByteSlice, _: AgByteSlice, _: u32) -> i32 {
        0
    }
    unsafe extern "C" fn begin(
        data: *mut c_void,
        _: AgByteSlice,
        _: AgByteSlice,
        _: i64,
        material: *mut AgHostBuffer,
        token: *mut AgHostBuffer,
    ) -> i32 {
        unsafe {
            output(data, material, br#"{"challenge_id":"id","generator_version":"1.0","nonce":"n","issued_at":1,"expires_at":2,"mac_key_id":"kid","answer_mac":"mac","answer_encoding":"base64url"}"#.to_vec())
        };
        unsafe { output(data, token, Vec::new()) };
        AgBeginStatus::Ok as i32
    }
    unsafe extern "C" fn finish(_: *mut c_void, _: AgByteSlice, _: i32) -> i32 {
        0
    }

    #[test]
    fn begin_allows_empty_token_and_releases_both_outputs_once() {
        let fixture = Box::new(Fixture {
            releases: AtomicUsize::new(0),
        });
        let ptr = Box::into_raw(fixture);
        let callbacks = AgLifecycleCallbacks {
            struct_size: size_of::<AgLifecycleCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data: ptr.cast(),
            store_issued: Some(store),
            begin_attempt: Some(begin),
            finish_attempt: Some(finish),
        };
        let flag = Arc::new(AtomicBool::new(false));
        let mut adapter = CallbackLifecycle::new(callbacks, Arc::clone(&flag));
        assert!(
            adapter
                .begin_attempt(SubmissionIdentity::new("id", "n"), b"binding", 2)
                .is_ok()
        );
        assert_eq!(unsafe { &*ptr }.releases.load(Ordering::SeqCst), 2);
        assert!(!flag.load(Ordering::SeqCst));
        drop(unsafe { Box::from_raw(ptr) });
    }

    unsafe extern "C" fn active_invalid(
        data: *mut c_void,
        id: *mut AgHostBuffer,
        key: *mut AgHostBuffer,
    ) -> i32 {
        unsafe { output(data, id, vec![0xff]) };
        unsafe { output(data, key, vec![7; 32]) };
        0
    }
    unsafe extern "C" fn by_id(_: *mut c_void, _: AgByteSlice, _: *mut AgHostBuffer) -> i32 {
        2
    }

    #[test]
    fn active_key_utf8_failure_releases_outputs_and_marks_violation() {
        let fixture = Box::new(Fixture {
            releases: AtomicUsize::new(0),
        });
        let ptr = Box::into_raw(fixture);
        let callbacks = AgKeyCallbacks {
            struct_size: size_of::<AgKeyCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data: ptr.cast(),
            active_key: Some(active_invalid),
            key_by_id: Some(by_id),
        };
        let flag = Arc::new(AtomicBool::new(false));
        let mut adapter = CallbackKeys::new(callbacks, Arc::clone(&flag));
        assert!(adapter.active_key().is_err());
        assert_eq!(unsafe { &*ptr }.releases.load(Ordering::SeqCst), 2);
        assert!(flag.load(Ordering::SeqCst));
        drop(unsafe { Box::from_raw(ptr) });
    }

    #[test]
    fn attempt_outcomes_have_exact_raw_values() {
        assert_eq!(super::attempt_outcome_raw(AttemptOutcome::Accepted), 1);
        assert_eq!(super::attempt_outcome_raw(AttemptOutcome::Rejected), 2);
        assert_eq!(super::attempt_outcome_raw(AttemptOutcome::SystemFailure), 3);
    }

    #[test]
    fn every_lifecycle_status_maps_exactly_and_unknown_is_closed() {
        assert_eq!(super::map_lifecycle_status(0), Ok(Ok(())));
        assert_eq!(
            super::map_lifecycle_status(1),
            Ok(Err(LifecycleAdapterError::Unavailable))
        );
        assert_eq!(
            super::map_lifecycle_status(2),
            Ok(Err(LifecycleAdapterError::Conflict))
        );
        assert_eq!(
            super::map_lifecycle_status(3),
            Ok(Err(LifecycleAdapterError::Internal))
        );
        assert_eq!(super::map_lifecycle_status(99), Err(()));
    }

    #[test]
    fn every_begin_status_maps_exactly_and_unknown_is_closed() {
        assert_eq!(super::map_begin_status(0), Ok(()));
        for (raw, expected) in [
            (
                1,
                BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable),
            ),
            (
                2,
                BeginAttemptError::Adapter(LifecycleAdapterError::Conflict),
            ),
            (
                3,
                BeginAttemptError::Adapter(LifecycleAdapterError::Internal),
            ),
            (
                10,
                BeginAttemptError::Rejected(LifecycleRejection::NotFound),
            ),
            (11, BeginAttemptError::Rejected(LifecycleRejection::Expired)),
            (
                12,
                BeginAttemptError::Rejected(LifecycleRejection::AlreadyConsumed),
            ),
            (
                13,
                BeginAttemptError::Rejected(LifecycleRejection::BindingMismatch),
            ),
            (
                14,
                BeginAttemptError::Rejected(LifecycleRejection::NonceMismatch),
            ),
            (
                15,
                BeginAttemptError::Rejected(LifecycleRejection::AttemptsExhausted),
            ),
        ] {
            assert_eq!(super::map_begin_status(raw), Err(Some(expected)));
        }
        assert_eq!(super::map_begin_status(99), Err(None));
    }

    #[test]
    fn every_key_status_maps_exactly_and_unknown_is_closed() {
        assert_eq!(super::map_key_status(0), Ok(()));
        assert_eq!(
            super::map_key_status(1),
            Err(Some(KeyProviderError::Unavailable))
        );
        assert_eq!(
            super::map_key_status(2),
            Err(Some(KeyProviderError::NotFound))
        );
        assert_eq!(
            super::map_key_status(3),
            Err(Some(KeyProviderError::InvalidMaterial))
        );
        assert_eq!(super::map_key_status(99), Err(None));
    }

    #[test]
    fn known_callback_statuses_map_exactly_through_trait_methods() {
        for (raw, expected) in [
            (1, LifecycleAdapterError::Unavailable),
            (2, LifecycleAdapterError::Conflict),
            (3, LifecycleAdapterError::Internal),
        ] {
            let mut fixture = ContractFixture::new();
            fixture.store_status.store(raw, Ordering::SeqCst);
            assert_eq!(
                fixture
                    .lifecycle(Arc::new(AtomicBool::new(false)))
                    .store_issued(private_material(), b"binding", AttemptLimit::One),
                Err(expected)
            );
            fixture.finish_status.store(raw, Ordering::SeqCst);
            assert_eq!(
                fixture
                    .lifecycle(Arc::new(AtomicBool::new(false)))
                    .finish_attempt(Vec::new(), AttemptOutcome::Rejected),
                Err(expected)
            );
        }

        for (raw, expected) in [
            (
                1,
                BeginAttemptError::Adapter(LifecycleAdapterError::Unavailable),
            ),
            (
                2,
                BeginAttemptError::Adapter(LifecycleAdapterError::Conflict),
            ),
            (
                3,
                BeginAttemptError::Adapter(LifecycleAdapterError::Internal),
            ),
            (
                10,
                BeginAttemptError::Rejected(LifecycleRejection::NotFound),
            ),
            (11, BeginAttemptError::Rejected(LifecycleRejection::Expired)),
            (
                12,
                BeginAttemptError::Rejected(LifecycleRejection::AlreadyConsumed),
            ),
            (
                13,
                BeginAttemptError::Rejected(LifecycleRejection::BindingMismatch),
            ),
            (
                14,
                BeginAttemptError::Rejected(LifecycleRejection::NonceMismatch),
            ),
            (
                15,
                BeginAttemptError::Rejected(LifecycleRejection::AttemptsExhausted),
            ),
        ] {
            let mut fixture = ContractFixture::new();
            fixture.begin_status.store(raw, Ordering::SeqCst);
            assert_eq!(
                fixture
                    .lifecycle(Arc::new(AtomicBool::new(false)))
                    .begin_attempt(SubmissionIdentity::new("id", "n"), b"binding", 1)
                    .err(),
                Some(expected)
            );
            assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
            fixture.clean_host_allocations();
        }

        for (raw, expected) in [
            (1, KeyProviderError::Unavailable),
            (2, KeyProviderError::NotFound),
            (3, KeyProviderError::InvalidMaterial),
        ] {
            let mut fixture = ContractFixture::new();
            fixture.key_status.store(raw, Ordering::SeqCst);
            assert_eq!(
                fixture
                    .keys(Arc::new(AtomicBool::new(false)))
                    .active_key()
                    .err(),
                Some(expected)
            );
            fixture.clean_host_allocations();
            assert_eq!(
                fixture
                    .keys(Arc::new(AtomicBool::new(false)))
                    .key_by_id("id")
                    .err(),
                Some(expected)
            );
            fixture.clean_host_allocations();
        }
    }

    #[derive(Clone)]
    enum OutputSpec {
        Bytes(Vec<u8>),
        MissingRelease(Vec<u8>),
        NullNonzero,
    }

    type StoreCall = (Vec<u8>, Vec<u8>, u32);
    type BeginCall = (Vec<u8>, Vec<u8>, i64);

    struct ContractFixture {
        store_status: AtomicI32,
        begin_status: AtomicI32,
        finish_status: AtomicI32,
        key_status: AtomicI32,
        releases: AtomicUsize,
        store_calls: Mutex<Vec<StoreCall>>,
        begin_calls: Mutex<Vec<BeginCall>>,
        finish_calls: Mutex<Vec<(Vec<u8>, i32)>>,
        by_id_calls: Mutex<Vec<Vec<u8>>>,
        material: Mutex<OutputSpec>,
        token: Mutex<OutputSpec>,
        key_id: Mutex<OutputSpec>,
        key: Mutex<OutputSpec>,
        host_allocations: Mutex<Vec<(usize, usize)>>,
    }

    impl ContractFixture {
        fn new() -> Self {
            Self {
                store_status: AtomicI32::new(0),
                begin_status: AtomicI32::new(0),
                finish_status: AtomicI32::new(0),
                key_status: AtomicI32::new(0),
                releases: AtomicUsize::new(0),
                store_calls: Mutex::new(Vec::new()),
                begin_calls: Mutex::new(Vec::new()),
                finish_calls: Mutex::new(Vec::new()),
                by_id_calls: Mutex::new(Vec::new()),
                material: Mutex::new(OutputSpec::Bytes(private_json())),
                token: Mutex::new(OutputSpec::Bytes(b"opaque-token".to_vec())),
                key_id: Mutex::new(OutputSpec::Bytes(b"primary".to_vec())),
                key: Mutex::new(OutputSpec::Bytes(vec![7; 32])),
                host_allocations: Mutex::new(Vec::new()),
            }
        }

        fn lifecycle(&mut self, flag: Arc<AtomicBool>) -> CallbackLifecycle {
            CallbackLifecycle::new(
                AgLifecycleCallbacks {
                    struct_size: size_of::<AgLifecycleCallbacks>() as u32,
                    abi_version: AG_ABI_VERSION_1,
                    user_data: std::ptr::from_mut(self).cast(),
                    store_issued: Some(contract_store),
                    begin_attempt: Some(contract_begin),
                    finish_attempt: Some(contract_finish),
                },
                flag,
            )
        }

        fn keys(&mut self, flag: Arc<AtomicBool>) -> CallbackKeys {
            CallbackKeys::new(
                AgKeyCallbacks {
                    struct_size: size_of::<AgKeyCallbacks>() as u32,
                    abi_version: AG_ABI_VERSION_1,
                    user_data: std::ptr::from_mut(self).cast(),
                    active_key: Some(contract_active),
                    key_by_id: Some(contract_by_id),
                },
                flag,
            )
        }

        fn clean_host_allocations(&self) {
            for (address, len) in self.host_allocations.lock().unwrap().drain(..) {
                if len != 0 {
                    drop(unsafe { Vec::from_raw_parts(address as *mut u8, len, len) });
                }
            }
        }
    }

    unsafe extern "C" fn contract_release(data: *mut c_void, bytes: *mut u8, len: usize) {
        let fixture = unsafe { &*data.cast::<ContractFixture>() };
        fixture.releases.fetch_add(1, Ordering::SeqCst);
        if !bytes.is_null() && len != 0 {
            drop(unsafe { Vec::from_raw_parts(bytes, len, len) });
        }
    }

    unsafe fn copy_slice(slice: AgByteSlice) -> Vec<u8> {
        unsafe { slice.copy_bytes() }.unwrap()
    }

    unsafe fn write_spec(
        fixture: &ContractFixture,
        out: *mut AgHostBuffer,
        spec: OutputSpec,
        rust_owns: bool,
    ) {
        match spec {
            OutputSpec::Bytes(bytes) => {
                write_bytes(fixture, out, bytes, false, rust_owns);
            }
            OutputSpec::MissingRelease(bytes) => {
                write_bytes(fixture, out, bytes, true, rust_owns);
            }
            OutputSpec::NullNonzero => unsafe {
                *out = AgHostBuffer {
                    data: std::ptr::null_mut(),
                    len: 1,
                    release_data: std::ptr::from_ref(fixture).cast_mut().cast(),
                    release: Some(contract_release),
                }
            },
        }
    }

    fn write_bytes(
        fixture: &ContractFixture,
        out: *mut AgHostBuffer,
        bytes: Vec<u8>,
        missing_release: bool,
        rust_owns: bool,
    ) {
        let mut bytes = bytes.into_boxed_slice();
        let len = bytes.len();
        let data = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        if missing_release || !rust_owns {
            fixture
                .host_allocations
                .lock()
                .unwrap()
                .push((data as usize, len));
        }
        unsafe {
            *out = AgHostBuffer {
                data,
                len,
                release_data: std::ptr::from_ref(fixture).cast_mut().cast(),
                release: (!missing_release).then_some(contract_release),
            }
        };
    }

    unsafe extern "C" fn contract_store(
        data: *mut c_void,
        material: AgByteSlice,
        binding: AgByteSlice,
        limit: u32,
    ) -> i32 {
        let fixture = unsafe { &*data.cast::<ContractFixture>() };
        fixture.store_calls.lock().unwrap().push((
            unsafe { copy_slice(material) },
            unsafe { copy_slice(binding) },
            limit,
        ));
        fixture.store_status.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn contract_begin(
        data: *mut c_void,
        identity: AgByteSlice,
        binding: AgByteSlice,
        time: i64,
        material: *mut AgHostBuffer,
        token: *mut AgHostBuffer,
    ) -> i32 {
        let fixture = unsafe { &*data.cast::<ContractFixture>() };
        let status = fixture.begin_status.load(Ordering::SeqCst);
        fixture.begin_calls.lock().unwrap().push((
            unsafe { copy_slice(identity) },
            unsafe { copy_slice(binding) },
            time,
        ));
        unsafe {
            write_spec(
                fixture,
                material,
                fixture.material.lock().unwrap().clone(),
                status == 0,
            )
        };
        unsafe {
            write_spec(
                fixture,
                token,
                fixture.token.lock().unwrap().clone(),
                status == 0,
            )
        };
        status
    }

    unsafe extern "C" fn contract_finish(
        data: *mut c_void,
        token: AgByteSlice,
        outcome: i32,
    ) -> i32 {
        let fixture = unsafe { &*data.cast::<ContractFixture>() };
        fixture
            .finish_calls
            .lock()
            .unwrap()
            .push((unsafe { copy_slice(token) }, outcome));
        fixture.finish_status.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn contract_active(
        data: *mut c_void,
        key_id: *mut AgHostBuffer,
        key: *mut AgHostBuffer,
    ) -> i32 {
        let fixture = unsafe { &*data.cast::<ContractFixture>() };
        let status = fixture.key_status.load(Ordering::SeqCst);
        unsafe {
            write_spec(
                fixture,
                key_id,
                fixture.key_id.lock().unwrap().clone(),
                status == 0,
            )
        };
        unsafe {
            write_spec(
                fixture,
                key,
                fixture.key.lock().unwrap().clone(),
                status == 0,
            )
        };
        status
    }

    unsafe extern "C" fn contract_by_id(
        data: *mut c_void,
        key_id: AgByteSlice,
        key: *mut AgHostBuffer,
    ) -> i32 {
        let fixture = unsafe { &*data.cast::<ContractFixture>() };
        let status = fixture.key_status.load(Ordering::SeqCst);
        fixture
            .by_id_calls
            .lock()
            .unwrap()
            .push(unsafe { copy_slice(key_id) });
        unsafe {
            write_spec(
                fixture,
                key,
                fixture.key.lock().unwrap().clone(),
                status == 0,
            )
        };
        status
    }

    fn private_material() -> PrivateChallengeMaterial {
        PrivateChallengeMaterial {
            challenge_id: "challenge".into(),
            generator_version: "1.0".into(),
            nonce: "nonce".into(),
            issued_at: 10,
            expires_at: 20,
            mac_key_id: "primary".into(),
            answer_mac: "secret-mac".into(),
            answer_encoding: AnswerEncoding::Base64Url,
        }
    }

    fn private_json() -> Vec<u8> {
        serde_json::to_vec(&private_material()).unwrap()
    }

    #[test]
    fn store_issued_passes_exact_json_binding_and_attempt_limits() {
        let mut fixture = ContractFixture::new();
        let flag = Arc::new(AtomicBool::new(false));
        let mut adapter = fixture.lifecycle(flag);
        for limit in [AttemptLimit::One, AttemptLimit::Two] {
            adapter
                .store_issued(private_material(), b"exact-binding", limit)
                .unwrap();
        }
        let calls = fixture.store_calls.lock().unwrap();
        assert_eq!(calls[0], (private_json(), b"exact-binding".to_vec(), 1));
        assert_eq!(calls[1], (private_json(), b"exact-binding".to_vec(), 2));
    }

    #[test]
    fn begin_and_finish_pass_exact_callback_inputs_and_outcomes() {
        let mut fixture = ContractFixture::new();
        let flag = Arc::new(AtomicBool::new(false));
        let mut adapter = fixture.lifecycle(flag);
        adapter
            .begin_attempt(
                SubmissionIdentity::new("challenge", "secret-nonce"),
                b"binding",
                1_234,
            )
            .unwrap();
        assert_eq!(
            fixture.begin_calls.lock().unwrap()[0],
            (
                br#"{"challenge_id":"challenge","nonce":"secret-nonce"}"#.to_vec(),
                b"binding".to_vec(),
                1_234
            )
        );
        for (outcome, raw) in [
            (AttemptOutcome::Accepted, 1),
            (AttemptOutcome::Rejected, 2),
            (AttemptOutcome::SystemFailure, 3),
        ] {
            adapter
                .finish_attempt(b"opaque-token".to_vec(), outcome)
                .unwrap();
            assert_eq!(
                fixture.finish_calls.lock().unwrap().last().unwrap(),
                &(b"opaque-token".to_vec(), raw)
            );
        }
    }

    #[test]
    fn service_round_trips_successful_begin_token_into_finish() {
        let mut fixture = ContractFixture::new();
        let mut invalid_material = private_material();
        invalid_material.mac_key_id.clear();
        *fixture.material.lock().unwrap() =
            OutputSpec::Bytes(serde_json::to_vec(&invalid_material).unwrap());
        let flag = Arc::new(AtomicBool::new(false));
        let lifecycle = fixture.lifecycle(Arc::clone(&flag));
        let keys = fixture.keys(flag);
        let mut service = ChallengeService::new(lifecycle, keys);
        let submission = Submission {
            challenge_id: "challenge".into(),
            nonce: "nonce".into(),
            answer: "AQ".into(),
        };
        assert_eq!(
            service.verify_submission(VerifyRequest::new(&submission, b"binding").unwrap()),
            Err(ServiceError::InvalidChallengeMaterial)
        );
        assert_eq!(
            fixture.finish_calls.lock().unwrap().as_slice(),
            &[(b"opaque-token".to_vec(), 3)]
        );
    }

    #[test]
    fn unknown_actual_callback_statuses_mark_protocol_violation() {
        let mut fixture = ContractFixture::new();
        let flag = Arc::new(AtomicBool::new(false));
        fixture.store_status.store(99, Ordering::SeqCst);
        assert!(
            fixture
                .lifecycle(Arc::clone(&flag))
                .store_issued(private_material(), b"b", AttemptLimit::One)
                .is_err()
        );
        assert!(flag.swap(false, Ordering::SeqCst));
        fixture.begin_status.store(99, Ordering::SeqCst);
        assert!(
            fixture
                .lifecycle(Arc::clone(&flag))
                .begin_attempt(SubmissionIdentity::new("id", "n"), b"b", 0)
                .is_err()
        );
        assert!(flag.swap(false, Ordering::SeqCst));
        fixture.finish_status.store(99, Ordering::SeqCst);
        assert!(
            fixture
                .lifecycle(Arc::clone(&flag))
                .finish_attempt(Vec::new(), AttemptOutcome::Rejected)
                .is_err()
        );
        assert!(flag.swap(false, Ordering::SeqCst));
        fixture.key_status.store(99, Ordering::SeqCst);
        assert!(fixture.keys(Arc::clone(&flag)).active_key().is_err());
        assert!(flag.swap(false, Ordering::SeqCst));
        assert!(fixture.keys(Arc::clone(&flag)).key_by_id("id").is_err());
        assert!(flag.load(Ordering::SeqCst));
        fixture.clean_host_allocations();
    }

    #[test]
    fn non_ok_begin_outputs_remain_host_owned() {
        let mut fixture = ContractFixture::new();
        fixture.begin_status.store(1, Ordering::SeqCst);
        let flag = Arc::new(AtomicBool::new(false));
        assert!(
            fixture
                .lifecycle(flag)
                .begin_attempt(SubmissionIdentity::new("id", "n"), b"b", 0)
                .is_err()
        );
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.host_allocations.lock().unwrap().len(), 2);
        fixture.clean_host_allocations();

        let mut fixture = ContractFixture::new();
        fixture.key_status.store(1, Ordering::SeqCst);
        let flag = Arc::new(AtomicBool::new(false));
        assert!(fixture.keys(flag).active_key().is_err());
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.host_allocations.lock().unwrap().len(), 2);
        fixture.clean_host_allocations();
    }

    #[test]
    fn malformed_begin_json_releases_both_owned_outputs() {
        let mut fixture = ContractFixture::new();
        *fixture.material.lock().unwrap() = OutputSpec::Bytes(b"not-json".to_vec());
        let flag = Arc::new(AtomicBool::new(false));
        assert!(
            fixture
                .lifecycle(Arc::clone(&flag))
                .begin_attempt(SubmissionIdentity::new("id", "n"), b"b", 0)
                .is_err()
        );
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn malformed_host_buffers_and_required_empty_outputs_are_closed() {
        for spec in [
            OutputSpec::NullNonzero,
            OutputSpec::MissingRelease(vec![7; 32]),
            OutputSpec::Bytes(Vec::new()),
        ] {
            let mut fixture = ContractFixture::new();
            *fixture.key.lock().unwrap() = spec;
            let flag = Arc::new(AtomicBool::new(false));
            assert!(fixture.keys(Arc::clone(&flag)).active_key().is_err());
            assert!(flag.load(Ordering::SeqCst));
            assert_eq!(
                fixture.releases.load(Ordering::SeqCst),
                2 - usize::from(matches!(
                    *fixture.key.lock().unwrap(),
                    OutputSpec::MissingRelease(_)
                ))
            );
            fixture.clean_host_allocations();
        }

        let mut fixture = ContractFixture::new();
        *fixture.material.lock().unwrap() = OutputSpec::Bytes(Vec::new());
        let flag = Arc::new(AtomicBool::new(false));
        assert!(
            fixture
                .lifecycle(Arc::clone(&flag))
                .begin_attempt(SubmissionIdentity::new("id", "n"), b"b", 0)
                .is_err()
        );
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 2);

        let mut fixture = ContractFixture::new();
        *fixture.key_id.lock().unwrap() = OutputSpec::Bytes(Vec::new());
        let flag = Arc::new(AtomicBool::new(false));
        assert!(fixture.keys(Arc::clone(&flag)).active_key().is_err());
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn active_key_rejects_invalid_ids_and_short_keys_with_exact_release() {
        let cases = [
            (
                OutputSpec::Bytes(Vec::new()),
                OutputSpec::Bytes(vec![7; 32]),
            ),
            (
                OutputSpec::Bytes(vec![0xff]),
                OutputSpec::Bytes(vec![7; 32]),
            ),
            (
                OutputSpec::Bytes(vec![b'x'; agentgate_core::MAX_MAC_KEY_ID_BYTES + 1]),
                OutputSpec::Bytes(vec![7; 32]),
            ),
            (
                OutputSpec::Bytes(b"id".to_vec()),
                OutputSpec::Bytes(vec![7; 31]),
            ),
        ];
        for (id, key) in cases {
            let mut fixture = ContractFixture::new();
            *fixture.key_id.lock().unwrap() = id;
            *fixture.key.lock().unwrap() = key;
            let flag = Arc::new(AtomicBool::new(false));
            assert!(fixture.keys(Arc::clone(&flag)).active_key().is_err());
            assert!(flag.load(Ordering::SeqCst));
            assert_eq!(fixture.releases.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn key_by_id_passes_exact_id_and_rejects_empty_or_short_keys() {
        for key in [
            OutputSpec::Bytes(Vec::new()),
            OutputSpec::Bytes(vec![7; 31]),
        ] {
            let mut fixture = ContractFixture::new();
            *fixture.key.lock().unwrap() = key;
            let flag = Arc::new(AtomicBool::new(false));
            assert!(
                fixture
                    .keys(Arc::clone(&flag))
                    .key_by_id("exact-id")
                    .is_err()
            );
            assert_eq!(fixture.by_id_calls.lock().unwrap()[0], b"exact-id");
            assert!(flag.load(Ordering::SeqCst));
            assert_eq!(fixture.releases.load(Ordering::SeqCst), 1);
        }
    }

    unsafe extern "C" fn record_observer(data: *mut c_void, json: AgByteSlice) {
        let calls = unsafe { &*data.cast::<Mutex<Vec<Vec<u8>>>>() };
        calls.lock().unwrap().push(unsafe { copy_slice(json) });
    }

    #[test]
    fn observer_is_optional_and_forwards_safe_json_synchronously() {
        let flag = Arc::new(AtomicBool::new(false));
        let event = ServiceEvent::ServiceFailed(ServiceFailureEvent {
            challenge_id: None,
            generator_version: None,
            stage: ServiceStage::Clock,
            error: ServiceError::InternalError,
            attempts: 0,
            duration: std::time::Duration::ZERO,
        });
        CallbackObserver::new(None, Arc::clone(&flag)).observe(&event);
        assert!(!flag.load(Ordering::SeqCst));

        let mut calls: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
        let callbacks = AgObserverCallbacks {
            struct_size: size_of::<AgObserverCallbacks>() as u32,
            abi_version: AG_ABI_VERSION_1,
            user_data: std::ptr::from_mut(&mut calls).cast(),
            observe: Some(record_observer),
        };
        CallbackObserver::new(Some(callbacks), Arc::clone(&flag)).observe(&event);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let json = std::str::from_utf8(&calls[0]).unwrap();
        assert!(json.contains(r#""event":"service_failed""#));
        assert!(!json.contains("answer"));
        assert!(!flag.load(Ordering::SeqCst));
    }
}
