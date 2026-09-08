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
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use agentgate_core::{
        AttemptOutcome, BeginAttemptError, KeyProviderError, LifecycleAdapter,
        LifecycleAdapterError, LifecycleRejection, MacKeyProvider, SubmissionIdentity,
    };

    use crate::{
        AG_ABI_VERSION_1, AgBeginStatus, AgByteSlice, AgHostBuffer, AgKeyCallbacks,
        AgLifecycleCallbacks,
    };

    use super::{CallbackKeys, CallbackLifecycle};

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
}
