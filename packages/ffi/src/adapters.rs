use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use coggate_core::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, BeginAttemptError, KeyProviderError,
    LifecycleAdapter, LifecycleAdapterError, LifecycleRejection, MAX_MAC_KEY_ID_BYTES, MacKey,
    MacKeyProvider, Observer, PendingAttempt, SubmissionIdentity, service::ServiceEvent,
};
use zeroize::Zeroizing;

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

pub(crate) struct OpaqueAttemptToken(Zeroizing<Vec<u8>>);

impl OpaqueAttemptToken {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for OpaqueAttemptToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueAttemptToken([REDACTED])")
    }
}

impl CallbackLifecycle {
    /// Constructs a lifecycle adapter from a validated, copied callback table.
    ///
    /// # Safety
    ///
    /// The table's function pointers must remain callable and `user_data` must
    /// remain valid for the adapter lifetime. Its pointee must support
    /// host-synchronized, serialized calls from arbitrary threads. The callback
    /// functions and releases must obey the documented ABI ownership rules and
    /// must not unwind or reenter the same service handle.
    #[allow(dead_code)]
    pub(crate) unsafe fn new(
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

// SAFETY: `new` requires the callback table and user_data pointee to remain
// valid and host-synchronized for serialized invocation from arbitrary threads.
// The copied function pointers are immutable, and service handles serialize all
// access to the adapter. Those construction invariants therefore make moving
// the adapter between threads sound.
unsafe impl Send for CallbackLifecycle {}

impl LifecycleAdapter for CallbackLifecycle {
    type AttemptToken = OpaqueAttemptToken;

    fn store_issued(
        &mut self,
        material: coggate_contracts::PrivateChallengeMaterial,
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
            .copy_required()
            .map_err(|()| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?;
        let token = OpaqueAttemptToken::new(
            token_guard
                .copy_optional()
                .map_err(|()| BeginAttemptError::Adapter(LifecycleAdapterError::Internal))?,
        );
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
                byte_slice(token.expose()),
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
    /// Constructs a key adapter from a validated, copied callback table.
    ///
    /// # Safety
    ///
    /// The table's function pointers must remain callable and `user_data` must
    /// remain valid for the adapter lifetime. Its pointee must support
    /// host-synchronized, serialized calls from arbitrary threads. The callback
    /// functions and releases must obey the documented ABI ownership rules and
    /// must not unwind or reenter the same service handle.
    #[allow(dead_code)]
    pub(crate) unsafe fn new(
        callbacks: AgKeyCallbacks,
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

// SAFETY: `new` requires the callback table and user_data pointee to remain
// valid and host-synchronized for serialized invocation from arbitrary threads.
// The copied function pointers are immutable, and service handles serialize all
// access to the adapter. Those construction invariants therefore make moving
// the adapter between threads sound.
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
            .copy_required()
            .map_err(|()| KeyProviderError::InvalidMaterial)?;
        let key_id = String::from_utf8(key_id_bytes).map_err(|_| {
            self.mark_violation();
            KeyProviderError::InvalidMaterial
        })?;
        if key_id.len() > MAX_MAC_KEY_ID_BYTES {
            self.mark_violation();
            return Err(KeyProviderError::InvalidMaterial);
        }
        let key_bytes = key_guard
            .copy_required()
            .map_err(|()| KeyProviderError::InvalidMaterial)?;
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
            .copy_required()
            .map_err(|()| KeyProviderError::InvalidMaterial)?;
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
    /// Constructs an observer adapter from a validated, copied callback table.
    ///
    /// # Safety
    ///
    /// For `Some`, the function pointer must remain callable and `user_data`
    /// must remain valid for the adapter lifetime. Its pointee must support
    /// host-synchronized, serialized calls from arbitrary threads. The callback
    /// must obey the documented ABI borrowing rules and must not unwind or
    /// reenter the same service handle.
    #[allow(dead_code)]
    pub(crate) unsafe fn new(
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

// SAFETY: `new` requires any callback table and user_data pointee to remain
// valid and host-synchronized for serialized invocation from arbitrary threads.
// The copied function pointer is immutable, and service handles serialize all
// access to the adapter. Those construction invariants therefore make moving
// the adapter between threads sound.
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
mod tests;
