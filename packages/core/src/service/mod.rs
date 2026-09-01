mod error;
mod keys;
mod lifecycle;
mod model;
mod observer;

pub use error::{
    BeginAttemptError, KeyProviderError, LifecycleAdapterError, LifecycleRejection, ServiceError,
};
pub use keys::{ActiveMacKey, MAX_MAC_KEY_ID_BYTES, MIN_MAC_KEY_BYTES, MacKey, MacKeyProvider};
pub use lifecycle::LifecycleAdapter;
pub use model::{
    AttemptLimit, AttemptOutcome, IssueRequest, MAX_BINDING_BYTES, PendingAttempt,
    SubmissionIdentity, VerificationOutcome, VerifyRequest,
};
pub use observer::{
    ChallengeIssuedEvent, NoopObserver, Observer, SecretLengthBucket, ServiceEvent,
    ServiceFailureEvent, ServiceStage, VerificationDisposition, VerificationEvent,
};

#[expect(dead_code, reason = "consumed by Phase 4 orchestration")]
pub struct ChallengeService<L, K, O = NoopObserver> {
    lifecycle: L,
    keys: K,
    observer: O,
}

impl<L, K> ChallengeService<L, K, NoopObserver> {
    pub fn new(lifecycle: L, keys: K) -> Self {
        Self {
            lifecycle,
            keys,
            observer: NoopObserver,
        }
    }
}

impl<L, K, O> ChallengeService<L, K, O> {
    pub fn with_observer(lifecycle: L, keys: K, observer: O) -> Self {
        Self {
            lifecycle,
            keys,
            observer,
        }
    }
}
