#![forbid(unsafe_code)]

mod answer;
mod error;
mod mac;
mod verifier;

pub mod service;

pub mod generation;

pub use agentgate_contracts as contracts;
pub use agentgate_contracts::{PrivateChallengeMaterial, Submission};
pub use answer::canonicalize_answer;
pub use error::CoreError;
pub use mac::{MacContext, compute_answer_mac};
pub use service::{
    ActiveMacKey, AttemptLimit, AttemptOutcome, BeginAttemptError, ChallengeIssuedEvent,
    ChallengeService, IssueRequest, KeyProviderError, LifecycleAdapter, LifecycleAdapterError,
    LifecycleRejection, MAX_BINDING_BYTES, MAX_MAC_KEY_ID_BYTES, MIN_MAC_KEY_BYTES, MacKey,
    MacKeyProvider, NoopObserver, Observer, PendingAttempt, SecretLengthBucket, ServiceError,
    ServiceEvent, ServiceFailureEvent, ServiceStage, SubmissionIdentity, VerificationDisposition,
    VerificationEvent, VerificationOutcome, VerifyRequest,
};
pub use verifier::verify_answer;
