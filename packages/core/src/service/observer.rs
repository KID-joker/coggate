use std::time::Duration;
use std::{panic::AssertUnwindSafe, panic::catch_unwind};

use crate::generation::RenderLanguage;

use super::{LifecycleRejection, ServiceError};

/// Receives a fixed allowlist of secret-safe lifecycle events.
///
/// Callbacks are synchronous diagnostics only: their return value cannot
/// authorize a request or change a durable lifecycle result. Under an
/// unwind-capable Rust build, [`ChallengeService`](crate::ChallengeService)
/// catches and discards callback panics. A host compiled with panic-abort still
/// controls process-abort behavior.
///
/// Success and completion events are emitted only after the durable decision
/// they describe; failure callbacks cannot change the operation result. Events
/// never contain bindings, answers, nonces, MACs, key material or key IDs, private
/// challenge material, complete questions, render plans, or adapter/provider
/// error text. Implementations must preserve that boundary in their own
/// enrichment and logging.
pub trait Observer {
    /// Observes one already-classified service event.
    fn observe(&mut self, event: &ServiceEvent);
}

/// Observer implementation that discards every event.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopObserver;

impl Observer for NoopObserver {
    fn observe(&mut self, _event: &ServiceEvent) {}
}

pub(super) fn observe_safely(observer: &mut impl Observer, event: &ServiceEvent) {
    let _discarded_observer_panic = catch_unwind(AssertUnwindSafe(|| observer.observe(event)));
}

/// Secret-safe events emitted by [`crate::ChallengeService`].
///
/// `ChallengeIssued` includes the now-public challenge ID after durable store.
/// A lifecycle rejection may include a canonical submitted ID; a completed
/// core verification includes the canonical stored ID. System failures omit
/// IDs and versions. Versions appear only when they are recognized and bounded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceEvent {
    /// A public challenge became returnable after durable private-state storage.
    ChallengeIssued(ChallengeIssuedEvent),
    /// Issuance failed, with no public challenge returned.
    IssueFailed(ServiceFailureEvent),
    /// Verification reached a durable normal acceptance or rejection decision.
    VerificationCompleted(VerificationEvent),
    /// Verification encountered a system failure.
    ServiceFailed(ServiceFailureEvent),
}

/// Coarse secret-length telemetry that avoids exposing the exact length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretLengthBucket {
    /// An 8- through 10-byte generated secret.
    EightToTen,
    /// An 11- through 13-byte generated secret.
    ElevenToThirteen,
    /// A 14- through 16-byte generated secret.
    FourteenToSixteen,
}

/// Stable processing stage attached to a service failure event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStage {
    /// Request validation.
    Request,
    /// Strict generator-version dispatch.
    VersionDispatch,
    /// Candidate or random-token generation.
    Candidate,
    /// Server clock acquisition or timestamp calculation.
    Clock,
    /// MAC key acquisition or exact key lookup.
    KeyProvider,
    /// Initial private-state persistence.
    LifecycleStore,
    /// Atomic lifecycle validation and reservation.
    LifecycleBegin,
    /// MAC construction, material validation, or answer verification.
    CoreVerification,
    /// Durable finalization of a reserved attempt.
    LifecycleFinish,
}

/// Stable, secret-free disposition of a completed verification observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDisposition {
    /// Verification was accepted and durable consumption succeeded.
    Accepted,
    /// Lifecycle storage rejected the attempt before private material was used.
    LifecycleRejected(LifecycleRejection),
    /// The submitted answer was not canonical unpadded base64url.
    InvalidAnswerEncoding,
    /// The submitted answer did not authenticate.
    AnswerMismatch,
    /// Verification could not complete because of a system failure.
    ///
    /// Current service failures are reported through
    /// [`ServiceEvent::ServiceFailed`]; this variant is reserved for stable
    /// disposition compatibility.
    SystemFailure,
}

/// Allowlisted metadata for successful issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeIssuedEvent {
    /// Public challenge identifier, emitted only after durable storage.
    pub challenge_id: String,
    /// Supported generator version used for issuance.
    pub generator_version: String,
    /// Coarse generated-secret length bucket.
    pub secret_length_bucket: SecretLengthBucket,
    /// Number of semantic fragments in the generated candidate.
    pub fragment_count: usize,
    /// UTF-8 byte length of the public question, not the question itself.
    pub question_byte_length: usize,
    /// Renderer languages present in the public question.
    pub render_languages: Vec<RenderLanguage>,
    /// Whether the public question contains a validated distractor.
    pub has_distractor: bool,
    /// Candidate attempts consumed before success, including the successful one.
    pub candidate_attempts: usize,
    /// Time spent generating the successful candidate.
    pub duration: Duration,
}

/// Allowlisted metadata for issuance or verification system failure.
///
/// Verification system failures omit challenge IDs and generator versions.
/// Issuance failures may include a recognized bounded version, but never
/// caller-controlled unsupported text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceFailureEvent {
    /// Optional safe challenge ID; currently omitted for service failures.
    pub challenge_id: Option<String>,
    /// Optional recognized, bounded generator version.
    pub generator_version: Option<String>,
    /// Stage at which the operation failed.
    pub stage: ServiceStage,
    /// Stable failure category without underlying diagnostic text.
    pub error: ServiceError,
    /// Candidate attempts consumed; zero when not applicable.
    pub attempts: usize,
    /// Non-secret duration measured for the reported operation or stage.
    pub duration: Duration,
}

/// Allowlisted metadata for a durably completed verification decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationEvent {
    /// Canonical challenge ID, or an empty string for a malformed submitted ID.
    pub challenge_id: String,
    /// Supported stored generator version when private material was available.
    pub generator_version: Option<String>,
    /// Stable verification disposition.
    pub disposition: VerificationDisposition,
    /// Nonnegative server-time interval since issuance, when computable.
    pub elapsed_since_issue: Option<Duration>,
    /// Time spent in core answer verification; zero when it did not run.
    pub duration: Duration,
}
