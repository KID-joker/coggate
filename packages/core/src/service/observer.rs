use std::time::Duration;

use crate::generation::RenderLanguage;

use super::{LifecycleRejection, ServiceError};

pub trait Observer {
    fn observe(&mut self, event: &ServiceEvent);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopObserver;

impl Observer for NoopObserver {
    fn observe(&mut self, _event: &ServiceEvent) {}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceEvent {
    ChallengeIssued(ChallengeIssuedEvent),
    IssueFailed(ServiceFailureEvent),
    VerificationCompleted(VerificationEvent),
    ServiceFailed(ServiceFailureEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretLengthBucket {
    EightToTen,
    ElevenToThirteen,
    FourteenToSixteen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStage {
    Request,
    VersionDispatch,
    Candidate,
    Clock,
    KeyProvider,
    LifecycleStore,
    LifecycleBegin,
    CoreVerification,
    LifecycleFinish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDisposition {
    Accepted,
    LifecycleRejected(LifecycleRejection),
    InvalidAnswerEncoding,
    AnswerMismatch,
    SystemFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeIssuedEvent {
    pub challenge_id: String,
    pub generator_version: String,
    pub secret_length_bucket: SecretLengthBucket,
    pub fragment_count: usize,
    pub question_byte_length: usize,
    pub render_languages: Vec<RenderLanguage>,
    pub has_distractor: bool,
    pub candidate_attempts: usize,
    pub duration: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceFailureEvent {
    pub challenge_id: Option<String>,
    pub generator_version: Option<String>,
    pub stage: ServiceStage,
    pub error: ServiceError,
    pub attempts: usize,
    pub duration: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationEvent {
    pub challenge_id: String,
    pub generator_version: Option<String>,
    pub disposition: VerificationDisposition,
    pub elapsed_since_issue: Option<Duration>,
    pub duration: Duration,
}
