#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agentgate_core::{
        LifecycleRejection, SubmissionIdentity, VerificationOutcome,
        generation::RenderLanguage,
        service::{ChallengeIssuedEvent, SecretLengthBucket, ServiceEvent},
    };

    use super::{
        parse_private_material, parse_submission, serialize_event, serialize_identity,
        serialize_outcome,
    };

    #[test]
    fn contract_json_parsers_reject_unknown_fields() {
        assert!(parse_private_material(br#"{"unexpected":true}"#).is_err());
        assert!(
            parse_submission(
                br#"{"challenge_id":"id","nonce":"n","answer":"a","unexpected":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn identity_and_outcomes_have_exact_tagged_json() {
        assert_eq!(
            String::from_utf8(
                serialize_identity(SubmissionIdentity::new("id", "secret-nonce")).unwrap()
            )
            .unwrap(),
            r#"{"challenge_id":"id","nonce":"secret-nonce"}"#
        );
        assert_eq!(
            String::from_utf8(serialize_outcome(VerificationOutcome::Accepted).unwrap()).unwrap(),
            r#"{"status":"accepted"}"#
        );
        assert_eq!(
            String::from_utf8(
                serialize_outcome(VerificationOutcome::Rejected(
                    LifecycleRejection::BindingMismatch
                ))
                .unwrap()
            )
            .unwrap(),
            r#"{"status":"rejected","reason":"binding_mismatch"}"#
        );
        for (reason, expected) in [
            (LifecycleRejection::NotFound, "not_found"),
            (LifecycleRejection::Expired, "expired"),
            (LifecycleRejection::AlreadyConsumed, "already_consumed"),
            (LifecycleRejection::BindingMismatch, "binding_mismatch"),
            (LifecycleRejection::NonceMismatch, "nonce_mismatch"),
            (LifecycleRejection::AttemptsExhausted, "attempts_exhausted"),
        ] {
            let json = String::from_utf8(
                serialize_outcome(VerificationOutcome::Rejected(reason)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                json,
                format!(r#"{{"status":"rejected","reason":"{expected}"}}"#)
            );
        }
    }

    #[test]
    fn observer_json_contains_only_allowlisted_fields() {
        let event = ServiceEvent::ChallengeIssued(ChallengeIssuedEvent {
            challenge_id: "public-id".into(),
            generator_version: "1.0".into(),
            secret_length_bucket: SecretLengthBucket::EightToTen,
            fragment_count: 3,
            question_byte_length: 123,
            render_languages: vec![RenderLanguage::C, RenderLanguage::Cpp],
            has_distractor: true,
            candidate_attempts: 2,
            duration: Duration::from_micros(7),
        });
        let json = String::from_utf8(serialize_event(&event).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"event":"challenge_issued","challenge_id":"public-id","generator_version":"1.0","secret_length_bucket":"eight_to_ten","fragment_count":3,"question_byte_length":123,"render_languages":["c","cpp"],"has_distractor":true,"candidate_attempts":2,"duration_us":7}"#
        );
        for sentinel in [
            "answer",
            "binding",
            "nonce",
            "mac",
            "key",
            "private",
            "question\"",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(sentinel),
                "found {sentinel} in {json}"
            );
        }
    }
}
use std::time::Duration;

use agentgate_contracts::{PrivateChallengeMaterial, Submission};
use agentgate_core::{
    LifecycleRejection, SubmissionIdentity, VerificationOutcome,
    generation::RenderLanguage,
    service::{
        ChallengeIssuedEvent, SecretLengthBucket, ServiceEvent, ServiceFailureEvent, ServiceStage,
        VerificationDisposition, VerificationEvent,
    },
};
use serde::Serialize;

#[derive(Serialize)]
struct SubmissionIdentityDto<'a> {
    challenge_id: &'a str,
    nonce: &'a str,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(dead_code)]
enum VerificationOutcomeDto {
    Accepted,
    Rejected { reason: &'static str },
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum ServiceEventDto<'a> {
    ChallengeIssued(ChallengeIssuedDto<'a>),
    IssueFailed(ServiceFailureDto<'a>),
    VerificationCompleted(VerificationDto<'a>),
    ServiceFailed(ServiceFailureDto<'a>),
}

#[derive(Serialize)]
struct ChallengeIssuedDto<'a> {
    challenge_id: &'a str,
    generator_version: &'a str,
    secret_length_bucket: &'static str,
    fragment_count: usize,
    question_byte_length: usize,
    render_languages: Vec<&'static str>,
    has_distractor: bool,
    candidate_attempts: usize,
    duration_us: u64,
}

#[derive(Serialize)]
struct ServiceFailureDto<'a> {
    challenge_id: Option<&'a str>,
    generator_version: Option<&'a str>,
    stage: &'static str,
    error: &'static str,
    attempts: usize,
    duration_us: u64,
}

#[derive(Serialize)]
struct VerificationDto<'a> {
    challenge_id: &'a str,
    generator_version: Option<&'a str>,
    disposition: &'static str,
    elapsed_since_issue_us: Option<u64>,
    duration_us: u64,
}

pub(crate) fn parse_private_material(bytes: &[u8]) -> Result<PrivateChallengeMaterial, ()> {
    serde_json::from_slice(bytes).map_err(|_| ())
}

#[allow(dead_code)]
pub(crate) fn parse_submission(bytes: &[u8]) -> Result<Submission, ()> {
    serde_json::from_slice(bytes).map_err(|_| ())
}

pub(crate) fn serialize_identity(identity: SubmissionIdentity<'_>) -> Result<Vec<u8>, ()> {
    serde_json::to_vec(&SubmissionIdentityDto {
        challenge_id: identity.challenge_id(),
        nonce: identity.nonce(),
    })
    .map_err(|_| ())
}

#[allow(dead_code)]
pub(crate) fn serialize_outcome(outcome: VerificationOutcome) -> Result<Vec<u8>, ()> {
    let dto = match outcome {
        VerificationOutcome::Accepted => VerificationOutcomeDto::Accepted,
        VerificationOutcome::Rejected(reason) => VerificationOutcomeDto::Rejected {
            reason: rejection_name(reason),
        },
    };
    serde_json::to_vec(&dto).map_err(|_| ())
}

pub(crate) fn serialize_event(event: &ServiceEvent) -> Result<Vec<u8>, ()> {
    let dto = match event {
        ServiceEvent::ChallengeIssued(event) => {
            ServiceEventDto::ChallengeIssued(challenge_issued_dto(event))
        }
        ServiceEvent::IssueFailed(event) => ServiceEventDto::IssueFailed(failure_dto(event)),
        ServiceEvent::VerificationCompleted(event) => {
            ServiceEventDto::VerificationCompleted(verification_dto(event))
        }
        ServiceEvent::ServiceFailed(event) => ServiceEventDto::ServiceFailed(failure_dto(event)),
    };
    serde_json::to_vec(&dto).map_err(|_| ())
}

fn challenge_issued_dto(event: &ChallengeIssuedEvent) -> ChallengeIssuedDto<'_> {
    ChallengeIssuedDto {
        challenge_id: &event.challenge_id,
        generator_version: &event.generator_version,
        secret_length_bucket: match event.secret_length_bucket {
            SecretLengthBucket::EightToTen => "eight_to_ten",
            SecretLengthBucket::ElevenToThirteen => "eleven_to_thirteen",
            SecretLengthBucket::FourteenToSixteen => "fourteen_to_sixteen",
        },
        fragment_count: event.fragment_count,
        question_byte_length: event.question_byte_length,
        render_languages: event
            .render_languages
            .iter()
            .copied()
            .map(language_name)
            .collect(),
        has_distractor: event.has_distractor,
        candidate_attempts: event.candidate_attempts,
        duration_us: duration_us(event.duration),
    }
}

fn failure_dto(event: &ServiceFailureEvent) -> ServiceFailureDto<'_> {
    ServiceFailureDto {
        challenge_id: event.challenge_id.as_deref(),
        generator_version: event.generator_version.as_deref(),
        stage: stage_name(event.stage),
        error: event.error.code(),
        attempts: event.attempts,
        duration_us: duration_us(event.duration),
    }
}

fn verification_dto(event: &VerificationEvent) -> VerificationDto<'_> {
    VerificationDto {
        challenge_id: &event.challenge_id,
        generator_version: event.generator_version.as_deref(),
        disposition: disposition_name(event.disposition),
        elapsed_since_issue_us: event.elapsed_since_issue.map(duration_us),
        duration_us: duration_us(event.duration),
    }
}

fn rejection_name(reason: LifecycleRejection) -> &'static str {
    match reason {
        LifecycleRejection::NotFound => "not_found",
        LifecycleRejection::Expired => "expired",
        LifecycleRejection::AlreadyConsumed => "already_consumed",
        LifecycleRejection::BindingMismatch => "binding_mismatch",
        LifecycleRejection::NonceMismatch => "nonce_mismatch",
        LifecycleRejection::AttemptsExhausted => "attempts_exhausted",
    }
}

fn disposition_name(disposition: VerificationDisposition) -> &'static str {
    match disposition {
        VerificationDisposition::Accepted => "accepted",
        VerificationDisposition::LifecycleRejected(reason) => rejection_name(reason),
        VerificationDisposition::InvalidAnswerEncoding => "invalid_answer_encoding",
        VerificationDisposition::AnswerMismatch => "answer_mismatch",
        VerificationDisposition::SystemFailure => "system_failure",
    }
}

fn stage_name(stage: ServiceStage) -> &'static str {
    match stage {
        ServiceStage::Request => "request",
        ServiceStage::VersionDispatch => "version_dispatch",
        ServiceStage::Candidate => "candidate",
        ServiceStage::Clock => "clock",
        ServiceStage::KeyProvider => "key_provider",
        ServiceStage::LifecycleStore => "lifecycle_store",
        ServiceStage::LifecycleBegin => "lifecycle_begin",
        ServiceStage::CoreVerification => "core_verification",
        ServiceStage::LifecycleFinish => "lifecycle_finish",
    }
}

fn language_name(language: RenderLanguage) -> &'static str {
    match language {
        RenderLanguage::C => "c",
        RenderLanguage::Cpp => "cpp",
        RenderLanguage::Rust => "rust",
        RenderLanguage::Go => "go",
        RenderLanguage::Java => "java",
        RenderLanguage::Pseudocode => "pseudocode",
    }
}

fn duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
