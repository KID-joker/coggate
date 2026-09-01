#![allow(
    dead_code,
    reason = "crate-private candidate API is consumed by the Phase 4 service"
)]

use std::fmt;

use agentgate_contracts::{MAX_SECRET_LENGTH, MIN_SECRET_LENGTH, fragment_count_for_secret_length};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::{
    GenerationError,
    planner::plan_with,
    random::RandomSource,
    render::{MAX_QUESTION_BYTES, RenderMetadata, RenderedQuestion, render_with},
    secret::generate_with,
};

pub(crate) const MAX_CANDIDATE_ATTEMPTS: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateError {
    Rejected,
    RandomnessUnavailable,
    Internal,
    Exhausted,
}

pub(crate) fn retry_candidates<T>(
    mut generate: impl FnMut() -> Result<T, CandidateError>,
) -> Result<(T, u8), CandidateError> {
    for attempt in 1..=MAX_CANDIDATE_ATTEMPTS {
        match generate() {
            Ok(candidate) => return Ok((candidate, attempt)),
            Err(CandidateError::Rejected) if attempt < MAX_CANDIDATE_ATTEMPTS => continue,
            Err(CandidateError::Rejected) => return Err(CandidateError::Exhausted),
            Err(error) => return Err(error),
        }
    }

    unreachable!("bounded candidate attempts are non-empty")
}

pub(crate) struct ChallengeCandidate {
    question: RenderedQuestion,
    answer: String,
    secret_length: usize,
    fragment_count: usize,
    operation_count: usize,
}

impl ChallengeCandidate {
    pub(crate) fn question(&self) -> &str {
        self.question.question()
    }

    pub(crate) fn render_metadata(&self) -> &RenderMetadata {
        self.question.metadata()
    }

    pub(crate) fn answer(&self) -> &str {
        &self.answer
    }

    pub(crate) fn secret_length(&self) -> usize {
        self.secret_length
    }

    pub(crate) fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    pub(crate) fn operation_count(&self) -> usize {
        self.operation_count
    }
}

impl fmt::Debug for ChallengeCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChallengeCandidate")
            .field("question", &"[REDACTED]")
            .field("answer", &"[REDACTED]")
            .field("render_metadata", self.render_metadata())
            .field("secret_length", &self.secret_length)
            .field("fragment_count", &self.fragment_count)
            .field("operation_count", &self.operation_count)
            .finish()
    }
}

pub(crate) fn generate_candidate_with(
    random: &mut impl RandomSource,
) -> Result<ChallengeCandidate, CandidateError> {
    let secret = generate_with(random).map_err(map_generation_error)?;
    let secret_length = secret.len();
    let semantics = plan_with(&secret, random).map_err(map_generation_error)?;
    let fragment_count = semantics.fragments().len();
    let operation_count = semantics.graph().operation_count();
    let answer = URL_SAFE_NO_PAD.encode(semantics.answer());
    let question = render_with(semantics.graph(), semantics.fragments(), random)
        .map_err(|_| CandidateError::Rejected)?;

    let candidate = ChallengeCandidate {
        question,
        answer,
        secret_length,
        fragment_count,
        operation_count,
    };
    validate_candidate(&candidate)?;
    Ok(candidate)
}

fn map_generation_error(error: GenerationError) -> CandidateError {
    match error {
        GenerationError::RandomnessUnavailable => CandidateError::RandomnessUnavailable,
        _ => CandidateError::Rejected,
    }
}

fn validate_candidate(candidate: &ChallengeCandidate) -> Result<(), CandidateError> {
    let expected_fragment_count = fragment_count_for_secret_length(
        u8::try_from(candidate.secret_length).map_err(|_| CandidateError::Internal)?,
    )
    .ok_or(CandidateError::Internal)?;
    let canonical_answer = URL_SAFE_NO_PAD
        .decode(candidate.answer())
        .map(|decoded| URL_SAFE_NO_PAD.encode(decoded) == candidate.answer())
        .unwrap_or(false);

    if candidate.answer().is_empty()
        || !canonical_answer
        || candidate.question().len() != candidate.render_metadata().byte_length()
        || candidate.question().len() > MAX_QUESTION_BYTES
        || !(usize::from(MIN_SECRET_LENGTH)..=usize::from(MAX_SECRET_LENGTH))
            .contains(&candidate.secret_length)
        || candidate.fragment_count != usize::from(expected_fragment_count)
        || !(4..=8).contains(&candidate.operation_count)
        || !(2..=3).contains(&candidate.render_metadata().languages().len())
    {
        return Err(CandidateError::Internal);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use agentgate_contracts::fragment_count_for_secret_length;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{
        CandidateError, ChallengeCandidate, MAX_CANDIDATE_ATTEMPTS, generate_candidate_with,
        retry_candidates,
    };
    use crate::generation::{MAX_QUESTION_BYTES, test_random::DeterministicRandom};

    fn candidate_for_seed(seed: u8) -> ChallengeCandidate {
        let mut random = DeterministicRandom::new([seed; 32]);
        generate_candidate_with(&mut random).unwrap()
    }

    fn assert_candidate_invariants(candidate: &ChallengeCandidate) {
        let decoded = URL_SAFE_NO_PAD.decode(candidate.answer()).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(decoded), candidate.answer());
        assert!(!candidate.answer().is_empty());
        assert_eq!(
            candidate.question().len(),
            candidate.render_metadata().byte_length()
        );
        assert!(candidate.question().len() <= MAX_QUESTION_BYTES);
        assert!((8..=16).contains(&candidate.secret_length()));
        assert_eq!(
            candidate.fragment_count(),
            usize::from(fragment_count_for_secret_length(candidate.secret_length() as u8).unwrap())
        );
        assert!((4..=8).contains(&candidate.operation_count()));
        assert!((2..=3).contains(&candidate.render_metadata().languages().len()));

        let debug = format!("{candidate:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(candidate.question()));
        assert!(!debug.contains(candidate.answer()));
    }

    #[test]
    fn retries_rejections_until_a_candidate_succeeds() {
        let mut calls = 0;

        let result = retry_candidates(|| {
            calls += 1;
            if calls < 3 {
                Err(CandidateError::Rejected)
            } else {
                Ok(41)
            }
        });

        assert_eq!(result, Ok((41, 3)));
        assert_eq!(calls, 3);
    }

    #[test]
    fn exhausts_after_exactly_eight_rejections() {
        let mut calls = 0;

        let result: Result<((), u8), CandidateError> = retry_candidates(|| {
            calls += 1;
            Err(CandidateError::Rejected)
        });

        assert_eq!(result, Err(CandidateError::Exhausted));
        assert_eq!(calls, usize::from(MAX_CANDIDATE_ATTEMPTS));
    }

    #[test]
    fn does_not_retry_terminal_errors() {
        for error in [
            CandidateError::RandomnessUnavailable,
            CandidateError::Internal,
        ] {
            let mut calls = 0;
            let result: Result<((), u8), CandidateError> = retry_candidates(|| {
                calls += 1;
                Err(error)
            });

            assert_eq!(result, Err(error));
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn assembles_an_atomic_candidate_from_one_random_stream() {
        let candidate = candidate_for_seed(23);

        assert_candidate_invariants(&candidate);
    }

    #[test]
    fn candidate_generation_is_deterministic_for_the_same_seed() {
        let first = candidate_for_seed(23);
        let second = candidate_for_seed(23);

        assert_eq!(first.question(), second.question());
        assert_eq!(first.render_metadata(), second.render_metadata());
        assert_eq!(first.answer(), second.answer());
        assert_eq!(first.secret_length(), second.secret_length());
        assert_eq!(first.fragment_count(), second.fragment_count());
        assert_eq!(first.operation_count(), second.operation_count());
    }

    #[test]
    fn candidate_generation_varies_across_representative_seeds() {
        let first = candidate_for_seed(23);
        let second = candidate_for_seed(24);

        assert_candidate_invariants(&first);
        assert_candidate_invariants(&second);
        assert!(
            first.question() != second.question()
                || first.answer() != second.answer()
                || first.secret_length() != second.secret_length()
                || first.fragment_count() != second.fragment_count()
                || first.operation_count() != second.operation_count()
                || first.render_metadata() != second.render_metadata()
        );
    }
}
