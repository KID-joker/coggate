use agentgate_benchmark::{
    baseline::{Baseline, BaselineError, NoGuessReason, Outcome, Prediction, score_baseline},
    corpus::{Corpus, CorpusCase},
    manifest::{ProfileName, SuiteManifest},
};

struct NeverGuess;

impl Baseline for NeverGuess {
    fn id(&self) -> &'static str {
        "never"
    }

    fn predict(&self, _case: &CorpusCase) -> Result<Prediction, BaselineError> {
        Ok(Prediction::NoGuess(NoGuessReason::Unsupported))
    }
}

#[test]
fn scorer_owns_oracle_comparison_and_preserves_case_order() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let results = score_baseline(&NeverGuess, &corpus.scored()[..3]).unwrap();

    assert_eq!(results.len(), 3);
    for (result, case) in results.iter().zip(corpus.scored()) {
        assert_eq!(result.case_id(), case.id());
        assert_eq!(result.outcome(), Outcome::Unsolved);
        assert_eq!(result.reason(), Some(NoGuessReason::Unsupported));
    }
}

struct InfrastructureFailure;

impl Baseline for InfrastructureFailure {
    fn id(&self) -> &'static str {
        "infrastructure_failure"
    }

    fn predict(&self, _case: &CorpusCase) -> Result<Prediction, BaselineError> {
        Err(BaselineError::Infrastructure)
    }
}

#[test]
fn infrastructure_failure_aborts_scoring_without_results() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();

    assert_eq!(
        score_baseline(&InfrastructureFailure, &corpus.scored()[..3]),
        Err(BaselineError::Infrastructure)
    );
}

#[test]
fn baseline_error_diagnostic_is_redacted() {
    assert_eq!(
        BaselineError::Infrastructure.to_string(),
        "baseline infrastructure failed"
    );
}
