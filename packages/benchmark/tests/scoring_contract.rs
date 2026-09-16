use agentgate_benchmark::{
    baseline::{Baseline, NoGuessReason, Outcome, Prediction, score_baseline},
    corpus::{Corpus, CorpusCase},
    manifest::{ProfileName, SuiteManifest},
};

struct NeverGuess;

impl Baseline for NeverGuess {
    fn id(&self) -> &'static str {
        "never"
    }

    fn predict(&self, _case: &CorpusCase) -> Prediction {
        Prediction::NoGuess(NoGuessReason::Unsupported)
    }
}

#[test]
fn scorer_owns_oracle_comparison_and_preserves_case_order() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let results = score_baseline(&NeverGuess, &corpus.scored()[..3]);

    assert_eq!(results.len(), 3);
    for (result, case) in results.iter().zip(corpus.scored()) {
        assert_eq!(result.case_id(), case.id());
        assert_eq!(result.outcome(), Outcome::Unsolved);
        assert_eq!(result.reason(), Some(NoGuessReason::Unsupported));
    }
}
