use std::collections::BTreeSet;

use agentgate_benchmark::{
    corpus::Corpus,
    manifest::{ProfileName, SuiteManifest},
};

#[test]
fn quick_corpus_is_complete_disjoint_and_repeatable() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let first = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let second = Corpus::generate(&suite, ProfileName::Quick).unwrap();

    assert_eq!(first.calibration().len(), 100);
    assert_eq!(first.scored().len(), 100);
    assert_eq!(first.public_fingerprints(), second.public_fingerprints());

    let calibration = first
        .calibration()
        .iter()
        .map(|case| case.id())
        .collect::<BTreeSet<_>>();
    assert!(
        first
            .scored()
            .iter()
            .all(|case| !calibration.contains(case.id()))
    );
}

#[test]
fn case_ids_and_question_digests_are_lowercase_sha256_hex() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();

    for case in corpus.calibration().iter().chain(corpus.scored()) {
        for value in [case.id(), case.question_digest()] {
            assert_eq!(value.len(), 64);
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
        }
        assert!(!case.question().is_empty());
        let debug = format!("{case:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(case.question()));
    }
}

#[test]
fn release_profile_has_exact_contract_counts() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Release).unwrap();

    assert_eq!(corpus.calibration().len(), 1_000);
    assert_eq!(corpus.scored().len(), 1_000);
}

#[test]
fn same_index_scored_case_ids_are_profile_bound() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let quick = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let release = Corpus::generate(&suite, ProfileName::Release).unwrap();

    assert_ne!(quick.scored()[0].id(), release.scored()[0].id());
}
