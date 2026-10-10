use std::collections::BTreeSet;

use coggate_benchmark::{
    corpus::Corpus,
    manifest::{ProfileName, SuiteManifest},
};
use sha2::{Digest, Sha256};

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

#[test]
fn corpus_ids_and_questions_use_coggate_domains() {
    let suite = SuiteManifest::tracked_v1().unwrap();
    let corpus = Corpus::generate(&suite, ProfileName::Quick).unwrap();
    let first = &corpus.scored()[0];
    let profile = suite.profile(ProfileName::Quick).unwrap();

    let mut case = Sha256::new();
    case.update(b"coggate:benchmark-case:v1");
    for field in [
        suite.digest().as_bytes(),
        b"scored".as_slice(),
        profile.scored_namespace().as_bytes(),
    ] {
        case.update((field.len() as u64).to_be_bytes());
        case.update(field);
    }
    case.update(0_u64.to_be_bytes());

    let mut question = Sha256::new();
    question.update(b"coggate:question:v1");
    question.update((first.question().len() as u64).to_be_bytes());
    question.update(first.question().as_bytes());

    assert_eq!(first.id(), hex::encode(case.finalize()));
    assert_eq!(first.question_digest(), hex::encode(question.finalize()));
    assert_eq!(
        first.id(),
        "1937519fc0cd0a1cf751aabb4f5a93baf2da66d31a9e17a62a9cbd03d7d5a684"
    );
    assert_eq!(
        first.question_digest(),
        "932d2ec5a5c2d6506fdc7aa6ee451b52d23e5701b126726985b655cf1eadc6d1"
    );
}
