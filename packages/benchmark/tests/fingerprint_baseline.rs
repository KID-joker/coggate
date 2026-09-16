use agentgate_benchmark::{
    baseline::{Baseline, NoGuessReason, Prediction, fingerprint::FingerprintBaseline},
    threshold::Threshold,
};

#[test]
fn evaluates_exact_integer_threshold_boundaries() {
    assert!(Threshold::at_least(80).evaluate(80, 100).unwrap());
    assert!(!Threshold::at_least(80).evaluate(799, 1_000).unwrap());
    assert!(Threshold::at_most(1).evaluate(10, 1_000).unwrap());
    assert!(!Threshold::at_most(1).evaluate(11, 1_000).unwrap());
    assert!(Threshold::at_most(5).evaluate(5, 100).unwrap());
    assert!(Threshold::at_most(5).evaluate(0, 0).is_err());
    assert!(Threshold::at_most(5).evaluate(6, 5).is_err());
}

#[test]
fn predicts_a_unique_calibrated_template_after_surface_normalization() {
    let baseline = FingerprintBaseline::from_examples([
        (
            "let alpha = reverse(bytes_ascii(\"abc\")); // exports alpha",
            "YQ",
        ),
        (
            "let beta = reverse(bytes_ascii(\"xyz\")); // exports beta",
            "YQ",
        ),
    ])
    .unwrap();

    match baseline
        .predict_text("let another_name = reverse(bytes_ascii(\"Q7r\")); // exports another_name")
    {
        Prediction::Guess(answer) => assert_eq!(answer.as_str(), "YQ"),
        Prediction::NoGuess(reason) => panic!("unexpected no-guess: {reason:?}"),
    }
}

#[test]
fn ambiguous_calibration_fingerprints_never_guess() {
    let baseline = FingerprintBaseline::from_examples([
        ("let alpha = reverse(bytes_ascii(\"abc\"));", "YQ"),
        ("let beta = reverse(bytes_ascii(\"xyz\"));", "Yg"),
    ])
    .unwrap();

    assert!(matches!(
        baseline.predict_text("let gamma = reverse(bytes_ascii(\"pqr\"));"),
        Prediction::NoGuess(NoGuessReason::Ambiguous)
    ));
    let debug = format!("{baseline:?}");
    assert!(!debug.contains("YQ"));
    assert!(!debug.contains("Yg"));
}

#[test]
fn unseen_or_oversized_templates_never_mutate_training() {
    let baseline =
        FingerprintBaseline::from_examples([("let alpha = reverse(bytes_ascii(\"abc\"));", "YQ")])
            .unwrap();

    assert!(matches!(
        baseline.predict_text("let alpha = concat(bytes_ascii(\"a\"), bytes_ascii(\"b\"));"),
        Prediction::NoGuess(NoGuessReason::NoCandidate)
    ));
    assert!(matches!(
        baseline.predict_text(&"x".repeat(12_289)),
        Prediction::NoGuess(NoGuessReason::Unsupported)
    ));
    assert_eq!(baseline.id(), "fingerprint");
}

#[test]
fn rejects_noncanonical_calibration_answers() {
    assert!(
        FingerprintBaseline::from_examples([("let alpha = bytes_ascii(\"a\");", "YQ==")]).is_err()
    );
}
