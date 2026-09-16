use std::{collections::BTreeMap, time::Duration};

use agentgate_benchmark::{
    baseline::{
        NoGuessReason, Prediction,
        direct::{DirectBaseline, FragmentLanguage, extract_fragments},
    },
    process::{ProcessRunner, ToolId},
};

fn rejecting_baseline(root: &tempfile::TempDir) -> DirectBaseline {
    let executable = std::env::current_exe().unwrap();
    let programs = ["c", "cpp", "rust", "go", "java"]
        .into_iter()
        .map(|name| (ToolId::new(name).unwrap(), executable.clone()))
        .collect::<BTreeMap<_, _>>();
    let runner = ProcessRunner::new(
        root.path().to_path_buf(),
        Duration::from_secs(2),
        65_536,
        programs,
    )
    .unwrap();
    DirectBaseline::new(runner)
}

#[test]
fn extracts_only_public_fragment_bodies() {
    let question = concat!(
        "preamble\n",
        "[Fragment 1 — Rust]\nlet a = bytes_ascii(\"abc\"); // exports a\n",
        "[Fragment 2 — Pseudocode]\nb <- reverse(a) # exports b\n",
        "Dependency clues:\nignored\n",
        "Display order is not evaluation order.\n"
    );
    let fragments = extract_fragments(question).unwrap();

    assert_eq!(fragments.len(), 2);
    assert_eq!(fragments[0].language(), FragmentLanguage::Rust);
    assert_eq!(
        fragments[0].body(),
        "let a = bytes_ascii(\"abc\"); // exports a\n"
    );
    assert_eq!(fragments[1].language(), FragmentLanguage::Pseudocode);
    assert_eq!(fragments[1].body(), "b <- reverse(a) # exports b\n");
}

#[test]
fn unchanged_nonprogram_fragment_is_rejected_without_guessing() {
    let root = tempfile::tempdir().unwrap();
    let baseline = rejecting_baseline(&root);
    let question = concat!(
        "[Fragment 1 — Rust]\n",
        "let out = reverse(bytes_ascii(\"abc\")); // exports out\n",
        "Display order is not evaluation order.\n",
        "The requested result is output label out. Submit its byte array as unpadded base64url.\n"
    );

    assert!(matches!(
        baseline.predict_text(question),
        Prediction::NoGuess(NoGuessReason::ToolRejected)
    ));
}

#[test]
fn pseudocode_only_question_is_non_executable() {
    let root = tempfile::tempdir().unwrap();
    let baseline = rejecting_baseline(&root);
    let question = "[Fragment 1 — Pseudocode]\nout <- bytes_ascii(\"abc\") # exports out\n";

    assert!(matches!(
        baseline.predict_text(question),
        Prediction::NoGuess(NoGuessReason::Unsupported)
    ));
}
