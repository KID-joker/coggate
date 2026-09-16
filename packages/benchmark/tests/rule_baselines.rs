use agentgate_benchmark::baseline::{
    NoGuessReason, Prediction,
    regex_extract::RegexBaseline,
    simple_parser::{SimpleParserBaseline, parse_one_fragment},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

#[test]
fn regex_extracts_one_adjacent_answer_and_rejects_ambiguity() {
    let baseline = RegexBaseline::new().unwrap();
    assert!(matches!(
        baseline.predict_text("Final answer: YQ"),
        Prediction::Guess(answer) if answer.as_str() == "YQ"
    ));
    assert!(matches!(
        baseline.predict_text("answer: YQ\nresult: Yg"),
        Prediction::NoGuess(NoGuessReason::Ambiguous)
    ));
    assert!(matches!(
        baseline.predict_text("let value = bytes_ascii(\"YQ\"); // exports value"),
        Prediction::NoGuess(NoGuessReason::NoCandidate)
    ));
}

#[test]
fn parser_evaluates_local_assignments_but_not_remote_dependencies() {
    assert_eq!(
        parse_one_fragment(
            "let out = reverse(bytes_ascii(\"abc\")); // exports out",
            "out"
        ),
        Some(b"cba".to_vec())
    );
    assert_eq!(
        parse_one_fragment(
            "out <- rotate_left(bytes_ascii(\"abcd\"), 1) # exports out",
            "out"
        ),
        Some(b"bcda".to_vec())
    );
    assert_eq!(
        parse_one_fragment(
            "let out = concat(remote, bytes_ascii(\"ab\")); // exports out",
            "out"
        ),
        None
    );
    assert_eq!(
        parse_one_fragment(
            "Dependency: output labels x (Fragment 1) are inputs to output label y in Fragment 2.",
            "y"
        ),
        None
    );
}

#[test]
fn parser_supports_the_complete_local_helper_set() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("rotate_right(bytes_ascii(\"abcd\"), 1)", b"dabc".to_vec()),
        ("xor_repeat(bytes_ascii(\"AB\"), [1, 2])", b"@@".to_vec()),
        ("even_bytes(bytes_ascii(\"abcde\"))", b"ace".to_vec()),
        ("odd_bytes(bytes_ascii(\"abcde\"))", b"bd".to_vec()),
        ("permute(bytes_ascii(\"abc\"), [2, 0, 1])", b"cab".to_vec()),
        ("slice(bytes_ascii(\"abcde\"), 1, 4)", b"bcd".to_vec()),
        (
            "concat(bytes_ascii(\"ab\"), bytes_ascii(\"cd\"))",
            b"abcd".to_vec(),
        ),
        (
            "add_u8(hex_decode_lower(bytes_ascii(\"ff01\")), hex_decode_lower(bytes_ascii(\"0102\")))",
            vec![0, 3],
        ),
        (
            "sub_u8(hex_decode_lower(bytes_ascii(\"0003\")), hex_decode_lower(bytes_ascii(\"0102\")))",
            vec![255, 1],
        ),
        ("hex_lower(bytes_ascii(\"Az\"))", b"417a".to_vec()),
        ("hex_decode_lower(bytes_ascii(\"417a\"))", b"Az".to_vec()),
        ("base64url_no_pad(bytes_ascii(\"abc\"))", b"YWJj".to_vec()),
        (
            "base64url_decode_no_pad(bytes_ascii(\"YWJj\"))",
            b"abc".to_vec(),
        ),
        (
            "rotate_left_derived(bytes_ascii(\"abcd\"), bytes_ascii(\"B\"))",
            b"cdab".to_vec(),
        ),
        (
            "conditional_order(bytes_ascii(\"B\"), bytes_ascii(\"ab\"), bytes_ascii(\"cd\"))",
            b"abcd".to_vec(),
        ),
    ];
    for (expression, expected) in cases {
        let source = format!("let out = {expression}; // exports out");
        assert_eq!(
            parse_one_fragment(&source, "out"),
            Some(expected),
            "{expression}"
        );
    }

    let source = "let out = sha256_prefix(bytes_ascii(\"abc\"), 8); // exports out";
    assert_eq!(
        parse_one_fragment(source, "out"),
        Some(Sha256::digest(b"abc")[..8].to_vec())
    );
}

#[test]
fn parser_resolves_same_fragment_helper_templates() {
    let source = concat!(
        "fn local() -> Bytes { reverse(bytes_ascii(\"abc\")) }\n",
        "let out = local(); // exports out"
    );
    assert_eq!(parse_one_fragment(source, "out"), Some(b"cba".to_vec()));
}

#[test]
fn parser_is_bounded_and_total_on_malformed_text() {
    for source in [
        "let out = reverse((((bytes_ascii(\"a\")); // exports out",
        "let out = bytes_ascii(\"unterminated); // exports out",
        &format!(
            "let {} = bytes_ascii(\"a\"); // exports out",
            "x".repeat(257)
        ),
        "依赖：不是受支持的表达式",
    ] {
        assert_eq!(parse_one_fragment(source, "out"), None);
    }
    assert_eq!(parse_one_fragment(&"x".repeat(12_289), "out"), None);
}

#[test]
fn simple_parser_returns_one_canonical_answer_from_one_fragment() {
    let expected = URL_SAFE_NO_PAD.encode(b"cba");
    let question = concat!(
        "[Fragment 1 — Rust]\n",
        "let out = reverse(bytes_ascii(\"abc\")); // exports out\n\n",
        "Display order is not evaluation order.\n",
        "The requested result is output label out. Submit its byte array as unpadded base64url.\n"
    );
    assert!(matches!(
        SimpleParserBaseline.predict_text(question),
        Prediction::Guess(answer) if answer.as_str() == expected
    ));
}
