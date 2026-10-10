#![cfg(feature = "insecure-benchmarking")]

use coggate_core::generation::{BenchmarkError, generate_benchmark_case};

#[test]
fn equal_version_namespace_and_index_are_reproducible() {
    let first = generate_benchmark_case("1.0", b"phase6a-scored-v1", 7).unwrap();
    let second = generate_benchmark_case("1.0", b"phase6a-scored-v1", 7).unwrap();

    assert_eq!(first.question(), second.question());
    assert_eq!(first.metadata(), second.metadata());
    let answer = first.calibration_answer();
    assert!(second.oracle().matches(&answer));
}

#[test]
fn namespace_and_index_are_domain_separated() {
    let scored = generate_benchmark_case("1.0", b"phase6a-scored-v1", 7).unwrap();
    let calibration = generate_benchmark_case("1.0", b"phase6a-calibration-v1", 7).unwrap();
    let adjacent = generate_benchmark_case("1.0", b"phase6a-scored-v1", 8).unwrap();

    assert_ne!(scored.question(), calibration.question());
    assert_ne!(scored.question(), adjacent.question());
}

#[test]
fn rejects_unsupported_versions_and_invalid_namespaces() {
    assert_eq!(
        generate_benchmark_case("1.1", b"phase6a-scored-v1", 0).unwrap_err(),
        BenchmarkError::UnsupportedGeneratorVersion,
    );

    assert_eq!(
        generate_benchmark_case("1.0", b"", 0).unwrap_err(),
        BenchmarkError::InvalidSeedNamespace,
    );
    assert_eq!(
        generate_benchmark_case("1.0", &[b'x'; 65], 0).unwrap_err(),
        BenchmarkError::InvalidSeedNamespace,
    );
}

#[test]
fn debug_output_redacts_question_and_answer() {
    let case = generate_benchmark_case("1.0", b"phase6a-scored-v1", 1).unwrap();
    let answer = case.calibration_answer();
    let debug = format!("{case:?} {:?}", case.oracle());

    assert!(!debug.contains(case.question()));
    assert!(!debug.contains(answer.as_str()));
    assert!(debug.contains("[REDACTED]"));
}
