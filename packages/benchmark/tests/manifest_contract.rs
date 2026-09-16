use agentgate_benchmark::manifest::{Comparison, ProfileName, SuiteManifest};

#[test]
fn loads_the_tracked_v1_suite() {
    let suite = SuiteManifest::tracked_v1().unwrap();

    assert_eq!(suite.schema_version(), 1);
    assert_eq!(suite.suite_version(), "1.0");
    assert_eq!(suite.generator_version(), "1.0");
    assert_eq!(
        suite.profile(ProfileName::Quick).unwrap().scored_cases(),
        100
    );
    assert_eq!(
        suite
            .profile(ProfileName::Quick)
            .unwrap()
            .calibration_cases(),
        100
    );
    assert_eq!(
        suite.profile(ProfileName::Release).unwrap().scored_cases(),
        1_000
    );
    assert_eq!(
        suite
            .profile(ProfileName::Release)
            .unwrap()
            .calibration_cases(),
        1_000
    );
    assert_eq!(
        suite.threshold("llm").unwrap().comparison(),
        Comparison::AtLeast
    );
    assert_eq!(suite.threshold("llm").unwrap().percent(), 80);
    assert_eq!(suite.threshold("direct").unwrap().percent(), 5);
    for baseline in ["fingerprint", "regex", "simple_parser"] {
        assert_eq!(suite.threshold(baseline).unwrap().percent(), 1);
    }
    assert_eq!(suite.digest().len(), 64);
    assert!(suite.digest().bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn tracked_manifest_digest_is_deterministic() {
    let first = SuiteManifest::tracked_v1().unwrap();
    let second = SuiteManifest::tracked_v1().unwrap();
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn rejects_unknown_fields_and_invalid_thresholds() {
    let source = include_str!("../../../benchmarks/suites/v1.json");
    let unknown = source.replacen('{', "{\"unknown\":true,", 1);
    assert!(SuiteManifest::parse(&unknown).is_err());

    let invalid = source.replace("\"percent\": 80", "\"percent\": 101");
    assert!(SuiteManifest::parse(&invalid).is_err());
}

#[test]
fn rejects_incomplete_keys_and_overlapping_namespaces() {
    let source = include_str!("../../../benchmarks/suites/v1.json");
    let missing = source.replace(
        concat!(
            "    \"regex\": { \"comparison\": \"at_most\", \"percent\": 1 },\n",
            "    \"simple_parser\": { \"comparison\": \"at_most\", \"percent\": 1 }\n",
        ),
        "    \"regex\": { \"comparison\": \"at_most\", \"percent\": 1 }\n",
    );
    assert_ne!(missing, source);
    assert!(SuiteManifest::parse(&missing).is_err());

    let overlapping = source.replace("phase6a-calibration-v1", "phase6a-scored-v1");
    assert!(SuiteManifest::parse(&overlapping).is_err());
}
