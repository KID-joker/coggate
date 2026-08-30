use agentgate_contracts::{ChallengeConfig, ContractError, Difficulty};

#[test]
fn medium_defaults_match_the_approved_spec() {
    let config = ChallengeConfig::for_difficulty(Difficulty::Medium);

    assert_eq!(config.secret_length, 10);
    assert_eq!(config.fragment_count, 4);
    assert_eq!(config.max_question_tokens, 1000);
    assert_eq!(config.ttl_seconds, 8);
    assert_eq!(config.max_attempts, 1);
    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn invalid_attempt_count_is_rejected() {
    let config = ChallengeConfig {
        difficulty: Difficulty::Short,
        secret_length: 8,
        fragment_count: 3,
        max_question_tokens: 700,
        ttl_seconds: 5,
        max_attempts: 3,
    };

    assert_eq!(
        config.validate(),
        Err(ContractError::InvalidConfiguration(
            "max_attempts must be 1 or 2"
        ))
    );
}

#[test]
fn hard_is_reserved_in_v1() {
    let config = ChallengeConfig::for_difficulty(Difficulty::Hard);

    assert_eq!(config.validate(), Err(ContractError::UnsupportedDifficulty));
}
