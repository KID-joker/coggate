use coggate_contracts::{
    CHALLENGE_TTL_SECONDS, MAX_SECRET_LENGTH, MIN_SECRET_LENGTH, fragment_count_for_secret_length,
};

const THREE_FRAGMENTS: Option<u8> = fragment_count_for_secret_length(MIN_SECRET_LENGTH);

#[test]
fn exposes_unified_generation_limits() {
    assert_eq!(MIN_SECRET_LENGTH, 8);
    assert_eq!(MAX_SECRET_LENGTH, 16);
    assert_eq!(CHALLENGE_TTL_SECONDS, 15);
}

#[test]
fn maps_supported_secret_lengths_to_fragment_counts() {
    assert_eq!(THREE_FRAGMENTS, Some(3));

    for secret_length in 8..=10 {
        assert_eq!(fragment_count_for_secret_length(secret_length), Some(3));
    }

    for secret_length in 11..=13 {
        assert_eq!(fragment_count_for_secret_length(secret_length), Some(4));
    }

    for secret_length in 14..=16 {
        assert_eq!(fragment_count_for_secret_length(secret_length), Some(5));
    }
}

#[test]
fn rejects_unsupported_secret_lengths() {
    for secret_length in [0, 7, 17, u8::MAX] {
        assert_eq!(fragment_count_for_secret_length(secret_length), None);
    }
}
