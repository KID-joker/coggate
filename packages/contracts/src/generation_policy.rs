pub const MIN_SECRET_LENGTH: u8 = 8;
pub const MAX_SECRET_LENGTH: u8 = 16;
pub const CHALLENGE_TTL_SECONDS: u8 = 15;

pub const fn fragment_count_for_secret_length(secret_length: u8) -> Option<u8> {
    match secret_length {
        8..=10 => Some(3),
        11..=13 => Some(4),
        14..=16 => Some(5),
        _ => None,
    }
}
