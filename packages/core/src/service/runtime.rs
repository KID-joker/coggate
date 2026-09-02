use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::generation::{GenerationError, RandomSource};

use super::ServiceError;

pub(crate) fn unix_time_now() -> Result<i64, ServiceError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError::InternalError)?;
    i64::try_from(duration.as_secs()).map_err(|_| ServiceError::InternalError)
}

pub(crate) fn random_token(random: &mut impl RandomSource) -> Result<String, GenerationError> {
    let mut bytes = [0_u8; 16];
    random.fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
