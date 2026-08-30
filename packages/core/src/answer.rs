use agentgate_contracts::AnswerEncoding;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::CoreError;

pub fn canonicalize_answer(encoding: AnswerEncoding, submitted: &str) -> Result<String, CoreError> {
    if submitted.is_empty() || submitted.len() > 256 {
        return Err(CoreError::InvalidAnswerEncoding);
    }

    match encoding {
        AnswerEncoding::Base64Url => {
            let decoded = URL_SAFE_NO_PAD
                .decode(submitted)
                .map_err(|_| CoreError::InvalidAnswerEncoding)?;
            let canonical = URL_SAFE_NO_PAD.encode(decoded);

            (canonical == submitted)
                .then_some(canonical)
                .ok_or(CoreError::InvalidAnswerEncoding)
        }
    }
}
