use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

pub type ArenaResult<T> = Result<T, ArenaError>;

#[derive(Debug, thiserror::Error)]
pub enum ArenaError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not_found")]
    NotFound,
    #[error("arena_closed")]
    ArenaClosed,
    #[error("epoch_changed")]
    EpochChanged,
    #[error("quota_exhausted")]
    QuotaExhausted,
    #[error("submission_in_flight")]
    SubmissionInFlight(Option<String>),
    #[error("queue_full")]
    QueueFull,
    #[error("invalid_request: {0}")]
    InvalidRequest(&'static str),
    #[error("payload_too_large")]
    PayloadTooLarge,
    #[error("conflict")]
    Conflict,
    #[error("configuration: {0}")]
    Configuration(String),
    #[error("database failure")]
    Database(#[from] rusqlite::Error),
    #[error("upstream failure")]
    Upstream,
    #[error("internal failure")]
    Internal,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    submission_id: Option<&'a str>,
}

impl IntoResponse for ArenaError {
    fn into_response(self) -> Response {
        let (status, code, submission_id) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", None),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None),
            Self::ArenaClosed => (StatusCode::CONFLICT, "arena_closed", None),
            Self::EpochChanged => (StatusCode::CONFLICT, "epoch_changed", None),
            Self::QuotaExhausted => (StatusCode::TOO_MANY_REQUESTS, "quota_exhausted", None),
            Self::SubmissionInFlight(id) => {
                (StatusCode::CONFLICT, "submission_in_flight", id.as_deref())
            }
            Self::QueueFull => (StatusCode::TOO_MANY_REQUESTS, "queue_full", None),
            Self::InvalidRequest(code) => (StatusCode::UNPROCESSABLE_ENTITY, *code, None),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", None),
            Self::Conflict => (StatusCode::CONFLICT, "conflict", None),
            Self::Configuration(_) | Self::Database(_) | Self::Upstream | Self::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
            }
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                submission_id,
            }),
        )
            .into_response()
    }
}
