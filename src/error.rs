use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("validation failed")]
    Validation(serde_json::Value),
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("Invalid email or password")]
    InvalidCredentials,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("too many requests")]
    TooManyRequests,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, details) = match &self {
            AppError::Validation(d) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                Some(d.clone()),
            ),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", None),
            AppError::Unauthorized | AppError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", None)
            }
            AppError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN", None),
            AppError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND", None),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT", None),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED", None),
            AppError::Db(e) => {
                tracing::error!(error = %e, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", None)
            }
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", None),
        };
        let message = match &self {
            AppError::Db(_) => "internal error".to_string(),
            e => e.to_string(),
        };
        (
            status,
            Json(json!({ "error": { "code": code, "message": message, "details": details } })),
        )
            .into_response()
    }
}
