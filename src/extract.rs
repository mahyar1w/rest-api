use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Query, Request},
    http::{header::AUTHORIZATION, request::Parts},
};
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::AppError,
    models::Role,
    security::decode_access_token,
    state::AppState,
};

/// The logged-in user. Any handler that takes this as a parameter is protected.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub role: Role,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        // 1. Read "Authorization: Bearer <token>", or 401 if it is missing
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;

        // 2. Verify the signature and expiry, or 401
        let claims = decode_access_token(token, &state.config).ok_or(AppError::Unauthorized)?;

        // 3. Load the user on EVERY request, so a deleted or deactivated user gets 401
        sqlx::query_as!(
            AuthUser,
            r#"SELECT id, role AS "role: Role" FROM users WHERE id = $1 AND is_active"#,
            claims.sub
        )
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)
    }
}

pub struct ValidatedJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, AppError> {
        let Json(v) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| AppError::BadRequest(e.body_text()))?;
        v.validate().map_err(validation_error)?;
        Ok(Self(v))
    }
}

/// Keeps only each field's code and message. The validator's default output also
/// echoes the submitted value, which would send a password back in the response.
fn validation_error(e: validator::ValidationErrors) -> AppError {
    let fields: serde_json::Map<String, serde_json::Value> = e
        .field_errors()
        .iter()
        .map(|(field, errs)| {
            let msgs: Vec<_> = errs
                .iter()
                .map(|err| json!({ "code": err.code, "message": err.message }))
                .collect();
            (field.to_string(), json!(msgs))
        })
        .collect();
    AppError::Validation(serde_json::Value::Object(fields))
}

pub struct ValidatedQuery<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedQuery<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, AppError> {
        let Query(v) = Query::<T>::from_request(req, state)
            .await
            .map_err(|e| AppError::BadRequest(e.body_text()))?;
        v.validate().map_err(validation_error)?;
        Ok(Self(v))
    }
}
