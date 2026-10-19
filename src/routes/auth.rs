use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_governor::{GovernorLayer, errors::GovernorError, governor::GovernorConfigBuilder};
use validator::Validate;

use crate::{
    error::AppError,
    extract::{AuthUser, ValidatedJson},
    models::{Role, User, UserResponse},
    security,
    state::AppState,
};

// ---------- Request and response types ----------

#[derive(Deserialize, Validate)]
pub struct RegisterReq {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    #[validate(length(min = 1, max = 100))]
    pub full_name: String,
}

#[derive(Deserialize, Validate)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

/// Used by both `/auth/refresh` and `/auth/logout`.
#[derive(Deserialize, Validate)]
pub struct RefreshReq {
    pub refresh_token: String,
}

#[derive(Deserialize, Validate)]
pub struct ChangePasswordReq {
    pub current_password: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

// ---------- Router ----------

pub fn router() -> Router<AppState> {
    // One token every 12 seconds, with a burst of 5 per IP. Only login is limited.
    let governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(12)
            .burst_size(5)
            .finish()
            .expect("valid governor config"),
    );
    let login = post(login).layer(GovernorLayer::new(governor).error_handler(governor_error));

    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", login)
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/me/password", put(change_password))
}

/// Sends rate-limit rejections in the same JSON shape as every other error.
fn governor_error(err: GovernorError) -> Response {
    match err {
        GovernorError::TooManyRequests { headers, .. } => {
            let mut res = AppError::TooManyRequests.into_response();
            if let Some(h) = headers {
                res.headers_mut().extend(h);
            }
            res
        }
        _ => AppError::Internal.into_response(),
    }
}

// ---------- 8a. POST /auth/register ----------

async fn register(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RegisterReq>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    let email = req.email.trim().to_lowercase();
    let hash = security::hash_password(req.password).await?;

    let user = sqlx::query_as!(
        User,
        r#"INSERT INTO users (email, password_hash, full_name)
           VALUES ($1, $2, $3)
           RETURNING id, email, password_hash, full_name, role AS "role: Role", is_active, created_at"#,
        email,
        hash,
        req.full_name.trim()
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            AppError::Conflict("email is already registered".into())
        } else {
            AppError::Db(e)
        }
    })?;

    Ok((StatusCode::CREATED, Json(user.into())))
}

// ---------- 8b. POST /auth/login ----------

async fn login(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<LoginReq>,
) -> Result<Json<TokenResponse>, AppError> {
    let email = req.email.trim().to_lowercase();
    let user = sqlx::query_as!(
        User,
        r#"SELECT id, email, password_hash, full_name, role AS "role: Role", is_active, created_at
           FROM users WHERE email = $1"#,
        email
    )
    .fetch_optional(&state.db)
    .await?;

    // Always run one argon2 check, so an unknown email is not faster than a wrong password.
    let hash = match &user {
        Some(u) => u.password_hash.clone(),
        None => security::dummy_hash(),
    };
    let password_ok = security::verify_password(req.password, hash).await;

    // Wrong password, unknown email and inactive user all get the same 401.
    let user = match user {
        Some(u) if password_ok && u.is_active => u,
        _ => return Err(AppError::InvalidCredentials),
    };

    let access_token = security::create_access_token(user.id, &state.config)?;
    let (refresh_token, refresh_hash) = security::new_refresh_token();
    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user.id,
        refresh_hash,
        Utc::now() + Duration::days(state.config.refresh_days)
    )
    .execute(&state.db)
    .await?;

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: state.config.access_minutes * 60,
    }))
}

// ---------- 8c. POST /auth/refresh (rotation with reuse detection) ----------

async fn refresh(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RefreshReq>,
) -> Result<Json<TokenResponse>, AppError> {
    let hash = security::hash_refresh_token(&req.refresh_token);

    // One transaction, and FOR UPDATE locks the row. Two parallel refreshes with the
    // same token can't both succeed: the second waits, then sees it as revoked.
    let mut tx = state.db.begin().await?;

    let row = sqlx::query!(
        r#"SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked_at, u.is_active
           FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
           WHERE rt.token_hash = $1
           FOR UPDATE OF rt"#,
        hash
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if row.revoked_at.is_some() {
        // Reuse detected: an old token came back, so assume theft and end every session.
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
            row.user_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }
    if row.expires_at < Utc::now() || !row.is_active {
        return Err(AppError::Unauthorized);
    }

    // Revoke the old token and issue a new one.
    sqlx::query!("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1", row.id)
        .execute(&mut *tx)
        .await?;
    let (new_token, new_hash) = security::new_refresh_token();
    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        row.user_id,
        new_hash,
        Utc::now() + Duration::days(state.config.refresh_days)
    )
    .execute(&mut *tx)
    .await?;
    let access_token = security::create_access_token(row.user_id, &state.config)?;
    tx.commit().await?;

    Ok(Json(TokenResponse {
        access_token,
        refresh_token: new_token,
        token_type: "Bearer",
        expires_in: state.config.access_minutes * 60,
    }))
}

// ---------- 8d. POST /auth/logout (idempotent) ----------

async fn logout(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RefreshReq>,
) -> Result<StatusCode, AppError> {
    let hash = security::hash_refresh_token(&req.refresh_token);
    // Already revoked or unknown is fine. We still return 204.
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL",
        hash
    )
    .execute(&state.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- 8e. GET /auth/me ----------

async fn me(State(state): State<AppState>, user: AuthUser) -> Result<Json<UserResponse>, AppError> {
    let row = sqlx::query_as!(
        User,
        r#"SELECT id, email, password_hash, full_name, role AS "role: Role", is_active, created_at
           FROM users WHERE id = $1"#,
        user.id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)?;

    Ok(Json(row.into()))
}

// ---------- 8f. PUT /auth/me/password ----------

async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    ValidatedJson(req): ValidatedJson<ChangePasswordReq>,
) -> Result<StatusCode, AppError> {
    let current = sqlx::query_as!(
        User,
        r#"SELECT id, email, password_hash, full_name, role AS "role: Role", is_active, created_at
           FROM users WHERE id = $1"#,
        user.id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if !security::verify_password(req.current_password, current.password_hash).await {
        // 400, not 401. A 401 would make clients think their login has expired.
        return Err(AppError::BadRequest("current password is incorrect".into()));
    }

    let new_hash = security::hash_password(req.new_password).await?;

    // Update the hash and end every session in the same transaction.
    let mut tx = state.db.begin().await?;
    sqlx::query!("UPDATE users SET password_hash = $2 WHERE id = $1", user.id, new_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        user.id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
