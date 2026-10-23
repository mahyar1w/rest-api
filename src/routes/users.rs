use axum::{
    Json, Router,
    extract::State,
    routing::{get, patch},
};
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::AppError,
    extract::{AuthUser, Path, ValidatedJson, ValidatedQuery},
    models::{Role, User, UserResponse},
    page::{Page, Paged, clamp},
    policy,
    routes::auth::{revoke_all_sessions, user_by_id},
    state::AppState,
};

#[derive(Deserialize, Validate)]
pub struct RoleReq {
    role: Role,
}

#[derive(Deserialize, Validate)]
pub struct StatusReq {
    is_active: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list))
        .route("/users/{id}", get(read))
        .route("/users/{id}/role", patch(set_role))
        .route("/users/{id}/status", patch(set_status))
}

/// Admin only (403 otherwise), and never on yourself (400), so an admin can't lock themselves out.
fn admin_acting_on_other(user: &AuthUser, target: Uuid, own_msg: &str) -> Result<(), AppError> {
    if !policy::is_admin(user) {
        return Err(AppError::Forbidden);
    }
    if target == user.id {
        return Err(AppError::BadRequest(own_msg.into()));
    }
    Ok(())
}

async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    ValidatedQuery(q): ValidatedQuery<Page>,
) -> Result<Json<Paged<UserResponse>>, AppError> {
    if !policy::is_admin(&user) {
        return Err(AppError::Forbidden);
    }
    let (page, limit, offset) = clamp(q.page, q.limit);
    let rows =
        sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at, id LIMIT ? OFFSET ?")
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    let data = rows.into_iter().map(UserResponse::from).collect();
    Ok(Json(Paged::new(data, page, limit, total)))
}

/// Decision: a non-admin asking for someone else gets 403, matching the admin-only list above.
async fn read(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>, AppError> {
    if !policy::is_admin(&user) && id != user.id {
        return Err(AppError::Forbidden);
    }
    let target = user_by_id(&state.db, id).await?.ok_or(AppError::NotFound)?;
    Ok(Json(target.into()))
}

async fn set_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<RoleReq>,
) -> Result<Json<UserResponse>, AppError> {
    admin_acting_on_other(&user, id, "You cannot change your own role")?;
    let mut target = user_by_id(&state.db, id).await?.ok_or(AppError::NotFound)?;
    sqlx::query("UPDATE users SET role = ? WHERE id = ?")
        .bind(req.role)
        .bind(id)
        .execute(&state.db)
        .await?;
    target.role = req.role;
    Ok(Json(target.into()))
}

async fn set_status(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<StatusReq>,
) -> Result<Json<UserResponse>, AppError> {
    admin_acting_on_other(&user, id, "You cannot change your own status")?;
    let mut target = user_by_id(&state.db, id).await?.ok_or(AppError::NotFound)?;

    let mut tx = state.db.begin().await?;
    sqlx::query!(
        "UPDATE users SET is_active = ? WHERE id = ?",
        req.is_active,
        id
    )
    .execute(&mut *tx)
    .await?;
    if !req.is_active {
        // The user can't log in again, and their existing sessions end now.
        revoke_all_sessions(&mut tx, id).await?;
    }
    tx.commit().await?;

    target.is_active = req.is_active;
    Ok(Json(target.into()))
}
