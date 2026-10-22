use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::Deserialize;
use sqlx::MySqlPool;
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::AppError,
    extract::{AuthUser, ValidatedJson, ValidatedQuery},
    models::Project,
    page::{Page, Paged, clamp},
    policy::{self, ProjectCtx},
    state::AppState,
};

#[derive(Deserialize, Validate)]
pub struct CreateProject {
    #[validate(length(min = 1, max = 255))]
    name: String,
    #[validate(length(max = 5000))]
    description: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct UpdateProject {
    #[validate(length(min = 1, max = 255))]
    name: Option<String>,
    #[validate(length(max = 5000))]
    description: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct AddMember {
    user_id: Uuid,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/projects", post(create).get(list))
        .route("/projects/{id}", get(read).patch(update).delete(remove))
        .route("/projects/{id}/members", post(add_member))
        .route("/projects/{id}/members/{user_id}", delete(remove_member))
}

async fn find_project(db: &MySqlPool, id: Uuid) -> Result<Option<Project>, sqlx::Error> {
    sqlx::query_as::<_, Project>("SELECT * FROM projects WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// Loads a project the user is allowed to SEE, or returns 404. A project the user can't see
/// looks the same as one that doesn't exist, so its existence is not revealed.
pub async fn load_visible_project(
    db: &MySqlPool,
    u: &AuthUser,
    id: Uuid,
) -> Result<(Project, ProjectCtx), AppError> {
    let project = find_project(db, id).await?.ok_or(AppError::NotFound)?;
    let members: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM project_members WHERE project_id = ? AND user_id = ?",
    )
    .bind(id)
    .bind(u.id)
    .fetch_one(db)
    .await?;
    let ctx = ProjectCtx {
        owner_id: project.owner_id,
        is_member: members > 0,
    };
    if !policy::can_view_project(u, &ctx) {
        return Err(AppError::NotFound);
    }
    Ok((project, ctx))
}

/// Visible (404 if not), then manageable (403 if visible but not allowed).
pub async fn load_manageable_project(
    db: &MySqlPool,
    u: &AuthUser,
    id: Uuid,
) -> Result<(Project, ProjectCtx), AppError> {
    let (project, ctx) = load_visible_project(db, u, id).await?;
    if !policy::can_manage_project(u, &ctx) {
        return Err(AppError::Forbidden);
    }
    Ok((project, ctx))
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    ValidatedJson(req): ValidatedJson<CreateProject>,
) -> Result<(StatusCode, Json<Project>), AppError> {
    if !policy::can_create_project(&user) {
        return Err(AppError::Forbidden);
    }
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO projects (id, name, description, owner_id) VALUES (?, ?, ?, ?)",
        id,
        req.name.trim(),
        req.description,
        user.id
    )
    .execute(&state.db)
    .await?;
    let project = find_project(&state.db, id)
        .await?
        .ok_or(AppError::Internal)?;
    Ok((StatusCode::CREATED, Json(project)))
}

/// Admins see everything. Everyone else sees projects they own or belong to.
/// A macro, not a const, so `concat!` can build whole static SQL strings from it.
macro_rules! visible {
    () => {
        "(? OR p.owner_id = ? OR EXISTS \
         (SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = ?))"
    };
}

async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    ValidatedQuery(q): ValidatedQuery<Page>,
) -> Result<Json<Paged<Project>>, AppError> {
    let (page, limit, offset) = clamp(q.page, q.limit);
    let is_admin = policy::is_admin(&user);

    // The filter runs in SQL, so the page and the total both count only visible projects.
    let rows = sqlx::query_as::<_, Project>(concat!(
        "SELECT p.* FROM projects p WHERE ",
        visible!(),
        " ORDER BY p.created_at DESC, p.id LIMIT ? OFFSET ?"
    ))
    .bind(is_admin)
    .bind(user.id)
    .bind(user.id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total: i64 = sqlx::query_scalar(concat!(
        "SELECT COUNT(*) FROM projects p WHERE ",
        visible!()
    ))
    .bind(is_admin)
    .bind(user.id)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(Paged::new(rows, page, limit, total)))
}

async fn read(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Project>, AppError> {
    let (project, _) = load_visible_project(&state.db, &user, id).await?;
    Ok(Json(project))
}

async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateProject>,
) -> Result<Json<Project>, AppError> {
    load_manageable_project(&state.db, &user, id).await?;
    // COALESCE keeps the old value for any field the client left out.
    sqlx::query("UPDATE projects SET name = COALESCE(?, name), description = COALESCE(?, description) WHERE id = ?")
        .bind(req.name.map(|n| n.trim().to_string()))
        .bind(req.description)
        .bind(id)
        .execute(&state.db)
        .await?;
    let project = find_project(&state.db, id)
        .await?
        .ok_or(AppError::Internal)?;
    Ok(Json(project))
}

async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    load_manageable_project(&state.db, &user, id).await?;
    // Members and tasks go with it: both foreign keys are ON DELETE CASCADE.
    sqlx::query!("DELETE FROM projects WHERE id = ?", id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<AddMember>,
) -> Result<StatusCode, AppError> {
    load_manageable_project(&state.db, &user, id).await?;

    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = ? AND is_active")
        .bind(req.user_id)
        .fetch_one(&state.db)
        .await?;
    if active == 0 {
        return Err(AppError::NotFound);
    }

    sqlx::query!(
        "INSERT INTO project_members (project_id, user_id) VALUES (?, ?)",
        id,
        req.user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::conflict_or_db(e, "user is already a member"))?;
    Ok(StatusCode::CREATED)
}

async fn remove_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    load_manageable_project(&state.db, &user, id).await?;

    // Decision: the removed member's tasks in this project become unassigned, in the same
    // transaction, so a task never stays assigned to someone who can no longer see it.
    let mut tx = state.db.begin().await?;
    sqlx::query!(
        "UPDATE tasks SET assignee_id = NULL WHERE project_id = ? AND assignee_id = ?",
        id,
        member_id
    )
    .execute(&mut *tx)
    .await?;
    let removed = sqlx::query!(
        "DELETE FROM project_members WHERE project_id = ? AND user_id = ?",
        id,
        member_id
    )
    .execute(&mut *tx)
    .await?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound); // not a member (the owner is not a row here), so nothing was changed
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
