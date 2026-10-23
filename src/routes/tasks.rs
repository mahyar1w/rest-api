use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, patch},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::MySqlPool;
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::AppError,
    extract::{AuthUser, Path, ValidatedJson, ValidatedQuery, present_or_null},
    models::{Project, Task, TaskStatus},
    page::{Paged, clamp},
    policy::{self, ProjectCtx, TaskCtx},
    routes::projects::{is_member, load_manageable_project, load_visible_project},
    state::AppState,
};

#[derive(Deserialize, Validate)]
pub struct CreateTask {
    #[validate(length(min = 1, max = 255))]
    title: String,
    #[validate(length(max = 5000))]
    description: Option<String>,
    assignee_id: Option<Uuid>,
}

/// `description` and `assignee_id` are `Option<Option<_>>` so a PATCH can tell "leave it"
/// (absent) from "clear it" (null) from "set it" (a value).
#[derive(Deserialize, Validate)]
pub struct UpdateTask {
    #[validate(length(min = 1, max = 255))]
    title: Option<String>,
    #[validate(length(max = 5000))]
    #[serde(default, deserialize_with = "present_or_null")]
    description: Option<Option<String>>,
    #[serde(default, deserialize_with = "present_or_null")]
    assignee_id: Option<Option<Uuid>>,
}

#[derive(Deserialize, Validate)]
pub struct StatusReq {
    status: TaskStatus,
}

#[derive(Deserialize, Validate)]
pub struct TaskQuery {
    status: Option<TaskStatus>,
    assignee_id: Option<Uuid>,
    page: Option<i64>,
    limit: Option<i64>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/projects/{id}/tasks", get(list).post(create))
        .route("/tasks/{id}", get(read).patch(update).delete(remove))
        .route("/tasks/{id}/status", patch(set_status))
}

async fn find_task(db: &MySqlPool, id: Uuid) -> Result<Option<Task>, sqlx::Error> {
    sqlx::query_as::<_, Task>("SELECT * FROM tasks WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// A task is visible exactly when its project is: otherwise 404.
async fn load_task(
    db: &MySqlPool,
    u: &AuthUser,
    id: Uuid,
) -> Result<(Task, Project, ProjectCtx), AppError> {
    let task = find_task(db, id).await?.ok_or(AppError::NotFound)?;
    let (project, ctx) = load_visible_project(db, u, task.project_id).await?;
    Ok((task, project, ctx))
}

/// An assignee must be the project's owner or one of its members, otherwise 422.
async fn ensure_assignable(
    db: &MySqlPool,
    project: &Project,
    assignee: Uuid,
) -> Result<(), AppError> {
    if assignee == project.owner_id || is_member(db, project.id, assignee).await? {
        return Ok(());
    }
    Err(AppError::Validation(
        json!({ "assignee_id": [{ "code": "not_a_project_member", "message": null }] }),
    ))
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Path(project_id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<CreateTask>,
) -> Result<(StatusCode, Json<Task>), AppError> {
    let (project, _) = load_manageable_project(&state.db, &user, project_id).await?;
    if let Some(assignee) = req.assignee_id {
        ensure_assignable(&state.db, &project, assignee).await?;
    }
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO tasks (id, project_id, title, description, assignee_id, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        id,
        project_id,
        req.title.trim(),
        req.description,
        req.assignee_id,
        user.id
    )
    .execute(&state.db)
    .await?;
    let task = find_task(&state.db, id).await?.ok_or(AppError::Internal)?;
    Ok((StatusCode::CREATED, Json(task)))
}

/// `? IS NULL OR ...` makes each filter optional, so one query serves every combination.
macro_rules! filter {
    () => {
        "project_id = ? AND (? IS NULL OR status = ?) AND (? IS NULL OR assignee_id = ?)"
    };
}

async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(project_id): Path<Uuid>,
    ValidatedQuery(q): ValidatedQuery<TaskQuery>,
) -> Result<Json<Paged<Task>>, AppError> {
    load_visible_project(&state.db, &user, project_id).await?;
    let (page, limit, offset) = clamp(q.page, q.limit);

    let rows = sqlx::query_as::<_, Task>(concat!(
        "SELECT * FROM tasks WHERE ",
        filter!(),
        " ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
    ))
    .bind(project_id)
    .bind(q.status)
    .bind(q.status)
    .bind(q.assignee_id)
    .bind(q.assignee_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total: i64 = sqlx::query_scalar(concat!("SELECT COUNT(*) FROM tasks WHERE ", filter!()))
        .bind(project_id)
        .bind(q.status)
        .bind(q.status)
        .bind(q.assignee_id)
        .bind(q.assignee_id)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(Paged::new(rows, page, limit, total)))
}

async fn read(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Task>, AppError> {
    let (task, _, _) = load_task(&state.db, &user, id).await?;
    Ok(Json(task))
}

async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateTask>,
) -> Result<Json<Task>, AppError> {
    let (_, project, ctx) = load_task(&state.db, &user, id).await?;
    if !policy::can_manage_project(&user, &ctx) {
        return Err(AppError::Forbidden);
    }
    if let Some(Some(assignee)) = req.assignee_id {
        ensure_assignable(&state.db, &project, assignee).await?;
    }

    let mut tx = state.db.begin().await?;
    // IF(present, value, old): a null value with present = true clears the description.
    sqlx::query("UPDATE tasks SET title = COALESCE(?, title), description = IF(?, ?, description), updated_at = NOW(6) WHERE id = ?")
        .bind(req.title.map(|t| t.trim().to_string()))
        .bind(req.description.is_some())
        .bind(req.description.flatten())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if let Some(assignee) = req.assignee_id {
        sqlx::query("UPDATE tasks SET assignee_id = ? WHERE id = ?")
            .bind(assignee) // None clears the assignee
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    let task = find_task(&state.db, id).await?.ok_or(AppError::Internal)?;
    Ok(Json(task))
}

/// The only write a plain member can do, and only on a task assigned to them.
async fn set_status(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<StatusReq>,
) -> Result<Json<Task>, AppError> {
    let (task, _, ctx) = load_task(&state.db, &user, id).await?;
    let task_ctx = TaskCtx {
        assignee_id: task.assignee_id,
    };
    if !policy::can_change_task_status(&user, &ctx, &task_ctx) {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE tasks SET status = ?, updated_at = NOW(6) WHERE id = ?")
        .bind(req.status)
        .bind(id)
        .execute(&state.db)
        .await?;
    let task = find_task(&state.db, id).await?.ok_or(AppError::Internal)?;
    Ok(Json(task))
}

async fn remove(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let (_, _, ctx) = load_task(&state.db, &user, id).await?;
    if !policy::can_manage_project(&user, &ctx) {
        return Err(AppError::Forbidden);
    }
    sqlx::query!("DELETE FROM tasks WHERE id = ?", id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
