use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, serde::Serialize, serde::Deserialize)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Manager,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, serde::Serialize, serde::Deserialize)]
#[sqlx(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
}

// Reading a MariaDB ENUM column straight into the derived enums fails sqlx's runtime type
// check (the derive pins a collation the server doesn't report). So FromRow structs read
// those columns as a String and convert here. The serde names are exactly the stored values.
impl TryFrom<String> for Role {
    type Error = serde_json::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        serde_json::from_value(s.into())
    }
}

impl TryFrom<String> for TaskStatus {
    type Error = serde_json::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        serde_json::from_value(s.into())
    }
}

/// A full `users` row. Contains `password_hash`, so never serialize it. Convert to `UserResponse` first.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub full_name: String,
    #[sqlx(try_from = "String")]
    pub role: Role,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// The public view of a user. It has no `password_hash` field.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: Role,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            full_name: u.full_name,
            role: u.role,
            is_active: u.is_active,
            created_at: u.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Task {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    #[sqlx(try_from = "String")]
    pub status: TaskStatus,
    pub assignee_id: Option<Uuid>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
