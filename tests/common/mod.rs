//! Shared helpers. Every test builds its own app (so its own rate limiter) on the shared
//! `DATABASE_URL` database and uses unique emails, so tests don't collide.
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use task_api::{build_app, config::Config, state::AppState};
use tower::ServiceExt;
use uuid::Uuid;

pub struct TestApp {
    pub app: Router,
    pub db: sqlx::MySqlPool,
}

pub async fn app() -> TestApp {
    dotenvy::dotenv().ok();
    let mut config = Config::from_env();
    config.jwt_secret = "test-secret-test-secret-test-secret".into();
    let db = sqlx::MySqlPool::connect(&config.database_url)
        .await
        .unwrap();
    sqlx::migrate!().run(&db).await.unwrap();
    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
    };
    let app = build_app(state);
    TestApp { app, db }
}

impl TestApp {
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        // The login rate limiter keys on the peer address, which oneshot requests don't have.
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Registers a user and returns (id, email).
    pub async fn register(&self, tag: &str) -> (Uuid, String) {
        let email = format!("{tag}-{}@example.com", Uuid::new_v4());
        let (s, b) = self
            .call(
                "POST",
                "/auth/register",
                None,
                Some(json!({"email": email, "password": "password123", "full_name": tag})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        (b["id"].as_str().unwrap().parse().unwrap(), email)
    }

    pub async fn login(&self, email: &str) -> Value {
        let (s, b) = self
            .call(
                "POST",
                "/auth/login",
                None,
                Some(json!({"email": email, "password": "password123"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        b
    }

    /// A registered user with the given role (set directly in the DB), plus their access token.
    pub async fn user(&self, role: &str) -> (Uuid, String) {
        let (id, email) = self.register(role).await;
        sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(role)
            .bind(id)
            .execute(&self.db)
            .await
            .unwrap();
        let token = self.login(&email).await["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        (id, token)
    }
}
