pub mod config;
pub mod error;
pub mod extract;
pub mod models;
pub mod page;
pub mod policy;
pub mod routes;
pub mod security;
pub mod state;

use axum::{Router, routing::get};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use state::AppState;

/// Builds the whole app. The integration tests in Step 12 call this too.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(routes::auth::router())
        .merge(routes::users::router())
        .merge(routes::projects::router())
        .merge(routes::tasks::router())
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
