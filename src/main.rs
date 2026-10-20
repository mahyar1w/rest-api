use std::{net::SocketAddr, sync::Arc};

use sqlx::mysql::MySqlPoolOptions;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use task_api::{build_app, config::Config, state::AppState};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env();
    let db = MySqlPoolOptions::new()
        .connect(&config.database_url)
        .await
        .expect("failed to connect to the database");
    sqlx::migrate!()
        .run(&db)
        .await
        .expect("failed to run migrations");

    let app = build_app(AppState {
        db,
        config: Arc::new(config),
    });
    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind port 3000");
    tracing::info!("listening on {}", listener.local_addr().unwrap());

    // connect_info gives the rate limiter the client's IP address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    tracing::info!("shutting down");
}
