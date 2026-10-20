use std::sync::Arc;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::MySqlPool,
    pub config: Arc<Config>,
}
