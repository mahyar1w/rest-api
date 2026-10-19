pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub access_minutes: i64,
    pub refresh_days: i64,
}

impl Config {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set"));
        Self {
            database_url: get("DATABASE_URL"),
            jwt_secret: get("JWT_SECRET"),
            access_minutes: get("ACCESS_TOKEN_MINUTES").parse().expect("number"),
            refresh_days: get("REFRESH_TOKEN_DAYS").parse().expect("number"),
        }
    }
}
