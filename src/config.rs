pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub access_minutes: i64,
    pub refresh_days: i64,
}

impl Config {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set"));
        let jwt_secret = get("JWT_SECRET");
        // Anyone who knows the secret can sign a token for any user, so refuse short or example values.
        assert!(
            jwt_secret.len() >= 32 && !jwt_secret.starts_with("replace-"),
            "JWT_SECRET must be at least 32 characters and not the example value"
        );
        Self {
            database_url: get("DATABASE_URL"),
            jwt_secret,
            access_minutes: get("ACCESS_TOKEN_MINUTES").parse().expect("number"),
            refresh_days: get("REFRESH_TOKEN_DAYS").parse().expect("number"),
        }
    }
}
