use std::sync::LazyLock;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{config::Config, error::AppError};

// ---------- a) Password hashing (argon2) ----------

fn hash_password_blocking(pw: &str) -> Result<String, AppError> {
    // The salt is generated automatically and stored inside the PHC string.
    Argon2::default()
        .hash_password(pw.as_bytes())
        .map(|h| h.to_string())
        .map_err(|_| AppError::Internal)
}

fn verify_password_blocking(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// Hashes a password on a blocking thread, because argon2 is deliberately slow.
pub async fn hash_password(pw: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || hash_password_blocking(&pw))
        .await
        .map_err(|_| AppError::Internal)?
}

/// Verifies a password on a blocking thread. A join failure counts as a mismatch.
pub async fn verify_password(pw: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password_blocking(&pw, &hash))
        .await
        .unwrap_or(false)
}

/// A real argon2 hash of a throwaway password. Login checks against it when the
/// email is unknown, so unknown and known emails take the same time to answer.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    hash_password_blocking("dummy-password-for-timing").expect("argon2 dummy hash")
});

pub fn dummy_hash() -> String {
    DUMMY_HASH.clone()
}

// ---------- b) JWT access tokens ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_access_token(user_id: Uuid, cfg: &Config) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(cfg.access_minutes)).timestamp() as usize,
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .map_err(|_| AppError::Internal)
}

pub fn decode_access_token(token: &str, cfg: &Config) -> Option<Claims> {
    jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &Validation::default(), // checks exp automatically
    )
    .ok()
    .map(|d| d.claims)
}

// ---------- c) Refresh tokens: random, opaque, stored only as a hash ----------

/// Returns `(token, hash)`. Send `token` to the client and store `hash` in the database.
pub fn new_refresh_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh_token(&token);
    (token, hash)
}

pub fn hash_refresh_token(t: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(t.as_bytes()))
}
