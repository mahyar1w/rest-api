//! Creates the first admin from ADMIN_EMAIL and ADMIN_PASSWORD. Safe to run repeatedly.
//! There is deliberately no API route that creates admins.

use sqlx::mysql::MySqlPoolOptions;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set"));

    let db = MySqlPoolOptions::new()
        .connect(&env("DATABASE_URL"))
        .await
        .expect("failed to connect to the database");
    // Runs the migrations too, so the seed works on a database the server hasn't touched yet.
    sqlx::migrate!()
        .run(&db)
        .await
        .expect("failed to run migrations");

    let email = env("ADMIN_EMAIL").trim().to_lowercase();

    // Check first: sqlx connects with MySQL's "found rows" flag, so rows_affected() can't
    // tell a new row from an untouched duplicate.
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&db)
        .await
        .expect("failed to look up the admin");
    if existing > 0 {
        println!("admin {email} already exists, nothing changed");
        return;
    }

    let hash = task_api::security::hash_password(env("ADMIN_PASSWORD"))
        .await
        .expect("failed to hash the admin password");
    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, full_name, role)
         VALUES (?, ?, ?, 'Administrator', 'admin')",
        Uuid::new_v4(),
        email,
        hash
    )
    .execute(&db)
    .await
    .expect("failed to insert the admin");
    println!("created admin {email}");
}
