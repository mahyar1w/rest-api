# Project & Task Management API

Rust, Axum 0.8, SQLx 0.9 on MariaDB. JWT access tokens, rotating refresh tokens, role and ownership rules.

## Run

```bash
# MariaDB with a database `tasks` and user app/app (GRANT ALL ON tasks.*)
cp .env.example .env        # set JWT_SECRET and ADMIN_PASSWORD
cargo run --bin seed        # migrates and creates the admin (safe to rerun)
cargo run                   # http://localhost:3000, GET /health
cargo test                  # needs the database from .env
```

`query!` macros check SQL at compile time. The `.sqlx/` folder caches that check, so `SQLX_OFFLINE=true cargo build` works without a database. After changing any `query!` SQL, rerun `cargo sqlx prepare --workspace -- --all-targets` and commit `.sqlx/`.

## Endpoints

| Area | Routes |
|------|--------|
| Auth | `POST /auth/register`, `/auth/login` (rate limited), `/auth/refresh`, `/auth/logout`; `GET /auth/me`; `PUT /auth/me/password` |
| Users (admin) | `GET /users`, `GET /users/{id}`, `PATCH /users/{id}/role`, `PATCH /users/{id}/status` |
| Projects | `GET/POST /projects`, `GET/PATCH/DELETE /projects/{id}`, `POST /projects/{id}/members`, `DELETE /projects/{id}/members/{user_id}` |
| Tasks | `GET/POST /projects/{id}/tasks` (`status`, `assignee_id`, `page`, `limit`), `GET/PATCH/DELETE /tasks/{id}`, `PATCH /tasks/{id}/status` |

Errors: `{ "error": { "code", "message", "details" } }`. Lists: `{ "data", "meta": { "page", "limit", "total" } }`, limit 1..100.

## Design decisions

- **Roles:** admin sees and does everything. A manager owns projects and manages them. A member only sees projects they belong to and changes the status of tasks assigned to them.
- **404 vs 403:** an invisible project or task is 404 (existence isn't leaked); visible but not permitted is 403.
- **400 vs 422:** unreadable requests are 400, rule violations 422.
- **Refresh tokens:** random, stored only as SHA-256, rotated in one transaction. Reusing an old token revokes all of that user's sessions.
- **Login:** same error for wrong password and unknown email, dummy hash for equal timing, 5 burst then 1 per 12 s per IP.
- **Admins** come only from the seed binary; no route creates one.
- Users can't change their own role or status. Deactivating a user revokes their refresh tokens, and their access token stops working at once (user is loaded on every request).

## Known limits

- `TIMESTAMP` columns stop at 2038.
- Expired refresh tokens are never purged, and the rate limiter's memory isn't cleaned.
- Rate limiting keys on the peer IP; behind a proxy switch to `SmartIpKeyExtractor`.
- A malformed UUID in a URL returns axum's plain-text 400.
- Tests share the `tasks` database and use unique emails; no cleanup.
