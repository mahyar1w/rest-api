# Project & Task Management API

Rust, Axum 0.8, SQLx 0.9 on MariaDB. JWT access tokens, rotating refresh tokens, role and ownership rules.

## Prerequisites

Rust (stable, edition 2024), MariaDB 11 (MySQL 8 should work too), and Python 3 for the API tests (standard library only).

## Run

```bash
# MariaDB with a database `tasks` and user app/app (GRANT ALL ON tasks.*)
cp .env.example .env        # set JWT_SECRET and ADMIN_PASSWORD
cargo run --bin seed        # migrates and creates the admin (safe to rerun)
cargo run                   # http://localhost:3000, GET /health
cargo test                  # unit tests
python3 -m unittest -v tests/test_api.py   # API tests, against the running server (stdlib only, Linux)
```

`query!` macros check SQL at compile time. The `.sqlx/` folder caches that check, so `SQLX_OFFLINE=true cargo build` works without a database. After changing any `query!` SQL, rerun `cargo sqlx prepare --workspace -- --all-targets` and commit `.sqlx/`.

CI (`.github/workflows/ci.yml`) runs fmt, clippy and the unit tests, then starts the server against a MariaDB service container and runs the Python API tests, building from the `.sqlx/` cache.

## Project structure

```
src/
  main.rs        starts the server: config, DB pool, migrations, graceful shutdown
  lib.rs         build_app(): mounts the routers, body limit, tracing, JSON 404 fallback
  config.rs      reads and checks the environment
  state.rs       AppState shared by every handler (DB pool + config)
  error.rs       AppError: every error becomes one JSON shape and status code
  extract.rs     AuthUser (auth guard), ValidatedJson/ValidatedQuery (input checks), Path (JSON 400)
  policy.rs      every authorization rule, as pure functions with unit tests
  security.rs    argon2 hashing, JWT signing/checking, refresh-token generation
  models.rs      DB rows and public response types (UserResponse never has the hash)
  page.rs        pagination clamping and the list response shape
  routes/        one file per area: auth, users, projects, tasks
  bin/seed.rs    creates the first admin
migrations/      the schema
tests/test_api.py  black-box API tests
```

Layering: handlers are thin. They parse input (extractors), ask `policy.rs` whether the action is allowed, and run the SQL. The SQL stays in the handler instead of a separate repository layer: each query is used in one place, and `query!` checks it against the schema at compile time. Authorization is the part that must stay in one place, and it does.

## Endpoints

| Area | Routes |
|------|--------|
| Auth | `POST /auth/register`, `/auth/login` (both rate limited), `/auth/refresh`, `/auth/logout`; `GET /auth/me`; `PUT /auth/me/password` |
| Users (admin) | `GET /users`, `GET /users/{id}`, `PATCH /users/{id}/role`, `PATCH /users/{id}/status` |
| Projects | `GET/POST /projects`, `GET/PATCH/DELETE /projects/{id}`, `POST /projects/{id}/members`, `DELETE /projects/{id}/members/{user_id}` |
| Tasks | `GET/POST /projects/{id}/tasks` (`status`, `assignee_id`, `page`, `limit`), `GET/PATCH/DELETE /tasks/{id}`, `PATCH /tasks/{id}/status` |

Errors: `{ "error": { "code", "message", "details" } }`. Lists: `{ "data", "meta": { "page", "limit", "total" } }`, limit 1..100.

## Example requests

```bash
API=http://localhost:3000

# Register (role is always member) and log in
curl -s -X POST $API/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"sara@example.com","password":"password123","full_name":"Sara"}'
# 201 {"id":"…","email":"sara@example.com","full_name":"Sara","role":"member","is_active":true,"created_at":"…"}

curl -s -X POST $API/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"sara@example.com","password":"password123"}'
# 200 {"access_token":"eyJ…","refresh_token":"…","token_type":"Bearer","expires_in":900}

# The admin (from the seed) makes Sara a manager
curl -s -X PATCH $API/users/$SARA_ID/role -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{"role":"manager"}'

# Sara creates a project, adds a member and gives them a task
curl -s -X POST $API/projects -H "Authorization: Bearer $SARA" \
  -H 'Content-Type: application/json' -d '{"name":"Website","description":"Relaunch"}'
# 201 {"id":"…","name":"Website","description":"Relaunch","owner_id":"…","created_at":"…"}

curl -s -X POST $API/projects/$PROJECT/members -H "Authorization: Bearer $SARA" \
  -H 'Content-Type: application/json' -d '{"user_id":"'$ALI_ID'"}'
# 201

curl -s -X POST $API/projects/$PROJECT/tasks -H "Authorization: Bearer $SARA" \
  -H 'Content-Type: application/json' -d '{"title":"Design home page","assignee_id":"'$ALI_ID'"}'
# 201 {"id":"…","status":"todo","assignee_id":"…",…}

# Ali (a member) moves the assigned task forward, then lists the project's in-progress tasks
curl -s -X PATCH $API/tasks/$TASK/status -H "Authorization: Bearer $ALI" \
  -H 'Content-Type: application/json' -d '{"status":"in_progress"}'
curl -s "$API/projects/$PROJECT/tasks?status=in_progress&page=1&limit=20" -H "Authorization: Bearer $ALI"
# 200 {"data":[…],"meta":{"page":1,"limit":20,"total":1}}

# Clear a field with null (leaving it out keeps it)
curl -s -X PATCH $API/tasks/$TASK -H "Authorization: Bearer $SARA" \
  -H 'Content-Type: application/json' -d '{"assignee_id":null}'

# New token pair; the old refresh token stops working. Logout revokes the current one.
curl -s -X POST $API/auth/refresh -H 'Content-Type: application/json' -d '{"refresh_token":"'$REFRESH'"}'
curl -s -X POST $API/auth/logout  -H 'Content-Type: application/json' -d '{"refresh_token":"'$REFRESH'"}'
# 204

# Change password: every refresh token of the user is revoked
curl -s -X PUT $API/auth/me/password -H "Authorization: Bearer $ALI" \
  -H 'Content-Type: application/json' -d '{"current_password":"password123","new_password":"another-pass1"}'
# 204

# An error, in the same shape as every other
curl -s $API/projects/$PROJECT -H "Authorization: Bearer $STRANGER"
# 404 {"error":{"code":"NOT_FOUND","message":"not found","details":null}}
```

## Why MariaDB

- **SQLx:** plain SQL with compile-time checking against the real schema, no ORM layer to learn or hide behind.
- **MariaDB:** a common, free relational database. The data is relational (users, projects, members, tasks) and needs foreign keys, cascades and transactions.

## Design decisions

- **Roles:** admin sees and does everything. A manager owns projects and manages them. A member only sees projects they belong to and changes the status of tasks assigned to them.
- **404 vs 403:** an invisible project or task is 404 (existence isn't leaked); visible but not permitted is 403.
- **400 vs 422:** unreadable requests are 400, rule violations 422.
- **Refresh tokens:** random, stored only as SHA-256, rotated in one transaction. Reusing an old token revokes all of that user's sessions.
- **Login:** same error for wrong password and unknown email, dummy hash for equal timing. Register and login share one limit: 5 burst then 1 per 12 s per IP. At most 8 argon2 hashes run at once (~150 MiB), so floods queue instead of exhausting memory.
- **PATCH:** a field left out is kept; `null` clears `description` and `assignee_id`.
- **JWT_SECRET** must be 32+ characters; the server refuses to start otherwise.
- **Admins** come only from the seed binary; no route creates one.
- Users can't change their own role or status. Deactivating a user revokes their refresh tokens, and their access token stops working at once (user is loaded on every request).

## Assumptions

Where the brief left room, I chose:

- **The project owner counts as part of the project:** they can be assigned tasks and see everything in it, without a `project_members` row.
- **Register answers 409 for a taken email.** That reveals the email exists, which login avoids. The brief lists 409 and a signup form must say why it failed, so I kept it; register is rate limited, which slows down anyone collecting emails this way.
- **The rate limit counts every login and register attempt per IP**, not only failed ones: 5 at once, then 1 every 12 s (5 per minute).
- **Removing a member unassigns their tasks in that project**, in the same transaction, so no task stays assigned to someone who can't see it.
- **A manager demoted to member keeps ownership** of their projects and can still see them, but can no longer manage them. An admin can.
- **A user's status changes take effect at once:** the user is loaded from the database on every request, so a deactivated user's access token fails right away, not after it expires.

## Known limits

- `TIMESTAMP` columns stop at 2038.
- sqlx's migration lock does nothing on MariaDB (`GET_LOCK(name, -1)` returns NULL at once instead of waiting), so never start two processes on an empty database at the same time. Run `seed` first; it migrates.
- Expired refresh tokens are never purged, and the rate limiter's memory isn't cleaned.
- Rate limiting keys on the peer IP; behind a proxy switch to `SmartIpKeyExtractor`.
- A wrong HTTP method (405) and a too-large body (413) still answer in axum's own format, not the JSON error shape.
- API tests share the `tasks` database and use unique emails; no cleanup. Each request comes from a random 127.x.y.z address so the login limiter doesn't trip, which needs Linux.

## With more time

- OpenAPI/Swagger docs generated from the handlers (e.g. `utoipa`).
- A background job that deletes expired refresh tokens, and a session list with "log out everywhere".
- An audit log for role changes, deactivations and project deletes.
- Soft delete for projects and tasks.
- Docker Compose to start MariaDB and the API with one command.
- Permission-based checks (e.g. `project:manage`) instead of role names in `policy.rs`.

## Acknowledgement
Ai agents have been used in this project for debugging purposes. As well as creating documentation and tests. however the code itself is mostly hand-written
