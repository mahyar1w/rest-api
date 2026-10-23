mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::app;

#[tokio::test]
async fn register_login_me_and_no_password_leak() {
    let t = app().await;
    let (_, email) = t.register("alice").await;
    let tokens = t.login(&email).await;
    let (s, me) = t
        .call("GET", "/auth/me", tokens["access_token"].as_str(), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["email"], email);
    assert!(!me.to_string().contains("password"));
    assert_eq!(me["role"], "member");
}

#[tokio::test]
async fn duplicate_email_is_409_and_bad_input_is_422() {
    let t = app().await;
    let (_, email) = t.register("dup").await;
    let body = json!({"email": email, "password": "password123", "full_name": "x"});
    assert_eq!(
        t.call("POST", "/auth/register", None, Some(body)).await.0,
        StatusCode::CONFLICT
    );
    let bad = json!({"email": "nope", "password": "short", "full_name": ""});
    let (s, b) = t.call("POST", "/auth/register", None, Some(bad)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        !b.to_string().contains("short"),
        "must not echo the password"
    );
}

#[tokio::test]
async fn wrong_password_and_unknown_email_look_identical() {
    let t = app().await;
    let (_, email) = t.register("who").await;
    let wrong = t
        .call(
            "POST",
            "/auth/login",
            None,
            Some(json!({"email": email, "password": "wrongpass1"})),
        )
        .await;
    let unknown = t
        .call(
            "POST",
            "/auth/login",
            None,
            Some(json!({"email": "ghost@example.com", "password": "wrongpass1"})),
        )
        .await;
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong, unknown);
}

#[tokio::test]
async fn refresh_rotates_and_reuse_revokes_everything() {
    let t = app().await;
    let (_, email) = t.register("rot").await;
    let first = t.login(&email).await;
    let r1 = first["refresh_token"].as_str().unwrap();

    let (s, second) = t
        .call(
            "POST",
            "/auth/refresh",
            None,
            Some(json!({"refresh_token": r1})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let r2 = second["refresh_token"].as_str().unwrap();
    assert_ne!(r1, r2);

    // Replaying the old token is theft: 401, and the new token dies too.
    let replay = t
        .call(
            "POST",
            "/auth/refresh",
            None,
            Some(json!({"refresh_token": r1})),
        )
        .await;
    assert_eq!(replay.0, StatusCode::UNAUTHORIZED);
    let after = t
        .call(
            "POST",
            "/auth/refresh",
            None,
            Some(json!({"refresh_token": r2})),
        )
        .await;
    assert_eq!(after.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_is_rate_limited() {
    let t = app().await;
    let mut last = StatusCode::OK;
    for _ in 0..8 {
        last = t
            .call(
                "POST",
                "/auth/login",
                None,
                Some(json!({"email": "x@example.com", "password": "wrongpass1"})),
            )
            .await
            .0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn permissions_and_visibility() {
    let t = app().await;
    let (_, member) = t.user("member").await;
    let (m1_id, m1) = t.user("manager").await;
    let (_, m2) = t.user("manager").await;
    let (alice_id, alice) = t.user("member").await;
    let (_, stranger) = t.user("member").await;

    // member can't create a project
    assert_eq!(
        t.call(
            "POST",
            "/projects",
            Some(&member),
            Some(json!({"name": "n"}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    let (s, p) = t
        .call(
            "POST",
            "/projects",
            Some(&m1),
            Some(json!({"name": "Alpha"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(p["owner_id"], m1_id.to_string());
    let pid = p["id"].as_str().unwrap();

    // another manager, and a stranger, can't even see it
    assert_eq!(
        t.call(
            "PATCH",
            &format!("/projects/{pid}"),
            Some(&m2),
            Some(json!({"name": "x"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.call("GET", &format!("/projects/{pid}"), Some(&stranger), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let (s, _) = t
        .call(
            "POST",
            &format!("/projects/{pid}/members"),
            Some(&m1),
            Some(json!({"user_id": alice_id})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    // a member sees it but can't edit it
    assert_eq!(
        t.call("GET", &format!("/projects/{pid}"), Some(&alice), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        t.call(
            "PATCH",
            &format!("/projects/{pid}"),
            Some(&alice),
            Some(json!({"name": "x"}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    // tasks: assignee can change status, others can't
    let (s, task) = t
        .call(
            "POST",
            &format!("/projects/{pid}/tasks"),
            Some(&m1),
            Some(json!({"title": "A", "assignee_id": alice_id})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let tid = task["id"].as_str().unwrap();
    let (s, b) = t
        .call(
            "PATCH",
            &format!("/tasks/{tid}/status"),
            Some(&alice),
            Some(json!({"status": "in_progress"})),
        )
        .await;
    assert_eq!(
        (s, b["status"].as_str()),
        (StatusCode::OK, Some("in_progress"))
    );
    assert_eq!(
        t.call(
            "PATCH",
            &format!("/tasks/{tid}/status"),
            Some(&stranger),
            Some(json!({"status": "done"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.call(
            "PATCH",
            &format!("/tasks/{tid}"),
            Some(&alice),
            Some(json!({"title": "x"}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    // assignee must belong to the project
    let (s, _) = t
        .call(
            "POST",
            &format!("/projects/{pid}/tasks"),
            Some(&m1),
            Some(json!({"title": "B", "assignee_id": uuid::Uuid::new_v4()})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn admin_deactivation_kills_the_token_and_pagination_is_clamped() {
    let t = app().await;
    let (_, admin) = t.user("admin").await;
    let (victim_id, victim) = t.user("member").await;

    let (s, b) = t
        .call("GET", "/projects?limit=100000", Some(&admin), None)
        .await;
    assert_eq!(
        (s, b["meta"]["limit"].as_i64()),
        (StatusCode::OK, Some(100))
    );

    assert_eq!(
        t.call("GET", "/users", Some(&victim), None).await.0,
        StatusCode::FORBIDDEN
    );
    let (s, _) = t
        .call(
            "PATCH",
            &format!("/users/{victim_id}/status"),
            Some(&admin),
            Some(json!({"is_active": false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        t.call("GET", "/auth/me", Some(&victim), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.call("GET", "/projects", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
}
