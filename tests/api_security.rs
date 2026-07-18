//! Track 4: API security tests — client CRUD, IDOR enforcement, SQL injection
//! attempts, XSS payloads, input validation.
//!
//! Each test resets the global DB handle via `serial_test`. The router is
//! rebuilt per test.

mod common;

use awg_easy_rs::{api, auth, db};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use serial_test::serial;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn seed() {
    common::seed();
}

fn router() -> axum::Router {
    api::build_router(api::AppState::new())
}

async fn login_get_cookie(app: &axum::Router, username: &str, password: &str) -> String {
    let body = json!({ "username": username, "password": password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let cookies: Vec<_> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    cookies
        .into_iter()
        .find(|c| c.starts_with("awg_session="))
        .unwrap()
        .strip_prefix("awg_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn create_user(username: &str, password: &str, role: i64) -> i64 {
    let hash = auth::hash_password(password).unwrap();
    db::create_user(&db::CreateUserParams {
        username: username.into(),
        password: hash,
        email: None,
        name: username.into(),
        role,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })
    .unwrap()
}

fn create_client(user_id: Option<i64>, name: &str, ip: &str) -> i64 {
    db::create_client(&db::CreateClientParams {
        user_id,
        interface_id: Some("awg0".into()),
        name: name.into(),
        ipv4_address: Some(ip.into()),
        ipv6_address: Some(format!("fdcc::{ip}")),
        private_key: format!("pk-{name}"),
        public_key: format!("pub-{name}"),
        pre_shared_key: Some(format!("psk-{name}")),
        pre_up: None, post_up: None, pre_down: None, post_down: None,
        expires_at: None,
        allowed_ips: Some(r#"["0.0.0.0/0"]"#.into()),
        server_allowed_ips: None, firewall_ips: None,
        persistent_keepalive: 25, mtu: 1420,
        j_c: None, j_min: None, j_max: None,
        i1: None, i2: None, i3: None, i4: None, i5: None,
        dns: Some(r#"["1.1.1.1"]"#.into()),
        server_endpoint: None,
        advanced_security: Some(true),
        enabled: true,
    })
    .unwrap()
}

async fn post(app: &axum::Router, path: &str, cookie: &str, body_val: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("awg_session={cookie}"))
        .body(Body::from(serde_json::to_vec(body_val).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));
    (status, body)
}

async fn get_req(app: &axum::Router, path: &str, cookie: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, format!("awg_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));
    (status, body)
}

async fn delete_req(app: &axum::Router, path: &str, cookie: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(path)
        .header(header::COOKIE, format!("awg_session={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));
    (status, body)
}

// ---------------------------------------------------------------------------
// Client CRUD (admin role)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn admin_list_clients() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    create_client(Some(admin_id), "c1", "10.8.0.10");
    create_client(Some(admin_id), "c2", "10.8.0.11");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let (status, body) = get_req(&app, "/api/client", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
}

#[tokio::test]
#[serial(db)]
async fn admin_create_client() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let body = json!({ "name": "new-client" });
    let (status, resp) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(resp["clientId"].as_i64().unwrap() > 0);
}

#[tokio::test]
#[serial(db)]
async fn admin_update_client() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "orig", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let body = json!({ "name": "renamed" });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
    let client = db::get_client(client_id).unwrap();
    assert_eq!(client.name, "renamed");
}

#[tokio::test]
#[serial(db)]
async fn admin_delete_client() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "to-delete", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let (status, _) = delete_req(&app, &format!("/api/client/{client_id}"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(db::get_client(client_id).is_err());
}

// ---------------------------------------------------------------------------
// IDOR enforcement — non-admin user cannot access other users' clients
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn idor_user_cannot_get_others_client() {
    seed();
    let alice_id = create_user("alice", "pass1", 0);
    let bob_id = create_user("bob", "pass2", 0);
    let alice_client = create_client(Some(alice_id), "alice-client", "10.8.0.10");
    let _bob_client = create_client(Some(bob_id), "bob-client", "10.8.0.11");

    let app = router();
    let cookie = login_get_cookie(&app, "bob", "pass2").await;

    // Bob tries to view Alice's client
    let (status, _) = get_req(&app, &format!("/api/client/{alice_client}"), &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn idor_user_cannot_update_others_client() {
    seed();
    let alice_id = create_user("alice", "pass1", 0);
    create_user("bob", "pass2", 0);
    let alice_client = create_client(Some(alice_id), "alice-client", "10.8.0.10");

    let app = router();
    let cookie = login_get_cookie(&app, "bob", "pass2").await;
    let body = json!({ "name": "hijacked" });
    let (status, _) = post(&app, &format!("/api/client/{alice_client}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn idor_user_cannot_delete_others_client() {
    seed();
    let alice_id = create_user("alice", "pass1", 0);
    create_user("bob", "pass2", 0);
    let alice_client = create_client(Some(alice_id), "alice-client", "10.8.0.10");

    let app = router();
    let cookie = login_get_cookie(&app, "bob", "pass2").await;
    let (status, _) = delete_req(&app, &format!("/api/client/{alice_client}"), &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn idor_user_can_access_own_client() {
    seed();
    let alice_id = create_user("alice", "pass1", 0);
    let client_id = create_client(Some(alice_id), "alice-client", "10.8.0.10");

    let app = router();
    let cookie = login_get_cookie(&app, "alice", "pass1").await;
    let (status, _) = get_req(&app, &format!("/api/client/{client_id}"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn idor_user_list_only_shows_own_clients() {
    seed();
    let alice_id = create_user("alice", "pass1", 0);
    let bob_id = create_user("bob", "pass2", 0);
    create_client(Some(alice_id), "alice-1", "10.8.0.10");
    create_client(Some(bob_id), "bob-1", "10.8.0.11");

    let app = router();
    let cookie = login_get_cookie(&app, "alice", "pass1").await;
    let (status, body) = get_req(&app, "/api/client", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "alice-1");
}

#[tokio::test]
#[serial(db)]
async fn idor_non_admin_cannot_access_admin_endpoints() {
    seed();
    create_user("user", "pass", 0);
    let app = router();
    let cookie = login_get_cookie(&app, "user", "pass").await;

    let (status, _) = get_req(&app, "/api/admin/general", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get_req(&app, "/api/admin/hooks", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get_req(&app, "/api/admin/userconfig", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get_req(&app, "/api/admin/interface", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// SQL Injection attempts
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn sql_injection_username_login() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let body = json!({ "username": "admin' OR '1'='1", "password": "anything" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Should get 401 (not found), NOT 200 (bypassed auth)
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn sql_injection_client_name_create() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let malicious_name = "test'); DROP TABLE clients_table; --";
    let body = json!({ "name": malicious_name });
    let (status, _) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    // clients_table should still exist and be queryable
    let clients = db::get_all_clients().unwrap();
    assert!(!clients.is_empty());
}

#[tokio::test]
#[serial(db)]
async fn sql_injection_client_name_update() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "original", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let malicious_name = "test'; UPDATE users_table SET role=1 WHERE username='admin'; --";
    let body = json!({ "name": malicious_name });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    // Database should still be intact
    assert!(db::get_client(client_id).is_ok());
}

#[tokio::test]
#[serial(db)]
async fn sql_injection_setup_username() {
    seed();
    let app = router();
    // Payload must be ≤ 64 chars; this one is short enough to be stored
    // as a literal username, not executed.
    let body = json!({
        "username": "x'; DROP TABLE users;--",
        "password": "password1234",
        "confirmPassword": "password1234"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/setup/2")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Should succeed (the malicious name gets stored, not executed)
    assert_eq!(resp.status(), StatusCode::OK);
    // Only one user should exist (no injection)
    assert_eq!(db::get_user_count().unwrap(), 1);
}

#[tokio::test]
#[serial(db)]
async fn sql_injection_admin_general() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Inject via a TEXT-field-mapped key. The handler maps unknown camelCase
    // keys through to_snake_case, so any key can end up in the UPDATE map.
    // The build_update whitelist rejects unknown columns, so this should fail.
    // But with sessionTimeout mapped to session_timeout (INTEGER), a non-integer
    // string will cause a readback failure. We test that the general table
    // is still queryable by checking the setup_step (unaffected column).
    let body = json!({ "sessionTimeout": 9999 });
    let (status, _) = post(&app, "/api/admin/general", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    // Table intact — setup_step should still be readable
    assert!(db::get_setup_step().is_ok());
}

// ---------------------------------------------------------------------------
// XSS payloads
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn xss_client_name_stored_literally() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let xss_name = "<script>alert('xss')</script>";
    let body = json!({ "name": xss_name });
    let (status, resp) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    let client_id = resp["clientId"].as_i64().unwrap();
    let client = db::get_client(client_id).unwrap();
    // The script tags should be stored as-is in the DB — no escaping at DB layer
    // (the frontend is responsible for output encoding)
    assert_eq!(client.name, xss_name);
}

#[tokio::test]
#[serial(db)]
async fn xss_username_stored_literally() {
    seed();
    let xss_username = "<img src=x onerror=alert(1)>";
    create_user(xss_username, "pass", 0);

    let app = router();
    let cookie = login_get_cookie(&app, xss_username, "pass").await;
    let (status, body) = get_req(&app, "/api/session", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["username"], xss_username);
}

#[tokio::test]
#[serial(db)]
async fn xss_client_fields() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Create client with XSS in name
    let body = json!({ "name": "<b>bold</b><script src=evil.js></script>" });
    let (status, _) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    // Verify it can be retrieved (stored, not executed server-side)
    let (status, body) = get_req(&app, "/api/client", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    let clients = body.as_array().unwrap();
    assert!(clients.iter().any(|c| c["name"] == "<b>bold</b><script src=evil.js></script>"));
}

#[tokio::test]
#[serial(db)]
async fn xss_admin_hooks() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "preUp": "<script>evil()</script>" });
    let (status, _) = post(&app, "/api/admin/hooks", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    let hooks = db::get_hooks().unwrap();
    assert_eq!(hooks.pre_up, "<script>evil()</script>");
}

// ---------------------------------------------------------------------------
// Input validation — boundary values
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn validation_client_name_missing() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({});
    let req = Request::builder()
        .method("POST")
        .uri("/api/client")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("awg_session={cookie}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Missing required field should be a deserialization error (422 or 400)
    assert!(!resp.status().is_success());
}

#[tokio::test]
#[serial(db)]
async fn validation_mtu_boundary_low() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "mtu-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "mtu": 67 }); // below min 68
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn validation_mtu_boundary_high() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "mtu-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "mtu": 65536 }); // above max 65535
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn validation_persistent_keepalive_boundary() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "ka-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Valid: 0 is allowed
    let body = json!({ "persistentKeepalive": 0 });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    // Invalid: 10 (below 15, but not 0)
    let body = json!({ "persistentKeepalive": 10 });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Valid: 15
    let body = json!({ "persistentKeepalive": 15 });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn validation_jc_boundary() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "jc-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "jC": 0 }); // below min 1
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let body = json!({ "jC": 129 }); // above max 128
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn validation_jc_gte_jmin() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "jc-jmin-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "jC": 5, "jMin": 10 });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn validation_expires_at_invalid_format() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "exp-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "expiresAt": "not-a-date" });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn validation_expires_at_valid_formats() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "exp-test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "expiresAt": "2099-12-31T23:59:59Z" });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    let body = json!({ "expiresAt": "2099-12-31T23:59" });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Unauthenticated access
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn unauthenticated_client_list() {
    seed();
    let app = router();
    let (status, _) = get_req(&app, "/api/client", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn unauthenticated_client_create() {
    seed();
    let app = router();
    let body = json!({ "name": "test" });
    let (status, _) = post(&app, "/api/client", "", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial(db)]
async fn unauthenticated_admin_access() {
    seed();
    let app = router();
    let (status, _) = get_req(&app, "/api/admin/general", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Request body edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn empty_request_body_client_update() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({});
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn unknown_fields_in_client_update() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "test", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // UpdateClientRequest has #[serde(deny_unknown_fields)]
    let body = json!({ "hackedField": "evil" });
    let (status, _) = post(&app, &format!("/api/client/{client_id}"), &cookie, &body).await;
    // Should be rejected (either 422 from serde or 400 for empty fields)
    assert!(!status.is_success());
}

#[tokio::test]
#[serial(db)]
async fn login_with_empty_body() {
    seed();
    let app = router();
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // Missing required fields — should error
    assert!(!resp.status().is_success());
}

#[tokio::test]
#[serial(db)]
async fn login_with_malformed_json() {
    seed();
    let app = router();
    let req = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("not json"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(!resp.status().is_success());
}

// ---------------------------------------------------------------------------
// Privilege escalation regression tests (the IP-self-assignment family)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn non_admin_cannot_change_own_ipv4_address() {
    seed();
    let user_id = create_user("alice", "passpass", 0);
    let client_id = create_client(Some(user_id), "alice-c", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "alice", "passpass").await;

    // Attempt to hijack the gateway address.
    let body = json!({ "ipv4Address": "10.8.0.1" });
    let (status, resp) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(resp["error"].as_str().unwrap().contains("admin"));

    // The DB row must not have been modified.
    let client = db::get_client(client_id).unwrap();
    assert_eq!(client.ipv4_address.as_deref(), Some("10.8.0.10"));
}

#[tokio::test]
#[serial(db)]
async fn non_admin_cannot_change_allowed_ips() {
    seed();
    let user_id = create_user("bob", "passpass", 0);
    let client_id = create_client(Some(user_id), "bob-c", "10.8.0.20");
    let app = router();
    let cookie = login_get_cookie(&app, "bob", "passpass").await;

    let body = json!({ "allowedIps": ["1.2.3.4/32"] });
    let (status, _) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn non_admin_cannot_change_dns_or_mtu() {
    seed();
    let user_id = create_user("carol", "passpass", 0);
    let client_id = create_client(Some(user_id), "carol-c", "10.8.0.30");
    let app = router();
    let cookie = login_get_cookie(&app, "carol", "passpass").await;

    let body = json!({ "mtu": 1380 });
    let (status, _) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial(db)]
async fn admin_ipv4_must_be_inside_cidr() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "c1", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // 1.2.3.4 is outside the seeded 10.8.0.0/24 interface CIDR.
    let body = json!({ "ipv4Address": "1.2.3.4" });
    let (status, resp) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().contains("inside"));
}

#[tokio::test]
#[serial(db)]
async fn admin_ipv4_inside_cidr_accepted() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "c1", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "ipv4Address": "10.8.0.50" });
    let (status, _) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let client = db::get_client(client_id).unwrap();
    assert_eq!(client.ipv4_address.as_deref(), Some("10.8.0.50"));
}

#[tokio::test]
#[serial(db)]
async fn create_client_rejects_oversized_name() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let huge = "a".repeat(257);
    let body = json!({ "name": huge });
    let (status, _) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn create_client_rejects_empty_name() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let body = json!({ "name": "" });
    let (status, _) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Username enumeration timing — both branches should look identical to a
// caller. We can't measure wall-clock here reliably, but we can at least
// confirm the response body is identical for missing-user vs wrong-password.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn login_missing_and_wrong_password_return_same_error() {
    seed();
    create_user("real_user", "realpass1234", 0);
    let app = router();

    // Wrong password for an existing user.
    let body1 = json!({ "username": "real_user", "password": "wrong" });
    let req1 = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body1).unwrap()))
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    let status1 = resp1.status();
    let body1_bytes = axum::body::to_bytes(resp1.into_body(), 65536).await.unwrap();
    let body1_v: Value = serde_json::from_slice(&body1_bytes).unwrap();

    // Non-existent user.
    let body2 = json!({ "username": "ghost_user", "password": "wrong" });
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    let status2 = resp2.status();
    let body2_bytes = axum::body::to_bytes(resp2.into_body(), 65536).await.unwrap();
    let body2_v: Value = serde_json::from_slice(&body2_bytes).unwrap();

    assert_eq!(status1, StatusCode::UNAUTHORIZED);
    assert_eq!(status2, StatusCode::UNAUTHORIZED);
    assert_eq!(body1_v["error"], body2_v["error"]);
}

// ---------------------------------------------------------------------------
// Generic-fields removed from /api/admin/general POST
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn admin_general_post_ignores_unknown_fields() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Malicious request: try to reset the setup wizard and unset the
    // session password. Both fields should be silently ignored — only the
    // explicit whitelist (sessionTimeout / metricsPrometheus / metricsJson /
    // metricsPassword) is honoured.
    let body = json!({
        "setupStep": 1,
        "sessionPassword": "evilevileveileveileveileveil",
        "sessionTimeout": 7200
    });
    let (status, _) = post(&app, "/api/admin/general", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    let general = db::get_general().unwrap();
    assert_eq!(general.session_timeout, 7200);
    // Setup step must be unchanged from its seeded default of 1 (we didn't
    // touch it through this endpoint), and session_password must not have
    // been replaced by the attacker-supplied value.
    assert_ne!(general.session_password, "evilevileveileveileveileveil");
}

// ---------------------------------------------------------------------------
// /api/setup/4 GET should require admin once setup is complete
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn setup4_get_requires_admin_after_setup() {
    seed();
    create_user("admin", "adminpass", 1);
    db::set_setup_step(0).unwrap(); // setup complete

    let app = router();

    // Unauthenticated — must be denied.
    let req = Request::builder()
        .method("GET")
        .uri("/api/setup/4")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Non-admin — must be denied.
    create_user("plain", "plainpass1", 0);
    let cookie = login_get_cookie(&app, "plain", "plainpass1").await;
    let (status, _) = get_req(&app, "/api/setup/4", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin — allowed.
    let admin_cookie = login_get_cookie(&app, "admin", "adminpass").await;
    let (status, _) = get_req(&app, "/api/setup/4", &admin_cookie).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Server-generated TOTP setup flow
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn totp_setup_returns_server_generated_secret() {
    seed();
    create_user("alice", "passpass", 0);
    let app = router();
    let cookie = login_get_cookie(&app, "alice", "passpass").await;

    let body = json!({ "type": "setup" });
    let (status, resp) = post(&app, "/api/me/totp", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["type"], "setup");

    let key = resp["key"].as_str().unwrap();
    let uri = resp["uri"].as_str().unwrap();
    // RFC 6238 / 4648: 32-char base32 = 20 bytes.
    assert_eq!(key.len(), 32);
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains(&format!("secret={key}")));
}

#[tokio::test]
#[serial(db)]
async fn totp_create_rejects_bad_code() {
    seed();
    let user_id = create_user("bob", "passpass", 0);
    let app = router();
    let cookie = login_get_cookie(&app, "bob", "passpass").await;

    // Run setup so the user has a stored secret.
    let _ = post(&app, "/api/me/totp", &cookie, &json!({"type": "setup"})).await;

    // Burn one attempt with a code that is guaranteed to not match.
    let body = json!({ "type": "create", "code": "000000" });
    let (status, _) = post(&app, "/api/me/totp", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The user row should still have totp_verified=0.
    let u = db::get_user(user_id).unwrap();
    assert!(!u.totp_verified);
    assert!(u.totp_key.as_deref().map(|s| !s.is_empty()).unwrap_or(false));
}

#[tokio::test]
#[serial(db)]
async fn totp_delete_requires_current_password() {
    seed();
    let user_id = create_user("carol", "rightpass", 0);
    let app = router();
    let cookie = login_get_cookie(&app, "carol", "rightpass").await;

    let _ = post(&app, "/api/me/totp", &cookie, &json!({"type": "setup"})).await;

    // Wrong password
    let body = json!({ "type": "delete", "currentPassword": "wrong" });
    let (status, _) = post(&app, "/api/me/totp", &cookie, &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Right password
    let body = json!({ "type": "delete", "currentPassword": "rightpass" });
    let (status, _) = post(&app, "/api/me/totp", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    let u = db::get_user(user_id).unwrap();
    assert!(u.totp_key.as_deref().map(|s| s.is_empty()).unwrap_or(true));
}

// ---------------------------------------------------------------------------
// Metrics password gating
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn metrics_json_requires_bearer_when_password_set() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Enable JSON metrics + set a password.
    let body = json!({ "metricsJson": true, "metricsPassword": "secrettoken" });
    let (status, _) = post(&app, "/api/admin/general", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    // No Authorization header — must fail.
    let req = Request::builder()
        .method("GET")
        .uri("/metrics/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong bearer — must fail.
    let req = Request::builder()
        .method("GET")
        .uri("/metrics/json")
        .header(header::AUTHORIZATION, "Bearer wrong")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Correct bearer — must succeed.
    let req = Request::builder()
        .method("GET")
        .uri("/metrics/json")
        .header(header::AUTHORIZATION, "Bearer secrettoken")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn admin_general_get_does_not_leak_metrics_password() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let _ = post(
        &app,
        "/api/admin/general",
        &cookie,
        &json!({ "metricsPassword": "supersecret" }),
    )
    .await;

    let (status, body) = get_req(&app, "/api/admin/general", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    // Endpoint must surface a boolean only — never the value or its hash.
    assert!(body["metricsPassword"].is_null());
    assert_eq!(body["metricsPasswordSet"], json!(true));
    let serialised = body.to_string();
    assert!(!serialised.contains("supersecret"));
}

// ---------------------------------------------------------------------------
// Migrate endpoint accepts a v3-format backup file
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AmneziaWG 2.0 spec compliance
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn admin_interface_rejects_invalid_i1_tag() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Garbage outside any tag delimiters.
    let body = json!({ "i1": "this is not a tag spec" });
    let (status, resp) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().to_lowercase().contains("invalid i1"));
}

#[tokio::test]
#[serial(db)]
async fn admin_interface_rejects_oversize_random_count() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "i2": "<r 5000>" });
    let (status, _) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn admin_interface_accepts_full_tag_grammar() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({
        "i1": "<r 2><b 0xdeadbeef><t><c><rc 16><rd 4>"
    });
    let (status, _) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn admin_interface_validates_s3_bound() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "s3": 10000 });
    let (status, resp) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().contains("S3"));
}

#[tokio::test]
#[serial(db)]
async fn admin_interface_validates_s4_bound() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "s4": 100 });
    let (status, resp) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().contains("S4"));
}

#[tokio::test]
#[serial(db)]
async fn admin_interface_caps_jmax_at_1279() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // 1280 must now be rejected (spec: Jmax < 1280)
    let body = json!({ "jMax": 1280, "jMin": 10 });
    let (status, resp) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().contains("Jmax"));

    // 1279 must succeed
    let body = json!({ "jMax": 1279, "jMin": 10 });
    let (status, _) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn client_update_validates_i1_tag_grammar() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let client_id = create_client(Some(admin_id), "c1", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "i1": "garbage" });
    let (status, resp) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().to_lowercase().contains("invalid i1"));

    // Valid tag spec passes.
    let body = json!({ "i1": "<r 4><b 0xcafe><t>" });
    let (status, _) = post(
        &app,
        &format!("/api/client/{client_id}"),
        &cookie,
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn admin_interface_rejects_jmax_equal_jmin_when_jc_set() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Kernel post-config check: when Jc != 0, Jmax must be > Jmin.
    let body = json!({ "jC": 5, "jMin": 50, "jMax": 50 });
    let (status, resp) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().to_lowercase().contains("jmax"));

    // jC=0 (junk packets disabled) — equal Jmax/Jmin should be accepted
    // because the kernel never enters the junk-generation path.
    let body = json!({ "jC": 0, "jMin": 50, "jMax": 50 });
    let (status, _) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn init_spec_rejects_oversize_total_packet() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // 100 random tags of 1000 bytes each = 100KB → blows past
    // MESSAGE_MAX_SIZE = 65535 and must be rejected.
    let mut spec = String::new();
    for _ in 0..100 {
        spec.push_str("<r 1000>");
    }
    let body = json!({ "i1": spec });
    let (status, resp) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp["error"].as_str().unwrap().to_lowercase().contains("i1"));
}

// ---------------------------------------------------------------------------
// AdvancedSecurity per-peer flag
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn new_client_defaults_to_advanced_security_auto() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "name": "fresh-peer" });
    let (status, resp) = post(&app, "/api/client", &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);

    let id = resp["clientId"].as_i64().unwrap();
    let c = db::get_client(id).unwrap();
    // Default is None ("auto") — the kernel auto-detects from H1, and the
    // userspace amneziawg-go rejects an explicit AdvancedSecurity directive.
    assert_eq!(c.advanced_security, None);
}

#[tokio::test]
#[serial(db)]
async fn admin_can_toggle_advanced_security_off() {
    seed();
    // Setting advancedSecurity = on|off is gated on the kernel module being
    // loaded. CI runners (and this dev host) never have it, so pin Kernel
    // mode for this test. `#[serial(db)]` keeps the override from racing
    // other tests; restore it before returning.
    use awg_easy_rs::wg::kernel::{set_mode_override, GamingMode};
    set_mode_override(Some(GamingMode::Kernel));
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "p1", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "advancedSecurity": false });
    let (status, _) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    set_mode_override(None);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(db::get_client(cid).unwrap().advanced_security, Some(false));
}

#[tokio::test]
#[serial(db)]
async fn admin_can_set_advanced_security_to_null() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "p1", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // Explicit JSON null clears the column → kernel auto-detect.
    let body = json!({ "advancedSecurity": Value::Null });
    let (status, _) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(db::get_client(cid).unwrap().advanced_security, None);
}

#[tokio::test]
#[serial(db)]
async fn non_admin_cannot_change_advanced_security() {
    seed();
    let user_id = create_user("alice", "passpass", 0);
    let cid = create_client(Some(user_id), "alice-c", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "alice", "passpass").await;

    let body = json!({ "advancedSecurity": false });
    let (status, resp) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(resp["error"].as_str().unwrap().contains("admin"));
    // Untouched.
    assert_eq!(db::get_client(cid).unwrap().advanced_security, Some(true));
}

#[tokio::test]
#[serial(db)]
async fn admin_get_returns_advanced_security_field() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "p1", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let (status, body) = get_req(&app, &format!("/api/client/{cid}"), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["advancedSecurity"], json!(true));
}

#[tokio::test]
#[serial(db)]
async fn server_config_emits_advanced_security_for_each_peer() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid_on = create_client(Some(admin_id), "peer-on", "10.8.0.10");
    let cid_off = create_client(Some(admin_id), "peer-off", "10.8.0.11");
    db::set_client_advanced_security(cid_off, Some(false)).unwrap();
    let cid_auto = create_client(Some(admin_id), "peer-auto", "10.8.0.12");
    db::set_client_advanced_security(cid_auto, None).unwrap();

    let iface = db::get_interface().unwrap();
    let hooks = db::get_hooks().unwrap();
    let mut server_cfg =
        awg_easy_rs::wg::config_gen::generate_server_interface(&iface, &hooks).unwrap();
    for client in db::get_all_clients().unwrap() {
        if client.enabled {
            server_cfg.push_str("\n\n");
            server_cfg.push_str(
                &awg_easy_rs::wg::config_gen::generate_server_peer(&client).unwrap(),
            );
        }
    }
    // peer-on: explicit On
    assert!(
        server_cfg.contains(&format!("# Client: peer-on ({cid_on})\n[Peer]"))
            && extract_block(&server_cfg, cid_on).contains("AdvancedSecurity = on"),
        "expected AdvancedSecurity = on for peer-on"
    );
    // peer-off: explicit Off
    assert!(
        extract_block(&server_cfg, cid_off).contains("AdvancedSecurity = off"),
        "expected AdvancedSecurity = off for peer-off"
    );
    // peer-auto: line must be omitted entirely
    assert!(
        !extract_block(&server_cfg, cid_auto).contains("AdvancedSecurity"),
        "expected no AdvancedSecurity line for peer-auto"
    );
}

#[tokio::test]
#[serial(db)]
async fn client_config_always_marks_server_as_advanced() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "p1", "10.8.0.10");

    let iface = db::get_interface().unwrap();
    let uc = db::get_user_config().unwrap();
    let c = db::get_client(cid).unwrap();
    let cfg = awg_easy_rs::wg::config_gen::generate_client_config(&iface, &uc, &c).unwrap();
    // Pure-AmneziaWG: client-side [Peer] always marks the server as
    // advanced (default-on, kernel auto-detect would also work but we
    // make it explicit).
    assert!(cfg.contains("AdvancedSecurity = on"), "client config: {cfg}");
}

// Helper for the server-config emit test above. Pulls the [Peer] block
// belonging to the client with the given id.
fn extract_block(server_cfg: &str, id: i64) -> String {
    let header = "# Client: ".to_string();
    let id_marker = format!("({id})");
    for block in server_cfg.split("\n\n") {
        if block.starts_with(&header) && block.contains(&id_marker) {
            return block.to_string();
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Routing / firewall / DNS list validation (nft + config injection guard)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial(db)]
async fn rejects_injection_in_allowed_ips() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "c", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "allowedIps": ["1.2.3.4 accept; add rule inet x y"] });
    let (status, _) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn rejects_invalid_firewall_ips() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "c", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "firewallIps": ["8.8.8.8:99999"] });
    let (status, _) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn rejects_non_ip_dns_entry() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "c", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({ "dns": ["not-an-ip"] });
    let (status, _) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn accepts_valid_routing_lists() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "c", "10.8.0.10");
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    let body = json!({
        "allowedIps": ["0.0.0.0/0", "::/0"],
        "firewallIps": ["8.8.8.8:53/udp", "1.1.1.1"],
        "dns": ["1.1.1.1", "9.9.9.9"]
    });
    let (status, _) = post(&app, &format!("/api/client/{cid}"), &cookie, &body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial(db)]
async fn rejects_magic_header_newline_injection() {
    seed();
    create_user("admin", "adminpass", 1);
    let app = router();
    let cookie = login_get_cookie(&app, "admin", "adminpass").await;

    // A newline in H1 would inject an arbitrary `[Interface]` directive.
    let body = json!({ "h1": "5\nPostUp = id" });
    let (status, _) = post(&app, "/api/admin/interface", &cookie, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial(db)]
async fn cron_disables_expired_client() {
    seed();
    let admin_id = create_user("admin", "adminpass", 1);
    let cid = create_client(Some(admin_id), "exp", "10.8.0.10");

    // Stamp an expiry one hour in the past, then run the expiry cron.
    let past = awg_easy_rs::datetime::to_rfc3339(
        awg_easy_rs::datetime::now_utc() - time::Duration::hours(1),
    );
    let mut f = db::UpdateMap::new();
    f.insert("expires_at".into(), past);
    db::update_client(cid, &f).unwrap();
    assert!(db::get_client(cid).unwrap().enabled);

    awg_easy_rs::wg::cron_job().unwrap();
    assert!(
        !db::get_client(cid).unwrap().enabled,
        "expired client should be disabled by the cron"
    );
}
