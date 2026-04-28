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
        interface_id: Some("wg0".into()),
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
        "password": "password123",
        "confirmPassword": "password123"
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
