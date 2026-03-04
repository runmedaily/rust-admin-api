use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use rust_admin_api::admin::{self, AppConfig};
use rust_admin_api::db;
use rust_admin_api::proxy::status::RouteInfo;

/// Build an Axum router backed by an in-memory SQLite database.
fn app() -> (Router, db::Db) {
    let database = db::init_db(":memory:");
    let config = AppConfig {
        cookie_domain: None,
        cookie_secure: false,
        jwt_secret: "integration-test-secret".to_string(),
    };
    let routes: Vec<RouteInfo> = vec![];
    let router = admin::build_router(database.clone(), config, routes);
    (router, database)
}

/// Minimal cookie jar that tracks Set-Cookie headers across requests.
struct TestClient {
    cookies: Vec<(String, String)>,
}

impl TestClient {
    fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }

    /// Send a request through the router, tracking cookies.
    async fn send(&mut self, router: Router, req: Request<Body>) -> TestResponse {
        // Inject current cookies into the request
        let (mut parts, body) = req.into_parts();
        if !self.cookies.is_empty() {
            let cookie_header: String = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            parts
                .headers
                .insert(header::COOKIE, cookie_header.parse().unwrap());
        }
        let req = Request::from_parts(parts, body);

        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();

        // Extract Set-Cookie headers and update our jar
        for value in resp.headers().get_all(header::SET_COOKIE) {
            let val = value.to_str().unwrap_or("");
            // Parse "name=value; ..." or removal cookies "name=; ..."
            if let Some((name_value, _rest)) = val.split_once(';') {
                if let Some((name, value)) = name_value.split_once('=') {
                    let name = name.trim().to_string();
                    let value = value.trim().to_string();
                    // Remove existing cookie with this name
                    self.cookies.retain(|(n, _)| n != &name);
                    // Only add if value is non-empty (empty = deletion)
                    if !value.is_empty() {
                        self.cookies.push((name, value));
                    }
                }
            }
        }

        let location = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();

        TestResponse {
            status,
            location,
            body,
        }
    }

    fn has_cookie(&self, name: &str) -> bool {
        self.cookies.iter().any(|(n, _)| n == name)
    }

    fn get_cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

struct TestResponse {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn post_form(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn index_redirects_to_login_when_unauthenticated() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client.send(router, get("/")).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn login_page_renders() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client.send(router, get("/login")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("Login"));
}

#[tokio::test]
async fn login_with_valid_credentials() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client
        .send(
            router,
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
    assert!(client.has_cookie("session"));
}

#[tokio::test]
async fn login_with_invalid_credentials() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client
        .send(
            router,
            post_form("/login", "username=admin&password=wrong&rd="),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("Invalid username or password"));
    assert!(!client.has_cookie("session"));
}

#[tokio::test]
async fn login_redirect_parameter() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client
        .send(
            router,
            post_form(
                "/login",
                "username=admin&password=admin&rd=%2Fdashboard%3Ffoo%3Dbar",
            ),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard?foo=bar"));
}

#[tokio::test]
async fn login_rejects_unsafe_redirect() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client
        .send(
            router,
            post_form(
                "/login",
                "username=admin&password=admin&rd=//evil.com",
            ),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    // Should redirect to /dashboard, not //evil.com
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
}

#[tokio::test]
async fn dashboard_requires_auth() {
    let (router, _db) = app();
    let mut client = TestClient::new();
    let resp = client.send(router, get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn dashboard_renders_when_authenticated() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login first
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Now access dashboard
    let resp = client.send(router, get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("Dashboard"));
    assert!(resp.body.contains("admin"));
}

#[tokio::test]
async fn index_redirects_to_dashboard_when_authenticated() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    let resp = client.send(router, get("/")).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
}

#[tokio::test]
async fn login_page_redirects_when_already_authenticated() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    let resp = client.send(router, get("/login")).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
}

#[tokio::test]
async fn logout_clears_session() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;
    assert!(client.has_cookie("session"));

    // Logout
    let resp = client.send(router.clone(), get("/logout")).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
    assert!(!client.has_cookie("session"));

    // Dashboard should now redirect to login
    let resp = client.send(router, get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn create_user_admin_only() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login as admin, create a regular user
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;
    let resp = client
        .send(
            router.clone(),
            post_form(
                "/users/create",
                "username=alice&password=pass123&role=user",
            ),
        )
        .await;
    // PRG: should redirect to dashboard
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));

    // Flash cookie should contain success message
    assert!(client.has_cookie("flash_success"));

    // Verify dashboard shows the user
    let resp = client.send(router, get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("alice"));
}

#[tokio::test]
async fn create_user_rejected_for_non_admin() {
    let (router, db) = app();

    // Create a regular user directly in DB
    db::create_user(&db, "bob", "pass", "user").unwrap();

    let mut client = TestClient::new();
    // Login as bob (regular user)
    client
        .send(
            router.clone(),
            post_form("/login", "username=bob&password=pass&rd="),
        )
        .await;

    // Try to create a user — should be rejected
    let resp = client
        .send(
            router,
            post_form(
                "/users/create",
                "username=mallory&password=hack&role=admin",
            ),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
}

#[tokio::test]
async fn create_user_duplicate_username_shows_error() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login as admin
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Create alice
    client
        .send(
            router.clone(),
            post_form(
                "/users/create",
                "username=alice&password=pass&role=user",
            ),
        )
        .await;

    // Try to create alice again — clears flash cookies first
    client
        .send(router.clone(), get("/dashboard"))
        .await;

    let resp = client
        .send(
            router.clone(),
            post_form(
                "/users/create",
                "username=alice&password=pass2&role=user",
            ),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert!(client.has_cookie("flash_error"));

    // Dashboard shows the error
    let resp = client.send(router, get("/dashboard")).await;
    assert!(resp.body.contains("Username already exists"));
}

#[tokio::test]
async fn delete_user_works() {
    let (router, db) = app();
    let mut client = TestClient::new();

    // Login as admin
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Create alice
    client
        .send(
            router.clone(),
            post_form(
                "/users/create",
                "username=alice&password=pass&role=user",
            ),
        )
        .await;

    // Clear flash
    client.send(router.clone(), get("/dashboard")).await;

    // Find alice's ID
    let users = db::list_users(&db);
    let alice_id = users.iter().find(|u| u.username == "alice").unwrap().id;

    // Delete alice
    let resp = client
        .send(
            router.clone(),
            post_form("/users/delete", &format!("user_id={alice_id}")),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert!(client.has_cookie("flash_success"));

    // Verify alice is gone
    let resp = client.send(router, get("/dashboard")).await;
    assert!(!resp.body.contains("alice"));
}

#[tokio::test]
async fn cannot_delete_yourself() {
    let (router, db) = app();
    let mut client = TestClient::new();

    // Login as admin
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Find admin's ID
    let users = db::list_users(&db);
    let admin_id = users.iter().find(|u| u.username == "admin").unwrap().id;

    // Try to delete yourself
    let resp = client
        .send(
            router.clone(),
            post_form("/users/delete", &format!("user_id={admin_id}")),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert!(client.has_cookie("flash_error"));

    let resp = client.send(router, get("/dashboard")).await;
    assert!(resp.body.contains("Cannot delete yourself"));
}

#[tokio::test]
async fn create_token_admin_only_with_prg() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login as admin
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Create a token
    let resp = client
        .send(
            router.clone(),
            post_form("/tokens/create", "token_name=deploy-key"),
        )
        .await;
    // PRG redirect
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
    assert!(client.has_cookie("flash_token"));
    assert!(client.has_cookie("flash_success"));

    // Follow redirect — dashboard should show the token
    let resp = client.send(router.clone(), get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("deploy-key"));
    // The JWT token value should be in the response
    assert!(resp.body.contains("New API Token"));

    // Flash cookies should be cleared after reading
    assert!(!client.has_cookie("flash_token"));
    assert!(!client.has_cookie("flash_success"));

    // Refreshing should NOT show the token again
    let resp = client.send(router, get("/dashboard")).await;
    assert!(!resp.body.contains("New API Token"));
}

#[tokio::test]
async fn create_token_rejected_for_non_admin() {
    let (router, db) = app();
    db::create_user(&db, "bob", "pass", "user").unwrap();

    let mut client = TestClient::new();
    client
        .send(
            router.clone(),
            post_form("/login", "username=bob&password=pass&rd="),
        )
        .await;

    let resp = client
        .send(
            router,
            post_form("/tokens/create", "token_name=sneaky"),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/dashboard"));
    // No flash_token should be set (non-admin redirect)
    assert!(!client.has_cookie("flash_token"));
}

#[tokio::test]
async fn create_token_empty_name_rejected() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Login as admin
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    let resp = client
        .send(
            router.clone(),
            post_form("/tokens/create", "token_name="),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert!(client.has_cookie("flash_error"));

    let resp = client.send(router, get("/dashboard")).await;
    assert!(resp.body.contains("Token name cannot be empty"));
}

#[tokio::test]
async fn revoke_token_works() {
    let (router, db) = app();
    let mut client = TestClient::new();

    // Login as admin
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Create a token directly in DB for simpler testing
    let admin = db::authenticate(&db, "admin", "admin").unwrap();
    let token_id = db::create_api_token(&db, "revoke-me", admin.id).unwrap();

    // Revoke it
    let resp = client
        .send(
            router.clone(),
            post_form("/tokens/revoke", &format!("token_id={token_id}")),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert!(client.has_cookie("flash_success"));

    // Verify it's gone
    let resp = client.send(router, get("/dashboard")).await;
    assert!(resp.body.contains("Token revoked"));
    assert!(!resp.body.contains("revoke-me"));
}

#[tokio::test]
async fn two_admins_see_own_tokens() {
    let (router, db) = app();

    // Create second admin
    db::create_user(&db, "admin2", "pass", "admin").unwrap();

    // Admin1 creates a token
    let admin1 = db::authenticate(&db, "admin", "admin").unwrap();
    db::create_api_token(&db, "admin1-token", admin1.id).unwrap();

    // Admin2 creates a token
    let admin2 = db::authenticate(&db, "admin2", "pass").unwrap();
    db::create_api_token(&db, "admin2-token", admin2.id).unwrap();

    // Login as admin1 — should see ALL tokens (admins see all)
    let mut client = TestClient::new();
    client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;
    let resp = client.send(router.clone(), get("/dashboard")).await;
    assert!(resp.body.contains("admin1-token"));
    assert!(resp.body.contains("admin2-token"));
}

#[tokio::test]
async fn regular_user_sees_only_own_data() {
    let (router, db) = app();

    // Create a regular user
    db::create_user(&db, "alice", "pass", "user").unwrap();
    let alice = db::authenticate(&db, "alice", "pass").unwrap();
    db::create_api_token(&db, "alice-key", alice.id).unwrap();

    // Create a token for admin too
    let admin = db::authenticate(&db, "admin", "admin").unwrap();
    db::create_api_token(&db, "admin-key", admin.id).unwrap();

    // Login as alice
    let mut client = TestClient::new();
    client
        .send(
            router.clone(),
            post_form("/login", "username=alice&password=pass&rd="),
        )
        .await;

    let resp = client.send(router, get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::OK);
    // Alice should see her own token but not admin's
    assert!(resp.body.contains("alice-key"));
    assert!(!resp.body.contains("admin-key"));
    // Alice should not see the "Add User" form
    assert!(!resp.body.contains("Add User"));
}

#[tokio::test]
async fn unauthenticated_post_redirects_to_login() {
    let (router, _db) = app();
    let mut client = TestClient::new();

    // Try to create user without being logged in
    let resp = client
        .send(
            router.clone(),
            post_form(
                "/users/create",
                "username=hacker&password=hack&role=admin",
            ),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));

    // Try to create token without being logged in
    let resp = client
        .send(
            router.clone(),
            post_form("/tokens/create", "token_name=sneaky"),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));

    // Try to delete user without being logged in
    let resp = client
        .send(
            router.clone(),
            post_form("/users/delete", "user_id=1"),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));

    // Try to revoke token without being logged in
    let resp = client
        .send(
            router,
            post_form("/tokens/revoke", "token_id=1"),
        )
        .await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn multiple_sessions_independent() {
    let (router, _db) = app();

    // Two separate clients login
    let mut client1 = TestClient::new();
    let mut client2 = TestClient::new();

    // Create a second user for client2
    let mut admin_client = TestClient::new();
    admin_client
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;
    admin_client
        .send(
            router.clone(),
            post_form(
                "/users/create",
                "username=bob&password=pass&role=user",
            ),
        )
        .await;

    // Client1 logs in as admin
    client1
        .send(
            router.clone(),
            post_form("/login", "username=admin&password=admin&rd="),
        )
        .await;

    // Client2 logs in as bob
    client2
        .send(
            router.clone(),
            post_form("/login", "username=bob&password=pass&rd="),
        )
        .await;

    // Both have different session cookies
    assert_ne!(
        client1.get_cookie("session"),
        client2.get_cookie("session")
    );

    // Client1 dashboard shows admin
    let resp = client1.send(router.clone(), get("/dashboard")).await;
    assert!(resp.body.contains("admin"));

    // Client2 dashboard shows bob
    let resp = client2.send(router.clone(), get("/dashboard")).await;
    assert!(resp.body.contains("bob"));

    // Logging out client1 doesn't affect client2
    client1.send(router.clone(), get("/logout")).await;
    let resp = client2.send(router, get("/dashboard")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.contains("bob"));
}
