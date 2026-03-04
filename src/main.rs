mod config;
mod db;

use std::path::PathBuf;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Extension, Form, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use askama::Template;
use clap::Parser;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

const SESSION_COOKIE: &str = "session";

#[derive(Parser)]
#[command(name = "rust-admin-api", about = "Admin panel with forward auth for reverse proxies")]
struct Cli {
    /// Path to config.toml
    #[arg(long, default_value = "/etc/rust-admin-api/config.toml")]
    config: PathBuf,

    /// Web server port (overrides config file)
    #[arg(long)]
    web_port: Option<u16>,
}

#[derive(Clone)]
struct AppConfig {
    auth_url: String,
    cookie_domain: Option<String>,
    cookie_secure: bool,
    jwt_secret: String,
}

// --- JWT Claims ---

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    /// User ID
    sub: i64,
    /// Token ID in the api_tokens table
    tid: i64,
    /// Username
    username: String,
    /// Role
    role: String,
    /// Issued at (unix timestamp)
    iat: i64,
}

// --- Templates ---

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    rd: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    user: db::User,
    users: Vec<db::User>,
    api_tokens: Vec<db::ApiToken>,
    error: Option<String>,
    success: Option<String>,
    new_token: Option<String>,
}

// --- Form data ---

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    rd: String,
}

#[derive(serde::Deserialize)]
struct CreateUserForm {
    username: String,
    password: String,
    role: String,
}

#[derive(serde::Deserialize)]
struct DeleteUserForm {
    user_id: i64,
}

#[derive(serde::Deserialize)]
struct CreateTokenForm {
    token_name: String,
}

#[derive(serde::Deserialize)]
struct RevokeTokenForm {
    token_id: i64,
}

#[derive(serde::Deserialize)]
struct LoginQuery {
    #[serde(default)]
    rd: Option<String>,
}

// --- Helpers ---

fn get_session_user(jar: &CookieJar, database: &db::Db) -> Option<db::User> {
    let token = jar.get(SESSION_COOKIE)?.value().to_string();
    db::get_user_by_session(database, &token)
}

fn render_template<T: Template>(tmpl: &T) -> impl IntoResponse {
    match tmpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {e}")).into_response(),
    }
}

/// Reconstruct the original URL from proxy-forwarded headers.
fn build_original_url(headers: &HeaderMap) -> Option<String> {
    let host = headers.get("x-forwarded-host")?.to_str().ok()?;
    let uri = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    Some(format!("{proto}://{host}{uri}"))
}

/// Basic open-redirect protection: only allow relative or http(s) URLs.
fn is_safe_redirect(url: &str) -> bool {
    url.starts_with('/') || url.starts_with("http://") || url.starts_with("https://")
}

/// Create a signed JWT for an API token.
fn encode_jwt(user: &db::User, token_id: i64, secret: &str) -> Result<String, String> {
    let claims = Claims {
        sub: user.id,
        tid: token_id,
        username: user.username.clone(),
        role: user.role.clone(),
        iat: chrono::Utc::now().timestamp(),
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("JWT encode error: {e}"))
}

/// Verify a Bearer JWT token: check signature, then check token_id is not revoked in DB.
fn verify_bearer(token: &str, database: &db::Db, secret: &str) -> Option<db::User> {
    let mut validation = Validation::default();
    validation.required_spec_claims.clear(); // we don't use exp
    validation.validate_exp = false;

    let token_data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;

    // Check the token ID still exists in DB (not revoked)
    db::verify_api_token(database, token_data.claims.tid)
}

/// Build the dashboard template with all data for the current user.
fn build_dashboard(
    user: db::User,
    database: &db::Db,
    error: Option<String>,
    success: Option<String>,
    new_token: Option<String>,
) -> axum::response::Response {
    let users = if user.role == "admin" {
        db::list_users(database)
    } else {
        vec![user.clone()]
    };
    let api_tokens = if user.role == "admin" {
        db::list_api_tokens(database)
    } else {
        db::list_user_api_tokens(database, user.id)
    };
    let tmpl = DashboardTemplate {
        user,
        users,
        api_tokens,
        error,
        success,
        new_token,
    };
    render_template(&tmpl).into_response()
}

// --- Handlers ---

async fn index(jar: CookieJar, State(database): State<db::Db>) -> impl IntoResponse {
    if get_session_user(&jar, &database).is_some() {
        Redirect::to("/dashboard").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn login_page(
    jar: CookieJar,
    State(database): State<db::Db>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    if get_session_user(&jar, &database).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let tmpl = LoginTemplate {
        error: None,
        rd: query.rd.unwrap_or_default(),
    };
    render_template(&tmpl).into_response()
}

async fn login_submit(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    match db::authenticate(&database, &form.username, &form.password) {
        Some(user) => {
            let token = db::create_session(&database, user.id);
            let mut cookie = Cookie::build((SESSION_COOKIE, token))
                .path("/")
                .http_only(true);
            if let Some(domain) = &config.cookie_domain {
                cookie = cookie.domain(domain.clone());
            }
            if config.cookie_secure {
                cookie = cookie.secure(true);
            }
            let jar = jar.add(cookie);
            let redirect_to = if !form.rd.is_empty() && is_safe_redirect(&form.rd) {
                form.rd
            } else {
                "/dashboard".to_string()
            };
            (jar, Redirect::to(&redirect_to)).into_response()
        }
        None => {
            let tmpl = LoginTemplate {
                error: Some("Invalid username or password".to_string()),
                rd: form.rd,
            };
            render_template(&tmpl).into_response()
        }
    }
}

async fn logout(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
) -> impl IntoResponse {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        db::delete_session(&database, cookie.value());
    }
    let mut removal = Cookie::build((SESSION_COOKIE, "")).path("/");
    if let Some(domain) = &config.cookie_domain {
        removal = removal.domain(domain.clone());
    }
    let jar = jar.remove(removal.build());
    (jar, Redirect::to("/login"))
}

/// Forward auth endpoint for Traefik / Nginx / Caddy.
///
/// Authenticates via session cookie OR `Authorization: Bearer <jwt>`.
/// Returns 200 with `X-Forwarded-User` and `X-Forwarded-Role` headers if valid.
/// Otherwise redirects browsers to login or returns 401 for API clients.
async fn verify_auth(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // 1. Try session cookie
    if let Some(user) = get_session_user(&jar, &database) {
        return ok_with_user_headers(user);
    }

    // 2. Try Bearer JWT token
    if let Some(user) = extract_bearer(&headers, &database, &config.jwt_secret) {
        return ok_with_user_headers(user);
    }

    // 3. Not authenticated
    let original_url = build_original_url(&headers);
    let rd = original_url.as_deref().unwrap_or("/");
    let login_url = format!(
        "{}/login?rd={}",
        config.auth_url,
        urlencoding::encode(rd)
    );

    let accepts_html = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);

    if accepts_html {
        Redirect::temporary(&login_url).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [("X-Auth-Redirect", login_url)],
        )
            .into_response()
    }
}

fn ok_with_user_headers(user: db::User) -> axum::response::Response {
    let mut response = StatusCode::OK.into_response();
    let resp_headers = response.headers_mut();
    resp_headers.insert("X-Forwarded-User", user.username.parse().unwrap());
    resp_headers.insert("X-Forwarded-Role", user.role.parse().unwrap());
    response
}

fn extract_bearer(headers: &HeaderMap, database: &db::Db, jwt_secret: &str) -> Option<db::User> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    verify_bearer(token, database, jwt_secret)
}

async fn dashboard(jar: CookieJar, State(database): State<db::Db>) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };
    build_dashboard(user, &database, None, None, None)
}

async fn create_user(
    jar: CookieJar,
    State(database): State<db::Db>,
    Form(form): Form<CreateUserForm>,
) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };

    if user.role != "admin" {
        return Redirect::to("/dashboard").into_response();
    }

    let role = if form.role == "admin" { "admin" } else { "user" };

    let (error, success) = match db::create_user(&database, &form.username, &form.password, role) {
        Ok(()) => (None, Some(format!("User '{}' created as {}", form.username, role))),
        Err(e) => (Some(e), None),
    };

    build_dashboard(user, &database, error, success, None)
}

async fn delete_user(
    jar: CookieJar,
    State(database): State<db::Db>,
    Form(form): Form<DeleteUserForm>,
) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };

    if user.role != "admin" {
        return Redirect::to("/dashboard").into_response();
    }

    if form.user_id == user.id {
        return build_dashboard(
            user,
            &database,
            Some("Cannot delete yourself".to_string()),
            None,
            None,
        );
    }

    let (error, success) = match db::delete_user(&database, form.user_id) {
        Ok(()) => (None, Some("User deleted".to_string())),
        Err(e) => (Some(e), None),
    };

    build_dashboard(user, &database, error, success, None)
}

async fn create_token(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    Form(form): Form<CreateTokenForm>,
) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };

    if user.role != "admin" {
        return Redirect::to("/dashboard").into_response();
    }

    let name = form.token_name.trim();
    if name.is_empty() {
        return build_dashboard(
            user,
            &database,
            Some("Token name cannot be empty".to_string()),
            None,
            None,
        );
    }

    match db::create_api_token(&database, name, user.id) {
        Ok(token_id) => match encode_jwt(&user, token_id, &config.jwt_secret) {
            Ok(jwt) => build_dashboard(
                user,
                &database,
                None,
                Some(format!("Token '{}' created — copy it now, it won't be shown again", name)),
                Some(jwt),
            ),
            Err(e) => {
                // Clean up the DB row if JWT encoding fails
                let _ = db::delete_api_token(&database, token_id);
                build_dashboard(user, &database, Some(e), None, None)
            }
        },
        Err(e) => build_dashboard(user, &database, Some(e), None, None),
    }
}

async fn revoke_token(
    jar: CookieJar,
    State(database): State<db::Db>,
    Form(form): Form<RevokeTokenForm>,
) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };

    if user.role != "admin" {
        return Redirect::to("/dashboard").into_response();
    }

    let (error, success) = match db::delete_api_token(&database, form.token_id) {
        Ok(()) => (None, Some("Token revoked".to_string())),
        Err(e) => (Some(e), None),
    };

    build_dashboard(user, &database, error, success, None)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load config from file, falling back to defaults
    let cfg = if cli.config.exists() {
        match config::Config::load(&cli.config) {
            Ok(c) => {
                tracing::info!(path = %cli.config.display(), "Loaded config");
                c
            }
            Err(e) => {
                tracing::warn!("Failed to load config: {e}, using defaults");
                config::Config::default()
            }
        }
    } else {
        tracing::info!("No config found at {}, using defaults", cli.config.display());
        config::Config::default()
    };

    // CLI --web-port overrides config file
    let listen_addr = if let Some(port) = cli.web_port {
        format!("0.0.0.0:{port}")
    } else {
        cfg.server.listen_addr.clone()
    };

    let jwt_secret = config::resolve_jwt_secret(&cfg.auth);

    let app_config = AppConfig {
        auth_url: cfg.auth.auth_url,
        cookie_domain: cfg.auth.cookie_domain,
        cookie_secure: cfg.auth.cookie_secure,
        jwt_secret,
    };

    let database = db::init_db(&cfg.database.path);

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/dashboard", get(dashboard))
        .route("/users/create", post(create_user))
        .route("/users/delete", post(delete_user))
        .route("/tokens/create", post(create_token))
        .route("/tokens/revoke", post(revoke_token))
        .route("/api/verify", get(verify_auth))
        .nest_service("/static", ServeDir::new("static"))
        .layer(Extension(app_config))
        .with_state(database);

    tracing::info!("Server running at http://{listen_addr}");
    tracing::info!("Default login: admin / admin");
    tracing::info!("Forward auth endpoint: GET /api/verify");

    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {listen_addr}: {e}");
            if e.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!("Port already in use. Kill the existing process: ss -tlnp | grep {}", listen_addr.split(':').last().unwrap_or("3000"));
            }
            std::process::exit(1);
        }
    };
    axum::serve(listener, app).await.unwrap();
}
