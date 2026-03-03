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
    error: Option<String>,
    success: Option<String>,
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
/// Returns 200 with `X-Forwarded-User` and `X-Forwarded-Role` headers if the
/// request has a valid session. Otherwise redirects browsers to the login page
/// (with `rd` param for post-login redirect) or returns 401 for API clients.
async fn verify_auth(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(user) = get_session_user(&jar, &database) {
        let mut response = StatusCode::OK.into_response();
        let resp_headers = response.headers_mut();
        resp_headers.insert("X-Forwarded-User", user.username.parse().unwrap());
        resp_headers.insert("X-Forwarded-Role", user.role.parse().unwrap());
        response
    } else {
        let original_url = build_original_url(&headers);
        let rd = original_url.as_deref().unwrap_or("/");
        let login_url = format!(
            "{}/login?rd={}",
            config.auth_url,
            urlencoding::encode(rd)
        );

        // Browsers get a redirect; API clients get 401
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
}

async fn dashboard(jar: CookieJar, State(database): State<db::Db>) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };

    let users = if user.role == "admin" {
        db::list_users(&database)
    } else {
        vec![user.clone()]
    };

    let tmpl = DashboardTemplate {
        user,
        users,
        error: None,
        success: None,
    };
    render_template(&tmpl).into_response()
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

    let users = db::list_users(&database);
    let tmpl = DashboardTemplate {
        user,
        users,
        error,
        success,
    };
    render_template(&tmpl).into_response()
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
        let users = db::list_users(&database);
        let tmpl = DashboardTemplate {
            user,
            users,
            error: Some("Cannot delete yourself".to_string()),
            success: None,
        };
        return render_template(&tmpl).into_response();
    }

    let (error, success) = match db::delete_user(&database, form.user_id) {
        Ok(()) => (None, Some("User deleted".to_string())),
        Err(e) => (Some(e), None),
    };

    let users = db::list_users(&database);
    let tmpl = DashboardTemplate {
        user,
        users,
        error,
        success,
    };
    render_template(&tmpl).into_response()
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

    let app_config = AppConfig {
        auth_url: cfg.auth.auth_url,
        cookie_domain: cfg.auth.cookie_domain,
        cookie_secure: cfg.auth.cookie_secure,
    };

    let database = db::init_db(&cfg.database.path);

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/dashboard", get(dashboard))
        .route("/users/create", post(create_user))
        .route("/users/delete", post(delete_user))
        .route("/api/verify", get(verify_auth))
        .nest_service("/static", ServeDir::new("static"))
        .layer(Extension(app_config))
        .with_state(database);

    tracing::info!("Server running at http://{listen_addr}");
    tracing::info!("Default login: admin / admin");
    tracing::info!("Forward auth endpoint: GET /api/verify");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
