use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    Extension, Form,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use askama::Template;

use crate::auth::jwt::encode_jwt;
use crate::auth::session::{get_session_user, SESSION_COOKIE};
use crate::db;
use crate::proxy::status::RouteInfo;

use super::forms::*;
use super::templates::*;

const FLASH_SUCCESS: &str = "flash_success";
const FLASH_ERROR: &str = "flash_error";
const FLASH_TOKEN: &str = "flash_token";

#[derive(Clone)]
pub struct AppConfig {
    pub cookie_domain: Option<String>,
    pub cookie_secure: bool,
    pub jwt_secret: String,
}

fn render_template<T: Template>(tmpl: &T) -> impl IntoResponse {
    match tmpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {e}")).into_response(),
    }
}

fn is_safe_redirect(url: &str) -> bool {
    url.starts_with('/') && !url.starts_with("//")
}

fn flash(name: &str, value: &str, secure: bool) -> Cookie<'static> {
    let mut builder = Cookie::build((name.to_string(), value.to_string()))
        .path("/")
        .http_only(true);
    if secure {
        builder = builder.secure(true);
    }
    builder.build()
}

fn require_admin(jar: &CookieJar, db: &db::Db) -> Result<db::User, axum::response::Response> {
    let user = get_session_user(jar, db)
        .ok_or_else(|| Redirect::to("/login").into_response())?;
    if user.role != "admin" {
        return Err(Redirect::to("/dashboard").into_response());
    }
    Ok(user)
}

fn build_dashboard(
    user: db::User,
    database: &db::Db,
    proxy_routes: &[RouteInfo],
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
        proxy_routes: proxy_routes.to_vec(),
    };
    render_template(&tmpl).into_response()
}

pub async fn index(jar: CookieJar, State(database): State<db::Db>) -> impl IntoResponse {
    if get_session_user(&jar, &database).is_some() {
        Redirect::to("/dashboard").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

pub async fn login_page(
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

pub async fn login_submit(
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

pub async fn logout(
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

pub async fn dashboard(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(proxy_routes): Extension<Vec<RouteInfo>>,
) -> impl IntoResponse {
    let Some(user) = get_session_user(&jar, &database) else {
        return Redirect::to("/login").into_response();
    };

    // Read and clear flash cookies (PRG pattern)
    let success = jar.get(FLASH_SUCCESS).map(|c| c.value().to_string());
    let error = jar.get(FLASH_ERROR).map(|c| c.value().to_string());
    let new_token = jar.get(FLASH_TOKEN).map(|c| c.value().to_string());

    let mut jar = jar;
    if success.is_some() {
        jar = jar.remove(Cookie::build((FLASH_SUCCESS, "")).path("/").build());
    }
    if error.is_some() {
        jar = jar.remove(Cookie::build((FLASH_ERROR, "")).path("/").build());
    }
    if new_token.is_some() {
        jar = jar.remove(Cookie::build((FLASH_TOKEN, "")).path("/").build());
    }

    let resp = build_dashboard(user, &database, &proxy_routes, error, success, new_token);
    (jar, resp).into_response()
}

pub async fn create_user(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    Form(form): Form<CreateUserForm>,
) -> impl IntoResponse {
    let user = match require_admin(&jar, &database) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let _ = user; // admin check passed

    let role = if form.role == "admin" { "admin" } else { "user" };

    let jar = match db::create_user(&database, &form.username, &form.password, role) {
        Ok(()) => jar.add(flash(FLASH_SUCCESS, &format!("User '{}' created as {}", form.username, role), config.cookie_secure)),
        Err(e) => jar.add(flash(FLASH_ERROR, &e, config.cookie_secure)),
    };

    (jar, Redirect::to("/dashboard")).into_response()
}

pub async fn delete_user(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    Form(form): Form<DeleteUserForm>,
) -> impl IntoResponse {
    let user = match require_admin(&jar, &database) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    if form.user_id == user.id {
        let jar = jar.add(flash(FLASH_ERROR, "Cannot delete yourself", config.cookie_secure));
        return (jar, Redirect::to("/dashboard")).into_response();
    }

    let jar = match db::delete_user(&database, form.user_id) {
        Ok(()) => jar.add(flash(FLASH_SUCCESS, "User deleted", config.cookie_secure)),
        Err(e) => jar.add(flash(FLASH_ERROR, &e, config.cookie_secure)),
    };

    (jar, Redirect::to("/dashboard")).into_response()
}

pub async fn create_token(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    Form(form): Form<CreateTokenForm>,
) -> impl IntoResponse {
    let user = match require_admin(&jar, &database) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let name = form.token_name.trim();
    if name.is_empty() {
        let jar = jar.add(flash(FLASH_ERROR, "Token name cannot be empty", config.cookie_secure));
        return (jar, Redirect::to("/dashboard")).into_response();
    }

    match db::create_api_token(&database, name, user.id) {
        Ok(token_id) => match encode_jwt(&user, token_id, &config.jwt_secret) {
            Ok(jwt) => {
                let jar = jar
                    .add(flash(FLASH_SUCCESS, &format!("Token '{}' created — copy it now, it won't be shown again", name), config.cookie_secure))
                    .add(flash(FLASH_TOKEN, &jwt, config.cookie_secure));
                (jar, Redirect::to("/dashboard")).into_response()
            }
            Err(e) => {
                let _ = db::delete_api_token(&database, token_id);
                let jar = jar.add(flash(FLASH_ERROR, &e, config.cookie_secure));
                (jar, Redirect::to("/dashboard")).into_response()
            }
        },
        Err(e) => {
            let jar = jar.add(flash(FLASH_ERROR, &e, config.cookie_secure));
            (jar, Redirect::to("/dashboard")).into_response()
        }
    }
}

pub async fn revoke_token(
    jar: CookieJar,
    State(database): State<db::Db>,
    Extension(config): Extension<AppConfig>,
    Form(form): Form<RevokeTokenForm>,
) -> impl IntoResponse {
    let user = match require_admin(&jar, &database) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let _ = user;

    let jar = match db::delete_api_token(&database, form.token_id) {
        Ok(()) => jar.add(flash(FLASH_SUCCESS, "Token revoked", config.cookie_secure)),
        Err(e) => jar.add(flash(FLASH_ERROR, &e, config.cookie_secure)),
    };

    (jar, Redirect::to("/dashboard")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_redirect() {
        assert!(is_safe_redirect("/dashboard"));
        assert!(is_safe_redirect("/users/1"));
        assert!(!is_safe_redirect("//evil.com"));
        assert!(!is_safe_redirect("https://evil.com"));
        assert!(!is_safe_redirect("http://evil.com"));
        assert!(!is_safe_redirect(""));
        assert!(!is_safe_redirect("evil.com"));
    }
}
