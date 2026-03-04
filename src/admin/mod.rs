mod forms;
mod handlers;
mod templates;

use axum::{
    routing::{get, post},
    Extension, Router,
};
use tower_http::services::ServeDir;

use crate::db;

pub use handlers::AppConfig;

/// Build the Axum router for the admin panel.
pub fn build_router(database: db::Db, app_config: AppConfig, proxy_routes: Vec<crate::proxy::status::RouteInfo>) -> Router {
    Router::new()
        .route("/", get(handlers::index))
        .route("/login", get(handlers::login_page).post(handlers::login_submit))
        .route("/logout", get(handlers::logout))
        .route("/dashboard", get(handlers::dashboard))
        .route("/users/create", post(handlers::create_user))
        .route("/users/delete", post(handlers::delete_user))
        .route("/tokens/create", post(handlers::create_token))
        .route("/tokens/revoke", post(handlers::revoke_token))
        .nest_service("/static", ServeDir::new("static"))
        .layer(Extension(app_config))
        .layer(Extension(proxy_routes))
        .with_state(database)
}
