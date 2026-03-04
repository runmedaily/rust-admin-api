use askama::Template;

use crate::db;
use crate::proxy::status::RouteInfo;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
    pub rd: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub user: db::User,
    pub users: Vec<db::User>,
    pub api_tokens: Vec<db::ApiToken>,
    pub error: Option<String>,
    pub success: Option<String>,
    pub new_token: Option<String>,
    pub proxy_routes: Vec<RouteInfo>,
}
