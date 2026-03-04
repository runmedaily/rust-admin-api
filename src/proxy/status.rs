/// Route information displayed on the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouteInfo {
    pub host: String,
    pub path_prefix: String,
    pub upstream: String,
    pub auth_required: bool,
}
