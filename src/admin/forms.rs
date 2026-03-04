#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub rd: String,
}

#[derive(serde::Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(serde::Deserialize)]
pub struct DeleteUserForm {
    pub user_id: i64,
}

#[derive(serde::Deserialize)]
pub struct CreateTokenForm {
    pub token_name: String,
}

#[derive(serde::Deserialize)]
pub struct RevokeTokenForm {
    pub token_id: i64,
}

#[derive(serde::Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub rd: Option<String>,
}
