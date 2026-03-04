use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Public URL of this auth service for redirect construction.
    pub auth_url: String,
    /// Cookie domain for cross-subdomain auth (e.g. ".example.com").
    pub cookie_domain: Option<String>,
    /// Set true when behind HTTPS.
    pub cookie_secure: bool,
    /// JWT signing secret (used directly if set).
    pub jwt_secret: String,
    /// Path to a file containing the JWT secret (takes precedence over jwt_secret).
    pub jwt_secret_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            database: DatabaseConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:3000".to_string(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            auth_url: String::new(),
            cookie_domain: None,
            cookie_secure: false,
            jwt_secret: String::new(),
            jwt_secret_file: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "admin.db".to_string(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {e}"))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse config: {e}"))
    }
}

/// Resolve the JWT secret from config: file > inline > auto-generate.
pub fn resolve_jwt_secret(auth: &AuthConfig) -> String {
    if let Some(file) = &auth.jwt_secret_file {
        match std::fs::read_to_string(file) {
            Ok(s) => {
                let secret = s.trim().to_string();
                if secret.is_empty() {
                    tracing::error!("jwt_secret_file {file} is empty");
                    std::process::exit(1);
                }
                return secret;
            }
            Err(e) => {
                tracing::error!("Failed to read jwt_secret_file {file}: {e}");
                std::process::exit(1);
            }
        }
    }

    if !auth.jwt_secret.is_empty() {
        return auth.jwt_secret.clone();
    }

    let secret = uuid::Uuid::new_v4().to_string();
    tracing::warn!("No jwt_secret configured — using auto-generated secret (tokens won't survive restart)");
    secret
}
