use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};

use crate::db::{self, Db, User};

/// JWT token lifetime: 90 days.
const TOKEN_TTL_SECS: i64 = 90 * 24 * 3600;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Claims {
    /// User ID
    pub sub: i64,
    /// Token ID in the api_tokens table
    pub tid: i64,
    /// Username
    pub username: String,
    /// Role
    pub role: String,
    /// Issued at (unix timestamp)
    pub iat: i64,
    /// Expiration (unix timestamp)
    pub exp: i64,
}

/// Create a signed JWT for an API token.
pub fn encode_jwt(user: &User, token_id: i64, secret: &str) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: user.id,
        tid: token_id,
        username: user.username.clone(),
        role: user.role.clone(),
        iat: now,
        exp: now + TOKEN_TTL_SECS,
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("JWT encode error: {e}"))
}

/// Verify a Bearer JWT token: check signature + expiry, then check token_id is not revoked in DB.
pub fn verify_jwt(token: &str, database: &Db, secret: &str) -> Option<User> {
    let token_data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?;

    db::verify_api_token(database, token_data.claims.tid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        db::init_db(":memory:")
    }

    #[test]
    fn encode_decode_roundtrip() {
        let db = test_db();
        let user = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "test-key", user.id).unwrap();

        let jwt = encode_jwt(&user, token_id, "secret").unwrap();
        let verified = verify_jwt(&jwt, &db, "secret");
        assert!(verified.is_some());
        assert_eq!(verified.unwrap().id, user.id);
    }

    #[test]
    fn wrong_secret_rejected() {
        let db = test_db();
        let user = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "test-key", user.id).unwrap();

        let jwt = encode_jwt(&user, token_id, "secret").unwrap();
        assert!(verify_jwt(&jwt, &db, "wrong-secret").is_none());
    }

    #[test]
    fn expired_token_rejected() {
        let db = test_db();
        let user = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "test-key", user.id).unwrap();

        // Manually create a token with exp in the past
        let claims = Claims {
            sub: user.id,
            tid: token_id,
            username: user.username.clone(),
            role: user.role.clone(),
            iat: 1000,
            exp: 1001, // long expired
        };
        let jwt = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        assert!(verify_jwt(&jwt, &db, "secret").is_none());
    }

    #[test]
    fn revoked_token_rejected() {
        let db = test_db();
        let user = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "test-key", user.id).unwrap();

        let jwt = encode_jwt(&user, token_id, "secret").unwrap();
        // Revoke the token
        db::delete_api_token(&db, token_id).unwrap();

        assert!(verify_jwt(&jwt, &db, "secret").is_none());
    }

    #[test]
    fn claims_contain_correct_fields() {
        let db = test_db();
        let user = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "test-key", user.id).unwrap();

        let jwt = encode_jwt(&user, token_id, "secret").unwrap();
        let token_data = jsonwebtoken::decode::<Claims>(
            &jwt,
            &DecodingKey::from_secret(b"secret"),
            &Validation::default(),
        )
        .unwrap();

        assert_eq!(token_data.claims.sub, user.id);
        assert_eq!(token_data.claims.tid, token_id);
        assert_eq!(token_data.claims.username, "admin");
        assert_eq!(token_data.claims.role, "admin");
        assert!(token_data.claims.exp > token_data.claims.iat);
    }
}
