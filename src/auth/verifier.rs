use crate::db::{Db, User};

/// The result of an auth check.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Request is authenticated.
    Authenticated(User),
    /// No credentials presented.
    Unauthenticated,
}

/// Protocol-agnostic request credentials.
pub struct RequestCredentials<'a> {
    pub session_token: Option<&'a str>,
    pub bearer_token: Option<&'a str>,
}

/// Auth verification backed by SQLite.
pub struct AuthVerifier {
    db: Db,
    jwt_secret: String,
}

impl AuthVerifier {
    pub fn new(db: Db, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }

    pub fn verify(&self, creds: &RequestCredentials<'_>) -> AuthOutcome {
        // 1. Session cookie
        if let Some(token) = creds.session_token {
            if let Some(user) = crate::db::get_user_by_session(&self.db, token) {
                return AuthOutcome::Authenticated(user);
            }
        }

        // 2. Bearer JWT
        if let Some(token) = creds.bearer_token {
            if let Some(user) = crate::auth::jwt::verify_jwt(token, &self.db, &self.jwt_secret) {
                return AuthOutcome::Authenticated(user);
            }
        }

        AuthOutcome::Unauthenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt;
    use crate::db;

    fn setup() -> (Db, AuthVerifier) {
        let database = db::init_db(":memory:");
        let verifier = AuthVerifier::new(database.clone(), "test-secret".to_string());
        (database, verifier)
    }

    #[test]
    fn session_auth_works() {
        let (db, verifier) = setup();
        let admin = db::authenticate(&db, "admin", "admin").unwrap();
        let token = db::create_session(&db, admin.id);

        let creds = RequestCredentials {
            session_token: Some(&token),
            bearer_token: None,
        };
        match verifier.verify(&creds) {
            AuthOutcome::Authenticated(user) => assert_eq!(user.id, admin.id),
            AuthOutcome::Unauthenticated => panic!("Expected authenticated"),
        }
    }

    #[test]
    fn bearer_auth_works() {
        let (db, verifier) = setup();
        let admin = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "test-key", admin.id).unwrap();
        let jwt_token = jwt::encode_jwt(&admin, token_id, "test-secret").unwrap();

        let creds = RequestCredentials {
            session_token: None,
            bearer_token: Some(&jwt_token),
        };
        match verifier.verify(&creds) {
            AuthOutcome::Authenticated(user) => assert_eq!(user.id, admin.id),
            AuthOutcome::Unauthenticated => panic!("Expected authenticated"),
        }
    }

    #[test]
    fn no_credentials_is_unauthenticated() {
        let (_db, verifier) = setup();
        let creds = RequestCredentials {
            session_token: None,
            bearer_token: None,
        };
        assert!(matches!(
            verifier.verify(&creds),
            AuthOutcome::Unauthenticated
        ));
    }

    #[test]
    fn invalid_session_is_unauthenticated() {
        let (_db, verifier) = setup();
        let creds = RequestCredentials {
            session_token: Some("bad-token"),
            bearer_token: None,
        };
        assert!(matches!(
            verifier.verify(&creds),
            AuthOutcome::Unauthenticated
        ));
    }

    #[test]
    fn invalid_bearer_is_unauthenticated() {
        let (_db, verifier) = setup();
        let creds = RequestCredentials {
            session_token: None,
            bearer_token: Some("not-a-valid-jwt"),
        };
        assert!(matches!(
            verifier.verify(&creds),
            AuthOutcome::Unauthenticated
        ));
    }

    #[test]
    fn session_takes_priority_over_bearer() {
        let (db, verifier) = setup();
        let admin = db::authenticate(&db, "admin", "admin").unwrap();
        db::create_user(&db, "alice", "pass", "user").unwrap();
        let alice = db::authenticate(&db, "alice", "pass").unwrap();

        // Session for admin, bearer for alice
        let session_token = db::create_session(&db, admin.id);
        let api_token_id = db::create_api_token(&db, "alice-key", alice.id).unwrap();
        let jwt_token = jwt::encode_jwt(&alice, api_token_id, "test-secret").unwrap();

        let creds = RequestCredentials {
            session_token: Some(&session_token),
            bearer_token: Some(&jwt_token),
        };
        match verifier.verify(&creds) {
            AuthOutcome::Authenticated(user) => {
                // Session (admin) should take priority
                assert_eq!(user.username, "admin");
            }
            AuthOutcome::Unauthenticated => panic!("Expected authenticated"),
        }
    }

    #[test]
    fn revoked_bearer_is_unauthenticated() {
        let (db, verifier) = setup();
        let admin = db::authenticate(&db, "admin", "admin").unwrap();
        let token_id = db::create_api_token(&db, "temp", admin.id).unwrap();
        let jwt_token = jwt::encode_jwt(&admin, token_id, "test-secret").unwrap();

        // Revoke the API token
        db::delete_api_token(&db, token_id).unwrap();

        let creds = RequestCredentials {
            session_token: None,
            bearer_token: Some(&jwt_token),
        };
        assert!(matches!(
            verifier.verify(&creds),
            AuthOutcome::Unauthenticated
        ));
    }
}
