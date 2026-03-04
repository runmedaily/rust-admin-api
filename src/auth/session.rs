use axum_extra::extract::cookie::CookieJar;

use crate::db::{self, Db, User};

pub const SESSION_COOKIE: &str = "session";

/// Get the authenticated user from a session cookie.
pub fn get_session_user(jar: &CookieJar, database: &Db) -> Option<User> {
    let token = jar.get(SESSION_COOKIE)?.value().to_string();
    db::get_user_by_session(database, &token)
}

/// Parse the session cookie value from a raw Cookie header string.
/// Used by the Pingora proxy which doesn't have CookieJar.
pub fn parse_session_cookie(cookie_header: &str) -> Option<&str> {
    cookie_header.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix("session=")
    })
}

/// Extract a Bearer token from an Authorization header value.
pub fn extract_bearer_value(auth_header: &str) -> Option<&str> {
    auth_header.strip_prefix("Bearer ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::cookie::Cookie;

    #[test]
    fn parse_session_cookie_basic() {
        assert_eq!(
            parse_session_cookie("session=abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn parse_session_cookie_among_others() {
        assert_eq!(
            parse_session_cookie("theme=dark; session=abc123; lang=en"),
            Some("abc123")
        );
    }

    #[test]
    fn parse_session_cookie_missing() {
        assert_eq!(parse_session_cookie("theme=dark; lang=en"), None);
    }

    #[test]
    fn parse_session_cookie_empty_string() {
        assert_eq!(parse_session_cookie(""), None);
    }

    #[test]
    fn parse_session_cookie_empty_value() {
        assert_eq!(parse_session_cookie("session="), Some(""));
    }

    #[test]
    fn extract_bearer_valid() {
        assert_eq!(
            extract_bearer_value("Bearer eyJhbGciOiJIUzI1NiJ9.test"),
            Some("eyJhbGciOiJIUzI1NiJ9.test")
        );
    }

    #[test]
    fn extract_bearer_missing_prefix() {
        assert_eq!(extract_bearer_value("Basic abc123"), None);
    }

    #[test]
    fn extract_bearer_empty() {
        assert_eq!(extract_bearer_value(""), None);
    }

    #[test]
    fn extract_bearer_lowercase_rejected() {
        assert_eq!(extract_bearer_value("bearer abc123"), None);
    }

    #[test]
    fn session_user_lookup_with_db() {
        let db = db::init_db(":memory:");
        let admin = db::authenticate(&db, "admin", "admin").unwrap();
        let token = db::create_session(&db, admin.id);

        // Build a CookieJar with the session cookie
        let jar = CookieJar::new();
        let jar = jar.add(Cookie::new(SESSION_COOKIE, token));

        let user = get_session_user(&jar, &db);
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, admin.id);
    }

    #[test]
    fn session_user_no_cookie_returns_none() {
        let db = db::init_db(":memory:");
        let jar = CookieJar::new();
        assert!(get_session_user(&jar, &db).is_none());
    }

    #[test]
    fn session_user_invalid_cookie_returns_none() {
        let db = db::init_db(":memory:");
        let jar = CookieJar::new();
        let jar = jar.add(Cookie::new(SESSION_COOKIE, "nonexistent-token"));
        assert!(get_session_user(&jar, &db).is_none());
    }
}
