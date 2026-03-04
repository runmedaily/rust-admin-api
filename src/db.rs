use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String, // "admin" or "user"
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub user_id: i64,
    pub username: String,
    pub created_at: String,
    pub last_used: Option<String>,
}

pub type Db = Arc<Mutex<Connection>>;

/// Lock the database, recovering from mutex poisoning.
fn lock(db: &Db) -> MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn row_to_api_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiToken> {
    Ok(ApiToken {
        id: row.get(0)?,
        name: row.get(1)?,
        user_id: row.get(2)?,
        username: row.get(3)?,
        created_at: row.get(4)?,
        last_used: row.get(5)?,
    })
}

/// Session TTL: sessions older than this are expired.
const SESSION_TTL_DAYS: i64 = 30;

pub fn init_db(path: &str) -> Db {
    let conn = Connection::open(path).expect("Failed to open database");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_used TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );",
    )
    .expect("Failed to create tables");

    // Seed default admin if no users exist
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap_or(0);

    if count == 0 {
        let password = "admin";
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("Failed to hash password")
            .to_string();

        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, 'admin')",
            params!["admin", hash],
        )
        .expect("Failed to seed admin user");

        tracing::info!("Seeded default admin user (admin/admin) — change the password immediately");
    }

    // Clean up expired sessions on startup
    let _ = conn.execute(
        &format!("DELETE FROM sessions WHERE created_at < datetime('now', '-{SESSION_TTL_DAYS} days')"),
        [],
    );

    Arc::new(Mutex::new(conn))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let parsed = PasswordHash::new(hash).ok();
    parsed
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Password hashing failed: {e}"))
}

pub fn authenticate(db: &Db, username: &str, password: &str) -> Option<User> {
    let conn = lock(db);
    let mut stmt = conn
        .prepare("SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?1")
        .ok()?;

    let user = stmt.query_row(params![username], row_to_user).ok()?;

    if verify_password(&user.password_hash, password) {
        Some(user)
    } else {
        None
    }
}

pub fn create_session(db: &Db, user_id: i64) -> String {
    let token = uuid::Uuid::new_v4().to_string();
    let conn = lock(db);
    conn.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?1, ?2)",
        params![token, user_id],
    )
    .expect("Failed to create session");
    token
}

pub fn get_user_by_session(db: &Db, token: &str) -> Option<User> {
    let conn = lock(db);
    let mut stmt = conn
        .prepare(&format!(
            "SELECT u.id, u.username, u.password_hash, u.role, u.created_at
             FROM users u JOIN sessions s ON u.id = s.user_id
             WHERE s.token = ?1
             AND s.created_at > datetime('now', '-{SESSION_TTL_DAYS} days')"
        ))
        .ok()?;

    stmt.query_row(params![token], row_to_user).ok()
}

pub fn delete_session(db: &Db, token: &str) {
    let conn = lock(db);
    let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token]);
}

pub fn list_users(db: &Db) -> Vec<User> {
    let conn = lock(db);
    let mut stmt = conn
        .prepare("SELECT id, username, password_hash, role, created_at FROM users ORDER BY id")
        .unwrap();

    stmt.query_map([], row_to_user)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

pub fn create_user(db: &Db, username: &str, password: &str, role: &str) -> Result<(), String> {
    let hash = hash_password(password)?;
    let conn = lock(db);
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)",
        params![username, hash, role],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            "Username already exists".to_string()
        } else {
            e.to_string()
        }
    })?;
    Ok(())
}

pub fn delete_user(db: &Db, user_id: i64) -> Result<(), String> {
    let conn = lock(db);
    // Cascade: delete sessions and tokens for this user
    let _ = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id]);
    let _ = conn.execute("DELETE FROM api_tokens WHERE user_id = ?1", params![user_id]);
    let affected = conn
        .execute("DELETE FROM users WHERE id = ?1", params![user_id])
        .map_err(|e| e.to_string())?;

    if affected == 0 {
        Err("User not found".to_string())
    } else {
        Ok(())
    }
}

// --- API Tokens ---

/// Create a new API token record. Returns the token ID.
pub fn create_api_token(db: &Db, name: &str, user_id: i64) -> Result<i64, String> {
    let conn = lock(db);
    conn.execute(
        "INSERT INTO api_tokens (name, user_id) VALUES (?1, ?2)",
        params![name, user_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

/// Check if a token ID exists (not revoked) and return the owning user.
pub fn verify_api_token(db: &Db, token_id: i64) -> Option<User> {
    let conn = lock(db);

    // Update last_used timestamp (best-effort)
    let _ = conn.execute(
        "UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?1",
        params![token_id],
    );

    let mut stmt = conn
        .prepare(
            "SELECT u.id, u.username, u.password_hash, u.role, u.created_at
             FROM users u JOIN api_tokens t ON u.id = t.user_id
             WHERE t.id = ?1",
        )
        .ok()?;

    stmt.query_row(params![token_id], row_to_user).ok()
}

/// List all API tokens (for admin dashboard).
pub fn list_api_tokens(db: &Db) -> Vec<ApiToken> {
    let conn = lock(db);
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.name, t.user_id, u.username, t.created_at, t.last_used
             FROM api_tokens t JOIN users u ON t.user_id = u.id
             ORDER BY t.id",
        )
        .unwrap();

    stmt.query_map([], row_to_api_token)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

/// List API tokens for a specific user.
pub fn list_user_api_tokens(db: &Db, user_id: i64) -> Vec<ApiToken> {
    let conn = lock(db);
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.name, t.user_id, u.username, t.created_at, t.last_used
             FROM api_tokens t JOIN users u ON t.user_id = u.id
             WHERE t.user_id = ?1
             ORDER BY t.id",
        )
        .unwrap();

    stmt.query_map(params![user_id], row_to_api_token)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

/// Delete (revoke) an API token.
pub fn delete_api_token(db: &Db, token_id: i64) -> Result<(), String> {
    let conn = lock(db);
    let affected = conn
        .execute("DELETE FROM api_tokens WHERE id = ?1", params![token_id])
        .map_err(|e| e.to_string())?;

    if affected == 0 {
        Err("Token not found".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an in-memory database for testing.
    fn test_db() -> Db {
        init_db(":memory:")
    }

    #[test]
    fn init_seeds_admin_user() {
        let db = test_db();
        let users = list_users(&db);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].role, "admin");
    }

    #[test]
    fn authenticate_with_correct_password() {
        let db = test_db();
        let user = authenticate(&db, "admin", "admin");
        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "admin");
    }

    #[test]
    fn authenticate_with_wrong_password() {
        let db = test_db();
        assert!(authenticate(&db, "admin", "wrong").is_none());
    }

    #[test]
    fn authenticate_nonexistent_user() {
        let db = test_db();
        assert!(authenticate(&db, "nobody", "admin").is_none());
    }

    #[test]
    fn hash_and_verify_password() {
        let hash = hash_password("mypassword").unwrap();
        assert!(verify_password(&hash, "mypassword"));
        assert!(!verify_password(&hash, "wrongpassword"));
    }

    #[test]
    fn verify_password_with_invalid_hash() {
        assert!(!verify_password("not-a-real-hash", "password"));
    }

    #[test]
    fn create_and_list_users() {
        let db = test_db();
        create_user(&db, "alice", "pass123", "user").unwrap();
        create_user(&db, "bob", "pass456", "admin").unwrap();

        let users = list_users(&db);
        assert_eq!(users.len(), 3); // admin + alice + bob
        assert_eq!(users[1].username, "alice");
        assert_eq!(users[1].role, "user");
        assert_eq!(users[2].username, "bob");
        assert_eq!(users[2].role, "admin");
    }

    #[test]
    fn create_user_duplicate_username_fails() {
        let db = test_db();
        create_user(&db, "alice", "pass1", "user").unwrap();
        let result = create_user(&db, "alice", "pass2", "user");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Username already exists"));
    }

    #[test]
    fn delete_user_removes_user() {
        let db = test_db();
        create_user(&db, "alice", "pass", "user").unwrap();
        let users = list_users(&db);
        let alice_id = users.iter().find(|u| u.username == "alice").unwrap().id;

        delete_user(&db, alice_id).unwrap();
        let users = list_users(&db);
        assert!(users.iter().all(|u| u.username != "alice"));
    }

    #[test]
    fn delete_user_not_found() {
        let db = test_db();
        let result = delete_user(&db, 9999);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("User not found"));
    }

    #[test]
    fn delete_user_cascades_sessions_and_tokens() {
        let db = test_db();
        create_user(&db, "alice", "pass", "user").unwrap();
        let alice = authenticate(&db, "alice", "pass").unwrap();

        // Create a session and token for alice
        let session_token = create_session(&db, alice.id);
        create_api_token(&db, "alice-token", alice.id).unwrap();

        // Verify they exist
        assert!(get_user_by_session(&db, &session_token).is_some());
        let tokens = list_user_api_tokens(&db, alice.id);
        assert_eq!(tokens.len(), 1);

        // Delete alice — sessions and tokens should be gone
        delete_user(&db, alice.id).unwrap();
        assert!(get_user_by_session(&db, &session_token).is_none());

        // Token list for alice's user_id should be empty
        let tokens = list_user_api_tokens(&db, alice.id);
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn session_create_and_lookup() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        let token = create_session(&db, admin.id);

        let user = get_user_by_session(&db, &token);
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, admin.id);
    }

    #[test]
    fn session_invalid_token_returns_none() {
        let db = test_db();
        assert!(get_user_by_session(&db, "nonexistent-token").is_none());
    }

    #[test]
    fn session_delete_invalidates() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        let token = create_session(&db, admin.id);

        delete_session(&db, &token);
        assert!(get_user_by_session(&db, &token).is_none());
    }

    #[test]
    fn session_expired_not_returned() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();

        // Insert a session with a timestamp beyond the TTL
        let old_token = "expired-session-token";
        {
            let conn = lock(&db);
            conn.execute(
                &format!(
                    "INSERT INTO sessions (token, user_id, created_at) VALUES (?1, ?2, datetime('now', '-{} days'))",
                    SESSION_TTL_DAYS + 1
                ),
                params![old_token, admin.id],
            )
            .unwrap();
        }

        assert!(get_user_by_session(&db, old_token).is_none());
    }

    #[test]
    fn api_token_create_and_verify() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        let token_id = create_api_token(&db, "deploy-key", admin.id).unwrap();

        let user = verify_api_token(&db, token_id);
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, admin.id);
    }

    #[test]
    fn api_token_verify_nonexistent() {
        let db = test_db();
        assert!(verify_api_token(&db, 9999).is_none());
    }

    #[test]
    fn api_token_list_all_and_per_user() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        create_user(&db, "alice", "pass", "admin").unwrap();
        let alice = authenticate(&db, "alice", "pass").unwrap();

        create_api_token(&db, "admin-token-1", admin.id).unwrap();
        create_api_token(&db, "admin-token-2", admin.id).unwrap();
        create_api_token(&db, "alice-token-1", alice.id).unwrap();

        // All tokens
        let all = list_api_tokens(&db);
        assert_eq!(all.len(), 3);

        // Per-user tokens
        let admin_tokens = list_user_api_tokens(&db, admin.id);
        assert_eq!(admin_tokens.len(), 2);
        let alice_tokens = list_user_api_tokens(&db, alice.id);
        assert_eq!(alice_tokens.len(), 1);
    }

    #[test]
    fn api_token_revoke() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        let token_id = create_api_token(&db, "temp-key", admin.id).unwrap();

        delete_api_token(&db, token_id).unwrap();
        assert!(verify_api_token(&db, token_id).is_none());
    }

    #[test]
    fn api_token_revoke_nonexistent() {
        let db = test_db();
        let result = delete_api_token(&db, 9999);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Token not found"));
    }

    #[test]
    fn api_token_updates_last_used() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        let token_id = create_api_token(&db, "usage-test", admin.id).unwrap();

        // Before verification, last_used is None
        let tokens = list_user_api_tokens(&db, admin.id);
        assert!(tokens[0].last_used.is_none());

        // Verify updates last_used
        verify_api_token(&db, token_id);
        let tokens = list_user_api_tokens(&db, admin.id);
        assert!(tokens[0].last_used.is_some());
    }

    #[test]
    fn two_admins_have_separate_tokens() {
        let db = test_db();
        let admin = authenticate(&db, "admin", "admin").unwrap();
        create_user(&db, "admin2", "pass", "admin").unwrap();
        let admin2 = authenticate(&db, "admin2", "pass").unwrap();

        create_api_token(&db, "token-a", admin.id).unwrap();
        create_api_token(&db, "token-b", admin2.id).unwrap();

        let tokens1 = list_user_api_tokens(&db, admin.id);
        let tokens2 = list_user_api_tokens(&db, admin2.id);
        assert_eq!(tokens1.len(), 1);
        assert_eq!(tokens2.len(), 1);
        assert_eq!(tokens1[0].name, "token-a");
        assert_eq!(tokens2[0].name, "token-b");
    }
}
