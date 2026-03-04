use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

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

        tracing::info!("Seeded default admin user (admin/admin)");
    }

    Arc::new(Mutex::new(conn))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let parsed = PasswordHash::new(hash).ok();
    parsed
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

pub fn authenticate(db: &Db, username: &str, password: &str) -> Option<User> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?1")
        .ok()?;

    let user = stmt
        .query_row(params![username], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                role: row.get(3)?,
                created_at: row.get(4)?,
            })
        })
        .ok()?;

    if verify_password(&user.password_hash, password) {
        Some(user)
    } else {
        None
    }
}

pub fn create_session(db: &Db, user_id: i64) -> String {
    let token = uuid::Uuid::new_v4().to_string();
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?1, ?2)",
        params![token, user_id],
    )
    .expect("Failed to create session");
    token
}

pub fn get_user_by_session(db: &Db, token: &str) -> Option<User> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT u.id, u.username, u.password_hash, u.role, u.created_at
             FROM users u JOIN sessions s ON u.id = s.user_id
             WHERE s.token = ?1",
        )
        .ok()?;

    stmt.query_row(params![token], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            role: row.get(3)?,
            created_at: row.get(4)?,
        })
    })
    .ok()
}

pub fn delete_session(db: &Db, token: &str) {
    let conn = db.lock().unwrap();
    let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token]);
}

pub fn list_users(db: &Db) -> Vec<User> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, username, password_hash, role, created_at FROM users ORDER BY id")
        .unwrap();

    stmt.query_map([], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            role: row.get(3)?,
            created_at: row.get(4)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

pub fn create_user(db: &Db, username: &str, password: &str, role: &str) -> Result<(), String> {
    let hash = hash_password(password);
    let conn = db.lock().unwrap();
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
    let conn = db.lock().unwrap();
    // Delete sessions and tokens first
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
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO api_tokens (name, user_id) VALUES (?1, ?2)",
        params![name, user_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

/// Check if a token ID exists (not revoked) and return the owning user.
pub fn verify_api_token(db: &Db, token_id: i64) -> Option<User> {
    let conn = db.lock().unwrap();

    // Update last_used timestamp
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

    stmt.query_row(params![token_id], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            role: row.get(3)?,
            created_at: row.get(4)?,
        })
    })
    .ok()
}

/// List all API tokens (for admin dashboard).
pub fn list_api_tokens(db: &Db) -> Vec<ApiToken> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.name, t.user_id, u.username, t.created_at, t.last_used
             FROM api_tokens t JOIN users u ON t.user_id = u.id
             ORDER BY t.id",
        )
        .unwrap();

    stmt.query_map([], |row| {
        Ok(ApiToken {
            id: row.get(0)?,
            name: row.get(1)?,
            user_id: row.get(2)?,
            username: row.get(3)?,
            created_at: row.get(4)?,
            last_used: row.get(5)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

/// List API tokens for a specific user.
pub fn list_user_api_tokens(db: &Db, user_id: i64) -> Vec<ApiToken> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.name, t.user_id, u.username, t.created_at, t.last_used
             FROM api_tokens t JOIN users u ON t.user_id = u.id
             WHERE t.user_id = ?1
             ORDER BY t.id",
        )
        .unwrap();

    stmt.query_map(params![user_id], |row| {
        Ok(ApiToken {
            id: row.get(0)?,
            name: row.get(1)?,
            user_id: row.get(2)?,
            username: row.get(3)?,
            created_at: row.get(4)?,
            last_used: row.get(5)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

/// Delete (revoke) an API token.
pub fn delete_api_token(db: &Db, token_id: i64) -> Result<(), String> {
    let conn = db.lock().unwrap();
    let affected = conn
        .execute("DELETE FROM api_tokens WHERE id = ?1", params![token_id])
        .map_err(|e| e.to_string())?;

    if affected == 0 {
        Err("Token not found".to_string())
    } else {
        Ok(())
    }
}
