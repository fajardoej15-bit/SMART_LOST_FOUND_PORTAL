from pathlib import Path
import hashlib
import sqlite3

DB_NAME = str(Path(__file__).resolve().parent / "lost_found.db")


def legacy_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def add_column(cursor, table, column, definition):
    columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', full_name TEXT, student_id TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, item_type TEXT NOT NULL, item_name TEXT NOT NULL, category TEXT NOT NULL, location TEXT NOT NULL, item_date TEXT NOT NULL, item_time TEXT, color TEXT, description TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS claims (id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL, claimant_id INTEGER NOT NULL, proof TEXT, status TEXT NOT NULL DEFAULT 'PENDING', admin_notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT, FOREIGN KEY(item_id) REFERENCES items(id), FOREIGN KEY(claimant_id) REFERENCES users(id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS matches (id INTEGER PRIMARY KEY AUTOINCREMENT, lost_item_id INTEGER NOT NULL, found_item_id INTEGER NOT NULL, score INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(lost_item_id, found_item_id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, details TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP)")
    cursor.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, recipient_id INTEGER, item_id INTEGER, claim_id INTEGER, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, read_at TEXT, FOREIGN KEY(sender_id) REFERENCES users(id), FOREIGN KEY(recipient_id) REFERENCES users(id), FOREIGN KEY(item_id) REFERENCES items(id), FOREIGN KEY(claim_id) REFERENCES claims(id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, claim_id INTEGER, item_id INTEGER, message TEXT NOT NULL, notification_type TEXT NOT NULL DEFAULT 'INFO', is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(claim_id) REFERENCES claims(id), FOREIGN KEY(item_id) REFERENCES items(id))")
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS otp_verifications ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, "
        "otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
        "resend_count INTEGER NOT NULL DEFAULT 0, last_sent_at TEXT NOT NULL, "
        "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"
    )

    add_column(cursor, "users", "full_name", "TEXT")
    add_column(cursor, "users", "student_id", "TEXT")
    add_column(cursor, "users", "security_question", "TEXT")
    add_column(cursor, "users", "security_answer_hash", "TEXT")
    add_column(cursor, "users", "account_status", "TEXT DEFAULT 'ACTIVE'")
    add_column(cursor, "users", "created_at", "TEXT")
    add_column(cursor, "users", "profile_picture", "TEXT")
    add_column(cursor, "users", "theme_preference", "TEXT DEFAULT 'light'")
    add_column(cursor, "items", "additional_details", "TEXT")
    add_column(cursor, "items", "contact_info", "TEXT")
    add_column(cursor, "items", "image_filename", "TEXT")
    add_column(cursor, "items", "specific_location", "TEXT")
    add_column(cursor, "items", "review_notes", "TEXT")
    add_column(cursor, "items", "updated_at", "TEXT")
    add_column(cursor, "claims", "reason", "TEXT")
    add_column(cursor, "claims", "proof_filename", "TEXT")
    add_column(cursor, "claims", "id_filename", "TEXT")
    add_column(cursor, "claims", "updated_at", "TEXT")
    add_column(cursor, "claims", "release_barangay", "TEXT")
    add_column(cursor, "claims", "release_location", "TEXT")
    add_column(cursor, "claims", "release_instructions", "TEXT")
    add_column(cursor, "claims", "required_documents", "TEXT")
    add_column(cursor, "claims", "coordination_contact", "TEXT")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(lower(email))")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_student_id ON users(student_id) WHERE student_id IS NOT NULL")
    cursor.execute("UPDATE users SET role='admin' WHERE upper(role)='ADMIN'")
    cursor.execute("UPDATE users SET role='user' WHERE upper(role) IN ('STUDENT','USER')")
    cursor.execute("UPDATE users SET account_status='ACTIVE' WHERE account_status IS NULL")
    cursor.execute("UPDATE users SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL")
    cursor.execute("UPDATE users SET theme_preference='light' WHERE theme_preference IS NULL OR theme_preference NOT IN ('light','dark','system')")

    cursor.execute("SELECT id FROM users WHERE username=?", ("admin",))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users(username,email,password_hash,role,full_name,student_id,account_status) VALUES(?,?,?,?,?,?,?)", ("admin", "admin@example.com", legacy_hash("Admin@123"), "admin", "Portal Administrator", "ADMIN", "ACTIVE"))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
