"""
seed.py - Populate the SQLite test database with sample users.

Run: python db/seed.py
"""
import sqlite3
import hashlib
import os
import sys

# Try to use bcrypt, fall back to SHA-256 for environments without it
try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False
    print("[WARN] bcrypt not installed. Using SHA-256 (for demo only — use bcrypt in production).")


def hash_password(password: str) -> str:
    if USE_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Fallback: SHA-256 with a fixed salt prefix (NOT production-safe)
    return "sha256:" + hashlib.sha256(("sqli_lab_salt_" + password).encode()).hexdigest()


def check_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("sha256:"):
        return stored_hash == "sha256:" + hashlib.sha256(("sqli_lab_salt_" + password).encode()).hexdigest()
    if USE_BCRYPT:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    return False


DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

USERS = [
    ("admin",   "SuperSecret123!", "admin",  "admin@lab.local"),
    ("alice",   "AlicePass456",    "user",   "alice@lab.local"),
    ("bob",     "BobPass789",      "user",   "bob@lab.local"),
    ("charlie", "Charlie!Secure",  "user",   "charlie@lab.local"),
]


def seed():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Load schema
    with open(SCHEMA_PATH) as f:
        cur.executescript(f.read())

    # Clear existing data
    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM login_attempts")

    # Insert users
    for username, password, role, email in USERS:
        h = hash_password(password)
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (username, h, role, email)
        )
        print(f"  [+] Created user: {username!r:15} role={role}")

    conn.commit()
    conn.close()
    print(f"\n[OK] Database seeded at: {DB_PATH}")
    print(f"     Using {'bcrypt' if USE_BCRYPT else 'SHA-256 fallback'} for password hashing.")


if __name__ == "__main__":
    seed()
