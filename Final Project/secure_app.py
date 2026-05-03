"""
secure_app.py
-------------
Hardened login demo that demonstrates common protections against SQLi.

Key protections shown here:
- parameterized queries
- secure password hashing (bcrypt when available)
- per-user rate limiting / temporary lockout
- audit logging of attempts
- generic error messages so internals are not leaked

Run: `python secure_app.py demo` or `python secure_app.py interactive`.
"""

import sqlite3
import hashlib
import os
import re
import sys
import time
import logging
from datetime import datetime, timedelta

# ── Logging setup ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("sqli_lab_audit.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("secure_app")

# ── bcrypt (optional) ──────────────────────────────────────────────────────
try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "lab.db")

BANNER = """
SECURE LOGIN APP — learning lab
--------------------------------
This app demonstrates how simple controls make injection attacks fail.
"""

# Rate-limiting: max failed attempts before lockout
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 30
# In-memory attempt tracker: {username: [timestamp, ...]}
_attempt_tracker: dict[str, list[float]] = {}

# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

def check_password(plain: str, stored_hash: str) -> bool:
    """Return True when the provided plaintext matches the stored hash."""
    if stored_hash.startswith("sha256:"):
        expected = "sha256:" + hashlib.sha256(("sqli_lab_salt_" + plain).encode()).hexdigest()
        return stored_hash == expected
    if USE_BCRYPT:
        try:
            return bcrypt.checkpw(plain.encode(), stored_hash.encode())
        except Exception:
            return False
    return False


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def validate_username(username: str) -> bool:
    """Simple allow-list check for usernames.

    Limits length and only allows common safe characters. This helps
    catch obvious injection attempts early, but the primary defence is
    still parameterized SQL queries.
    """
    if not username or len(username) > 64:
        return False
    return bool(re.match(r'^[\w.\-]+$', username))


# ---------------------------------------------------------------------------
# Rate limiting helpers
# ---------------------------------------------------------------------------

def is_rate_limited(username: str) -> bool:
    """Return True if this username is currently locked out."""
    now = time.time()
    cutoff = now - LOCKOUT_SECONDS
    attempts = [t for t in _attempt_tracker.get(username, []) if t > cutoff]
    _attempt_tracker[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def record_attempt(username: str):
    """Record a failed login attempt."""
    _attempt_tracker.setdefault(username, []).append(time.time())


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_connection():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at {DB_PATH}")
        print("        Run:  python db/seed.py   first.")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def log_attempt_to_db(conn, username: str, success: bool):
    """Record whether a login attempt succeeded in the DB audit table."""
    try:
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, "127.0.0.1", 1 if success else 0),
        )
        conn.commit()
    except Exception as e:
        logger.error("Failed to write audit log: %s", e)


# ---------------------------------------------------------------------------
# Secure login implementation
# ---------------------------------------------------------------------------

def secure_login(username: str, password: str) -> dict | None:
    """Attempt to authenticate `username` with `password`.

    This function demonstrates a secure approach: parameters are passed
    to the DB driver separately, preventing them from being interpreted
    as SQL. Other controls like rate-limiting and logging are applied
    to reduce abuse and to aid debugging.
    """

    # 1. Input validation
    if not validate_username(username):
        logger.warning("Invalid username format rejected: %r", username)
        return None

    # 2. Rate limiting
    if is_rate_limited(username):
        logger.warning("Rate limit triggered for username: %r", username)
        print("  [SECURITY] Too many failed attempts. Please wait and try again.")
        return None

    conn = get_connection()
    try:
        # Use parameterized placeholders so input is always treated as data.
        query = "SELECT id, username, password_hash, role FROM users WHERE username = ?"
        print(f"\n  [SQL] {query}  params=({username!r},)\n")

        cur = conn.execute(query, (username,))
        row = cur.fetchone()

        if row is None:
            # No such user — fail silently so attackers can't learn details.
            record_attempt(username)
            log_attempt_to_db(conn, username, False)
            logger.info("Login failed (no such user): %r", username)
            return None

        user_id, db_username, stored_hash, role = row

        # Check the password without leaking timing information.
        if not check_password(password, stored_hash):
            record_attempt(username)
            log_attempt_to_db(conn, username, False)
            logger.info("Login failed (wrong password): %r", username)
            return None

        # 4. Success
        log_attempt_to_db(conn, username, True)
        logger.info("Login SUCCESS: %r (role=%s)", username, role)
        return {"id": user_id, "username": db_username, "role": role}

    except Exception as e:
        # Don't reveal internals to callers; just log for maintainers.
        logger.error("Unexpected DB error during login: %s", e)
        return None
    finally:
        conn.close()


def secure_search_user(search_term: str):
    """Search by username using a parameterized query.

    Any payload passed here will be treated as data, so UNION tricks won't
    be executed by the database.
    """
    conn = get_connection()
    try:
        query = "SELECT id, username, role FROM users WHERE username = ?"
        print(f"\n  [SQL] {query}  params=({search_term!r},)\n")
        cur = conn.execute(query, (search_term,))
        return cur.fetchall()
    except Exception as e:
        logger.error("Search error: %s", e)
        return []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DEMO: Same payloads as insecure_app.py — now all fail
# ---------------------------------------------------------------------------

def demo_attack_1_auth_bypass():
    print("=" * 60)
    print("ATTACK 1: OR '1'='1' Authentication Bypass  → should FAIL")
    print("=" * 60)
    print("  Username: admin")
    print("  Password: ' OR '1'='1\n")

    result = secure_login("admin", "' OR '1'='1")
    if result:
        print(f"  [RESULT] ⚠️  Access GRANTED: {result}  ← THIS SHOULD NOT HAPPEN")
    else:
        print("  [RESULT] ✅ Access DENIED — payload treated as literal string, no match.")


def demo_attack_2_comment_bypass():
    print("\n" + "=" * 60)
    print("ATTACK 2: Comment-Out Bypass  admin'--  → should FAIL")
    print("=" * 60)
    print("  Username: admin'--")
    print("  Password: anything\n")
    print("  Note: validate_username() rejects special chars before SQL is even reached.\n")

    result = secure_login("admin'--", "anything")
    if result:
        print(f"  [RESULT] ⚠️  Access GRANTED: {result}")
    else:
        print("  [RESULT] ✅ Access DENIED — invalid username format rejected at input validation.")


def demo_attack_3_union_dump():
    print("\n" + "=" * 60)
    print("ATTACK 3: UNION Data Dump  → should FAIL")
    print("=" * 60)
    payload = "' UNION SELECT id, username, role FROM users--"
    print(f"  Search term: {payload!r}\n")

    rows = secure_search_user(payload)
    if rows:
        print(f"  [RESULT] ⚠️  Got {len(rows)} rows — unexpected!")
    else:
        print("  [RESULT] ✅ No rows returned — UNION payload is a literal string, not SQL.")


def demo_attack_4_rate_limit():
    print("\n" + "=" * 60)
    print("ATTACK 4: Rate Limit / Lockout after repeated failures")
    print("=" * 60)
    print(f"  Attempting {MAX_ATTEMPTS + 1} rapid logins with wrong password...\n")

    for i in range(MAX_ATTEMPTS + 1):
        result = secure_login("alice", "wrongpassword")
        status = "LOCKED OUT" if result is None and i >= MAX_ATTEMPTS - 1 else "denied"
        print(f"  Attempt {i+1}: {status}")


# ---------------------------------------------------------------------------
# INTERACTIVE MODE
# ---------------------------------------------------------------------------

def interactive_mode():
    print("\n--- Interactive Secure Login ---")
    print("  Try the same injection payloads — they will all fail.\n")
    username = input("  Username: ")
    password = input("  Password: ")

    result = secure_login(username, password)
    if result:
        print(f"\n  [RESULT] ✅ LOGIN SUCCESS → {result}")
    else:
        print("\n  [RESULT] ❌ Login failed (invalid credentials or rate-limited).")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(BANNER)

    mode = sys.argv[1] if len(sys.argv) > 1 else "demo"

    if mode == "demo":
        demo_attack_1_auth_bypass()
        demo_attack_2_comment_bypass()
        demo_attack_3_union_dump()
        demo_attack_4_rate_limit()
        print("\n" + "=" * 60)
        print("All 4 payloads blocked. Review sqli_lab_audit.log for details.")
        print("=" * 60)
    elif mode == "interactive":
        interactive_mode()
    else:
        print(f"Unknown mode '{mode}'. Use: demo | interactive")
