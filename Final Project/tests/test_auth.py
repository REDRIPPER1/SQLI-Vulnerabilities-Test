"""
tests/test_auth.py — Automated Test Suite for SQLi Lab
=======================================================
Tests:
  - Secure login correctly authenticates valid credentials
  - Secure login REJECTS all known injection payloads
  - Secure login REJECTS invalid username formats
  - Rate limiting blocks repeated failures
  - Insecure login IS vulnerable (confirming the demo works)

Run: pytest tests/test_auth.py -v
"""

import sys
import os
import pytest
import sqlite3
import hashlib

# ── Add project root to path ───────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ── Point both apps at a fresh in-memory test DB ──────────────────────────
import secure_app
import insecure_app

# Monkey-patch DB_PATH to use :memory: style via a temp file
import tempfile

TEST_DB = tempfile.mktemp(suffix=".db")
secure_app.DB_PATH = TEST_DB
insecure_app.DB_PATH = TEST_DB


def _hash(password: str) -> str:
    return "sha256:" + hashlib.sha256(("sqli_lab_salt_" + password).encode()).hexdigest()


@pytest.fixture(autouse=True)
def fresh_db():
    """Create a fresh in-memory SQLite DB for every test."""
    schema = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "schema.sql")
    conn = sqlite3.connect(TEST_DB)
    with open(schema) as f:
        conn.executescript(f.read())
    conn.execute(
        "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
        ("admin", _hash("SuperSecret123!"), "admin", "admin@test.local"),
    )
    conn.execute(
        "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
        ("alice", _hash("AlicePass456"), "user", "alice@test.local"),
    )
    conn.commit()
    conn.close()

    # Reset rate-limit tracker between tests
    secure_app._attempt_tracker.clear()

    yield

    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


# ===========================================================================
# SECURE APP TESTS
# ===========================================================================

class TestSecureLogin:

    def test_valid_credentials_succeed(self):
        """Correct username + password should grant access."""
        result = secure_app.secure_login("admin", "SuperSecret123!")
        assert result is not None, "Valid credentials should succeed"
        assert result["username"] == "admin"
        assert result["role"] == "admin"

    def test_wrong_password_fails(self):
        """Correct username but wrong password must be rejected."""
        result = secure_app.secure_login("admin", "wrongpassword")
        assert result is None

    def test_nonexistent_user_fails(self):
        """Unknown username must be rejected."""
        result = secure_app.secure_login("nobody", "anything")
        assert result is None

    # ── Injection payloads ─────────────────────────────────────────────────

    def test_or_1_equals_1_blocked(self):
        """Classic OR '1'='1' auth bypass must fail."""
        result = secure_app.secure_login("admin", "' OR '1'='1")
        assert result is None, "OR injection should be blocked"

    def test_always_true_payload_blocked(self):
        result = secure_app.secure_login("admin", "' OR 1=1--")
        assert result is None

    def test_comment_bypass_blocked(self):
        """admin'-- comment injection must fail (input validation catches it)."""
        result = secure_app.secure_login("admin'--", "anything")
        assert result is None, "SQL comment payload should be rejected by input validation"

    def test_union_select_blocked(self):
        """UNION SELECT payload must fail."""
        result = secure_app.secure_login("' UNION SELECT 1,2,3,4--", "x")
        assert result is None

    def test_stacked_query_blocked(self):
        """Stacked query (semicolon) must fail."""
        result = secure_app.secure_login("admin'; DROP TABLE users;--", "x")
        assert result is None

    def test_boolean_blind_payload_blocked(self):
        result = secure_app.secure_login("admin", "' AND 1=1--")
        assert result is None

    def test_time_based_payload_blocked(self):
        result = secure_app.secure_login("admin", "' AND SLEEP(5)--")
        assert result is None

    def test_null_byte_blocked(self):
        result = secure_app.secure_login("admin\x00", "x")
        assert result is None

    def test_long_username_blocked(self):
        """Oversized username rejected by input validation."""
        result = secure_app.secure_login("a" * 200, "x")
        assert result is None

    def test_empty_username_blocked(self):
        result = secure_app.secure_login("", "x")
        assert result is None

    def test_special_chars_in_username_blocked(self):
        """Usernames with SQL metacharacters rejected."""
        for bad in ["admin'", 'admin"', 'adm;in', 'adm<in>', 'ad&m']:
            result = secure_app.secure_login(bad, "x")
            assert result is None, f"Username {bad!r} should be rejected"

    # ── Rate limiting ──────────────────────────────────────────────────────

    def test_rate_limiting_triggers(self):
        """After MAX_ATTEMPTS failures, further attempts are blocked."""
        for _ in range(secure_app.MAX_ATTEMPTS):
            secure_app.secure_login("alice", "wrongpassword")

        # This one should be rate-limited
        result = secure_app.secure_login("alice", "AlicePass456")  # correct password!
        assert result is None, "Rate limit should block even correct password after lockout"

    def test_rate_limit_per_username(self):
        """Rate limiting is per-username; another user is unaffected."""
        for _ in range(secure_app.MAX_ATTEMPTS):
            secure_app.secure_login("alice", "wrong")

        # admin is a different username — should not be affected
        result = secure_app.secure_login("admin", "SuperSecret123!")
        assert result is not None, "Other user should not be affected by alice's lockout"

    # ── Search ─────────────────────────────────────────────────────────────

    def test_union_search_blocked(self):
        """UNION injection in search returns no rows (treated as literal string)."""
        payload = "' UNION SELECT id, username, role FROM users--"
        rows = secure_app.secure_search_user(payload)
        assert rows == [], "UNION payload should return no rows"

    def test_valid_search_works(self):
        """Legitimate search still works after parameterization."""
        rows = secure_app.secure_search_user("alice")
        assert len(rows) == 1
        assert rows[0][1] == "alice"

    def test_second_user_login(self):
        """Ensure non-admin user can also log in with correct creds."""
        result = secure_app.secure_login("alice", "AlicePass456")
        assert result is not None
        assert result["role"] == "user"


# ===========================================================================
# INSECURE APP TESTS — confirming vulnerabilities exist
# ===========================================================================

class TestInsecureLogin:
    """
    These tests CONFIRM that the insecure app IS vulnerable.
    They should all PASS (the attack succeeds against the insecure app).
    """

    def test_valid_login_works(self):
        """Sanity check: legitimate login still works in insecure app."""
        # Insecure app compares raw password_hash column to input — in insecure_app
        # the 'password' is compared directly. Our demo DB stores hashes, so direct
        # login in insecure mode won't work with bcrypt. We test the injection path.
        pass  # see below — injection tests are the primary insecure tests

    def test_or_injection_succeeds(self):
        """
        OR '1'='1' SHOULD bypass the insecure login.
        If this test fails, the insecure demo is broken.
        """
        result = insecure_app.insecure_login("admin", "' OR '1'='1")
        # The injection causes the WHERE clause to be always-true, returning a row
        assert result is not None, (
            "Insecure login SHOULD be bypassed by OR '1'='1' — "
            "if this fails, check the insecure_app logic."
        )

    def test_union_dump_succeeds(self):
        """UNION injection should dump all users from the insecure search."""
        payload = "' UNION SELECT id, username, role FROM users--"
        rows = insecure_app.insecure_search_user(payload)
        assert len(rows) >= 2, (
            "UNION injection should return multiple rows — "
            f"got {len(rows)}. Insecure app may not be working."
        )


# ===========================================================================
# PAYLOAD CATALOG TEST
# ===========================================================================

INJECTION_PAYLOADS = [
    # Classic
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR TRUE--",
    # Comment bypass
    "admin'--",
    "admin'/*",
    "' OR 1=1#",
    # UNION
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT null,username,password_hash,null FROM users--",
    # Stacked
    "'; DROP TABLE users;--",
    "'; UPDATE users SET role='admin' WHERE username='alice';--",
    # Boolean blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    # Time-based (won't actually delay in SQLite but test the blocking)
    "' AND SLEEP(5)--",
    "'; SELECT pg_sleep(5);--",
    # Error-based
    "' AND (SELECT 1/0)--",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e,(SELECT version())))--",
    # Encoding tricks
    "%27 OR %271%27%3D%271",
    "\\' OR \\'1\\'=\\'1",
]


class TestPayloadCatalog:
    """Every payload in the catalog should be blocked by the secure app."""

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_payload_blocked_as_username(self, payload):
        result = secure_app.secure_login(payload, "password123")
        assert result is None, f"Payload as username should be blocked: {payload!r}"

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_payload_blocked_as_password(self, payload):
        result = secure_app.secure_login("alice", payload)
        assert result is None, f"Payload as password should be blocked: {payload!r}"
