#!/usr/bin/env python3
"""
attack.py — automated comparison demo
-------------------------------------

Run a set of SQL injection payloads against the insecure example and then
against the secure example to compare results. Meant for local, offline
learning and experimentation.

Usage: `python attack.py`

The script prints a compact summary showing which attacks succeeded against
the insecure app and which were blocked by the secure app.
"""

import sys
import os
import sqlite3
import hashlib
import tempfile

# Setup and imports
# (this script creates a temporary test DB so it doesn't touch your demo DB)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import secure_app
import insecure_app

# Temporary test database setup
TEST_DB = tempfile.mktemp(suffix=".db")
secure_app.DB_PATH = TEST_DB
insecure_app.DB_PATH = TEST_DB
secure_app._attempt_tracker.clear()

SCHEMA = os.path.join(os.path.dirname(__file__), "db", "schema.sql")


def _hash(pw):
    """A simple deterministic hash used only for the test DB.

    The lab's seed uses a similar SHA-256 fallback; this mirrors that
    behavior so tests and demos are consistent.
    """
    return "sha256:" + hashlib.sha256(("sqli_lab_salt_" + pw).encode()).hexdigest()


def setup_test_db():
    """Create a fresh temporary database and populate it with two users."""
    conn = sqlite3.connect(TEST_DB)
    with open(SCHEMA) as f:
        conn.executescript(f.read())
    conn.execute(
        "INSERT INTO users VALUES (1, 'admin', ?, 'admin', 'admin@lab', CURRENT_TIMESTAMP)",
        (_hash("SuperSecret123!"),)
    )
    conn.execute(
        "INSERT INTO users VALUES (2, 'alice', ?, 'user', 'alice@lab', CURRENT_TIMESTAMP)",
        (_hash("AlicePass456"),)
    )
    conn.commit()
    conn.close()


# ── Result tracking ────────────────────────────────────────────────────────
results = {"insecure_exploited": 0, "secure_blocked": 0, "unexpected": 0}


def check(label: str, insecure_result, secure_result, expect_insecure_success: bool = True):
    """Print a single-line comparison for one payload.

    `expect_insecure_success` is True for attacks that should work against
    the insecure app (and be blocked by the secure app). The function
    updates a small `results` counter used to generate the final summary.
    """
    insecure_ok = (insecure_result is not None) == expect_insecure_success
    secure_ok = (secure_result is None)

    insecure_sym = "EXPLOITED" if insecure_ok else "MISSED"
    secure_sym = "BLOCKED" if secure_ok else "BYPASSED"

    print(f"  {label:<42}  insecure={insecure_sym}  secure={secure_sym}")

    if insecure_ok:
        results["insecure_exploited"] += 1
    else:
        results["unexpected"] += 1

    if secure_ok:
        results["secure_blocked"] += 1
    else:
        results["unexpected"] += 1


def run():
    setup_test_db()

    print(f"\n{'='*70}")
    print("  SQL Injection Lab — Automated Attack vs Defense Demo")
    print(f"{'='*70}\n")

    # ── Authentication bypass attacks ──────────────────────────────────────
    print("── Authentication Bypass Attacks ──────────────────────────────────")

    payloads_auth = [
        ("OR '1'='1'",              "' OR '1'='1"),
        ("OR 1=1 --",               "' OR 1=1--"),
        ("OR TRUE --",              "' OR TRUE--"),
        ("OR 'a'='a'",              "' OR 'a'='a"),
        ("password= x OR 1=1",      "x' OR '1'='1"),
    ]
    for label, payload in payloads_auth:
        ir = insecure_app.insecure_login("admin", payload)
        sr = secure_app.secure_login("admin", payload)
        check(label, ir, sr)

    # ── Comment-based bypass ───────────────────────────────────────────
    print(f"\n── Comment-Based Bypass Attacks ────────────────────────────────────")

    for label, user, pw in [
        ("admin'--  (comment)",          "admin'--",  "anything"),
        ("admin'/*  (block comment)",     "admin'/*",  "anything"),
        ("admin'# (MySQL hash comment)",  "admin'#",   "anything"),
    ]:
        ir = insecure_app.insecure_login(user, pw)
        sr = secure_app.secure_login(user, pw)
        check(label, ir, sr)

    # ── UNION injection ──────────────────────────────────────────────
    print(f"\n── UNION Data Dump Attacks ─────────────────────────────────────────")

    for label, payload in [
        ("UNION SELECT all users",  "' UNION SELECT id, username, role FROM users--"),
        ("UNION null columns",      "' UNION SELECT null,null,null--"),
    ]:
        try:
            ir = insecure_app.insecure_search_user(payload)
        except Exception as e:
            print(f"  [ERROR] insecure search raised: {e}")
            ir = None

        try:
            sr = secure_app.secure_search_user(payload)
        except Exception as e:
            print(f"  [ERROR] secure search raised: {e}")
            sr = None

        # For search, an exploit is when the insecure search returns rows;
        # the secure search should return no rows (an empty list). Normalize
        # values so the `check()` function can evaluate them consistently.
        ir_any = ir if ir else None
        sr_any = None if (not sr) else "rows_returned"
        check(label, ir_any, sr_any)

    # ── Stacked queries ───────────────────────────────────────────
    print(f"\n── Stacked Query Attacks ───────────────────────────────────────────")
    for label, user, pw in [
        ("DROP TABLE attempt",      "admin'; DROP TABLE users;--", "x"),
        ("UPDATE role attempt",     "alice'; UPDATE users SET role='admin';--", "x"),
    ]:
        # insecure_login uses execute() rather than executescript — many
        # DB drivers (including sqlite3) don't allow stacked statements in
        # a single execute call. Catch DB errors and treat them as a
        # non-exploitable outcome for the insecure app.
        try:
            ir = insecure_app.insecure_login(user, pw)
        except sqlite3.ProgrammingError as e:
            print(f"  [INFO] insecure login raised ProgrammingError: {e}")
            ir = None
        except sqlite3.OperationalError as e:
            print(f"  [INFO] insecure login raised OperationalError: {e}")
            ir = None

        try:
            sr = secure_app.secure_login(user, pw)
        except Exception as e:
            print(f"  [ERROR] secure login raised: {e}")
            sr = None

        check(label, ir, sr, expect_insecure_success=False)  # stacked usually fails in SQLite

    # ── Summary ────────────────────────────────────
    print(f"\n{'='*70}")
    print("  RESULTS SUMMARY")
    print(f"{'='*70}")
    total = results['insecure_exploited'] + results['secure_blocked'] + results['unexpected']
    print(f"  Insecure app exploited (confirmed vulnerable): {results['insecure_exploited']}")
    print(f"  Secure app payloads blocked:                  {results['secure_blocked']}")
    print(f"  Unexpected results:                           {results['unexpected']}")
    print(f"{'='*70}\n")

    # Cleanup
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


if __name__ == "__main__":
    run()
