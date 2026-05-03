#!/usr/bin/env python3
"""
db_patterns.py — Secure vs Insecure Query Patterns (Multi-DB Reference)
========================================================================
This module is a REFERENCE ONLY — it shows the correct and incorrect
query patterns for SQLite, MySQL (mysql-connector), and PostgreSQL (psycopg2).

No live DB connections are made unless the environment provides one.
"""

# ===========================================================================
# SECTION 1: SQLite (sqlite3)
# ===========================================================================

SQLITE_INSECURE_EXAMPLES = """
import sqlite3

username = input("Username: ")
password = input("Password: ")
conn = sqlite3.connect("lab.db")
cur = conn.cursor()

# ❌ BAD — f-string interpolation
query = f"SELECT * FROM users WHERE username='{username}' AND password_hash='{password}'"
cur.execute(query)

# ❌ BAD — % formatting (same problem)
query2 = "SELECT * FROM users WHERE username='%s'" % username
cur.execute(query2)

# ❌ BAD — .format()
query3 = "SELECT * FROM users WHERE username='{}'".format(username)
cur.execute(query3)
"""

SQLITE_SECURE_EXAMPLES = """
import sqlite3

username = input("Username: ")
password = input("Password: ")
conn = sqlite3.connect("lab.db")
cur = conn.cursor()

# ✅ GOOD — positional placeholders (?)
cur.execute(
    "SELECT * FROM users WHERE username = ? AND password_hash = ?",
    (username, password)
)

# ✅ GOOD — named placeholders
cur.execute(
    "SELECT * FROM users WHERE username = :user",
    {"user": username}
)

row = cur.fetchone()
"""

# ===========================================================================
# SECTION 2: MySQL (mysql-connector-python / PyMySQL)
# ===========================================================================

MYSQL_INSECURE_EXAMPLES = """
import mysql.connector

conn = mysql.connector.connect(host="localhost", user="app", password="...", database="lab")
cur = conn.cursor()

username = input("Username: ")

# ❌ BAD — %s used as Python string formatting (NOT as DB placeholder)
query = "SELECT * FROM users WHERE username = '%s'" % username
cur.execute(query)

# ❌ BAD — f-string
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
"""

MYSQL_SECURE_EXAMPLES = """
import mysql.connector

conn = mysql.connector.connect(host="localhost", user="app_ro", password="...", database="lab")
cur = conn.cursor()

username = input("Username: ")

# ✅ GOOD — pass %s as a placeholder, data as a tuple (NOT Python % formatting)
cur.execute("SELECT id, username, role FROM users WHERE username = %s", (username,))

# ✅ GOOD — named placeholders with PyMySQL
# cur.execute("SELECT * FROM users WHERE username = %(user)s", {"user": username})

row = cur.fetchone()
"""

# ===========================================================================
# SECTION 3: PostgreSQL (psycopg2)
# ===========================================================================

PSYCOPG2_INSECURE_EXAMPLES = """
import psycopg2

conn = psycopg2.connect("dbname=lab user=app password=...")
cur = conn.cursor()

username = input("Username: ")

# ❌ BAD — direct string concat
query = "SELECT * FROM users WHERE username = '" + username + "'"
cur.execute(query)

# ❌ BAD — % mogrify NOT the same as DB params
cur.execute("SELECT * FROM users WHERE username = '%s'" % username)
"""

PSYCOPG2_SECURE_EXAMPLES = """
import psycopg2
from psycopg2 import sql as pgsql

conn = psycopg2.connect("dbname=lab user=app_readonly password=...")
cur = conn.cursor()

username = input("Username: ")

# ✅ GOOD — %s as psycopg2 placeholder (passed as tuple)
cur.execute("SELECT id, username, role FROM users WHERE username = %s", (username,))

# ✅ GOOD — named params
cur.execute("SELECT * FROM users WHERE username = %(user)s", {"user": username})

# ✅ GOOD — composing dynamic identifiers safely (e.g. table name)
table = "users"
cur.execute(
    pgsql.SQL("SELECT * FROM {} WHERE username = %s").format(pgsql.Identifier(table)),
    (username,)
)

row = cur.fetchone()
"""

# ===========================================================================
# SECTION 4: SQLAlchemy ORM
# ===========================================================================

ORM_INSECURE_EXAMPLES = """
from sqlalchemy.orm import Session
from sqlalchemy import text

# ❌ BAD — raw() / text() with string formatting
username = input("Username: ")
session.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))

# ❌ BAD — Django-style raw() misuse
# User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % username)
"""

ORM_SECURE_EXAMPLES = """
from sqlalchemy.orm import Session
from sqlalchemy import text, select
from models import User  # your ORM model

username = input("Username: ")

# ✅ GOOD — ORM filter API (auto-parameterized)
user = session.query(User).filter(User.username == username).first()

# ✅ GOOD — SQLAlchemy Core select()
stmt = select(User).where(User.username == username)
result = session.execute(stmt).scalar_one_or_none()

# ✅ GOOD — text() with bindparams (if raw SQL is truly needed)
stmt = text("SELECT * FROM users WHERE username = :user")
result = session.execute(stmt, {"user": username}).fetchone()

# ✅ GOOD — Django ORM
# user = User.objects.get(username=username)   # automatically parameterized
"""

# ===========================================================================
# Pretty printer
# ===========================================================================

def print_section(title: str, insecure: str, secure: str):
    width = 68
    print("=" * width)
    print(f"  {title}")
    print("=" * width)
    print("\n  ❌ INSECURE PATTERNS:")
    print(insecure)
    print("\n  ✅ SECURE PATTERNS:")
    print(secure)
    print()


if __name__ == "__main__":
    print_section("SQLite  (sqlite3)",          SQLITE_INSECURE_EXAMPLES,   SQLITE_SECURE_EXAMPLES)
    print_section("MySQL   (mysql-connector)",  MYSQL_INSECURE_EXAMPLES,    MYSQL_SECURE_EXAMPLES)
    print_section("PostgreSQL (psycopg2)",      PSYCOPG2_INSECURE_EXAMPLES, PSYCOPG2_SECURE_EXAMPLES)
    print_section("SQLAlchemy ORM",             ORM_INSECURE_EXAMPLES,      ORM_SECURE_EXAMPLES)
