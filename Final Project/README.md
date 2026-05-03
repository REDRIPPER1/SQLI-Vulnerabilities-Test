# SQL Injection Lab 🔐

A hands-on Python lab demonstrating SQL injection attacks and their mitigations.

---

## Quick Start (recommended)

Run everything from the project root. These exact commands work in the included
virtual environment created for this workspace.

```bash
# (optional) create + activate a venv
python -m venv .venv
source .venv/bin/activate

# install dependencies
.venv/bin/python -m pip install -r requirements.txt

# seed the database (creates lab.db in the project root)
.venv/bin/python seed.py

# ensure the apps can find the DB (apps expect db/lab.db)
mkdir -p db
cp -f ./lab.db ./db/lab.db

# run the INSECURE demo (attacks should succeed)
.venv/bin/python insecure_app.py demo

# run the SECURE demo (same payloads should be blocked)
.venv/bin/python secure_app.py demo

# run the automated attack script (compares insecure vs secure)
.venv/bin/python attack.py

# run the full test suite (62 tests)
.venv/bin/python -m pytest tests/ -v
```

If you prefer to use the system Python directly, replace `.venv/bin/python` with
`python` (or the appropriate interpreter path).

---

## Project Layout

```
./
├── insecure_app.py        # intentionally vulnerable demo app
├── secure_app.py          # hardened app with parameterized queries + controls
├── attack.py              # automated attack vs defense demo (was demo_scripts/attack.py)
├── db_patterns.py        
├── db/
│   ├── schema.sql        # database schema used by tests and seed
│   └── lab.db            # copy or generated DB used by demos (can be recreated by seed.py)
├── seed.py               # populates lab.db with sample users
├── tests/
│   └── test_auth.py      # pytest suite (62 tests)
├── README.md
└── requirements.txt
```

Notes:
- `seed.py` lives at the project root and writes `lab.db` to the project root.
- The apps expect to find the DB at `db/lab.db`, so copy `lab.db` into `db/` as shown above.

---

## Running interactively

- Start interactive insecure demo:
    `.venv/bin/python insecure_app.py interactive`
- Start interactive secure demo:
    `.venv/bin/python secure_app.py interactive`

---

## Tests

Run the test suite with:

```bash
.venv/bin/python -m pytest tests/ -v
```

This repository currently contains 62 passing tests covering:
- valid login flows
- rejection of many SQL injection payload variants
- rate limiting and per-user lockouts
- demonstrating the insecure app is exploitable (so the lab is valid)

---

## Small housekeeping

- If you add `lab.db` to your repo, consider adding it to `.gitignore`.
- `attack.py` is an automated demo that creates a temporary DB for comparisons.

---

If you'd like, I can also commit these README changes for you.

---

## OWASP Mapping

| OWASP 2025 | Description | Addressed In |
|---|---|---|
| A05 – Injection | Core SQLi vulnerability | Both apps |
| A07 – Auth Failures | Login bypass via injection | `insecure_app.py` |
| A09 – Logging Failures | No logging in insecure app | `secure_app.py` |
| A02 – Misconfiguration | Overprivileged DB account | `secure_app.py` (notes) |
| A04 – Crypto Failures | Plaintext password storage | `seed.py` (bcrypt fallback noted)

---

## Further Reading

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10:2025 – A05 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP Web Security Testing Guide – SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [Python sqlite3 docs – Using placeholders](https://docs.python.org/3/library/sqlite3.html)
- [Real Python – Preventing SQL Injection in Python](https://realpython.com/prevent-python-sql-injection/)
- [Blind SQL Injection – OWASP](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [Palo Alto Networks – What Is an SQL Injection?](https://www.paloaltonetworks.com/cyberpedia/sql-injection)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP – Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)

