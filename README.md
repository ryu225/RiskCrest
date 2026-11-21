# RiskCrest

**A secure account-management web application with an isolated, intentionally vulnerable demonstration lab.**

RiskCrest is a local cybersecurity project built with Python, FastAPI, Jinja2, and SQLite. It pairs a secure application with a separate vulnerable baseline, allowing the same security concepts to be demonstrated before and after mitigation.

The application includes account registration, sign-in, a private dashboard, notes, optional encrypted contact details, administrator access, and session-aware sign-out.

## Applications

| Application | Local address | Purpose |
| --- | --- | --- |
| Secure application (`app/`) | `https://127.0.0.1:5443` | Account management with security controls |
| Vulnerable lab (`lab/`) | `http://127.0.0.1:5001` | Controlled demonstrations of common vulnerabilities |

**Safety:** Both servers bind to `127.0.0.1`. Never expose the vulnerable lab to the public internet, deploy it to a shared environment, or use real credentials in it.

## Features and security controls

- **Authentication:** Username/password sign-in with Argon2id password hashes, password policy, encrypted session tickets, server-side session records, and logout revocation.
- **Private accounts:** Personal dashboard, optional encrypted email address, and individually owned notes.
- **Authorization:** Server-enforced role-based access control (RBAC). Administrators are created through a local command; public registration cannot grant administrator privileges.
- **Input handling:** Parameterized SQL queries, input validation, sanitized note content, and HTML escaping.
- **Transport and session protections:** Local HTTPS/TLS, secure cookie flags, CSRF protection, security headers, expiration, and private-page cache controls.
- **Learning comparison:** Isolated SQL injection, weak hashing, XSS, broken access-control, and plaintext/HTTP examples in the intentionally vulnerable lab.

## Run the secure application

Requirements: Python 3.11 or later, pip, and a web browser. Run commands from the repository root.

**Windows PowerShell:**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts/create_dev_cert.py
python run_secure.py
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/create_dev_cert.py
python run_secure.py
```

Open **https://127.0.0.1:5443** to register and sign in.

The generated development certificate is self-signed, so the browser may display a certificate warning. This certificate is **only for local development** and is not a replacement for a publicly trusted production certificate.

### Create an administrator

With the virtual environment active, run:

```bash
python -m scripts.create_admin --username portal_admin
```

Enter the password securely when prompted. Ordinary registration always creates a standard user.

### Run the local vulnerability lab

In a separate terminal:

```bash
python run_lab.py
```

Open **http://127.0.0.1:5001**. The fictional demonstration credentials defined by the lab are:

| Username | Password | Role |
| --- | --- | --- |
| `lab_user` | `LabPass1!` | Standard user |
| `lab_admin` | `LabAdmin1!` | Administrator |

Use these only in the local vulnerable lab; they are not suitable for actual accounts.

## Vulnerability comparison

| Topic | Intentionally vulnerable lab | Secure application |
| --- | --- | --- |
| SQL injection | Unsafe SQL string interpolation | Parameterized queries and input validation |
| Password storage | MD5 hashes | Salted Argon2id hashes |
| Stored XSS | Unsafe rendering of note content | Sanitization and Jinja2 escaping |
| Access control | Missing role enforcement on the admin page | Server-side role checks |
| Personal data / transport | Plain HTTP and no email encryption | Local HTTPS and Fernet encryption |

For reproducible demonstration steps and code locations, see [the demonstration guide](docs/DEMONSTRATION_GUIDE.md).

## Automated tests

With dependencies installed, run:

```powershell
python -m pytest -q
```

Tests use isolated temporary databases and keys, rather than modifying your personal account data. The suite covers secure routes, the vulnerable lab, and regression scenarios including CSRF, encrypted storage, role restrictions, XSS mitigation, and session revocation.

**Verification:** The original local checkout reported **37 passing tests**. The GitHub version has two additional regression tests; run the command above after pulling to confirm the updated count in your own environment.

## Project structure

```text
RiskCrest/
├── app/
│   ├── main.py              # Secure FastAPI application
│   ├── db.py                # SQLite persistence
│   ├── security.py          # Password hashing, encryption, CSRF, sanitization
│   ├── templates/           # Pages for home, auth, dashboard and admin
│   └── static/              # Original RiskCrest SVGs, CSS and JavaScript
├── lab/
│   └── main.py              # Deliberately vulnerable local baseline
├── scripts/
│   ├── create_admin.py      # Local administrator creation
│   └── create_dev_cert.py   # Self-signed development TLS certificate
├── tests/                   # Automated security regression tests
├── docs/
│   └── DEMONSTRATION_GUIDE.md
├── instance/                # Runtime data; ignored by Git except .gitkeep
├── run_secure.py
├── run_lab.py
├── requirements.txt
└── README.md
```

## Local data and privacy

Local databases, encryption keys, certificates, virtual environments, and environment secrets are excluded through `.gitignore`. **Do not delete local `instance/keys/` files while encrypted data must remain readable.**

The project report is submitted separately. Actual browser screenshots of both apps, captured from synthetic demo accounts, are available in [docs/screenshots/](docs/screenshots/). The repository's Git history may still contain earlier documentation; deleting a file in a new commit does not erase it from past commits.

RiskCrest is an educational implementation, **not an audited production service**. Production deployment would require stronger operational controls, trusted TLS, secret-management and key-rotation procedures, monitoring, rate limiting, and a formal security review.

## Technical references

- [FastAPI documentation](https://fastapi.tiangolo.com/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cross-Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Argon2-cffi](https://argon2-cffi.readthedocs.io/)
- [Cryptography Fernet](https://cryptography.io/en/stable/fernet/)
