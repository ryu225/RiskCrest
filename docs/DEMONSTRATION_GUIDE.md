# RiskCrest - Short demonstration guide

## Recommended demonstration order (about 5 minutes)

1. **Secure workflow (60 seconds):** Run `python run_secure.py`. Open `https://127.0.0.1:5443`, register a normal account with a strong password, sign in, show profile and notes, and sign out. Try `/dashboard` again; it redirects to `/login`.
2. **SQL injection before/after (45 seconds):** Open the local lab on port 5001, enter `lab_user' --` as the username with any wrong password, and observe login succeeds. In the secure app, repeat it and show HTTP 401. In code compare `lab/main.py::login` with `app/main.py::login`, specifically raw SQL interpolation versus `?` placeholders.
3. **Password storage (30 seconds):** In `lab/main.py::md5` show the insecure MD5 code. In `app/security.py` show `PASSWORD_HASHER = PasswordHasher(... Type.ID)`. Point to the password-policy messages on the registration form and explain why Argon2id is memory-hard and salted.
4. **XSS before/after (45 seconds):** In the lab, sign in and save a note containing `<img src=x onerror=alert(1)>`; the browser treats this as markup. In the secure app the note content is sanitized. Compare the conditional rendering in `app/templates/dashboard.html` and `sanitize_note` in `app/security.py`.
5. **Role-based access (35 seconds):** In the lab, `lab_user` can open `/admin`. In the secure app a normal user gets 403; the role is checked in `app/main.py::admin`. Create a real secure admin with `python -m scripts.create_admin --username portal_admin`, then sign in to show authorized access.
6. **Encryption and HTTPS (40 seconds):** Show the secure URL begins with `https://`, `scripts/create_dev_cert.py`, the `Fernet` calls in `app/security.py`, the encrypted `email_encrypted` database column, and the protected authentication cookie in `app/main.py`. Explain that the generated self-signed certificate is for local development only.
7. **Automated tests (25 seconds):** Run `pytest -q` and show the passing summary. Use `tests/test_secure.py`, `tests/test_lab.py`, and the comparison in `README.md` to explain the implemented controls.

## Code locations to know

| Topic | Exact code location | Key idea |
|---|---|---|
| Secure registration | `app/main.py`, `register()` | Password policy, Argon2id hash, encrypted email, parameterized INSERT |
| Secure login | `app/main.py`, `login()` | Parameterized SELECT, verification, random session ticket |
| Authenticated routes | `app/main.py`, `current_user()` and `require_login()` | Fernet decrypt + digest lookup + expiry check |
| Administrator check | `app/main.py`, `admin()` | Server-side role enforcement |
| HTML sanitization | `app/security.py`, `sanitize_note()` | Strip HTML; Jinja2 escapes output |
| Logout | `app/main.py`, `logout()` | Session revocation and cookie deletion |
| Cookie and HTTPS headers | `app/main.py`, `security_headers()` | HSTS, CSP, no-store, other headers |
| Local vulnerable baseline | `lab/main.py` | SQLi, MD5, raw HTML, broken RBAC, HTTP-only |
| Access matrix | `README.md`, Vulnerability comparison | Visitor vs. user vs. administrator |

## Demonstration and submission checklist

- [ ] The secure app runs locally and opens with HTTPS.
- [ ] The vulnerable lab runs only on the local machine.
- [ ] Registration, login, dashboard, notes, admin access, and logout have been demonstrated.
- [ ] `pytest -q` passes.
- [ ] The assessment report is saved and submitted separately, as required by the course.
- [ ] `README.md` contains the setup and security-test instructions.
- [ ] Runtime keys, private databases, certificates, and personal passwords are not committed to GitHub.
- [ ] The actual GitHub repository URL is submitted as required.

**Reminder:** Do not run the intentionally vulnerable lab on a public-facing server or with real user data.
