# RiskCrest - Security Assessment Report

**Project:** Building a Secure Web Application - Detection and Mitigation of Security Vulnerabilities  
**Student:** Ryoouf Alsuwidany  
**Student ID:** 443201098  
**Assessment:** 15 points  
**Due date:** Saturday, 21 November 2026  
**Report date:** 21 November 2026

## Executive summary

RiskCrest is a Python/FastAPI web application providing user registration, login, account dashboards, personal notes, profile updates, administrator-only account listings, and logout. The project includes an isolated *before* application (`lab/main.py`) and a secured *after* application (`app/main.py`). Both share the user-interface templates for a fair, observable comparison but use **different databases**. The intentionally vulnerable version is restricted to a local demonstration environment. The final application enforces parameterized SQL queries, Argon2id password hashing and password policy, safe HTML rendering, role-based access control, encryption of sensitive data, and local HTTPS/TLS.

**Verification:** The original automated suite passed 37 tests on 18 November 2026; two additional session/browser-history regression checks were added and the updated suite passed **39 tests** on 21 November 2026 in a separate test environment. A live TLS server was also started locally and its HTTPS response/security headers were checked. This evidence supports functional correctness in the tested environment, rather than claiming that the application is secure against every possible attack.

## 1. Application design and functionality

The system has three access states: unauthenticated visitor, standard user, and administrator. Visitors can register and log in. After authentication, users see a private dashboard with username, role, account date, optional email, and personal notes. They can change their own email and add notes. An administrator can also open the account directory at `/admin`. Logout revokes the active server-side session and prevents future access to authenticated pages without another login.

**Code structure:** `app/main.py` contains secure HTTP handlers; `app/db.py` defines SQLite tables and transaction handling; `app/security.py` centralizes password hashing, sanitization, encryption, and CSRF checks; `app/templates/` contains Jinja2 UI; `lab/main.py` holds the intentionally vulnerable comparison; and `tests/` holds automated verification. Files inside `instance/` are local runtime data and excluded from repository commits.

**Database entities:** `users` (`id`, unique username, Argon2id `password_hash`, role, encrypted email, creation date); `auth_sessions` (SHA-256 token digest, user ID, creation/expiry times); and `notes` (note ID, owning user ID, sanitized body, creation date). Foreign keys protect ownership integrity.

## 2. Identified vulnerabilities and mitigations

### 2.1 SQL injection - login and registration (1 point)

**Before:** The lab concatenates the submitted username into SQL statements. In login, `lab_user' --` comments out the password condition and signs in with an incorrect password. In registration, the crafted username `injected_admin', 'injectedhash', 'admin') --` changes the inserted role from `user` to `admin`.

**After:** The secure app uses SQLite placeholder parameters (`?`) for all user-supplied values. The SQL command structure stays independent of the input. Registration also validates usernames and always assigns the `user` role. Secure login verifies the stored Argon2id hash separately from the SQL query. A login bypass attempt returns HTTP 401; the crafted registration username returns HTTP 400.

**Why this is effective:** The database driver treats values as data, not executable query syntax. Input validation is additional defense and is not a substitute for parameter binding.

### 2.2 Weak password storage (1 point)

**Before:** `lab/main.py` stores unsalted MD5 digests. MD5 is fast and unsuitable for password storage because it makes offline guessing inexpensive.

**After:** `app/security.py` uses Argon2id, a salted memory-hard password hashing algorithm. Configuration: 19 MiB memory (19,456 KiB), two iterations, one lane, 32-byte output and 16-byte salt. These values meet the OWASP Argon2id baseline noted in the references. The output begins with `$argon2id$`, and two users choosing the same password receive different hashes because of unique random salts. The application enforces at least 8 characters, uppercase, lowercase, digit, and special character. The registration page clearly displays this policy.

**Why hashing instead of encryption:** Password checking requires one-way verification, not recovery of a secret. Argon2id makes password guessing more expensive if the database is exposed.

### 2.3 Stored cross-site scripting (XSS) (1 point)

**Before:** Lab notes are stored raw and the shared dashboard deliberately renders lab notes using Jinja2's unsafe `|safe` filter. A test payload such as `<img src=x onerror=alert(1)>` appears in the document as actual HTML.

**After:** Secure note input is sanitized using Bleach with no permitted HTML tags. Jinja2 also applies HTML autoescaping to note display, and the secure template does not mark untrusted note content as safe. A restrictive Content-Security-Policy adds defense in depth. The test confirms that HTML tags and event handlers are absent from the secure output.

### 2.4 Missing role-based access control (2 points)

**Before:** Any logged-in lab user can browse `/admin`, even with the standard `user` role, revealing the account directory.

**After:** All authenticated routes validate the current server-side session. The `/admin` handler retrieves the role from the database and explicitly checks `role == 'admin'`; other logged-in users receive HTTP 403. Public registration assigns only `user`. A separate password-prompted local utility creates a privileged account, keeping privilege assignment out of untrusted HTTP registration input.

### 2.5 Sensitive-data encryption and HTTPS (2 points)

**Before:** The lab runs over HTTP and has no encryption for personal contact details. Its session approach does not encrypt session payloads.

**After - at rest:** Optional email addresses are encrypted using Fernet authenticated symmetric encryption before storage. Application decryption happens only when showing the owner's dashboard. Separate persistent Fernet keys are used for email and session tickets, with generated keys stored under ignored local `instance/keys/`.

**After - session protection:** The server creates a cryptographically random opaque authentication ticket. It puts **only its SHA-256 digest** in `auth_sessions`. The ticket is encrypted with Fernet before being sent in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie with a 30-minute expiration. Sessions are revoked on logout and rejected after expiry.

**After - in transit:** The secure runner serves HTTPS using TLS. Plain HTTP requests are redirected to HTTPS (308), HSTS is sent on HTTPS responses, and `Secure` cookies are configured for HTTPS transmission. A provided script generates a certificate for `localhost`/`127.0.0.1`; it is self-signed **only for local development**, so browsers correctly do not trust it by default. A production deployment would need a publicly trusted certificate and independently reviewed TLS configuration.

### 2.6 Additional security controls

**Cross-site request forgery (CSRF):** An HMAC-SHA-256 form signature is bound to a random HTTP-only CSRF cookie. Sensitive POST operations reject missing or invalid signatures with HTTP 403.

**Logout and back-navigation:** Logout deletes the server-side session digest and authentication cookie. Private routes return `Cache-Control: no-store, no-cache, max-age=0, must-revalidate`, `Pragma: no-cache` and `Expires: 0`. Thus navigating Back should require a fresh authenticated request instead of restoring a cached dashboard. Automated tests verify that the dashboard redirects to login after logout.

**Other headers and input constraints:** `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a restrictive Content-Security-Policy, and `Referrer-Policy: strict-origin-when-cross-origin`. Server-side validation limits usernames, email size, passwords and notes.

## 3. Security testing table

The *actual result* column below records verified observations from the local automated test suite; HTTP codes reflect the application under test. Before-state tests intentionally assert that the vulnerable behavior occurs; after-state tests assert that it is prevented.

| Test performed | Expected secure result | Actual result |
|---|---|---|
| Register, sign in and open dashboard | Account created; authorized dashboard available | PASS - HTTP 303 on registration/login, HTTP 200 dashboard |
| SQL injection in *lab* login | Vulnerability reproducible in before state | PASS - wrong-password bypass returned HTTP 303 |
| SQL injection in *secure* login | Injected username treated as data; login rejected | PASS - HTTP 401; dashboard redirects to login |
| SQL injection in *lab* registration | Vulnerability reproducible in before state | PASS - injected record stored with `admin` role |
| SQL injection in *secure* registration | Crafted role injection rejected; no admin created | PASS - HTTP 400; administrator count remains 0 |
| Inspect password hashes | Salted Argon2id, no MD5 or plaintext | PASS - `$argon2id$` hashes differ across users |
| Test six invalid password patterns | Weak passwords refused | PASS - all six returned HTTP 400 |
| Check password policy on registration page | Rules visible to the user | PASS - length, case, number, special character visible |
| Save XSS payload in *lab* note | Unsafe HTML demonstrable before mitigation | PASS - raw `<img ... onerror=...>` appears in HTML |
| Save XSS payload in *secure* note | HTML stripped, never rendered as active markup | PASS - dangerous tag/event handler absent in DB/output |
| Standard user requests secure `/admin` | Access denied | PASS - HTTP 403 |
| Administrator requests secure `/admin` | Access permitted | PASS - HTTP 200 |
| Access dashboard without login | Redirect to sign-in | PASS - HTTP 303 |
| One user requests another user's notes | Cannot see other account's notes | PASS - other user's note absent |
| Inspect email value in SQLite | Ciphertext rather than plaintext | PASS - Fernet token stored, valid email displayed after decryption |
| Inspect authentication cookie/session database | Encrypted cookie, HTTP-only/Secure/SameSite; digest in DB | PASS - flags present; 64-character SHA-256 digest in DB |
| Log out and revisit dashboard | Session revoked; private pages uncached and inaccessible | PASS - session deleted; dashboard HTTP 303; `no-store` header |
| Submit form without CSRF token | Request rejected | PASS - HTTP 403 |
| Request secure route via HTTP | HTTPS enforced | PASS - HTTP 308 redirect; HTTPS security headers present |
| Expired or tampered authentication ticket | Authorization denied | PASS - dashboard HTTP 303 |
| Generate local TLS certificate | Certificate contains localhost subject alternative name | PASS - certificate generated and verified |
| Lab request from a non-local client | Local-only lab refuses it | PASS - HTTP 403 |

**Test command:** `pytest -q`  
**Execution result:** **39 passed** (test environment; test count includes parameterized password cases).

## 4. Access-control matrix

| Resource / action | Visitor | Standard user | Administrator |
|---|:---:|:---:|:---:|
| View home, sign-in and registration pages | Yes | Yes | Yes |
| Create a new **standard** account | Yes | Yes | Yes |
| Sign in with valid account credentials | Yes | Yes | Yes |
| View own dashboard / profile | No | Yes | Yes |
| Add and read own notes | No | Yes | Yes |
| Update own email | No | Yes | Yes |
| View other members' private notes | No | No | No |
| View `/admin` account directory | No | No | Yes |
| Provision administrator through web registration | No | No | No |
| Log out of an active session | No active session | Yes | Yes |

Administrator provisioning is performed through the restricted local command `python -m scripts.create_admin --username portal_admin`, outside the public application interface.

## 5. Challenges and resolutions

**Challenge 1 - Demonstrate vulnerabilities without accidentally publishing them.** A single application with a configurable insecure mode risks running the wrong mode. The solution was two entrypoints, physically separate databases, loopback-only listeners, and an explicit lab warning banner. The vulnerable implementation is never imported by the secured runner.

**Challenge 2 - Avoid stale access after browser Back.** Clearing a cookie alone might leave private pages in browser cache. The final design deletes the server-side session digest, clears the cookie, and sends `no-store` response headers on private endpoints. Direct dashboard access after logout was verified to redirect to login.

**Challenge 3 - Preserve encrypted fields across restarts without exposing secrets.** Generating a different encryption key for every run would make existing emails unreadable; hard-coding a key would expose it. A key-initialization helper persists separate random keys under ignored local files, supports production environment overrides, and restricts permissions where the operating system permits.

**Challenge 4 - Show HTTPS without requiring a public domain.** Public certificate authorities cannot issue trusted certificates for an arbitrary local development setup. A local certificate utility creates a short-lived self-signed certificate with an appropriate subject alternative name. The report explicitly limits its trust to the local demo; actual deployment needs a trusted certificate.

**Challenge 5 - Verify the security comparison reproducibly.** The before and after applications behave differently and must not share session or database data. Integration tests create temporary databases and keys for each run, use separate test clients, and record observable HTTP statuses and database state.

## 6. Implementation walkthrough

1. **Registration:** `app/main.py::register` checks the CSRF token, validates username/password/email, hashes the password with `PASSWORD_HASHER.hash`, encrypts optional email, and inserts a user via bound SQL parameters with role `user`.
2. **Sign-in:** `app/main.py::login` retrieves a user through a parameterized lookup, uses `verify_password` to compare Argon2id hashes, and generates a random bearer ticket. It stores only the ticket digest in `auth_sessions`, then sets an encrypted authentication cookie.
3. **Private pages:** `current_user` decrypts the cookie ticket, derives its digest, checks expiration and database membership, and reads the current role. `require_login` guards the dashboard and admin routes.
4. **Notes and XSS:** `app/main.py::add_note` sanitizes input through `sanitize_note`, inserts it with owner ID, and the dashboard safely escapes the output.
5. **RBAC:** `app/main.py::admin` checks `user['role'] == 'admin'` on the server before querying user summaries.
6. **Encryption:** `app/security.py::Protection` manages independent email and session Fernet keys and the HMAC-based CSRF secret. No key is embedded in the repository.
7. **Logout:** `app/main.py::logout` deletes the matching session digest and cookie; private-page caching headers prevent stale dashboard restoration.

## 7. Evidence and screenshots

The repository contains rendered screenshots for the responsive home page, registration form, login form, dashboard, administrator view, and mobile layout in `docs/screenshots/`. In addition to visual evidence, `tests/test_secure.py` and `tests/test_lab.py` preserve the executable evidence for each principal vulnerability and corresponding fix.

## 8. Conclusion

The project satisfies the brief's required functionality and implements direct comparisons for the five security categories: SQL injection, password storage, stored XSS, authorization, and encryption/HTTPS. The completed local test suite reports **39 passing tests**, including checks for session revocation and CSRF handling. The vulnerable lab is intentionally unsafe and must remain isolated. The secured application illustrates sound baseline techniques but is a course demonstration, not a certificate of comprehensive production security.

## References

1. Project brief: *Building a Secure Web Application - Detection and Mitigation of Security Vulnerabilities*, provided assignment PDF.
2. FastAPI project documentation: https://fastapi.tiangolo.com/
3. OWASP, *SQL Injection Prevention Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
4. OWASP, *Password Storage Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
5. OWASP, *Cross-Site Scripting Prevention Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
6. Cryptography, *Fernet (symmetric encryption)*: https://cryptography.io/en/stable/fernet/
7. Argon2-cffi documentation: https://argon2-cffi.readthedocs.io/
