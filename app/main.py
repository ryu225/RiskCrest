"""Secure web application: authentication, RBAC, encryption and safe rendering."""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import connect, initialize
from .security import (
    PASSWORD_HASHER, Protection, email_error, password_error,
    sanitize_note, token_digest, username_error, verify_password,
)

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(ROOT / 'app' / 'templates'))
SESSION_SECONDS = 1800


def create_app(*, database: Path | None = None, keys_dir: Path | None = None,
               require_https: bool = True, cookie_secure: bool = True) -> FastAPI:
    """Create independent app instances; optional paths make integration testing safe."""
    database = Path(database or os.getenv('SENTINEL_DATABASE', ROOT / 'instance' / 'secure.sqlite3'))
    keys_dir = Path(keys_dir or ROOT / 'instance' / 'keys')
    initialize(database)
    protection = Protection(keys_dir)
    app = FastAPI(title='RiskCrest', docs_url=None, redoc_url=None, openapi_url=None)
    app.mount('/static', StaticFiles(directory=ROOT / 'app' / 'static'), name='static')
    app.state.database = database
    app.state.protection = protection

    def current_user(request: Request):
        encrypted = request.cookies.get('sg_auth', '')
        raw = protection.recover_auth_token(encrypted) if encrypted else None
        if not raw:
            return None
        with connect(database) as db:
            return db.execute('''
                SELECT u.id, u.username, u.role, u.email_encrypted, u.created_at
                  FROM auth_sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ? AND s.expires_at > ?
            ''', (token_digest(raw), int(time.time()))).fetchone()

    def page(request: Request, filename: str, *, status_code: int = 200, **data):
        nonce = request.cookies.get('sg_csrf')
        generated = not nonce or len(nonce) > 128
        if generated:
            nonce = secrets.token_urlsafe(32)
        context = {
            'request': request,
            'csrf_token': protection.csrf_token(nonce),
            'user': current_user(request),
            'lab': False,
            **data,
        }
        response = TEMPLATES.TemplateResponse(request, filename, context, status_code=status_code)
        if generated:
            response.set_cookie('sg_csrf', nonce, max_age=SESSION_SECONDS,
                                secure=cookie_secure, httponly=True,
                                samesite='lax', path='/')
        return response

    async def require_csrf(request: Request) -> bool:
        form = await request.form()
        return protection.csrf_valid(request.cookies.get('sg_csrf'), str(form.get('_csrf', '')))

    def require_login(request: Request):
        user = current_user(request)
        if user is None:
            return None, RedirectResponse('/login?login_required=1', status_code=303)
        return user, None

    @app.middleware('http')
    async def security_headers(request: Request, call_next):
        # HTTPS is enforced *before* endpoints, including form submissions.
        if require_https and request.url.scheme != 'https':
            return RedirectResponse(str(request.url.replace(scheme='https')), status_code=308)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        if request.url.scheme == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if request.url.path.startswith(('/dashboard', '/admin', '/profile', '/notes', '/logout')):
            # A logged-out user must not see private pages via the Back button.
            response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response

    @app.get('/', response_class=HTMLResponse)
    def home(request: Request):
        return page(request, 'home.html', page_title='Welcome')

    @app.get('/register', response_class=HTMLResponse)
    def register_form(request: Request):
        return page(request, 'register.html', page_title='Create account', values={})

    @app.post('/register', response_class=HTMLResponse)
    async def register(request: Request):
        if not await require_csrf(request):
            return page(request, 'error.html', page_title='Invalid request',
                        message='Form security check failed. Refresh and try again.', status_code=403)
        form = await request.form()
        username = str(form.get('username', '')).strip()
        password = str(form.get('password', ''))
        email = str(form.get('email', '')).strip()
        error = username_error(username) or password_error(password) or email_error(email)
        if error:
            return page(request, 'register.html', page_title='Create account',
                        error=error, values={'username': username, 'email': email}, status_code=400)
        encrypted_email = protection.encrypt_data(email) if email else None
        try:
            with connect(database) as db:
                # Placeholder arguments prevent registration-time SQL injection.
                db.execute('''INSERT INTO users(username, password_hash, role, email_encrypted)
                              VALUES (?, ?, 'user', ?)''',
                           (username, PASSWORD_HASHER.hash(password), encrypted_email))
        except sqlite3.IntegrityError:
            return page(request, 'register.html', page_title='Create account',
                        error='That username is already taken.',
                        values={'username': username, 'email': email}, status_code=400)
        return RedirectResponse('/login?registered=1', status_code=303)

    @app.get('/login', response_class=HTMLResponse)
    def login_form(request: Request):
        return page(request, 'login.html', page_title='Sign in',
                    success='Account created. You can sign in.' if request.query_params.get('registered') else
                            'You have been signed out.' if request.query_params.get('logged_out') else None,
                    info='Sign in to continue.' if request.query_params.get('login_required') else None)

    @app.post('/login', response_class=HTMLResponse)
    async def login(request: Request):
        if not await require_csrf(request):
            return page(request, 'error.html', page_title='Invalid request',
                        message='Form security check failed. Refresh and try again.', status_code=403)
        form = await request.form()
        username = str(form.get('username', '')).strip()
        password = str(form.get('password', ''))
        # Neither field is ever interpolated into SQL.
        with connect(database) as db:
            account = db.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        if not account or not verify_password(account['password_hash'], password):
            return page(request, 'login.html', page_title='Sign in',
                        error='Invalid username or password.', values={'username': username}, status_code=401)
        raw_token = secrets.token_urlsafe(32)
        now = int(time.time())
        with connect(database) as db:
            db.execute('DELETE FROM auth_sessions WHERE expires_at <= ?', (now,))
            db.execute('''INSERT INTO auth_sessions(token_hash, user_id, created_at, expires_at)
                          VALUES (?, ?, ?, ?)''',
                       (token_digest(raw_token), account['id'], now, now + SESSION_SECONDS))
        response = RedirectResponse('/dashboard', status_code=303)
        # Authenticator: encrypted, HTTP-only, HTTPS-only cookie; DB stores only its digest.
        response.set_cookie('sg_auth', protection.make_auth_cookie(raw_token),
                            max_age=SESSION_SECONDS, secure=cookie_secure,
                            httponly=True, samesite='lax', path='/')
        return response

    @app.get('/dashboard', response_class=HTMLResponse)
    def dashboard(request: Request):
        user, rejection = require_login(request)
        if rejection:
            return rejection
        with connect(database) as db:
            notes = db.execute('''SELECT id, content, created_at FROM notes
                                   WHERE user_id = ? ORDER BY id DESC LIMIT 30''', (user['id'],)).fetchall()
        email = protection.decrypt_data(user['email_encrypted']) if user['email_encrypted'] else None
        return page(request, 'dashboard.html', page_title='Dashboard',
                    notes=notes, email=email, member_count=None)

    @app.post('/notes')
    async def add_note(request: Request):
        user, rejection = require_login(request)
        if rejection:
            return rejection
        if not await require_csrf(request):
            return page(request, 'error.html', page_title='Invalid request',
                        message='Form security check failed. Refresh and try again.', status_code=403)
        form = await request.form()
        original = str(form.get('content', ''))
        clean = sanitize_note(original)
        if not clean or len(clean) > 500:
            return page(request, 'error.html', page_title='Invalid note',
                        message='Notes must contain between 1 and 500 characters of text.', status_code=400)
        with connect(database) as db:
            db.execute('INSERT INTO notes(user_id, content) VALUES (?, ?)', (user['id'], clean))
        return RedirectResponse('/dashboard#notes', status_code=303)

    @app.post('/profile')
    async def update_profile(request: Request):
        user, rejection = require_login(request)
        if rejection:
            return rejection
        if not await require_csrf(request):
            return page(request, 'error.html', page_title='Invalid request',
                        message='Form security check failed. Refresh and try again.', status_code=403)
        form = await request.form()
        email = str(form.get('email', '')).strip()
        if email_error(email):
            return page(request, 'error.html', page_title='Invalid email',
                        message='Enter a valid email address.', status_code=400)
        encrypted = protection.encrypt_data(email) if email else None
        with connect(database) as db:
            db.execute('UPDATE users SET email_encrypted = ? WHERE id = ?', (encrypted, user['id']))
        return RedirectResponse('/dashboard?updated=1', status_code=303)

    @app.get('/admin', response_class=HTMLResponse)
    def admin(request: Request):
        user, rejection = require_login(request)
        if rejection:
            return rejection
        if user['role'] != 'admin':
            return page(request, 'error.html', page_title='Access denied',
                        message='Only administrators can view this page.', status_code=403)
        with connect(database) as db:
            accounts = db.execute('''SELECT username, role, created_at FROM users
                                     ORDER BY created_at DESC, id DESC''').fetchall()
            note_count = db.execute('SELECT COUNT(*) AS total FROM notes').fetchone()['total']
        return page(request, 'admin.html', page_title='Administration',
                    accounts=accounts, note_count=note_count)

    @app.post('/logout')
    async def logout(request: Request):
        if not await require_csrf(request):
            return page(request, 'error.html', page_title='Invalid request',
                        message='Form security check failed. Refresh and try again.', status_code=403)
        encrypted = request.cookies.get('sg_auth')
        raw = protection.recover_auth_token(encrypted) if encrypted else None
        if raw:
            with connect(database) as db:
                db.execute('DELETE FROM auth_sessions WHERE token_hash = ?', (token_digest(raw),))
        response = RedirectResponse('/login?logged_out=1', status_code=303)
        response.delete_cookie('sg_auth', path='/', secure=cookie_secure, httponly=True,
                               samesite='lax')
        return response

    return app
