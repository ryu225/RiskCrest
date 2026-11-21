"""BEFORE state: intentional vulnerabilities, only for local controlled tests.

NEVER deploy this application, open its port externally, or use real passwords.
The deliberately unsafe SQL and rendering statements exist to demonstrate fixes.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.db import connect
from app.main import ROOT

TEMPLATES = Jinja2Templates(directory=str(ROOT / 'app' / 'templates'))


def md5(value: str) -> str:
    """Intentionally weak password storage, not appropriate for real users."""
    return hashlib.md5(value.encode('utf-8')).hexdigest()


def initialize_lab(database: Path):
    with connect(database) as db:
        db.executescript('''
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_md5 TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
          );
          CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          );
        ''')
        for name, password, role in [
            ('lab_user', 'LabPass1!', 'user'),
            ('lab_admin', 'LabAdmin1!', 'admin'),
        ]:
            db.execute('INSERT OR IGNORE INTO users (username, password_md5, role) VALUES (?, ?, ?)',
                       (name, md5(password), role))


def create_lab(*, database: Path | None = None) -> FastAPI:
    database = Path(database or ROOT / 'instance' / 'lab.sqlite3')
    initialize_lab(database)
    app = FastAPI(title='Sentinel Portal local vulnerability lab', docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32), https_only=False,
                       session_cookie='lab_session')
    app.mount('/static', StaticFiles(directory=ROOT / 'app' / 'static'), name='static')

    @app.middleware('http')
    async def local_only(request: Request, call_next):
        # Defense in depth: the runner *also* binds only to 127.0.0.1.
        if request.client and request.client.host not in ('127.0.0.1', '::1', 'testclient'):
            return PlainTextResponse('This training lab is accessible only from localhost.', status_code=403)
        return await call_next(request)

    def current_user(request: Request):
        account_id = request.session.get('user_id')
        if not account_id:
            return None
        with connect(database) as db:
            return db.execute("SELECT id, username, role, '2026-11-18' AS created_at FROM users WHERE id = ?", (account_id,)).fetchone()

    def page(request: Request, filename: str, *, status_code: int = 200, **data):
        return TEMPLATES.TemplateResponse(request, filename, {
            'request': request,
            'user': current_user(request),
            'csrf_token': '',  # The original app had no CSRF protection.
            'lab': True,
            **data,
        }, status_code=status_code)

    @app.get('/')
    def home(request: Request):
        return page(request, 'home.html', page_title='Before: vulnerable demo')

    @app.get('/register')
    def register_form(request: Request):
        return page(request, 'register.html', page_title='Create account', values={})

    @app.post('/register')
    async def register(request: Request):
        form = await request.form()
        username = str(form.get('username', ''))
        password = str(form.get('password', ''))
        # INTENTIONALLY VULNERABLE: string concatenation makes role injection possible.
        sql = ("INSERT INTO users (username, password_md5, role) "
               f"VALUES ('{username}', '{md5(password)}', 'user')")
        try:
            with connect(database) as db:
                db.execute(sql)
        except sqlite3.Error:
            return page(request, 'register.html', page_title='Create account',
                        error='Could not register the supplied username.', values={}, status_code=400)
        return RedirectResponse('/login?registered=1', status_code=303)

    @app.get('/login')
    def login_form(request: Request):
        return page(request, 'login.html', page_title='Sign in',
                    success='Account created.' if request.query_params.get('registered') else None)

    @app.post('/login')
    async def login(request: Request):
        form = await request.form()
        username = str(form.get('username', ''))
        password = str(form.get('password', ''))
        # INTENTIONALLY VULNERABLE: SQL injection can bypass password verification.
        sql = ("SELECT id, username, role FROM users "
               f"WHERE username = '{username}' AND password_md5 = '{md5(password)}'")
        try:
            with connect(database) as db:
                user = db.execute(sql).fetchone()
        except sqlite3.Error:
            user = None
        if not user:
            return page(request, 'login.html', page_title='Sign in',
                        error='Invalid username or password.', status_code=401)
        request.session['user_id'] = user['id']
        return RedirectResponse('/dashboard', status_code=303)

    @app.get('/dashboard')
    def dashboard(request: Request):
        user = current_user(request)
        if not user:
            return RedirectResponse('/login', status_code=303)
        with connect(database) as db:
            notes = db.execute('SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC', (user['id'],)).fetchall()
        # A username is displayed in the template; notes are intentionally marked safe.
        return page(request, 'dashboard.html', page_title='Dashboard', notes=notes, email=None)

    @app.post('/notes')
    async def add_note(request: Request):
        user = current_user(request)
        if not user:
            return RedirectResponse('/login', status_code=303)
        form = await request.form()
        with connect(database) as db:
            db.execute('INSERT INTO notes(user_id, content) VALUES (?, ?)',
                       (user['id'], str(form.get('content', ''))))
        return RedirectResponse('/dashboard#notes', status_code=303)

    @app.post('/profile')
    async def update_profile(request: Request):
        return RedirectResponse('/dashboard', status_code=303)

    @app.get('/admin')
    def admin(request: Request):
        user = current_user(request)
        if not user:
            return RedirectResponse('/login', status_code=303)
        # INTENTIONALLY VULNERABLE: only checks login; ignores user.role.
        with connect(database) as db:
            accounts = db.execute("SELECT username, role, '2026-11-18' AS created_at FROM users ORDER BY id").fetchall()
            note_count = db.execute('SELECT COUNT(*) AS total FROM notes').fetchone()['total']
        return page(request, 'admin.html', page_title='Administration',
                    accounts=accounts, note_count=note_count)

    @app.post('/logout')
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse('/login', status_code=303)

    return app
