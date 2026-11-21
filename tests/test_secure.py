"""AFTER-state security regression tests mapped to the rubric."""
import re
import sqlite3
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.main import create_app
from scripts.create_admin import create_admin
from scripts.create_dev_cert import create_certificate
from tests.conftest import form_post, login, register


def sql(db_path, query, params=()):
    with sqlite3.connect(db_path) as db:
        return db.execute(query, params).fetchone()


def test_public_pages_render(secure_client):
    for route, phrase in [('/', 'Built for trust'), ('/register', 'Create an account'), ('/login', 'Sign in')]:
        result = secure_client.get(route)
        assert result.status_code == 200
        assert phrase in result.text


def test_register_and_dashboard_login(secure_client):
    assert register(secure_client).status_code == 303
    assert login(secure_client).status_code == 303
    result = secure_client.get('/dashboard')
    assert result.status_code == 200
    assert 'student_one' in result.text
    assert 'test@example.com' in result.text


@pytest.mark.parametrize('password', [
    'Short1!', 'alllowercase1!', 'ALLUPPERCASE1!', 'NoNumbers!', 'NoSpecial1', 'NoSpecial1 ',
])
def test_password_policy_rejects_invalid(secure_client, password):
    response = register(secure_client, username='passwordtester', password=password)
    assert response.status_code == 400
    assert 'alert-error' in response.text


def test_password_requirements_are_visible(secure_client):
    response = secure_client.get('/register')
    assert 'At least 8 characters' in response.text
    assert 'One uppercase and one lowercase letter' in response.text
    assert 'One number and one special character' in response.text


def test_argon2id_hash_is_unique_and_not_md5(secure_client, secure_db):
    assert register(secure_client, username='one_user').status_code == 303
    assert register(secure_client, username='two_user').status_code == 303
    hashes = [sql(secure_db, 'SELECT password_hash FROM users WHERE username=?', (u,))[0]
              for u in ('one_user', 'two_user')]
    assert all(value.startswith('$argon2id$') for value in hashes)
    assert hashes[0] != hashes[1]  # Random salts, even for same passwords.
    assert not any('ValidPass1!' in value or re.fullmatch('[a-f0-9]{32}', value) for value in hashes)


def test_sql_injection_cannot_bypass_login(secure_client):
    register(secure_client)
    injection = login(secure_client, username="' OR 1=1 --", password='fake')
    assert injection.status_code == 401
    assert secure_client.get('/dashboard', follow_redirects=False).status_code == 303


def test_sql_injection_registration_rejected(secure_client, secure_db):
    response = register(secure_client, username="evil', 'md5', 'admin') --")
    assert response.status_code == 400
    assert sql(secure_db, "SELECT COUNT(*) FROM users WHERE role='admin'")[0] == 0


def test_wrong_password_rejected(secure_client):
    register(secure_client)
    assert login(secure_client, password='WrongPass1!').status_code == 401


def test_duplicate_username_case_insensitive(secure_client):
    register(secure_client, username='Tester_1')
    response = register(secure_client, username='tester_1')
    assert response.status_code == 400
    assert 'already taken' in response.text


def test_registration_never_grants_admin(secure_client, secure_db):
    register(secure_client)
    assert sql(secure_db, 'SELECT role FROM users WHERE username=?', ('student_one',))[0] == 'user'


def test_private_routes_require_authentication(secure_client):
    for path in ('/dashboard', '/admin'):
        response = secure_client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers['location'].startswith('/login')


def test_user_blocked_from_admin(secure_client):
    register(secure_client)
    login(secure_client)
    response = secure_client.get('/admin')
    assert response.status_code == 403
    assert 'Only administrators' in response.text


def test_admin_can_access_admin_page(secure_client, secure_db):
    create_admin(secure_db, 'security_admin', 'AdminStrong8!')
    assert login(secure_client, 'security_admin', 'AdminStrong8!').status_code == 303
    response = secure_client.get('/admin')
    assert response.status_code == 200
    assert 'Registered members' in response.text


def test_notes_sanitized_before_storage_and_html_output(secure_client, secure_db):
    register(secure_client)
    login(secure_client)
    payload = '<img src=x onerror=alert(1)>hello<script>alert(2)</script>'
    response = form_post(secure_client, '/notes', {'content': payload})
    assert response.status_code == 303
    stored = sql(secure_db, 'SELECT content FROM notes LIMIT 1')[0]
    assert '<' not in stored and 'onerror=' not in stored
    dashboard = secure_client.get('/dashboard')
    assert '<script>' not in dashboard.text and '<img src=x' not in dashboard.text
    assert 'hello' in dashboard.text


def test_note_rejects_empty_post_sanitization(secure_client):
    register(secure_client)
    login(secure_client)
    response = form_post(secure_client, '/notes', {'content': '<b></b>'})
    assert response.status_code == 400


def test_notes_are_private_between_users(secure_client):
    register(secure_client, username='first_user')
    login(secure_client, 'first_user')
    form_post(secure_client, '/notes', {'content': 'Private to first_user'})
    form_post(secure_client, '/logout', {})
    register(secure_client, username='second_user')
    login(secure_client, 'second_user')
    assert 'Private to first_user' not in secure_client.get('/dashboard').text


def test_email_is_encrypted_in_database(secure_client, secure_db):
    register(secure_client, email='secret.person@example.com')
    value = sql(secure_db, 'SELECT email_encrypted FROM users LIMIT 1')[0]
    assert value != 'secret.person@example.com'
    assert 'secret.person@example.com' not in value
    assert value.startswith('gAAAA')  # Fernet encrypted token encoding.
    login(secure_client)
    assert 'secret.person@example.com' in secure_client.get('/dashboard').text


def test_profile_update_is_encrypted(secure_client, secure_db):
    register(secure_client)
    login(secure_client)
    response = form_post(secure_client, '/profile', {'email': 'updated@example.com'})
    assert response.status_code == 303
    assert 'updated@example.com' in secure_client.get('/dashboard').text
    assert 'updated@example.com' not in sql(secure_db, 'SELECT email_encrypted FROM users LIMIT 1')[0]


def test_auth_cookie_is_encrypted_and_protected(secure_client, secure_db):
    register(secure_client)
    result = login(secure_client)
    cookie = result.headers['set-cookie']
    assert 'httponly' in cookie.lower()
    assert 'secure' in cookie.lower()
    assert 'samesite=lax' in cookie.lower()
    assert 'max-age=1800' in cookie.lower()
    assert 'sg_auth=' in cookie
    assert 'student_one' not in cookie
    database_token = sql(secure_db, 'SELECT token_hash FROM auth_sessions LIMIT 1')[0]
    assert re.fullmatch('[a-f0-9]{64}', database_token)
    assert database_token not in cookie


def test_logout_revokes_server_session_and_disables_cache(secure_client, secure_db):
    register(secure_client)
    login(secure_client)
    private = secure_client.get('/dashboard')
    assert 'no-store' in private.headers['cache-control']
    assert private.headers['pragma'] == 'no-cache'
    assert form_post(secure_client, '/logout', {}).status_code == 303
    assert sql(secure_db, 'SELECT COUNT(*) FROM auth_sessions')[0] == 0
    assert secure_client.get('/dashboard', follow_redirects=False).status_code == 303


def test_csrf_requires_valid_token(secure_client):
    secure_client.get('/register')
    result = secure_client.post('/register', data={
        'username': 'csrfattack', 'password': 'ValidPass1!', 'email': 'x@example.com',
    })
    assert result.status_code == 403
    assert 'Form security check failed' in result.text


def test_http_redirect_to_https_and_security_headers(secure_db, tmp_path):
    app = create_app(database=secure_db, keys_dir=tmp_path / 'keys')
    with TestClient(app, base_url='http://testserver') as insecure_client:
        response = insecure_client.get('/login', follow_redirects=False)
        assert response.status_code == 308
        assert response.headers['location'] == 'https://testserver/login'
    with TestClient(app, base_url='https://testserver') as client:
        response = client.get('/login')
        assert response.headers['strict-transport-security'] == 'max-age=31536000'
        assert "script-src 'self'" in response.headers['content-security-policy']
        assert response.headers['x-frame-options'] == 'DENY'
        assert response.headers['x-content-type-options'] == 'nosniff'


def test_expired_session_is_rejected(secure_client, secure_db):
    register(secure_client)
    login(secure_client)
    with sqlite3.connect(secure_db) as db:
        db.execute('UPDATE auth_sessions SET expires_at = ?', (int(time.time()) - 1,))
    assert secure_client.get('/dashboard', follow_redirects=False).status_code == 303


def test_tampered_auth_cookie_is_rejected(secure_client):
    register(secure_client)
    login(secure_client)
    for cookie in secure_client.cookies.jar:
        if cookie.name == 'sg_auth':
            cookie.value = 'invalid-encrypted-auth-ticket'
    result = secure_client.get('/dashboard', follow_redirects=False)
    assert result.status_code == 303


def test_dev_tls_certificate_has_localhost_san(tmp_path):
    cert_file, key_file = create_certificate(tmp_path / 'certs')
    cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert 'localhost' in names.get_values_for_type(x509.DNSName)
    assert key_file.exists()
