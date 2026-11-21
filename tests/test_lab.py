"""BEFORE-state demonstration tests; do not run the lab on public networks."""
import hashlib
import sqlite3

from tests.conftest import form_post


def test_lab_login_password_bypass_via_sql_injection(lab_client):
    # Username closes the quoted string and comments out the password clause.
    response = form_post(lab_client, '/login', {
        'username': "lab_user' --", 'password': 'DefinitelyWrong',
    })
    assert response.status_code == 303
    assert lab_client.get('/dashboard').status_code == 200


def test_lab_registration_sql_injection_can_create_admin(lab_client, lab_db):
    crafted_username = "injected_admin', 'injectedhash', 'admin') --"
    response = form_post(lab_client, '/register', {
        'username': crafted_username, 'password': 'whatever', 'email': '',
    })
    assert response.status_code == 303
    with sqlite3.connect(lab_db) as db:
        role = db.execute("SELECT role FROM users WHERE username='injected_admin'").fetchone()[0]
    assert role == 'admin'


def test_lab_stores_weak_md5_hash(lab_client, lab_db):
    with sqlite3.connect(lab_db) as db:
        value = db.execute("SELECT password_md5 FROM users WHERE username='lab_user'").fetchone()[0]
    assert value == hashlib.md5(b'LabPass1!').hexdigest()
    assert len(value) == 32


def test_lab_xss_is_rendered_without_escaping(lab_client):
    form_post(lab_client, '/login', {'username': 'lab_user', 'password': 'LabPass1!'})
    payload = '<img src=x onerror=alert(1)>'
    result = form_post(lab_client, '/notes', {'content': payload})
    assert result.status_code == 303
    assert payload in lab_client.get('/dashboard').text


def test_lab_user_can_open_admin_page(lab_client):
    form_post(lab_client, '/login', {'username': 'lab_user', 'password': 'LabPass1!'})
    response = lab_client.get('/admin')
    assert response.status_code == 200
    assert 'lab_admin' in response.text


def test_lab_runs_without_https_or_encrypted_email(lab_client, lab_db):
    # This lab is deliberately HTTP-only and the users table has no encrypted email.
    response = lab_client.get('/login')
    assert response.status_code == 200
    assert 'strict-transport-security' not in response.headers
    with sqlite3.connect(lab_db) as db:
        columns = [c[1] for c in db.execute('PRAGMA table_info(users)').fetchall()]
    assert 'email_encrypted' not in columns


def test_lab_rejects_remote_clients(lab_db):
    from fastapi.testclient import TestClient
    from lab.main import create_lab
    with TestClient(create_lab(database=lab_db), base_url='http://testserver',
                    client=('203.0.113.5', 9999)) as client:
        result = client.get('/login')
    assert result.status_code == 403
