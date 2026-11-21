"""Isolated temporary databases: tests never modify real accounts."""
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from app.main import create_app
from lab.main import create_lab


@pytest.fixture
def secure_db(tmp_path):
    return tmp_path / 'secure.sqlite3'


@pytest.fixture
def secure_client(secure_db, tmp_path):
    app = create_app(database=secure_db, keys_dir=tmp_path / 'keys')
    with TestClient(app, base_url='https://testserver') as client:
        yield client


@pytest.fixture
def lab_db(tmp_path):
    return tmp_path / 'lab.sqlite3'


@pytest.fixture
def lab_client(lab_db):
    app = create_lab(database=lab_db)
    with TestClient(app, base_url='http://testserver') as client:
        yield client


def form_post(client, endpoint: str, data: dict, csrf_page: str | None = None):
    """Get a form first so the secure app can issue its CSRF nonce."""
    form_url = csrf_page or (endpoint if endpoint in ('/register', '/login') else '/dashboard')
    html = client.get(form_url).text
    hidden = BeautifulSoup(html, 'html.parser').select_one('input[name="_csrf"]')
    payload = {'_csrf': hidden.get('value', '') if hidden else '', **data}
    return client.post(endpoint, data=payload, follow_redirects=False)


def register(client, username='student_one', password='ValidPass1!', email='test@example.com'):
    return form_post(client, '/register', {'username': username, 'password': password, 'email': email})


def login(client, username='student_one', password='ValidPass1!'):
    return form_post(client, '/login', {'username': username, 'password': password})
