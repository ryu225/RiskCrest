"""Secure, interactive creation of a privileged account.

Usage: python -m scripts.create_admin --username portal_admin
Avoid entering the administrator password as a command-line argument.
"""
from __future__ import annotations

import argparse
import getpass
import sqlite3
from pathlib import Path

from app.db import connect, initialize
from app.main import ROOT
from app.security import PASSWORD_HASHER, password_error, username_error


def create_admin(database: Path, username: str, password: str) -> None:
    """Admin provisioning is never exposed through the public registration form."""
    error = username_error(username) or password_error(password)
    if error:
        raise ValueError(error)
    initialize(database)
    with connect(database) as db:
        db.execute('''INSERT INTO users (username, password_hash, role)
                      VALUES (?, ?, 'admin')''', (username, PASSWORD_HASHER.hash(password)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a local administrator account')
    parser.add_argument('--username', required=True, help='3–30 alphanumeric/underscore characters')
    args = parser.parse_args()
    pw = getpass.getpass('Admin password: ')
    confirm = getpass.getpass('Confirm password: ')
    if pw != confirm:
        raise SystemExit('Passwords do not match.')
    database = Path(__import__('os').environ.get('SENTINEL_DATABASE', ROOT / 'instance' / 'secure.sqlite3'))
    try:
        create_admin(database, args.username, pw)
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise SystemExit(f'Administrator not created: {exc}')
    print(f'Administrator {args.username!r} created in {database}.')
