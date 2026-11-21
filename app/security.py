"""Security primitives shared by authentication, data protection and forms."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

import bleach
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

# Argon2id is a modern, memory-hard alternative to bcrypt. The encoded hash
# stores its own random salt and work parameters, never the original password.
PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1,
                                 hash_len=32, salt_len=16, type=Type.ID)
USER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,29}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def password_error(value: str) -> str | None:
    if len(value) < 8:
        return "Use at least 8 characters."
    if not re.search(r"[A-Z]", value):
        return "Include an uppercase letter."
    if not re.search(r"[a-z]", value):
        return "Include a lowercase letter."
    if not re.search(r"[0-9]", value):
        return "Include a number."
    if not any(not char.isalnum() and not char.isspace() for char in value):
        return "Include a special character."
    if len(value) > 256:
        return "Password must be 256 characters or fewer."
    return None


def username_error(value: str) -> str | None:
    if not USER_RE.fullmatch(value):
        return "Use 3–30 characters: start with a letter, then letters, numbers or underscores."
    return None


def email_error(value: str) -> str | None:
    if value and (len(value) > 254 or not EMAIL_RE.fullmatch(value)):
        return "Enter a valid email address, or leave this field blank."
    return None


def sanitize_note(value: str) -> str:
    """Strip all HTML markup; templates also HTML-escape before output."""
    return bleach.clean(value.strip(), tags=[], attributes={}, strip=True)


def token_digest(raw_token: str) -> str:
    """Database sessions store a SHA-256 digest, not a reusable bearer token."""
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def verify_password(stored_hash: str, supplied: str) -> bool:
    try:
        return bool(PASSWORD_HASHER.verify(stored_hash, supplied))
    except (VerificationError, InvalidHashError, ValueError, TypeError):
        return False


def get_secret(keys_dir: Path, filename: str, env_name: str,
               *, fernet: bool) -> bytes:
    """Reuse a stable private key across restarts; support environment overrides."""
    supplied = os.environ.get(env_name)
    if supplied:
        material = supplied.encode('utf-8')
    else:
        keys_dir.mkdir(parents=True, exist_ok=True)
        location = keys_dir / filename
        if location.exists():
            material = location.read_bytes().strip()
        else:
            material = Fernet.generate_key() if fernet else secrets.token_urlsafe(32).encode('ascii')
            # x (exclusive creation) avoids overwriting keys on concurrent start.
            try:
                with location.open('xb') as out:
                    out.write(material)
                try:
                    location.chmod(0o600)
                except OSError:
                    pass  # Windows does not implement POSIX permissions in the same way.
            except FileExistsError:
                material = location.read_bytes().strip()
    if fernet:
        Fernet(material)  # Validate early rather than failing on first request.
    elif len(material) < 32:
        raise ValueError(f"{env_name} must contain at least 32 bytes")
    return material


class Protection:
    def __init__(self, keys_dir: Path):
        self.data = Fernet(get_secret(keys_dir, 'data.key', 'SENTINEL_DATA_KEY', fernet=True))
        self.session = Fernet(get_secret(keys_dir, 'session.key', 'SENTINEL_SESSION_KEY', fernet=True))
        self.csrf_secret = get_secret(keys_dir, 'csrf.key', 'SENTINEL_CSRF_SECRET', fernet=False)

    def csrf_token(self, nonce: str) -> str:
        return hmac.new(self.csrf_secret, nonce.encode('utf-8'), 'sha256').hexdigest()

    def csrf_valid(self, nonce: str | None, submitted: str | None) -> bool:
        if not nonce or not submitted or len(nonce) > 256 or len(submitted) > 256:
            return False
        return hmac.compare_digest(self.csrf_token(nonce), submitted)

    def encrypt_data(self, value: str) -> str:
        return self.data.encrypt(value.encode('utf-8')).decode('ascii')

    def decrypt_data(self, value: str) -> str:
        try:
            return self.data.decrypt(value.encode('ascii')).decode('utf-8')
        except (InvalidToken, ValueError):
            return '[Unavailable: encryption key mismatch]'

    def make_auth_cookie(self, raw_token: str) -> str:
        return self.session.encrypt(raw_token.encode('ascii')).decode('ascii')

    def recover_auth_token(self, encrypted_cookie: str) -> str | None:
        try:
            return self.session.decrypt(encrypted_cookie.encode('ascii'), ttl=1800).decode('ascii')
        except (InvalidToken, ValueError, UnicodeError):
            return None
