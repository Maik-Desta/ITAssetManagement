"""Password hashing, TOTP multi-factor authentication and collector API keys (stdlib only)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    actual = hashlib.scrypt(password.encode(), salt=salt, dklen=len(expected), **_SCRYPT)
    return hmac.compare_digest(actual, expected)


# --- TOTP (RFC 6238) ------------------------------------------------------


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def totp_now(secret: str, at: float | None = None, step: int = 30) -> str:
    return _hotp(secret, int((at or time.time()) // step))


def verify_totp(secret: str, code: str, window: int = 1, step: int = 30) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    counter = int(time.time() // step)
    return any(hmac.compare_digest(_hotp(secret, counter + d), code) for d in range(-window, window + 1))


def totp_uri(secret: str, username: str, issuer: str = "ITAM") -> str:
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"


# --- Collector API keys ---------------------------------------------------


def new_api_key() -> tuple[str, str, str]:
    """Returns (plaintext key, prefix, sha256 hash). Only the hash is stored."""
    key = "itamc_" + secrets.token_urlsafe(32)
    return key, key[:12], hashlib.sha256(key.encode()).hexdigest()


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
