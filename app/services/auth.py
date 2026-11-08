from __future__ import annotations

import collections
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, IS_DEV_JWT_SECRET, JWT_ALGORITHM, JWT_SECRET_KEY
from app.services.storage import claim_legacy_data, create_user, get_user_by_email, get_user_by_id, user_count

# Safe password hashing with Argon2 via pwdlib when available, or PBKDF2-SHA256 fallback
_argon_hasher = None
try:
    from pwdlib import PasswordHash
    _argon_hasher = PasswordHash.recommended()
except Exception:
    _argon_hasher = None

# In-memory sliding-window rate limiter for brute-force protection
_login_failures: dict[str, list[float]] = collections.defaultdict(list)
_MAX_LOGIN_FAILURES = 10
_LOGIN_WINDOW_SECONDS = 300  # 5 minutes


def hash_password(password: str) -> str:
    """Hash password using Argon2 if available, or salted PBKDF2-SHA256."""
    if _argon_hasher is not None:
        try:
            return _argon_hasher.hash(password)
        except Exception:
            pass
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2:sha256:100000${salt}${derived.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify password against Argon2 or PBKDF2-SHA256 stored hash."""
    if not stored_hash or not plain_password:
        return False
    if stored_hash.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_hash.split("$")
            if len(parts) == 3:
                iterations = int(parts[0].split(":")[-1])
                salt = parts[1]
                expected_hex = parts[2]
                candidate = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), iterations)
                return hmac.compare_digest(candidate.hex(), expected_hex)
        except Exception:
            return False
    if _argon_hasher is not None:
        try:
            return _argon_hasher.verify(plain_password, stored_hash)
        except Exception:
            return False
    return False


def ensure_jwt_configured() -> None:
    """Verify that JWT secret is present. A secure random secret is guaranteed by config.py."""
    if len(JWT_SECRET_KEY) < 32:
        raise ValueError("JWT_SECRET_KEY must be set to a secure string of at least 32 characters in .env")


def public_user(row) -> dict:
    return {
        "id": row.id,
        "email": row.email,
        "full_name": row.full_name,
        "role": row.role,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "is_dev_secret": IS_DEV_JWT_SECRET,
    }


def register_account(email: str, password: str, full_name: str) -> dict:
    ensure_jwt_configured()
    normalized_email = email.lower().strip()
    if get_user_by_email(normalized_email):
        raise ValueError("An account with this email already exists.")
    # The first account registered receives the administrator role.
    is_first_user = user_count() == 0
    role = "admin" if is_first_user else "analyst"
    row = create_user(str(uuid4()), normalized_email, full_name, hash_password(password), role)
    if is_first_user:
        claim_legacy_data(row.id)
    return public_user(row)


def login_account(email: str, password: str, client_ip: str = "127.0.0.1") -> dict:
    ensure_jwt_configured()
    email = email.lower().strip()
    now_ts = time.time()
    # Check rate limit
    attempts = [t for t in _login_failures[client_ip] if now_ts - t < _LOGIN_WINDOW_SECONDS]
    _login_failures[client_ip] = attempts
    if len(attempts) >= _MAX_LOGIN_FAILURES:
        raise ValueError("Too many failed login attempts. Please wait 5 minutes before trying again.")

    row = get_user_by_email(email)
    if not row or not row.is_active or not verify_password(password, row.password_hash):
        _login_failures[client_ip].append(now_ts)
        raise ValueError("Invalid email or password.")

    # Success: clear failure counters
    _login_failures.pop(client_ip, None)

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": row.id, "role": row.role, "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)},
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": public_user(row),
    }


def resolve_token(token: str) -> dict | None:
    try:
        ensure_jwt_configured()
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = str(payload.get("sub", ""))
        row = get_user_by_id(user_id) if user_id else None
        if not row or not row.is_active:
            return None
        return public_user(row)
    except Exception:
        return None
