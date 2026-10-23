"""Optional user accounts for multi-user deployments.

* Passwords are hashed with Argon2id (argon2-cffi; RFC 9106 parameters).
* Administrator accounts MUST enrol TOTP (RFC 6238, implemented with stdlib
  hmac) before a session is issued.
* Sessions are random 256-bit tokens, stored server-side with expiry;
  cookies are HttpOnly + SameSite=Strict (+Secure behind HTTPS).
* Login is rate-limited and behaves identically (timing + response) for
  unknown users.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError, VerifyMismatchError

from .config import Settings
from .store import Store

# RFC 9106 recommended baseline for Argon2id.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                         hash_len=32, salt_len=16)

_DUMMY_HASH = _hasher.hash("usb-shield-dummy-password-for-constant-time")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(phash: str, password: str) -> bool:
    try:
        return _hasher.verify(phash, password)
    except (VerifyMismatchError, VerificationError, Argon2Error):
        return False


def dummy_verify(password: str) -> None:
    try:
        _hasher.verify(_DUMMY_HASH, password)
    except Exception:
        pass


def needs_rehash(phash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(phash)
    except Exception:
        return False


# ------------------------------------------------------------------ TOTP
def totp_generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    pad = "=" * (-len(secret) % 8)
    return base64.b32decode(secret + pad, casefold=True)


def totp_code(secret: str, when: Optional[float] = None, step: int = 30,
              digits: int = 6) -> str:
    counter = int((when if when is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(_b32decode(secret), msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_verify(secret: str, code: str, window: int = 1,
                when: Optional[float] = None) -> bool:
    """±window steps of clock drift tolerated. Constant-time compare."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) in (6, 7, 8)):
        return False
    now = when if when is not None else time.time()
    for drift in range(-window, window + 1):
        expected = totp_code(secret, when=now + drift * 30)
        if hmac.compare_digest(expected, code):
            return True
    return False


def totp_uri(secret: str, username: str, issuer: str = "USB Shield") -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}&digits=6")


# ------------------------------------------------------------------ sessions
def new_session_token() -> str:
    return secrets.token_urlsafe(32)


class AccountService:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings

    def register(self, username: str, password: str) -> dict:
        count = self.store.user_count()
        role = "admin" if count == 0 else "viewer"
        if count > 0:
            from fastapi import HTTPException
            raise HTTPException(403, "registration is closed after the first "
                                     "administrator account; ask an admin to "
                                     "create additional accounts")
        self.store.create_user(username, hash_password(password), role)
        self.store.audit("auth.register", actor=username,
                         detail=f"role={role}")
        return {"username": username, "role": role}

    def login(self, username: str, password: str,
              totp: Optional[str]) -> dict:
        user = self.store.get_user(username)
        if not user or user.get("disabled"):
            dummy_verify(password)
            self.store.audit("auth.login_failed", actor=username)
            from fastapi import HTTPException
            raise HTTPException(401, "invalid credentials")
        if not verify_password(user["phash"], password):
            self.store.audit("auth.login_failed", actor=username)
            from fastapi import HTTPException
            raise HTTPException(401, "invalid credentials")
        if needs_rehash(user["phash"]):
            self.store.update_user_hash(username, hash_password(password))
        if user["role"] == "admin":
            if not user.get("totp_enabled"):
                # MFA is mandatory for administrators: force enrolment first.
                setup_token = new_session_token()
                self.store.kv_set(f"mfa_setup:{setup_token}", username)
                self.store.audit("auth.mfa_setup_required", actor=username)
                return {"mfa_setup_required": True, "setup_token": setup_token,
                        "session": None}
            if not totp or not totp_verify(user["totp_secret"] or "", totp):
                self.store.audit("auth.mfa_failed", actor=username)
                from fastapi import HTTPException
                raise HTTPException(401, "valid TOTP code required for "
                                         "administrator sign-in")
        token = new_session_token()
        self.store.create_session(token, username,
                                  self.settings.session_ttl_seconds,
                                  mfa_verified=True)
        self.store.audit("auth.login", actor=username)
        return {"session": token, "username": username, "role": user["role"],
                "mfa_setup_required": False}

    def mfa_enroll_begin(self, setup_token: str) -> dict:
        username = self.store.kv_get(f"mfa_setup:{setup_token}")
        if not username:
            from fastapi import HTTPException
            raise HTTPException(403, "invalid or expired MFA setup token")
        secret = totp_generate_secret()
        self.store.kv_set(f"mfa_secret:{setup_token}", secret)
        return {"secret": secret, "uri": totp_uri(secret, username),
                "username": username}

    def mfa_enroll_finish(self, setup_token: str, code: str) -> dict:
        username = self.store.kv_get(f"mfa_setup:{setup_token}")
        secret = self.store.kv_get(f"mfa_secret:{setup_token}")
        if not username or not secret:
            from fastapi import HTTPException
            raise HTTPException(403, "invalid or expired MFA setup token")
        if not totp_verify(secret, code):
            from fastapi import HTTPException
            raise HTTPException(400, "code does not match; try again")
        self.store.set_totp(username, secret, True)
        self.store.kv_set(f"mfa_setup:{setup_token}", "")
        self.store.kv_set(f"mfa_secret:{setup_token}", "")
        token = new_session_token()
        self.store.create_session(token, username,
                                  self.settings.session_ttl_seconds,
                                  mfa_verified=True)
        self.store.audit("auth.mfa_enrolled", actor=username)
        return {"session": token, "username": username}
