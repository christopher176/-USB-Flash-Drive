"""Agent API security: bearer tokens, pairing, rate limiting, middleware.

Browser-to-agent rules that keep malicious websites out of the local API:
  * every API route (except /api/health, /api/pair) requires a bearer token
  * /api/pair is loopback-only and rate-limited (a website cannot pair
    through your browser because pairing requires the response body, and
    CORS prevents cross-origin reading)
  * Origin headers must match the allowlist (server-side check)
  * mutating routes require the custom header ``X-USBShield-Client`` which
    cross-origin pages cannot set without a preflight (which CORS denies)
  * Host-header allowlist mitigates DNS rebinding
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from .config import Settings

CSRF_HEADER = "x-usbshield-client"
CSRF_VALUE = "usb-shield-web"


class TokenStore:
    """Agent bearer token persisted with strict permissions."""

    def __init__(self, data_dir: Path):
        self.path = data_dir / "agent_token"
        self.token = self._load()

    def _load(self) -> str:
        if self.path.exists():
            token = self.path.read_text(encoding="utf-8").strip()
            if len(token) >= 32:
                return token
        token = secrets.token_urlsafe(32)
        data_dir = self.path.parent
        data_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token + "\n")
        return token

    def verify(self, presented: str) -> bool:
        return bool(presented) and hmac.compare_digest(self.token, presented)


class ClientManager:
    """Short-lived access tokens for browser clients.

    Pairing (loopback-only) registers a *client credential* (id + secret,
    stored hashed on disk). The browser exchanges that credential for a
    short-lived access token; the long-lived root agent token never needs to
    leave ``~/.usb-shield`` for routine dashboard use. Access tokens live in
    memory only - they die with the process.

    The root token remains accepted for local admin/CLI use.
    """

    def __init__(self, store, root: TokenStore, ttl_seconds: int = 1200):
        import threading as _t
        self.store = store
        self.root = root
        self.ttl = ttl_seconds
        self._access: dict[str, float] = {}
        self._lock = _t.Lock()

    # ---- paired clients ------------------------------------------------
    def pair(self) -> dict:
        import json as _json
        client_id = secrets.token_hex(8)
        client_secret = secrets.token_urlsafe(32)
        self.store.kv_set(
            f"paired_client:{client_id}",
            _json.dumps({"secret_hash": self._hash_secret(client_secret),
                         "created_at": time.time()}))
        return {"client_id": client_id, "client_secret": client_secret,
                "access_token": self._mint(), "expires_in": self.ttl,
                "token_type": "bearer"}

    def exchange(self, client_id: str, client_secret: str) -> Optional[dict]:
        import json as _json
        raw = self.store.kv_get(f"paired_client:{client_id}")
        if not raw:
            return None
        try:
            rec = _json.loads(raw)
        except ValueError:
            return None
        if not hmac.compare_digest(rec.get("secret_hash", ""),
                                   self._hash_secret(client_secret)):
            return None
        return {"access_token": self._mint(), "expires_in": self.ttl,
                "token_type": "bearer"}

    # ---- tokens ---------------------------------------------------------
    @staticmethod
    def _hash_secret(secret: str) -> str:
        import hashlib
        return hashlib.sha256(secret.encode()).hexdigest()

    def _mint(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            if len(self._access) > 5000:
                now = time.time()
                for t, exp in [kv for kv in self._access.items() if kv[1] < now]:
                    self._access.pop(t, None)
            self._access[token] = time.time() + self.ttl
        return token

    def verify(self, presented: str) -> bool:
        if not presented:
            return False
        if self.root.verify(presented):
            return True
        with self._lock:
            exp = self._access.get(presented)
            if exp is None:
                return False
            if exp < time.time():
                self._access.pop(presented, None)
                return False
            return True


class RateLimiter:
    """In-memory sliding-window limiter (per key)."""

    def __init__(self):
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 5000:      # unbounded-map guard
                for dead in [k for k, v in self._hits.items()
                             if not v or v[-1] < cutoff]:
                    self._hits.pop(dead, None)
        return True

    def retry_after(self, key: str, window_seconds: float) -> int:
        with self._lock:
            q = self._hits.get(key)
            if not q:
                return 0
            return max(1, int(window_seconds - (time.monotonic() - q[0])))


# --------------------------------------------------------------- middleware
_LOOPBACKS = {"127.0.0.1", "::1", "localhost"}


class HostCheckMiddleware(BaseHTTPMiddleware):
    """DNS-rebinding mitigation: only serve expected Host headers."""

    def __init__(self, app, settings: Settings):
        super().__init__(app)
        hosts = {f"127.0.0.1:{settings.port}", f"localhost:{settings.port}",
                 "127.0.0.1", "localhost", f"[::1]:{settings.port}"}
        hosts.update(settings.extra_hosts())
        self._allowed = hosts

    async def dispatch(self, request: Request, call_next):
        host = (request.headers.get("host") or "").lower()
        if host and host not in self._allowed:
            return JSONResponse({"detail": "forbidden host header"}, status_code=403)
        return await call_next(request)


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Server-side Origin allowlist for browser-originated calls."""

    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self._allowed = set(settings.origins())

    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin")
        if origin is not None and origin not in self._allowed:
            if request.method != "OPTIONS":   # OPTIONS answered by CORS layer
                return JSONResponse({"detail": "origin not allowed"},
                                    status_code=403)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Permissions-Policy",
                                "camera=(), microphone=(), geolocation=()")
        if "content-security-policy" not in resp.headers:
            resp.headers["Content-Security-Policy"] = \
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        return resp


# --------------------------------------------------------------- dependencies
def require_csrf_header(request: Request) -> None:
    """Mutating routes must carry a header browsers can't forge cross-origin
    without a successful CORS preflight."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise HTTPException(403, "missing or invalid X-USBShield-Client header")


def ensure_loopback(request: Request) -> None:
    client = request.client.host if request.client else ""
    if client not in _LOOPBACKS:
        raise HTTPException(403, "pairing is restricted to the local machine")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
