"""Shared FastAPI dependencies: token auth + app state accessors."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from ..config import RuntimeOptionsStore, Settings
from ..drives import DeviceRegistry
from ..quarantine import Quarantine
from ..scanner import ScanManager
from ..security import RateLimiter, TokenStore, client_ip
from ..store import Store


def settings(request: Request) -> Settings:
    return request.app.state.settings


def store(request: Request) -> Store:
    return request.app.state.store


def registry(request: Request) -> DeviceRegistry:
    return request.app.state.registry


def manager(request: Request) -> ScanManager:
    return request.app.state.scan_manager


def quarantine(request: Request) -> Quarantine:
    return request.app.state.quarantine


def options_store(request: Request) -> RuntimeOptionsStore:
    return request.app.state.options_store


def rate_limiter(request: Request) -> RateLimiter:
    return request.app.state.rate_limiter


def require_token(request: Request) -> str:
    clients = request.app.state.clients  # ClientManager (root + short-lived)
    auth = request.headers.get("authorization", "")
    scheme, _, presented = auth.partition(" ")
    if scheme.lower() != "bearer" or not clients.verify(presented.strip()):
        request.app.state.store.audit(
            "api.unauthorized", detail=f"{request.method} {request.url.path}",
            ip=client_ip(request))
        raise HTTPException(401, "a valid bearer token is required",
                            headers={"WWW-Authenticate": "Bearer"})
    return presented.strip()
