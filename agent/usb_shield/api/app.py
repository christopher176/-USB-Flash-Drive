"""FastAPI application factory for the USB Shield local agent.

Everything the agent knows lives under ``app.state`` so tests can construct
isolated instances.  Middleware order (outermost first):
    CORS (answers preflights) -> Origin allowlist -> security headers ->
    Host allowlist (DNS-rebinding guard) -> routing (token-authed).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .. import __version__
from ..config import RuntimeOptionsStore, Settings, get_settings
from ..drives import DeviceRegistry
from ..quarantine import Quarantine, QuarantineError
from ..scanner import ScanManager
from ..security import (ClientManager, HostCheckMiddleware,
                        OriginCheckMiddleware, RateLimiter,
                        SecurityHeadersMiddleware, TokenStore)
from ..store import Store
from . import routes_auth, routes_basic, routes_drives, routes_quarantine, \
    routes_reports, routes_scans


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    data_dir = cfg.data_path
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        data_dir.chmod(0o700)
    except OSError:
        pass

    store = Store(data_dir)
    tokens = TokenStore(data_dir)
    registry = DeviceRegistry(cfg)
    options = RuntimeOptionsStore(cfg)
    manager = ScanManager(cfg, store, registry, options.get)
    quarantine = Quarantine(data_dir, store, registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store.audit("agent.start", detail=f"usb-shield {__version__} "
                                          f"bind={cfg.bind_host}:{cfg.port}")
        store.execute_audit_cleanup()
        yield
        store.audit("agent.stop")
        store.close()

    app = FastAPI(title="USB Shield Agent", version=__version__,
                  docs_url=None, redoc_url=None, openapi_url=None,  # no debug surface
                  lifespan=lifespan)

    app.state.settings = cfg
    app.state.store = store
    app.state.tokens = tokens
    app.state.clients = ClientManager(store, tokens)
    app.state.registry = registry
    app.state.options_store = options
    app.state.scan_manager = manager
    app.state.quarantine = quarantine
    app.state.rate_limiter = RateLimiter()

    @app.exception_handler(QuarantineError)
    async def quarantine_errors(request: Request, exc: QuarantineError):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    prefix = "/api"
    app.include_router(routes_basic.router, prefix=prefix, tags=["basic"])
    app.include_router(routes_drives.router, prefix=prefix, tags=["devices"])
    app.include_router(routes_scans.router, prefix=prefix, tags=["scans"])
    app.include_router(routes_quarantine.router, prefix=prefix,
                       tags=["quarantine"])
    app.include_router(routes_reports.router, prefix=prefix, tags=["reports"])
    app.include_router(routes_auth.router, prefix=prefix, tags=["auth"])

    # middleware: added in innermost-first order
    app.add_middleware(HostCheckMiddleware, settings=cfg)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(OriginCheckMiddleware, settings=cfg)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.origins(),
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-USBShield-Client"],
        allow_credentials=False,
        max_age=600,
    )
    return app
