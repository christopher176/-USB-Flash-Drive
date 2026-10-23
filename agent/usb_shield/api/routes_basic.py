"""Health, pairing, info, config, engines, audit."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import APP_NAME, __version__
from ..config import RuntimeOptions, Settings
from ..engines.clamav import run_freshclam
from ..models import PairResponse, TokenExchangeRequest, TokenExchangeResponse
from ..security import RateLimiter, client_ip, ensure_loopback, \
    require_csrf_header
from .deps import (manager, options_store, rate_limiter, registry,
                   require_token, settings, store)

router = APIRouter()


@router.get("/health")
def health():
    # Unauthenticated by design: it reveals nothing beyond liveness.
    return {"status": "ok", "name": APP_NAME, "version": __version__}


@router.post("/pair", response_model=PairResponse,
             dependencies=[Depends(require_csrf_header)])
def pair(request: Request, rl: RateLimiter = Depends(rate_limiter),
         cfg: Settings = Depends(settings)):
    """Register a browser client and return its credential plus a first
    short-lived access token. Loopback-only and rate-limited.

    A malicious website cannot ride the user's browser through this endpoint:
    the custom header requirement forces a CORS preflight that the allowlist
    denies; additionally only local sockets may pair, and responses are not
    readable cross-origin.
    """
    ensure_loopback(request)
    ip = client_ip(request)
    if not rl.allow(f"pair:{ip}", cfg.rate_pair_per_minute, 60.0):
        store(request).audit("api.pair_rate_limited", ip=ip)
        raise HTTPException(429, "too many pairing attempts; slow down",
                            headers={"Retry-After": str(rl.retry_after(f"pair:{ip}", 60))})
    creds = request.app.state.clients.pair()
    store(request).audit("api.pair", ip=ip)
    return PairResponse(
        **creds,
        note="These credentials stay in this browser only. The access token "
             "is short-lived and refreshes automatically. Never send them to "
             "any remote server.")


@router.post("/token", response_model=TokenExchangeResponse,
             dependencies=[Depends(require_csrf_header)])
def exchange_token(req: TokenExchangeRequest, request: Request,
                   rl: RateLimiter = Depends(rate_limiter)):
    """Exchange a paired client credential for a fresh short-lived token."""
    ip = client_ip(request)
    if not rl.allow(f"token:{ip}", 30, 60.0):
        raise HTTPException(429, "too many token requests; slow down")
    result = request.app.state.clients.exchange(req.client_id, req.client_secret)
    if result is None:
        store(request).audit("api.token_exchange_failed", ip=ip)
        raise HTTPException(401, "invalid client credential")
    return TokenExchangeResponse(**result)


@router.get("/info", dependencies=[Depends(require_token)])
def info(request: Request, cfg: Settings = Depends(settings)):
    mgr = manager(request)
    clam = mgr.clamav
    engines = [
        {"name": "clamav", "available": clam.available(),
         "version": clam.version(), "detail": clam.status_detail(),
         "description": clam.description},
        {"name": "usb-shield-heuristics", "available": True,
         "version": "built-in", "detail": "",
         "description": "Structural heuristics (disguise/autorun/script abuse)"},
        {"name": "eicar-test-signature", "available": True,
         "version": "built-in", "detail": "",
         "description": "EICAR standard test-signature check"},
    ]
    opts = options_store(request).get()
    return {
        "name": APP_NAME,
        "version": __version__,
        "loopback_bind": cfg.is_loopback_bind(),
        "accounts_enabled": cfg.accounts_enabled,
        "dev_demo": cfg.dev_demo,
        "engines": engines,
        "capabilities": {
            "quarantine": True, "reports": ["json", "txt", "html"],
            "scan_modes": ["quick", "full", "custom"],
            "archive_formats": ["zip", "tar", "tar.gz", "tar.bz2", "tar.xz"],
            "clamav_signature_updates": clam.available(),
        },
        "options": opts.model_dump(),
    }


@router.get("/config", dependencies=[Depends(require_token)])
def get_config(request: Request):
    return options_store(request).get().model_dump()


@router.patch("/config", dependencies=[Depends(require_token),
                                       Depends(require_csrf_header)])
def patch_config(request: Request, patch: dict):
    store_ = options_store(request)
    try:
        updated = store_.update(patch)
    except Exception as exc:
        raise HTTPException(422, f"invalid configuration: {exc}")
    store(request).audit("config.update", actor="user", detail=str(patch)[:500])
    return updated.model_dump()


@router.get("/engines", dependencies=[Depends(require_token)])
def engines_status(request: Request):
    return info(request, settings(request))["engines"]


@router.post("/engines/clamav/update",
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def update_clamav(request: Request, rl: RateLimiter = Depends(rate_limiter)):
    ip = client_ip(request)
    if not rl.allow("freshclam", 2, 300.0):
        raise HTTPException(429, "signature update already ran recently; wait a few minutes")
    ok, output = run_freshclam()
    st = store(request)
    st.audit("engines.clamav.update", actor="user",
             detail=f"ok={ok}; tail={output[-500:]}", ip=ip)
    mgr = manager(request)
    mgr.clamav._last_probe = 0            # force re-probe after update
    if not ok:
        raise HTTPException(503, f"signature update failed: {output[-800:]}")
    return {"ok": True, "output_tail": output[-2000:],
            "engine_version": mgr.clamav.version()}


@router.get("/audit", dependencies=[Depends(require_token)])
def audit_log(request: Request, limit: int = 200):
    limit = min(max(1, limit), 1000)
    return {"events": store(request).audit_rows(limit)}
