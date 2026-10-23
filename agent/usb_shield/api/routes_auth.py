"""Optional user accounts (Argon2id + TOTP MFA). Disabled unless
USBSHIELD_ACCOUNTS_ENABLED=true. Sessions ride in hardened cookies and are
separate from the agent bearer token."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ..auth import AccountService, new_session_token
from ..config import Settings
from ..models import LoginRequest, RegisterRequest, TotpVerifyRequest
from ..security import client_ip, require_csrf_header
from .deps import rate_limiter, require_token, settings, store

router = APIRouter()


def _enabled(cfg: Settings) -> None:
    if not cfg.accounts_enabled:
        raise HTTPException(404, "accounts are disabled on this agent")


def _set_session_cookie(resp: Response, token: str, cfg: Settings) -> None:
    resp.set_cookie("usbshield_session", token, max_age=cfg.session_ttl_seconds,
                    httponly=True, secure=cfg.session_secure,
                    samesite="strict", path="/api/auth")


def _session_user(request: Request) -> dict:
    token = request.cookies.get("usbshield_session", "")
    sess = store(request).get_session(token) if token else None
    if not sess:
        raise HTTPException(401, "not signed in")
    return sess


@router.post("/auth/register", dependencies=[Depends(require_csrf_header)])
def register(req: RegisterRequest, request: Request,
             cfg: Settings = Depends(settings)):
    _enabled(cfg)
    svc = AccountService(store(request), cfg)
    try:
        return svc.register(req.username, req.password)
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(409, "username already exists")
        raise


@router.post("/auth/login", dependencies=[Depends(require_csrf_header)])
def login(req: LoginRequest, request: Request, response: Response,
          cfg: Settings = Depends(settings)):
    _enabled(cfg)
    ip = client_ip(request)
    rl = rate_limiter(request)
    if not rl.allow(f"login:{ip}", cfg.rate_login_per_minute, 60.0):
        store(request).audit("auth.login_rate_limited", ip=ip)
        raise HTTPException(429, "too many login attempts; try again later")
    svc = AccountService(store(request), cfg)
    result = svc.login(req.username, req.password, req.totp_code)
    if result.get("session"):
        _set_session_cookie(response, result["session"], cfg)
        result.pop("session")
        result["signed_in"] = True
    return result


@router.post("/auth/mfa/enroll/begin", dependencies=[Depends(require_csrf_header)])
def mfa_begin(setup_token: dict, request: Request,
              cfg: Settings = Depends(settings)):
    _enabled(cfg)
    token = setup_token.get("setup_token", "")
    svc = AccountService(store(request), cfg)
    return svc.mfa_enroll_begin(token)


@router.post("/auth/mfa/enroll/finish", dependencies=[Depends(require_csrf_header)])
def mfa_finish(req: dict, request: Request, response: Response,
               cfg: Settings = Depends(settings)):
    _enabled(cfg)
    svc = AccountService(store(request), cfg)
    result = svc.mfa_enroll_finish(req.get("setup_token", ""),
                                   req.get("code", ""))
    _set_session_cookie(response, result["session"], cfg)
    return {"signed_in": True, "username": result["username"],
            "mfa_enrolled": True}


@router.get("/auth/me")
def me(request: Request, cfg: Settings = Depends(settings)):
    _enabled(cfg)
    sess = _session_user(request)
    public = store(request).user_public(sess["username"])
    return {"user": public.model_dump() if public else None,
            "session_expires_at": sess["expires_at"]}


@router.post("/auth/logout", dependencies=[Depends(require_csrf_header)])
def logout(request: Request, response: Response,
           cfg: Settings = Depends(settings)):
    _enabled(cfg)
    token = request.cookies.get("usbshield_session", "")
    if token:
        store(request).delete_session(token)
        store(request).audit("auth.logout", ip=client_ip(request))
    response.delete_cookie("usbshield_session", path="/api/auth")
    return {"signed_out": True}
