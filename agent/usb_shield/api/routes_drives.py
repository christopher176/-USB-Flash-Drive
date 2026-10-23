"""Device listing, eject, and the development demo-device endpoint."""
from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from ..config import Settings
from ..demo import build_demo_device
from ..drives import eject_device
from ..security import require_csrf_header
from .deps import registry, require_token, settings, store

router = APIRouter()


@router.get("/drives", dependencies=[Depends(require_token)])
def list_drives(request: Request):
    reg = registry(request)
    devices = reg.list()
    return {"devices": [d.model_dump() for d in devices],
            "note": "Only removable/external volumes are listed. System drives "
                    "are excluded by design."}


@router.post("/devices/{device_id}/eject",
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def eject(device_id: str, request: Request):
    reg = registry(request)
    device = reg.get(device_id)
    if device is None:
        raise HTTPException(404, "device not found or already disconnected")
    result = eject_device(device)
    store(request).audit("device.eject", actor="user",
                         detail=f"{device.label}: {result['message']}")
    return result


# ------------------------------------------------------------------ demo (dev)
@router.post("/devices/demo", dependencies=[Depends(require_token),
                                            Depends(require_csrf_header)])
def create_demo(request: Request, cfg: Settings = Depends(settings)):
    """Development-only: materialise a synthetic demo 'USB drive' with benign
    test content (including the harmless EICAR test string)."""
    if not cfg.dev_demo:
        raise HTTPException(403, "demo endpoint disabled (set USBSHIELD_DEV_DEMO=true "
                                 "for development only)")
    root = Path(cfg.data_path) / "demo-device"
    stats = build_demo_device(root)
    # register the demo root for this process (persist via env in dev scripts)
    if str(root) not in cfg.extra_device_roots:
        cfg.extra_device_roots = f"{cfg.extra_device_roots},{root}".strip(",")
    store(request).audit("demo.device.create", actor="user",
                         detail=f"{root} {stats}")
    reg = registry(request)
    device = next((d for d in reg.list()
                   if Path(d.mount_point) == root), None)
    return {"created": True, "stats": stats,
            "device": device.model_dump() if device else None,
            "warning": "Synthetic test data only - not a real USB device."}


@router.delete("/devices/demo", dependencies=[Depends(require_token),
                                              Depends(require_csrf_header)])
def remove_demo(request: Request, cfg: Settings = Depends(settings)):
    if not cfg.dev_demo:
        raise HTTPException(403, "demo endpoint disabled")
    root = Path(cfg.data_path) / "demo-device"
    if root.exists():
        shutil.rmtree(root)
    store(request).audit("demo.device.remove", actor="user", detail=str(root))
    return {"removed": True}
