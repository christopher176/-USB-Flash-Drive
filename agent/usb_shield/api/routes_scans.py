"""Scan lifecycle: start, status, live events, cancel, findings, file delete."""
from __future__ import annotations

import os
import stat as statmod
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..models import (Classification, ConfirmRequest, ScanMode, ScanRequest,
                      ScanStatus)
from ..security import client_ip, require_csrf_header
from ..walker import validate_custom_target
from .deps import manager, registry, require_token, store

router = APIRouter()


@router.post("/scans", status_code=201,
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
async def start_scan(req: ScanRequest, request: Request):
    reg = registry(request)
    device = reg.get(req.device_id)
    if device is None:
        raise HTTPException(404, "device not found. Only enumerated removable "
                                 "devices can be scanned - scanning arbitrary "
                                 "paths or system drives is refused.")
    if not device.available or not reg.is_accessible(device):
        raise HTTPException(409, "device is currently unavailable "
                                 "(disconnected or unreadable)")
    if req.mode == ScanMode.CUSTOM:
        if not req.custom_paths:
            raise HTTPException(422, "custom mode requires at least one path")
        for p in req.custom_paths:
            try:
                validate_custom_target(Path(device.mount_point), p)
            except ValueError as exc:
                raise HTTPException(422, f"invalid custom path '{p}': {exc}")
    mgr = manager(request)
    running = [j for j in mgr.jobs.values()
               if j.record.status in (ScanStatus.QUEUED, ScanStatus.SCANNING)]
    if running:
        raise HTTPException(409, "another scan is already in progress; "
                                 "cancel it first")
    job = mgr.start(device, req.mode, req.custom_paths)
    mgr.schedule(job, device)
    return job.record.model_dump() | {"duration_seconds": job.record.duration_seconds}


@router.get("/scans", dependencies=[Depends(require_token)])
def list_scans(request: Request, limit: int = Query(50, ge=1, le=500)):
    recs = store(request).list_scans(limit)
    return {"scans": [r.model_dump() | {"duration_seconds": r.duration_seconds}
                      for r in recs]}


@router.get("/scans/{scan_id}", dependencies=[Depends(require_token)])
def get_scan(scan_id: str, request: Request):
    rec = manager(request).get(scan_id)
    if rec is None:
        raise HTTPException(404, "scan not found")
    return rec.model_dump() | {"duration_seconds": rec.duration_seconds}


@router.get("/scans/{scan_id}/events", dependencies=[Depends(require_token)])
def scan_events(scan_id: str, request: Request,
                since: int = Query(0, ge=0),
                limit: int = Query(1000, ge=1, le=5000)):
    mgr = manager(request)
    job = mgr.get_job(scan_id)
    if job is None:
        rec = store(request).get_scan(scan_id)
        if rec is None:
            raise HTTPException(404, "scan not found")
        finished = rec.status not in (ScanStatus.QUEUED, ScanStatus.SCANNING)
        return {"events": [], "next": since, "done": finished,
                "record": rec.model_dump() |
                          {"duration_seconds": rec.duration_seconds}}
    events, seq = job.events_since(since, limit)
    finished = job.record.status not in (ScanStatus.QUEUED, ScanStatus.SCANNING)
    return {"events": [e.model_dump() for e in events], "next": seq,
            "done": finished, "dropped": job.dropped_events,
            "record": job.record.model_dump() |
                      {"duration_seconds": job.record.duration_seconds}}


@router.post("/scans/{scan_id}/cancel",
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def cancel_scan(scan_id: str, request: Request):
    mgr = manager(request)
    if mgr.get(scan_id) is None:
        raise HTTPException(404, "scan not found")
    if not mgr.cancel(scan_id):
        raise HTTPException(409, "scan is not running")
    store(request).audit("scan.cancel", actor="user", detail=scan_id,
                         ip=client_ip(request))
    return {"cancelling": True}


@router.get("/scans/{scan_id}/findings", dependencies=[Depends(require_token)])
def scan_findings(scan_id: str, request: Request):
    if manager(request).get(scan_id) is None:
        raise HTTPException(404, "scan not found")
    findings = store(request).findings_for_scan(scan_id)
    return {"findings": [f.model_dump() for f in findings]}


@router.post("/scans/{scan_id}/findings/{finding_id}/delete",
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def delete_finding_file(scan_id: str, finding_id: str, req: ConfirmRequest,
                        request: Request):
    """Permanently delete a detected file from the device. Requires explicit
    confirmation. Archive members cannot be deleted individually."""
    if not req.confirm:
        raise HTTPException(400, "explicit confirmation required "
                                 "({confirm: true}) - deletions are permanent")
    st = store(request)
    finding = st.get_finding(finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(404, "finding not found")
    if finding.classification not in (Classification.MALICIOUS,
                                      Classification.SUSPICIOUS,
                                      Classification.PUA):
        raise HTTPException(422, "only detected threats can be deleted")
    if finding.container is not None or "::" in finding.path:
        raise HTTPException(422, "files inside archives cannot be deleted "
                                 "individually; delete the archive file itself")
    if finding.quarantined:
        raise HTTPException(409, "file is already quarantined (original removed "
                                 "from the device); manage it in the vault")
    reg = registry(request)
    device = reg.get(finding.device_id)
    if device is None or not device.available:
        raise HTTPException(409, "device is not connected")
    try:
        target = resolve_within(Path(device.mount_point), finding.path)
    except ValueError as exc:
        raise HTTPException(422, f"unsafe path: {exc}")
    try:
        lst = os.lstat(target)
    except FileNotFoundError:
        raise HTTPException(404, "file no longer exists on the device")
    if statmod.S_ISLNK(lst.st_mode) or not statmod.S_ISREG(lst.st_mode):
        raise HTTPException(422, "target is not a regular file; refusing to delete")
    os.remove(target)
    finding.extra["deleted_from_device"] = True
    st.save_finding(finding)
    st.audit("finding.delete", actor="user", detail=finding.path,
             ip=client_ip(request))
    return {"deleted": True, "path": finding.path,
            "note": "file permanently removed from the device"}
