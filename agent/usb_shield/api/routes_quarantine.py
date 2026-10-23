"""Quarantine vault endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from ..models import (HistoryDeleteRequest, QuarantineRequest,
                      QuarantineRestoreRequest, QuarantineStatus)
from ..quarantine import QuarantineError
from ..security import client_ip, require_csrf_header
from .deps import quarantine, require_token, store

router = APIRouter()


@router.get("/quarantine", dependencies=[Depends(require_token)])
def list_vault(request: Request):
    entries = quarantine(request).store.list_quarantine()
    return {"entries": [e.model_dump() for e in entries]}


@router.post("/quarantine", status_code=201,
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def quarantine_finding(req: QuarantineRequest, request: Request):
    st = store(request)
    finding = st.get_finding(req.finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")
    if finding.quarantined:
        raise HTTPException(409, "already quarantined")
    rec = st.get_scan(finding.scan_id)
    label = rec.device_label if rec else ""
    try:
        entry = quarantine(request).quarantine(finding, device_label=label)
    except QuarantineError as exc:
        raise HTTPException(422, str(exc))
    return entry.model_dump()


@router.post("/quarantine/{qid}/restore",
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def restore(qid: str, req: QuarantineRestoreRequest, request: Request):
    if not req.confirm:
        raise HTTPException(400, "explicit confirmation required: restoring can "
                                 "reintroduce a threat. Send {confirm: true} to "
                                 "acknowledge the risk.")
    if req.destination not in ("original", "inbox"):
        raise HTTPException(422, "destination must be 'original' or 'inbox'")
    try:
        entry = quarantine(request).restore(qid, destination=req.destination)
    except QuarantineError as exc:
        raise HTTPException(422, str(exc))
    store(request).audit("quarantine.restore.api", ip=client_ip(request),
                         detail=f"{entry.original_path} -> {entry.restored_to}")
    return {"restored": True, "restored_to": entry.restored_to,
            "note": "file restored and hash-verified; rescan recommended"}


@router.post("/quarantine/{qid}/delete",
             dependencies=[Depends(require_token), Depends(require_csrf_header)])
def delete(qid: str, req: HistoryDeleteRequest, request: Request):
    if not req.confirm:
        raise HTTPException(400, "explicit confirmation required "
                                 "({confirm: true}) - this permanently destroys "
                                 "the quarantined copy")
    try:
        entry = quarantine(request).delete(qid)
    except QuarantineError as exc:
        raise HTTPException(422, str(exc))
    return {"deleted": True, "id": entry.id}
