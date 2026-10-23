"""Reports & history endpoints."""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from ..models import HistoryDeleteRequest
from ..reports import render_html, render_json, render_text
from ..security import require_csrf_header
from .deps import manager, require_token, settings, store

router = APIRouter()

_FORMATS = {
    "json": ("application/json", render_json),
    "txt": ("text/plain; charset=utf-8", render_text),
    "html": ("text/html; charset=utf-8", render_html),
}


@router.get("/scans/{scan_id}/report", dependencies=[Depends(require_token)])
def scan_report(scan_id: str, request: Request,
                format: str = Query("json", pattern="^(json|txt|html)$"),
                download: bool = Query(True)):
    st = store(request)
    rec = manager(request).get(scan_id)
    if rec is None:
        raise HTTPException(404, "scan not found")
    findings = st.findings_for_scan(scan_id)
    media, renderer = _FORMATS[format]
    body = renderer(rec, findings)
    # save a copy alongside the vault for later retrieval
    reports_dir = Path(settings(request).data_path) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", scan_id)[:64]
    fname = f"usb-shield-report-{safe_id}.{format}"
    try:
        (reports_dir / fname).write_text(body, encoding="utf-8")
    except OSError:
        pass
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    if format == "html":
        # permit embedded styles in the report, nothing else
        headers["Content-Security-Policy"] = \
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"
    st.audit("report.generate", actor="user", detail=f"{scan_id}.{format}")
    return Response(content=body, media_type=media, headers=headers)


@router.get("/history", dependencies=[Depends(require_token)])
def history(request: Request, limit: int = Query(100, ge=1, le=500)):
    recs = store(request).list_scans(limit)
    return {"scans": [r.model_dump() | {"duration_seconds": r.duration_seconds}
                      for r in recs]}


@router.delete("/history", dependencies=[Depends(require_token),
                                         Depends(require_csrf_header)])
def delete_history(req: HistoryDeleteRequest, request: Request):
    """Privacy control: wipe local scan history and saved reports."""
    if not req.confirm:
        raise HTTPException(400, "explicit confirmation required ({confirm: true})")
    st = store(request)
    n = st.delete_history()
    reports_dir = Path(settings(request).data_path) / "reports"
    removed = 0
    if reports_dir.exists():
        for f in reports_dir.glob("usb-shield-report-*"):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
    st.audit("history.delete", actor="user",
             detail=f"{n} scans, {removed} report files removed")
    return {"deleted_scans": n, "deleted_reports": removed}
