"""Scan report rendering: JSON, plain text, and a self-contained HTML report.

The HTML renderer escapes every dynamic value (filenames are untrusted input
and may contain markup).  Reports are generated locally and never leave the
machine unless the user downloads them.
"""
from __future__ import annotations

import html
import json
import time
from typing import Any

from . import APP_NAME, __version__
from .models import (Classification, Finding, ScanOutcome, ScanRecord,
                     ScanStatus)

DISCLAIMER = (
    "This report was produced locally by USB Shield. A 'clean' outcome means "
    "every accessible file in scope was fully inspected by the engines listed "
    "below and no threat was detected; it is not a guarantee that the device "
    "is free of malware. Outcomes marked as having gaps, or incomplete scans, "
    "must not be treated as clean."
)


def _finding_dict(f: Finding) -> dict[str, Any]:
    d = f.model_dump()
    d["classification"] = f.classification.value
    d["severity"] = f.severity.value
    return d


def render_json(rec: ScanRecord, findings: list[Finding]) -> str:
    doc = {
        "tool": {"name": APP_NAME, "version": __version__},
        "generated_at": time.time(),
        "scan": {
            "id": rec.id, "mode": rec.mode.value,
            "device": {"id": rec.device_id, "label": rec.device_label},
            "status": rec.status.value, "outcome": rec.outcome.value,
            "created_at": rec.created_at, "started_at": rec.started_at,
            "finished_at": rec.finished_at,
            "duration_seconds": rec.duration_seconds,
            "error_code": rec.error_code, "error_message": rec.error_message,
            "custom_paths": rec.custom_paths,
            "engines": rec.engines, "engine_versions": rec.engine_versions,
            "config": rec.config_snapshot,
            "counters": rec.counters.model_dump(),
        },
        "findings": [_finding_dict(f) for f in findings],
        "disclaimer": DISCLAIMER,
    }
    return json.dumps(doc, indent=2, sort_keys=False)


def _fmt_ts(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "-"


def render_text(rec: ScanRecord, findings: list[Finding]) -> str:
    c = rec.counters
    lines = [
        f"{APP_NAME} scan report",
        "=" * 60,
        f"Scan ID        : {rec.id}",
        f"Device         : {rec.device_label} ({rec.device_id})",
        f"Mode           : {rec.mode.value}",
        f"Status         : {rec.status.value}",
        f"Outcome        : {rec.outcome.value}",
        f"Started        : {_fmt_ts(rec.started_at)}",
        f"Finished       : {_fmt_ts(rec.finished_at)}",
        f"Duration       : {rec.duration_seconds}s",
        f"Engines        : {', '.join(rec.engines)}",
        f"Entries seen   : {c.entries_seen}",
        f"Files scanned  : {c.files_scanned} fully, {c.files_partial} partially",
        f"Files skipped  : {c.files_skipped} (mode filter) + "
        f"{c.symlinks_skipped} symlinks + {c.special_skipped} special files",
        f"Unable to scan : {c.files_unable} files, {c.dirs_failed} folders",
        f"Threats found  : {c.threats_found}",
        "",
    ]
    if rec.error_message:
        lines += [f"Error: [{rec.error_code}] {rec.error_message}", ""]
    if rec.mode.value == "quick":
        lines += ["NOTE: This was a QUICK scan. Only high-risk locations and file",
                  "      types were inspected. It does not provide the coverage of",
                  "      a Full Deep Scan.", ""]
    if findings:
        lines.append("Findings")
        lines.append("-" * 60)
        for f in findings:
            lines += [f"[{f.classification.value.upper()}|{f.severity.value}] {f.path}",
                      f"    detection : {f.detection_name or '(none)'}",
                      f"    engine    : {f.engine} ({f.method})",
                      f"    status    : {f.status}"
                      + (f" — {f.reason}" if f.reason else ""),
                      f"    sha256    : {f.sha256 or '-'}",
                      f"    action    : {f.recommended_action}", ""]
    else:
        lines += ["No findings.", ""]
    lines += ["-" * 60, DISCLAIMER, ""]
    return "\n".join(lines)


_STYLE = """
body{background:#0b1220;color:#dbe7f4;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;
margin:0;padding:2rem;line-height:1.45}
.wrap{max-width:960px;margin:auto}
h1{font-size:1.4rem;color:#58a6ff} h2{font-size:1.05rem;color:#8fb8e8;margin-top:2rem}
table{border-collapse:collapse;width:100%;font-size:.86rem}
th,td{border:1px solid #20304a;padding:.4rem .55rem;text-align:left;vertical-align:top}
th{background:#101d33;color:#9ec5f0}
tr:nth-child(even){background:#0e1930}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}
.malicious{background:#5c1a1a;color:#ff8a8a}.suspicious{background:#5c4413;color:#ffc97a}
.potentially_unwanted{background:#40350f;color:#e7d38d}.clean{background:#123d22;color:#7fe3a3}
.unable_to_scan{background:#2a3345;color:#aeb9c9}
.meta{color:#93a7c4;font-size:.85rem}.path{font-family:Consolas,monospace;word-break:break-all}
.note{border:1px solid #2b3d5c;border-radius:8px;padding:.8rem 1rem;background:#0e1930;color:#b9c9de}
"""


def render_html(rec: ScanRecord, findings: list[Finding]) -> str:
    e = html.escape
    c = rec.counters
    rows = []
    for f in sorted(findings, key=lambda x: (x.classification.value, x.path)):
        cls = e(f.classification.value)
        rows.append(
            f"<tr><td><span class='badge {cls}'>{e(f.classification.value.replace('_',' '))}</span>"
            f"</td><td>{e(f.severity.value)}</td>"
            f"<td class='path'>{e(f.path)}</td>"
            f"<td>{e(f.detection_name or '—')}</td>"
            f"<td>{e(f.engine)}</td><td>{e(f.status)}"
            + (f"<br><span class='meta'>{e(f.reason)}</span>" if f.reason else "")
            + f"</td><td>{e(f.recommended_action)}</td></tr>")
    outcome_cls = {ScanOutcome.CLEAN: "clean",
                   ScanOutcome.THREATS_FOUND: "malicious",
                   ScanOutcome.NO_THREATS_WITH_GAPS: "unable_to_scan",
                   ScanOutcome.INCOMPLETE: "suspicious",
                   ScanOutcome.PENDING: "unable_to_scan"}[rec.outcome]
    quick_note = ("<p class='note'><b>Quick scan.</b> Only high-risk locations and "
                  "file types were inspected - this does not provide the coverage "
                  "of a Full Deep Scan.</p>" if rec.mode.value == "quick" else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'">
<title>{e(APP_NAME)} scan report</title><style>{_STYLE}</style></head>
<body><div class="wrap">
<h1>{e(APP_NAME)} &mdash; scan report</h1>
<p class='meta'>Generated {e(_fmt_ts(time.time()))} &middot; agent v{e(__version__)}</p>
<p><span class='badge {outcome_cls}'>outcome: {e(rec.outcome.value.replace('_',' '))}</span>
<span class='badge unable_to_scan'>status: {e(rec.status.value)}</span></p>
{quick_note}
<h2>Summary</h2>
<table>
<tr><th>Scan ID</th><td>{e(rec.id)}</td></tr>
<tr><th>Device</th><td>{e(rec.device_label)} ({e(rec.device_id)})</td></tr>
<tr><th>Mode</th><td>{e(rec.mode.value)}</td></tr>
<tr><th>Started / finished</th><td>{e(_fmt_ts(rec.started_at))} &rarr; {e(_fmt_ts(rec.finished_at))} ({rec.duration_seconds}s)</td></tr>
<tr><th>Engines</th><td>{e(', '.join(rec.engines)) or '—'}</td></tr>
<tr><th>Engine versions</th><td>{e(json.dumps(rec.engine_versions))}</td></tr>
<tr><th>Coverage</th><td>{c.entries_seen} entries, {c.dirs_scanned} folders scanned,
{c.dirs_failed} folders failed, {c.symlinks_skipped} symlinks skipped,
{c.special_skipped} special files skipped</td></tr>
<tr><th>Files</th><td>{c.files_scanned} fully scanned, {c.files_partial} partially scanned,
{c.files_skipped} skipped by mode filter, {c.files_unable} unable to scan</td></tr>
<tr><th>Threats</th><td>{c.threats_found}</td></tr>
<tr><th>Result code</th><td>{e(str(rec.error_code or '—'))}{' — ' + e(rec.error_message) if rec.error_message else ''}</td></tr>
</table>
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Classification</th><th>Severity</th><th>Path</th><th>Detection</th>
<th>Engine</th><th>Status</th><th>Recommended action</th></tr>
{''.join(rows) or '<tr><td colspan="7">No findings.</td></tr>'}
</table>
<h2>Important</h2>
<p class='note'>{e(DISCLAIMER)}</p>
</div></body></html>"""
