"""Scan orchestration: modes, progress, cancellation, honest outcomes.

A scan is *never* reported clean unless it ran to completion with full
coverage of the requested scope and zero unscannable/skipped-by-error files.
"""
from __future__ import annotations

import asyncio
import io
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional

from . import __version__
from .archives import archive_kind, inspect_archive
from .config import RuntimeOptions, Settings
from .drives import Device, DeviceRegistry
from .engines import ClamAvEngine, EicarEngine, HeuristicsEngine
from .engines.base import Engine, Verdict
from .models import (Classification, Finding, RECOMMENDED, ScanCounters,
                     ScanEvent, ScanMode, ScanOutcome, ScanRecord, ScanStatus,
                     Severity)
from .store import Store
from .walker import (DeviceDisconnected, WalkCancelled, WalkEntry, iter_walk,
                     resolve_within, snapshot_file, stream_file)

MAX_EVENTS = 100_000
COUNT_CAP = 2_000_000

QUICK_EXTS = {
    ".exe", ".dll", ".scr", ".sys", ".com", ".ocx", ".cpl", ".drv", ".efi",
    ".msi", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".hta", ".php", ".pl", ".lnk", ".inf", ".doc", ".xls", ".ppt",
    ".docm", ".xlsm", ".pptm", ".zip", ".jar", ".tar", ".tgz", ".rar",
    ".7z", ".iso", ".apk",
}


class LimitExceeded(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _ext(name: str) -> str:
    i = name.rfind(".")
    return name[i:].lower() if i > 0 else ""


def quick_interested(entry: WalkEntry) -> bool:
    if "/" not in entry.rel:                      # device root is high risk
        return True
    if entry.hidden or entry.system:
        return True
    if _ext(entry.name) in QUICK_EXTS:
        return True
    lower = entry.name.lower()
    if lower == "autorun.inf":
        return True
    # double-extension camouflage files at any depth
    stem = lower[:lower.rfind(".")] if "." in lower else lower
    if "." in stem and _ext(lower) in QUICK_EXTS:
        return True
    return False


class ScanJob:
    def __init__(self, record: ScanRecord):
        self.record = record
        self.events: list[ScanEvent] = []
        self.dropped_events = 0
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.task: Optional[asyncio.Task] = None
        self.finding_ids: list[str] = []
        self._seq = 0
        self._last_progress = 0.0

    def emit(self, type_: str, level: str, message: str,
             path: Optional[str] = None, data: Optional[dict] = None,
             force: bool = False) -> None:
        with self.lock:
            if type_ == "progress" and not force:
                now = time.monotonic()
                if now - self._last_progress < 0.2:
                    return
                self._last_progress = now
            if len(self.events) >= MAX_EVENTS:
                self.dropped_events += 1
                return
            self._seq += 1
            self.events.append(ScanEvent(seq=self._seq, type=type_, level=level,
                                         message=message, path=path,
                                         data=data or {}))

    def events_since(self, since: int, limit: int = 2000) -> tuple[list[ScanEvent], int]:
        with self.lock:
            idx = max(0, since)
            tail = self.events[idx:idx + limit]
            return tail, self._seq


class ScanManager:
    def __init__(self, settings: Settings, store: Store,
                 registry: DeviceRegistry, get_options):
        self.settings = settings
        self.store = store
        self.registry = registry
        self.get_options = get_options
        self.jobs: dict[str, ScanJob] = {}
        self.clamav = ClamAvEngine(
            socket_path=settings.clamd_socket, tcp=settings.clamd_tcp,
            timeout=settings.clamav_timeout_seconds,
            max_file_bytes=settings.clamav_max_file_bytes)

    # ---------------------------------------------------------------- control
    def start(self, device: Device, mode: ScanMode,
              custom_paths: list[str]) -> ScanJob:
        rec = ScanRecord(device_id=device.id, device_label=device.label,
                         device_mount=device.mount_point, mode=mode,
                         custom_paths=custom_paths, agent_version=__version__)
        job = ScanJob(rec)
        opts = self.get_options()
        engines = self._engines(opts)
        rec.engines = [e.name for e in engines]
        rec.engine_versions = {e.name: e.version() for e in engines}
        rec.config_snapshot = opts.model_dump()
        self.jobs[rec.id] = job
        self.store.save_scan(rec)
        self.store.audit("scan.start", actor="user",
                         detail=f"{mode.value} scan of {device.label} ({device.mount_point})")
        return job

    def schedule(self, job: ScanJob, device: Device) -> None:
        job.task = asyncio.create_task(self._run(job, device))

    async def _run(self, job: ScanJob, device: Device) -> None:
        try:
            await asyncio.to_thread(self._run_sync, job, device)
        except Exception:                               # defensive; _run_sync handles
            job.record.status = ScanStatus.FAILED
            job.record.outcome = ScanOutcome.INCOMPLETE
            job.record.error_code = "INTERNAL_ERROR"
            job.record.error_message = "unexpected internal scanning error"
            self.store.audit("scan.crash", detail=traceback.format_exc()[-1500:])
        finally:
            self._finalize(job)

    def cancel(self, scan_id: str) -> bool:
        job = self.jobs.get(scan_id)
        if not job:
            return False
        job.cancel.set()
        return True

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        job = self.jobs.get(scan_id)
        if job:
            return job.record
        return self.store.get_scan(scan_id)

    def get_job(self, scan_id: str) -> Optional[ScanJob]:
        return self.jobs.get(scan_id)

    def _engines(self, opts: RuntimeOptions) -> list[Engine]:
        engines: list[Engine] = [EicarEngine(opts.test_signature_engine_enabled),
                                 HeuristicsEngine(opts.heuristics_enabled)]
        if self.clamav.available():
            engines.append(self.clamav)
        return [e for e in engines if e.available()]

    # ----------------------------------------------------------------- worker
    def _run_sync(self, job: ScanJob, device: Device) -> None:
        rec = job.record
        root = Path(device.mount_point)
        opts = RuntimeOptions(**rec.config_snapshot)
        engines = self._engines(opts)
        buffer_engines = [e for e in engines if not isinstance(e, ClamAvEngine)]
        clam = self.clamav if isinstance(self.clamav, ClamAvEngine) and \
            self.clamav.available() and any(isinstance(e, ClamAvEngine) for e in engines) \
            else None
        t0 = time.monotonic()
        rec.status = ScanStatus.SCANNING
        rec.started_at = time.time()
        self.store.save_scan(rec)
        liveness = lambda: self.registry.is_accessible(device)
        if not liveness():
            raise DeviceDisconnected("device is not accessible")

        def emit(type_, level, msg, path=None, data=None, force=False):
            job.emit(type_, level, msg, path, data, force)

        def on_dir_error(rel: str, msg: str) -> None:
            rec.counters.dirs_failed += 1
            emit("dir_error", "warn", f"folder '{rel}': {msg}", rel,
                 force=False)

        try:
            # ------------------------------------------------ phase 1: estimate
            targets = rec.custom_paths if rec.mode == ScanMode.CUSTOM else None
            for p in targets or []:
                resolve_within(root, p)                 # raises → caught below
            est = 0
            capped = False
            emit("phase", "info", "Enumerating device contents…")
            for _entry in iter_walk(root, opts.max_depth, job.cancel,
                                    targets=targets, liveness_probe=liveness):
                est += 1
                if est >= min(COUNT_CAP, opts.max_entries_per_scan):
                    capped = True
                    break
            rec.counters.estimate_total = est if not capped else None
            rec.counters.estimate_complete = not capped

            # -------------------------------------------------- phase 2: scan
            emit("phase", "info",
                 f"Scanning {rec.device_label} ({rec.mode.value} mode)…", force=True)
            deadline = t0 + opts.scan_time_limit_seconds
            persist_tick = 0
            for entry in iter_walk(root, opts.max_depth, job.cancel,
                                   targets=targets, liveness_probe=liveness,
                                   on_dir_error=on_dir_error):
                if time.monotonic() > deadline:
                    raise LimitExceeded("LIMIT_TIME",
                                        "scan time limit reached before completion")
                c = rec.counters
                c.entries_seen += 1
                if c.entries_seen > opts.max_entries_per_scan:
                    raise LimitExceeded("LIMIT_ENTRIES",
                                        "entry-count limit reached before completion")
                if entry.kind == "dir":
                    c.dirs_scanned += 1
                elif entry.kind == "symlink":
                    c.symlinks_skipped += 1
                elif entry.kind == "other":
                    c.special_skipped += 1
                elif entry.kind == "file":
                    interested = (rec.mode != ScanMode.QUICK or quick_interested(entry))
                    if not interested:
                        c.files_skipped += 1
                    else:
                        self._scan_file(job, entry, opts, buffer_engines, clam)
                if c.entries_seen % 100 == 0:
                    emit("progress", "info", "scanning…", entry.rel,
                         self._progress_data(rec), force=True)
                    persist_tick += 1
                    if persist_tick % 5 == 0:
                        self.store.save_scan(rec)
            self._finish_status(rec, ScanStatus.COMPLETED)
        except WalkCancelled:
            self._finish_status(rec, ScanStatus.CANCELLED, code="CANCELLED",
                                message="scan cancelled by the user")
        except DeviceDisconnected as disc:
            self._finish_status(rec, ScanStatus.FAILED, code="DEVICE_DISCONNECTED",
                                message=str(disc))
            job.emit("error", "error", f"device disconnected: {disc}", force=True)
        except LimitExceeded as lim:
            self._finish_status(rec, ScanStatus.COMPLETED, code=lim.code,
                                message=lim.message)
            job.emit("error", "error", lim.message, force=True)
        except ValueError as val:
            self._finish_status(rec, ScanStatus.FAILED, code="INVALID_TARGET",
                                message=str(val))
        except Exception as exc:
            self.store.audit("scan.exception", detail=traceback.format_exc()[-2000:])
            self._finish_status(rec, ScanStatus.FAILED, code="INTERNAL_ERROR",
                                message=f"internal scanning error ({type(exc).__name__})")
            job.emit("error", "error", "internal scanning error; see audit log",
                     force=True)

    # -------------------------------------------------------------- per file
    def _scan_file(self, job: ScanJob, entry: WalkEntry, opts: RuntimeOptions,
                   engines: list[Engine], clam: Optional[ClamAvEngine]) -> None:
        rec = job.record
        c = rec.counters
        rel = entry.rel
        size = entry.size

        def mk_finding(classification: Classification, severity: Severity,
                       detection: str, engine: str, method: str,
                       status: str = "detected", reason: Optional[str] = None,
                       sha256: Optional[str] = None, container: Optional[str] = None,
                       path: Optional[str] = None, is_test: bool = False,
                       extra: Optional[dict] = None, fsize: Optional[int] = None) -> Finding:
            f = Finding(scan_id=rec.id, device_id=rec.device_id,
                        path=path or rel, container=container,
                        classification=classification, severity=severity,
                        detection_name=detection, engine=engine, method=method,
                        status=status, reason=reason, size=fsize if fsize is not None else size,
                        sha256=sha256, hidden=entry.hidden,
                        system_path=entry.system,
                        recommended_action=RECOMMENDED[classification],
                        is_test_detection=is_test, extra=extra or {})
            self.store.save_finding(f)
            job.finding_ids.append(f.id)
            if classification in (Classification.MALICIOUS, Classification.SUSPICIOUS,
                                  Classification.PUA):
                c.threats_found += 1
                job.emit("threat", "warn",
                         f"{classification.value.upper()}: {f.path} — {detection}",
                         f.path, {"classification": classification.value,
                                  "severity": severity.value, "engine": engine},
                         force=True)
            elif classification == Classification.UNABLE:
                job.emit("unable", "warn", f"could not fully scan {f.path}: {reason}",
                         f.path, {"reason": reason}, force=True)
            return f

        oversized = size > opts.max_file_bytes
        buffer_cap = min(opts.small_file_buffer_bytes, opts.max_file_bytes)

        try:
            snap = snapshot_file(entry.abspath, buffer_cap=buffer_cap)
        except PermissionError as exc:
            c.files_unable += 1
            mk_finding(Classification.UNABLE, Severity.LOW, "", "scanner",
                       "filesystem read", status="unscannable",
                       reason="permission denied", fsize=size)
            return
        except OSError as exc:
            c.files_unable += 1
            mk_finding(Classification.UNABLE, Severity.LOW, "", "scanner",
                       "filesystem read", status="unscannable",
                       reason=f"read error: {exc.strerror or exc}", fsize=size)
            return

        if snap.changed:                       # one retry, then we refuse
            try:
                time.sleep(0.01)
                snap = snapshot_file(entry.abspath, buffer_cap=buffer_cap)
            except OSError as exc:
                c.files_unable += 1
                mk_finding(Classification.UNABLE, Severity.LOW, "", "scanner",
                           "filesystem read", status="unscannable",
                           reason=f"read error: {exc.strerror or exc}")
                return
            if snap.changed:
                c.files_unable += 1
                mk_finding(Classification.UNABLE, Severity.LOW, "", "scanner",
                           "filesystem read", status="unscannable",
                           reason="file changed while it was being scanned")
                return

        if oversized:
            c.files_partial += 1
            mk_finding(Classification.UNABLE, Severity.LOW, "", "scanner",
                       "size limit", status="partial",
                       reason=f"file exceeds inspection limit "
                              f"({size} bytes > {opts.max_file_bytes}); "
                              f"header and metadata inspected only",
                       sha256=snap.sha256)
            data = snap.header
            sha256 = None
        else:
            data = snap.body if snap.body is not None else snap.header
            sha256 = snap.sha256
            if snap.truncated:                 # between buffer cap and file cap
                c.files_partial += 1
                mk_finding(Classification.UNABLE, Severity.INFO, "", "scanner",
                           "size limit", status="partial",
                           reason="inspectable buffer smaller than file; large-file "
                                  "engines only (header + stream) inspected it",
                           sha256=snap.sha256)

        verdicts: list[Verdict] = []
        for eng in engines:
            try:
                verdicts.extend(eng.scan_buffer(rel=rel, name=entry.name, data=data,
                                                size=size, header=snap.header,
                                                hidden=entry.hidden,
                                                system=entry.system))
            except Exception as exc:
                c.files_unable += 1
                mk_finding(Classification.UNABLE, Severity.LOW, "", eng.name,
                           "engine inspection", status="unscannable",
                           reason=f"engine error: {type(exc).__name__}")
                self.store.audit("engine.error",
                                 detail=f"{eng.name} on {rel}: {exc!r}")

        if clam is not None:
            try:
                if size <= clam.max_file_bytes:
                    if snap.body is not None:
                        chunks = iter([snap.body])
                    else:
                        chunks = stream_file(entry.abspath, clam.max_file_bytes)
                    verdicts.extend(clam.scan_stream(path=entry.abspath, rel=rel,
                                                     chunks=chunks, size=size))
                else:
                    c.files_partial += 1
                    mk_finding(Classification.UNABLE, Severity.INFO, "", clam.name,
                               "size limit", status="partial",
                               reason="file exceeds antivirus engine limit")
            except Exception as exc:
                c.files_unable += 1
                mk_finding(Classification.UNABLE, Severity.LOW, "", clam.name,
                           "antivirus inspection", status="unscannable",
                           reason=f"antivirus engine error: {exc}")
                self.store.audit("engine.error", detail=f"clamav on {rel}: {exc!r}")

        for v in verdicts:
            mk_finding(v.classification, v.severity, v.detection_name, v.engine,
                       v.method, sha256=sha256, is_test=v.is_test, extra=v.details)

        # ------------------------------------------------ archive inspection
        kind = archive_kind(rel, snap.header[:512]) if (snap.header or snap.body) else None
        if kind and opts.archive_scan_enabled:
            if kind == "unsupported":
                c.files_unable += 1
                mk_finding(Classification.UNABLE, Severity.LOW, "", "archive-inspector",
                           "format detection", status="unscannable",
                           reason="unsupported archive format (contents not inspected)",
                           sha256=sha256)
            elif snap.body is None:
                c.files_partial += 1
                mk_finding(Classification.UNABLE, Severity.INFO, "", "archive-inspector",
                           "size limit", status="partial",
                           reason="archive exceeds in-memory inspection limit; "
                                  "contents not enumerated", sha256=sha256)
            else:
                c.archives_inspected += 1
                self._inspect_archive_members(job, entry, snap.body, opts,
                                              engines, clam, mk_finding)

        if snap.body is not None and not oversized:
            c.files_scanned += 1
            c.bytes_scanned += size

    # -------------------------------------------------------------- archives
    def _inspect_archive_members(self, job: ScanJob, entry: WalkEntry,
                                 body: bytes, opts: RuntimeOptions,
                                 engines: list[Engine],
                                 clam: Optional[ClamAvEngine],
                                 mk_finding) -> None:
        rec = job.record
        c = rec.counters

        def member_scan(inner_path: str, name: str, buf: bytes) -> list[Verdict]:
            out: list[Verdict] = []
            for eng in engines:
                out.extend(eng.scan_buffer(rel=inner_path, name=name, data=buf,
                                           size=len(buf), header=buf[:4096],
                                           hidden=entry.hidden,
                                           system=entry.system))
            if clam is not None and len(buf) <= clam.max_file_bytes:
                out.extend(clam.scan_stream(path=entry.abspath, rel=inner_path,
                                            chunks=iter([buf]), size=len(buf)))
            return out

        report = inspect_archive(entry.rel, body, opts, member_scan)
        for m in report.results:
            for v in m.verdicts:
                mk_finding(v.classification, v.severity, v.detection_name,
                           v.engine, f"archive inspection: {v.method}",
                           container=entry.rel, path=m.inner_path,
                           is_test=v.is_test, extra=v.details,
                           fsize=m.size)
            if m.error:
                c.files_unable += 1
                mk_finding(Classification.UNABLE, Severity.LOW, "",
                           "archive-inspector", "archive inspection",
                           status="unscannable", reason=m.error,
                           container=entry.rel, path=m.inner_path, fsize=m.size)
            elif m.truncated:
                c.files_partial += 1
                mk_finding(Classification.UNABLE, Severity.INFO, "",
                           "archive-inspector", "archive inspection",
                           status="partial",
                           reason="archive member exceeds per-member inspection limit",
                           container=entry.rel, path=m.inner_path, fsize=m.size)

        c_threat_ratio = {"compression_ratio", "member_ratio"}
        limits = set(report.limits_hit)
        if limits & c_threat_ratio:
            mk_finding(Classification.SUSPICIOUS, Severity.HIGH,
                       "Heur.Archive.PossibleBomb", "archive-inspector",
                       "archive structure analysis (extreme compression ratio)",
                       extra={"limits": sorted(report.limits_hit)})
        gap_limits = limits - c_threat_ratio - {"encrypted_members"}
        if gap_limits or report.fatal_error:
            c.files_partial += 1
            reason = report.fatal_error or (
                "archive inspection limits applied: " +
                ", ".join(sorted(gap_limits)) +
                "; some members were not scanned")
            mk_finding(Classification.UNABLE, Severity.INFO if not report.fatal_error
                       else Severity.LOW, "", "archive-inspector",
                       "archive inspection",
                       status="partial" if not report.fatal_error else "unscannable",
                       reason=reason)
        job.emit("info", "info",
                 f"archive {entry.rel}: {len(report.results)} members inspected"
                 + (f" (limits: {', '.join(sorted(report.limits_hit))})"
                    if report.limits_hit else ""), entry.rel)

    # ------------------------------------------------------------- finalize
    def _progress_data(self, rec: ScanRecord) -> dict:
        c = rec.counters
        pct = None
        if c.estimate_complete and c.estimate_total:
            pct = min(99.0, round(100.0 * c.entries_seen / max(1, c.estimate_total), 1))
        return {"percent": pct, "counters": c.model_dump(),
                "estimate_known": c.estimate_complete}

    def _finish_status(self, rec: ScanRecord, status: ScanStatus,
                       code: Optional[str] = None,
                       message: Optional[str] = None) -> None:
        rec.status = status
        rec.error_code = code
        rec.error_message = message
        c = rec.counters
        gaps = c.files_unable + c.dirs_failed + c.files_partial
        if status == ScanStatus.COMPLETED and code is None:
            if c.threats_found > 0:
                rec.outcome = ScanOutcome.THREATS_FOUND
            elif gaps > 0:
                rec.outcome = ScanOutcome.NO_THREATS_WITH_GAPS
            else:
                rec.outcome = ScanOutcome.CLEAN
        else:
            rec.outcome = ScanOutcome.INCOMPLETE

    def _finalize(self, job: ScanJob) -> None:
        rec = job.record
        rec.finished_at = time.time()
        c = rec.counters
        level = "info"
        if rec.outcome == ScanOutcome.THREATS_FOUND:
            level = "error"
        elif rec.outcome in (ScanOutcome.NO_THREATS_WITH_GAPS,
                             ScanOutcome.INCOMPLETE):
            level = "warn"
        summary = {
            ScanOutcome.CLEAN: "Scan complete - no threats detected.",
            ScanOutcome.THREATS_FOUND: f"Scan complete - {c.threats_found} threat(s) detected.",
            ScanOutcome.NO_THREATS_WITH_GAPS:
                "Scan complete - no threats detected, but some files could not "
                "be fully inspected; the device cannot be certified clean.",
            ScanOutcome.INCOMPLETE:
                f"Scan did not complete ({rec.error_code or 'stopped'}); "
                "results are partial only.",
            ScanOutcome.PENDING: "Scan aborted before producing results.",
        }[rec.outcome]
        job.emit("end", level, summary, data={
            "outcome": rec.outcome.value, "status": rec.status.value,
            "counters": c.model_dump(), "percent": 100.0}, force=True)
        self.store.save_scan(rec)
        self.store.audit("scan.finished",
                         detail=f"{rec.mode.value} {rec.device_label}: "
                                f"{rec.status.value}/{rec.outcome.value} "
                                f"files={c.files_scanned} threats={c.threats_found} "
                                f"unable={c.files_unable} partial={c.files_partial}")
        if len(self.jobs) > 50:                 # bound memory
            finished = [k for k, j in self.jobs.items()
                        if j.record.status in (ScanStatus.COMPLETED,
                                               ScanStatus.FAILED,
                                               ScanStatus.CANCELLED)
                        and k != rec.id]
            for k in finished[:-50]:
                self.jobs.pop(k, None)
