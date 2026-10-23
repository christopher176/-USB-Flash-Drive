"""SQLite persistence for scans, findings, quarantine index, user accounts,
sessions and the audit log.

The agent is a single-process local service, so one connection guarded by a
re-entrant lock is both correct and fast enough; no ORM needed.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from .models import Finding, QuarantineEntry, ScanRecord, UserPublic

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    device_id TEXT, device_label TEXT, device_mount TEXT, mode TEXT,
    status TEXT, outcome TEXT,
    counters_json TEXT, created_at REAL, started_at REAL, finished_at REAL,
    error_code TEXT, error_message TEXT,
    engines_json TEXT, engine_versions_json TEXT, config_json TEXT,
    agent_version TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT, device_id TEXT, classification TEXT, severity TEXT,
    path TEXT, detection_name TEXT, detected_at REAL,
    quarantined INTEGER DEFAULT 0,
    json TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    finding_id TEXT, scan_id TEXT, device_id TEXT, device_label TEXT,
    original_path TEXT, container TEXT, detection_name TEXT,
    classification TEXT, severity TEXT, engine TEXT,
    sha256 TEXT, size INTEGER, blob_name TEXT,
    status TEXT, created_at REAL, resolved_at REAL, restored_to TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, phash TEXT, role TEXT,
    totp_secret TEXT, totp_enabled INTEGER DEFAULT 0,
    disabled INTEGER DEFAULT 0, created_at REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, username TEXT,
    created_at REAL, expires_at REAL, mfa_verified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, actor TEXT, action TEXT, detail TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            data_dir.chmod(0o700)
        except OSError:
            pass
        self.db_path = data_dir / "usb_shield.db"
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)
        try:
            self.db_path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --------------------------------------------------------------- scans
    def save_scan(self, rec: ScanRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT OR REPLACE INTO scans
                (id, device_id, device_label, device_mount, mode, status, outcome,
                 counters_json, created_at, started_at, finished_at,
                 error_code, error_message, engines_json, engine_versions_json,
                 config_json, agent_version)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rec.id, rec.device_id, rec.device_label, rec.device_mount,
                 rec.mode.value, rec.status.value, rec.outcome.value,
                 rec.counters.model_dump_json(), rec.created_at, rec.started_at,
                 rec.finished_at, rec.error_code, rec.error_message,
                 json.dumps(rec.engines), json.dumps(rec.engine_versions),
                 json.dumps(rec.config_snapshot), rec.agent_version))

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanRecord(
            id=row["id"], device_id=row["device_id"], device_label=row["device_label"],
            device_mount=row["device_mount"], mode=row["mode"], status=row["status"],
            outcome=row["outcome"], counters=json.loads(row["counters_json"]),
            created_at=row["created_at"], started_at=row["started_at"],
            finished_at=row["finished_at"], error_code=row["error_code"],
            error_message=row["error_message"], engines=json.loads(row["engines_json"] or "[]"),
            engine_versions=json.loads(row["engine_versions_json"] or "{}"),
            config_snapshot=json.loads(row["config_json"] or "{}"),
            agent_version=row["agent_version"] or "")

    def list_scans(self, limit: int = 100) -> list[ScanRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            rec = self.get_scan(r["id"])
            if rec:
                out.append(rec)
        return out

    def delete_history(self) -> int:
        with self._lock, self._conn:
            n = self._conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
            self._conn.execute("DELETE FROM findings")
            self._conn.execute("DELETE FROM scans")
        return n

    # ------------------------------------------------------------ findings
    def save_finding(self, f: Finding) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                (id, scan_id, device_id, classification, severity, path,
                 detection_name, detected_at, quarantined, json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (f.id, f.scan_id, f.device_id, f.classification.value,
                 f.severity.value, f.path, f.detection_name, f.detected_at,
                 1 if f.quarantined else 0, f.model_dump_json()))

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._lock:
            row = self._conn.execute("SELECT json FROM findings WHERE id=?",
                                     (finding_id,)).fetchone()
        return Finding.model_validate_json(row["json"]) if row else None

    def findings_for_scan(self, scan_id: str) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT json FROM findings WHERE scan_id=? ORDER BY detected_at ASC",
                (scan_id,)).fetchall()
        return [Finding.model_validate_json(r["json"]) for r in rows]

    def mark_finding_quarantined(self, finding_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE findings SET quarantined=1 WHERE id=?",
                               (finding_id,))
            row = self._conn.execute("SELECT json FROM findings WHERE id=?",
                                     (finding_id,)).fetchone()
            if row:
                f = Finding.model_validate_json(row["json"])
                f.quarantined = True
                self._conn.execute("UPDATE findings SET json=? WHERE id=?",
                                   (f.model_dump_json(), finding_id))

    # ----------------------------------------------------------- quarantine
    def save_quarantine(self, e: QuarantineEntry, blob_name: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT OR REPLACE INTO quarantine
                (id, finding_id, scan_id, device_id, device_label, original_path,
                 container, detection_name, classification, severity, engine,
                 sha256, size, blob_name, status, created_at, resolved_at, restored_to)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (e.id, e.finding_id, e.scan_id, e.device_id, e.device_label,
                 e.original_path, e.container, e.detection_name,
                 e.classification.value, e.severity.value, e.engine, e.sha256,
                 e.size, blob_name, e.status.value, e.created_at, e.resolved_at,
                 e.restored_to))

    def get_quarantine(self, qid: str) -> Optional[tuple[QuarantineEntry, str]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
        if not row:
            return None
        e = QuarantineEntry(
            id=row["id"], finding_id=row["finding_id"], scan_id=row["scan_id"],
            device_id=row["device_id"], device_label=row["device_label"],
            original_path=row["original_path"], container=row["container"],
            detection_name=row["detection_name"], classification=row["classification"],
            severity=row["severity"], engine=row["engine"], sha256=row["sha256"],
            size=row["size"], status=row["status"], created_at=row["created_at"],
            resolved_at=row["resolved_at"], restored_to=row["restored_to"])
        return e, row["blob_name"]

    def list_quarantine(self) -> list[QuarantineEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM quarantine ORDER BY created_at DESC").fetchall()
        out = []
        for r in rows:
            got = self.get_quarantine(r["id"])
            if got:
                out.append(got[0])
        return out

    # ---------------------------------------------------------------- users
    def create_user(self, username: str, phash: str, role: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO users (username, phash, role, created_at) VALUES (?,?,?,?)",
                (username, phash, role, time.time()))

    def update_user_hash(self, username: str, phash: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE users SET phash=? WHERE username=?",
                               (phash, username))

    def get_user(self, username: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username=?",
                                     (username,)).fetchone()
        return dict(row) if row else None

    def user_public(self, username: str) -> Optional[UserPublic]:
        u = self.get_user(username)
        if not u:
            return None
        return UserPublic(username=u["username"], role=u["role"],
                          totp_enabled=bool(u["totp_enabled"]))

    def user_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]

    def set_totp(self, username: str, secret: Optional[str], enabled: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=? WHERE username=?",
                (secret, 1 if enabled else 0, username))

    # ------------------------------------------------------------- sessions
    def create_session(self, token: str, username: str, ttl: int,
                       mfa_verified: bool) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO sessions (token, username, created_at, expires_at, mfa_verified)"
                " VALUES (?,?,?,?,?)",
                (token, username, now, now + ttl, 1 if mfa_verified else 0))

    def get_session(self, token: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM sessions WHERE token=?",
                                     (token,)).fetchone()
        if not row or row["expires_at"] < time.time():
            return None
        return dict(row)

    def delete_session(self, token: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE token=?", (token,))

    # ---------------------------------------------------------------- audit
    def audit(self, action: str, actor: str = "agent", detail: str = "",
              ip: str = "") -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit (ts, actor, action, detail, ip) VALUES (?,?,?,?,?)",
                (time.time(), actor, action, detail[:2000], ip))

    def audit_rows(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- kv
    def kv_get(self, k: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return row["v"] if row else None

    def kv_set(self, k: str, v: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?,?)", (k, v))

    def execute_audit_cleanup(self, keep: int = 10_000) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT ?)",
                (keep,))
