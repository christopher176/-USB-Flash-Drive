"""Shared models.  Wire format, persistence format and API schema all derive
from these definitions so that nothing drifts."""
from __future__ import annotations

import enum
import time
import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- enums
class Classification(str, enum.Enum):
    MALICIOUS = "malicious"                    # confirmed signature match
    SUSPICIOUS = "suspicious"                  # heuristic indicators
    PUA = "potentially_unwanted"               # potentially unwanted
    CLEAN = "clean"                            # scanned, nothing detected
    UNABLE = "unable_to_scan"                  # could not be inspected


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class ScanMode(str, enum.Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanOutcome(str, enum.Enum):
    """Terminal, honest summary.  ``CLEAN`` is only ever produced when the
    scan ran to completion with full coverage and zero unscannable files."""
    PENDING = "pending"
    CLEAN = "clean"
    THREATS_FOUND = "threats_found"
    NO_THREATS_WITH_GAPS = "no_threats_with_gaps"  # complete but gaps remain
    INCOMPLETE = "incomplete"                       # cancelled / failed / limits


class QuarantineStatus(str, enum.Enum):
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    DELETED = "deleted"


# --------------------------------------------------------------------------- devices
class Device(BaseModel):
    id: str
    label: str
    mount_point: str
    fs_type: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    kind: str                                   # "removable" | "demo"
    available: bool = True
    detail: str = ""


# --------------------------------------------------------------------------- findings
RECOMMENDED = {
    Classification.MALICIOUS: "Quarantine immediately, then delete the original from the device.",
    Classification.SUSPICIOUS: "Quarantine for review. Delete if you do not recognise the file.",
    Classification.PUA: "Review. Delete if unwanted; otherwise keep.",
    Classification.CLEAN: "No action required.",
    Classification.UNABLE: "Do not open. Rescan when readable, or inspect manually from a safe environment.",
}


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    scan_id: str = ""
    device_id: str = ""
    path: str                                   # device-relative POSIX path
    container: Optional[str] = None             # enclosing archive rel path
    classification: Classification
    severity: Severity = Severity.NONE
    detection_name: str = ""
    engine: str = ""
    method: str = ""
    status: str = "detected"                    # detected | unscannable | partial
    reason: Optional[str] = None
    size: int = 0
    sha256: Optional[str] = None
    hidden: bool = False
    system_path: bool = False
    recommended_action: str = ""
    is_test_detection: bool = False
    quarantined: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)
    detected_at: float = Field(default_factory=time.time)


# --------------------------------------------------------------------------- scans
class ScanCounters(BaseModel):
    entries_seen: int = 0
    dirs_scanned: int = 0
    dirs_failed: int = 0
    files_scanned: int = 0          # fully inspected
    files_partial: int = 0          # inspected with size/time limits
    files_skipped: int = 0          # intentionally not inspected (mode filter)
    files_unable: int = 0           # attempted but failed
    symlinks_skipped: int = 0
    special_skipped: int = 0
    bytes_scanned: int = 0
    threats_found: int = 0
    archives_inspected: int = 0
    estimate_total: Optional[int] = None
    estimate_complete: bool = False


class TimelineEntry(BaseModel):
    ts: float = Field(default_factory=time.time)
    level: str = "info"             # info | warn | error
    message: str
    path: Optional[str] = None


class ScanEvent(BaseModel):
    seq: int = 0
    ts: float = Field(default_factory=time.time)
    type: str                       # phase|file|dir|threat|unable|progress|info|error|end
    level: str = "info"
    message: str
    path: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)


class ScanRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    device_id: str = ""
    device_label: str = ""
    device_mount: str = ""
    mode: ScanMode = ScanMode.FULL
    custom_paths: list[str] = Field(default_factory=list)
    status: ScanStatus = ScanStatus.QUEUED
    outcome: ScanOutcome = ScanOutcome.PENDING
    counters: ScanCounters = Field(default_factory=ScanCounters)
    created_at: float = Field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    engines: list[str] = Field(default_factory=list)
    engine_versions: dict[str, str] = Field(default_factory=dict)
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    agent_version: str = ""

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at is None:
            return None
        end = self.finished_at or time.time()
        return round(end - self.started_at, 1)


# --------------------------------------------------------------------------- API payloads
class ScanRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    mode: ScanMode = ScanMode.FULL
    custom_paths: list[str] = Field(default_factory=list, max_length=200)


class ConfirmRequest(BaseModel):
    confirm: bool = False


class QuarantineRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=64)


class QuarantineRestoreRequest(BaseModel):
    confirm: bool = False
    # Original location is preferred; fallback into the agent's restore inbox.
    destination: str = "original"   # "original" | "inbox"


class HistoryDeleteRequest(BaseModel):
    confirm: bool = False


class PairResponse(BaseModel):
    client_id: str
    client_secret: str
    access_token: str
    expires_in: int
    token_type: str = "bearer"
    note: str


class TokenExchangeRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=64)
    client_secret: str = Field(min_length=1, max_length=128)


class TokenExchangeResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str = "bearer"


# --------------------------------------------------------------------------- quarantine
class QuarantineEntry(BaseModel):
    id: str
    finding_id: str = ""
    scan_id: str = ""
    device_id: str = ""
    device_label: str = ""
    original_path: str = ""
    container: Optional[str] = None
    detection_name: str = ""
    classification: Classification = Classification.SUSPICIOUS
    severity: Severity = Severity.LOW
    engine: str = ""
    sha256: str = ""
    size: int = 0
    status: QuarantineStatus = QuarantineStatus.QUARANTINED
    created_at: float = Field(default_factory=time.time)
    resolved_at: Optional[float] = None
    restored_to: Optional[str] = None


# --------------------------------------------------------------------------- accounts
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: Optional[str] = Field(default=None, max_length=10)


class TotpVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class UserPublic(BaseModel):
    username: str
    role: str
    totp_enabled: bool
