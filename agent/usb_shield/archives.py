"""Safe, in-memory inspection of archives.

Supported for content scanning: zip, tar, tar.gz, tar.bz2, tar.xz.
Unsupported formats (rar, 7z, iso, cab, plain gzip) are *reported* as
unscannable - never silently accepted as clean.

Guards against archive bombs and resource exhaustion:
  * depth limit (archives inside archives)
  * member count limit
  * per-member and total decompressed-byte limits
  * compression-ratio checks (declared and observed)
  * wall-clock budget
Members are never extracted to disk; scanning happens on capped buffers.
"""
from __future__ import annotations

import io
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import RuntimeOptions
from .engines.base import Verdict

ZIP_EXTS = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk"}
TAR_EXTS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"}
UNSUPPORTED_ARCHIVE_EXTS = {".rar", ".7z", ".iso", ".cab", ".gz", ".bz2", ".xz",
                            ".zst", ".lz4", ".ace", ".arj"}

MAGIC_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_BZIP2 = b"BZh"
MAGIC_XZ = b"\xfd7zXZ\x00"


def archive_kind(name: str, header: bytes) -> Optional[str]:
    """→ "zip" | "tar" | "unsupported" | None."""
    lower = name.lower()
    if any(header.startswith(m) for m in MAGIC_ZIP) or any(
            lower.endswith(e) for e in ZIP_EXTS):
        return "zip"
    if header.startswith(MAGIC_GZIP) or header.startswith(MAGIC_BZIP2) or \
            header.startswith(MAGIC_XZ) or header[257:262] == b"ustar" or \
            any(lower.endswith(e) for e in TAR_EXTS):
        return "tar"
    if any(lower.endswith(e) for e in UNSUPPORTED_ARCHIVE_EXTS):
        return "unsupported"
    return None


@dataclass
class MemberResult:
    inner_path: str            # "outer.zip::dir/evil.exe" (nesting via ::)
    name: str
    size: int = 0
    encrypted: bool = False
    truncated: bool = False
    error: Optional[str] = None
    verdicts: list[Verdict] = field(default_factory=list)


@dataclass
class ArchiveReport:
    results: list[MemberResult] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)
    fatal_error: Optional[str] = None
    declared_members: int = 0
    fully_scanned: bool = True

    def hit(self, name: str) -> None:
        if name not in self.limits_hit:
            self.limits_hit.append(name)
        self.fully_scanned = False


class _Budget:
    def __init__(self, cfg: RuntimeOptions, container_size: int):
        self.cfg = cfg
        self.container_size = max(1, container_size)
        self.spent = 0
        self.start = time.monotonic()
        self.deadline = self.start + cfg.archive_time_budget_seconds

    def consume(self, n: int) -> bool:
        self.spent += n
        return self.spent <= self.cfg.archive_max_total_bytes

    def time_left(self) -> bool:
        return time.monotonic() < self.deadline

    def observed_ratio_exceeded(self) -> bool:
        return (self.spent > 10_000_000 and
                self.spent / self.container_size > self.cfg.archive_max_ratio)


MemberScanner = Callable[[str, str, bytes], list[Verdict]]


def inspect_archive(rel: str, data: bytes, cfg: RuntimeOptions,
                    member_scan: MemberScanner, depth: int = 0,
                    budget: Optional[_Budget] = None) -> ArchiveReport:
    budget = budget or _Budget(cfg, len(data))
    report = ArchiveReport()
    kind = archive_kind(rel, data[:512])
    if kind == "zip":
        _inspect_zip(rel, data, cfg, member_scan, depth, budget, report)
    elif kind == "tar":
        _inspect_tar(rel, data, cfg, member_scan, depth, budget, report)
    else:
        report.fatal_error = "not a supported archive"
        report.fully_scanned = False
    if budget.observed_ratio_exceeded():
        report.hit("compression_ratio")
    return report


def _scan_member(report: ArchiveReport, inner_path: str, name: str, buf: bytes,
                 cfg: RuntimeOptions, member_scan: MemberScanner, depth: int,
                 budget: _Budget, truncated: bool) -> None:
    verdicts: list[Verdict] = []
    err: Optional[str] = None
    try:
        verdicts = member_scan(inner_path, name, buf)
    except Exception as exc:                       # engine crash ≠ clean file
        err = f"engine error on member: {exc}"
        report.hit("engine_error")
    nested_kind = archive_kind(name, buf[:512])
    if nested_kind in ("zip", "tar") and err is None:
        if depth + 1 > cfg.archive_max_depth:
            report.hit("nesting_depth")
            verdicts.append(_limit_verdict(
                f"archive nested deeper than inspection limit ({cfg.archive_max_depth})"))
        else:
            sub = inspect_archive(inner_path, buf, cfg, member_scan,
                                  depth + 1, budget)
            report.results.extend(sub.results)
            for lim in sub.limits_hit:
                report.hit(lim)
            if sub.fatal_error:
                err = f"nested archive unreadable: {sub.fatal_error}"
    report.results.append(MemberResult(inner_path=inner_path, name=name,
                                       size=len(buf),
                                       truncated=truncated, error=err,
                                       verdicts=verdicts))


def _limited_read(fh, cap: int) -> tuple[bytes, bool]:
    buf = fh.read(cap + 1)
    if len(buf) > cap:
        return buf[:cap], True
    return buf, False


def _control_loop(i: int, total: int, cfg: RuntimeOptions, budget: _Budget,
                  report: ArchiveReport) -> bool:
    """Shared limits for zip/tar loops. True → keep going."""
    if i >= cfg.archive_max_members:
        report.hit("member_count")
        return False
    if not budget.time_left():
        report.hit("time_budget")
        return False
    if budget.spent > cfg.archive_max_total_bytes:
        report.hit("total_bytes")
        return False
    return True


def _inspect_zip(rel: str, data: bytes, cfg: RuntimeOptions,
                 member_scan: MemberScanner, depth: int, budget: _Budget,
                 report: ArchiveReport) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        report.fatal_error = f"malformed zip archive: {exc}"
        report.fully_scanned = False
        return
    with zf:
        infos = zf.infolist()
        report.declared_members = len(infos)
        for i, info in enumerate(infos):
            if not _control_loop(i, len(infos), cfg, budget, report):
                break
            if info.is_dir():
                continue
            inner = f"{rel}::{info.filename}"
            if info.flag_bits & 0x1:
                report.hit("encrypted_members")
                report.results.append(MemberResult(
                    inner_path=inner, name=info.filename, size=info.file_size,
                    encrypted=True, error="encrypted member - cannot inspect"))
                continue
            declared_ratio = (info.file_size / max(1, info.compress_size))
            if info.file_size > cfg.archive_max_member_bytes:
                report.hit("member_size")
                report.results.append(MemberResult(
                    inner_path=inner, name=info.filename, size=info.file_size,
                    error=f"declared size {info.file_size} exceeds inspection "
                          f"limit {cfg.archive_max_member_bytes}"))
                if declared_ratio > cfg.archive_max_ratio:
                    report.hit("member_ratio")
                continue
            try:
                with zf.open(info) as fh:
                    buf, truncated = _limited_read(fh, cfg.archive_max_member_bytes)
            except RuntimeError as exc:
                report.hit("encrypted_members")
                report.results.append(MemberResult(
                    inner_path=inner, name=info.filename, size=info.file_size,
                    encrypted=True, error=f"cannot read member: {exc}"))
                continue
            except (zipfile.BadZipFile, EOFError, OSError) as exc:
                report.hit("corrupt_members")
                report.results.append(MemberResult(
                    inner_path=inner, name=info.filename, size=info.file_size,
                    error=f"corrupt member: {exc}"))
                continue
            budget.consume(len(buf))
            if declared_ratio > cfg.archive_max_ratio and info.file_size > 1_000_000:
                report.hit("member_ratio")
            _scan_member(report, inner, info.filename, buf, cfg, member_scan,
                         depth, budget, truncated or
                         info.file_size > len(buf))


def _inspect_tar(rel: str, data: bytes, cfg: RuntimeOptions,
                 member_scan: MemberScanner, depth: int, budget: _Budget,
                 report: ArchiveReport) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        report.fatal_error = f"malformed tar archive: {exc}"
        report.fully_scanned = False
        return
    with tf:
        i = -1
        for member in tf:
            i += 1
            if not _control_loop(i, 0, cfg, budget, report):
                break
            report.declared_members += 1
            if member.isdir():
                continue
            if not member.isreg():
                # symlinks/hardlinks/devices inside archives are not followed
                report.results.append(MemberResult(
                    inner_path=f"{rel}::{member.name}", name=member.name,
                    size=member.size,
                    error="non-regular member (link/device) - skipped"))
                continue
            inner = f"{rel}::{member.name}"
            if member.size > cfg.archive_max_member_bytes:
                report.hit("member_size")
                report.results.append(MemberResult(
                    inner_path=inner, name=member.name, size=member.size,
                    error=f"declared size {member.size} exceeds inspection limit "
                          f"{cfg.archive_max_member_bytes}"))
                continue
            fh = tf.extractfile(member)
            if fh is None:
                report.hit("corrupt_members")
                report.results.append(MemberResult(inner_path=inner,
                                                   name=member.name,
                                                   size=member.size,
                                                   error="cannot extract member"))
                continue
            try:
                buf, truncated = _limited_read(fh, cfg.archive_max_member_bytes)
            except (tarfile.TarError, EOFError, OSError) as exc:
                report.hit("corrupt_members")
                report.results.append(MemberResult(inner_path=inner,
                                                   name=member.name,
                                                   size=member.size,
                                                   error=f"corrupt member: {exc}"))
                continue
            budget.consume(len(buf))
            _scan_member(report, inner, member.name, buf, cfg, member_scan,
                         depth, budget, truncated or member.size > len(buf))


def _limit_verdict(msg: str) -> Verdict:
    from .models import Classification, Severity
    return Verdict(Classification.SUSPICIOUS, "Heur.Archive.InspectionLimit",
                   Severity.LOW, msg, "archive-inspector")
