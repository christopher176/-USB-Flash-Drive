"""Engine protocol and verdict type.

An engine answers: given a file's bytes (buffer or stream) and metadata,
what — if anything — is it?  Engines must never claim ``MALICIOUS`` from
heuristic signals alone; that classification is reserved for confirmed
(signature-backed) detections.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from ..models import Classification, Severity


@dataclass
class Verdict:
    classification: Classification
    detection_name: str
    severity: Severity = Severity.NONE
    method: str = ""
    engine: str = ""
    details: dict = field(default_factory=dict)
    is_test: bool = False


class Engine:
    """Base class.  Implementations must be side-effect free."""

    name = "engine"
    description = ""

    def __init__(self) -> None:
        self._available = True

    def available(self) -> bool:
        return self._available

    def version(self) -> str:
        return "built-in"

    def status_detail(self) -> str:
        return ""

    def scan_buffer(self, *, rel: str, name: str, data: bytes, size: int,
                    header: bytes, hidden: bool, system: bool) -> list[Verdict]:
        """Inspect an in-memory buffer (whole small files, archive members)."""
        return []

    def scan_stream(self, *, path: Path, rel: str, chunks: Iterator[bytes],
                    size: int) -> list[Verdict]:
        """Inspect a large file as a byte stream (e.g. ClamAV INSTREAM)."""
        return []
