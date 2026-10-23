"""ClamAV integration over the clamd INSTREAM protocol.

- Speaks the documented ``zINSTREAM`` protocol directly (no third-party
  dependency): chunks are length-prefixed, terminated by a zero-length chunk,
  and clamd replies ``stream: OK`` or ``stream: <signature> FOUND``.
- Auto-detects the daemon via a unix socket or TCP fallback.
- ``update_signatures()`` shells out to ``freshclam`` with a fixed argv (never
  a shell string) - ClamAV's own updater authenticates its signature database
  cryptographically before loading it.

If clamd is not installed the engine reports itself unavailable; the agent
keeps running with its other engines and says so honestly in engine status.
"""
from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Iterator, Optional

from .base import Engine, Verdict
from ..models import Classification, Severity

CANDIDATE_SOCKETS = (
    "/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock", "/tmp/clamd.sock",
)
_PROBE_CACHE_SECONDS = 15


class ClamAvEngine(Engine):
    name = "clamav"
    description = "ClamAV daemon (clamd) real-time signature scanning"

    def __init__(self, socket_path: str = "", tcp: str = "127.0.0.1:3310",
                 timeout: int = 120, max_file_bytes: int = 256 * 1024 * 1024,
                 enabled: bool = True) -> None:
        super().__init__()
        self.socket_path = socket_path
        self.tcp = tcp
        self.timeout = timeout
        self.max_file_bytes = max_file_bytes
        self._enabled = enabled
        self._last_probe = 0.0
        self._probe_ok = False
        self._version = ""
        self._detail = ""

    # ------------------------------------------------------------- transport
    def _connect(self) -> socket.socket:
        path = self.socket_path
        if not path:
            for cand in CANDIDATE_SOCKETS:
                if Path(cand).exists():
                    path = cand
                    break
        if path:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect(path)
                return s
            except OSError:
                s.close()
                pass
        host, _, port = self.tcp.partition(":")
        s = socket.create_connection((host, int(port or 3310)), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    def _command(self, payload: bytes, recv_limit: int = 65536) -> bytes:
        s = self._connect()
        with s:
            s.sendall(payload)
            out = b""
            while len(out) < recv_limit:
                try:
                    data = s.recv(min(4096, recv_limit - len(out)))
                except socket.timeout:
                    break
                if not data:
                    break
                out += data
                if payload.startswith(b"z") and out:
                    break          # one-shot commands: first reply chunk suffices
            return out

    # ---------------------------------------------------------------- status
    def _probe(self) -> bool:
        if not self._enabled:
            self._detail = "disabled by configuration"
            self._probe_ok = False
            return False
        now = time.monotonic()
        if now - self._last_probe < _PROBE_CACHE_SECONDS:
            return self._probe_ok
        self._last_probe = now
        try:
            pong = self._command(b"zPING\x00")
            self._probe_ok = pong.strip() == b"PONG"
            if self._probe_ok:
                ver = self._command(b"zVERSION\x00").decode("utf-8", "replace").strip()
                # e.g. "ClamAV 1.0.5/27105/Mon Feb 12 08:26:32 2024"
                self._version = ver
                self._detail = "daemon reachable"
            else:
                self._detail = f"unexpected reply from clamd: {pong!r}"
        except OSError as exc:
            self._probe_ok = False
            self._detail = ("clamd not reachable (install ClamAV for full malware "
                            f"signature coverage): {exc.strerror or exc}")
        return self._probe_ok

    def available(self) -> bool:
        return bool(self._enabled and self._probe())

    def version(self) -> str:
        return self._version or "unavailable"

    def status_detail(self) -> str:
        self._probe()
        return self._detail

    # --------------------------------------------------------------- scanning
    def scan_stream(self, *, path, rel, chunks: Iterator[bytes], size) -> list[Verdict]:
        if size > self.max_file_bytes:
            return []    # caller records a partial-inspection note instead
        if not self.available():
            return []
        sig = self.instream(chunks)
        if sig:
            return [self._verdict_for(sig)]
        return []

    def instream(self, chunks: Iterator[bytes]) -> Optional[str]:
        """Returns the detection signature name, or None when clean."""
        s = self._connect()
        with s:
            s.sendall(b"zINSTREAM\x00")
            for chunk in chunks:
                if not chunk:
                    continue
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            reply = b""
            while b"\n" not in reply and len(reply) < 65536:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    raise RuntimeError("clamd timed out while scanning")
                if not data:
                    break
                reply += data
        text = reply.decode("utf-8", "replace").strip()
        if text.endswith("FOUND"):
            sig = text[len("stream:"):].rsplit("FOUND", 1)[0].strip()
            return sig or "Unknown"
        if text.endswith("OK") or text == "stream: OK":
            return None
        if "ERROR" in text:
            raise RuntimeError(f"clamd scan error: {text}")
        return None

    @staticmethod
    def _verdict_for(sig: str) -> Verdict:
        lower = sig.lower()
        is_pua = lower.startswith(("pua.", "pup.", "riskware")) or ".pua." in lower
        is_test = "test" in lower or "eicar" in lower
        if is_pua:
            return Verdict(Classification.PUA, sig, Severity.MEDIUM,
                           "ClamAV PUA signature match", ClamAvEngine.name,
                           {"signature": sig}, is_test=False)
        return Verdict(Classification.MALICIOUS, sig, Severity.CRITICAL,
                       "ClamAV malware signature match", ClamAvEngine.name,
                       {"signature": sig}, is_test=is_test)


def run_freshclam(timeout: int = 600) -> tuple[bool, str]:
    """Update the ClamAV signature database via freshclam.

    freshclam authenticates database updates (CDIFF/CVD digital signatures)
    itself; we simply run it with a fixed argument list and capture output.
    """
    exe = shutil.which("freshclam")
    if not exe:
        return False, "freshclam is not installed on this host"
    try:
        proc = subprocess.run(
            [exe, "--stdout", "--datadir", _freshclam_datadir()],
            capture_output=True, text=True, timeout=timeout, check=False)
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0 or "Database updated" in out or "up-to-date" in out.lower()
        return ok, out[-4000:]
    except subprocess.TimeoutExpired:
        return False, f"freshclam timed out after {timeout}s"


def _freshclam_datadir() -> str:
    for cand in ("/var/lib/clamav", "/usr/local/share/clamav", "/usr/share/clamav"):
        if Path(cand).exists():
            return cand
    return "/var/lib/clamav"
