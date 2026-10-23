"""Quarantine vault.

Suspect files are copied off the device, encrypted at rest with AES-256-GCM
(key generated locally, stored with 0600 permissions, never leaving the
machine), hashed, and indexed in the SQLite manifest.  Only after the
encrypted copy is durably written is the original unlinked from the device.

Safety properties:
  * vault directory is 0700, blobs 0600, filenames are random ids
  * blob plaintext is never executable (encrypted bytes, no exec bits)
  * restore verifies the SHA-256 recorded at quarantine time
  * every action is audit-logged
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .drives import DeviceRegistry
from .models import (Classification, Finding, QuarantineEntry, QuarantineStatus)
from .store import Store
from .walker import resolve_within, snapshot_file

MAGIC = b"USQ1"
NONCE_LEN = 12


class QuarantineError(Exception):
    pass


class Quarantine:
    def __init__(self, data_dir: Path, store: Store, registry: DeviceRegistry):
        self.dir = data_dir / "quarantine"
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            self.dir.chmod(0o700)
        except OSError:
            pass
        self.store = store
        self.registry = registry
        self._aes = AESGCM(self._load_key(data_dir))
        self.restore_inbox = data_dir / "restored"
        self.restore_inbox.mkdir(parents=True, exist_ok=True)
        try:
            self.restore_inbox.chmod(0o700)
        except OSError:
            pass

    # ---------------------------------------------------------------- key mgmt
    @staticmethod
    def _load_key(data_dir: Path) -> bytes:
        keyfile = data_dir / "quarantine.key"
        if keyfile.exists():
            key = keyfile.read_bytes()
            if len(key) != 32:
                raise QuarantineError("quarantine key file is corrupt; refusing to start")
            return key
        key = secrets.token_bytes(32)
        fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key

    # --------------------------------------------------------------- encrypt
    def _encrypt(self, data: bytes, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(NONCE_LEN)
        return MAGIC + nonce + self._aes.encrypt(nonce, data, aad)

    def _decrypt(self, blob: bytes, aad: bytes) -> bytes:
        if not blob.startswith(MAGIC):
            raise QuarantineError("quarantine blob has an invalid header")
        nonce = blob[len(MAGIC):len(MAGIC) + NONCE_LEN]
        body = blob[len(MAGIC) + NONCE_LEN:]
        try:
            return self._aes.decrypt(nonce, body, aad)
        except InvalidTag as exc:
            raise QuarantineError("quarantine blob failed integrity verification "
                                  "(tampered or wrong key)") from exc

    def _aad(self, sha256: str, original_path: str) -> bytes:
        return f"{sha256}|{original_path}".encode("utf-8")

    def _write_blob(self, name: str, payload: bytes) -> Path:
        path = self.dir / name
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        return path

    # ------------------------------------------------------------- operations
    def quarantine(self, finding: Finding, device_label: str = "") -> QuarantineEntry:
        if finding.classification not in (Classification.MALICIOUS,
                                          Classification.SUSPICIOUS,
                                          Classification.PUA):
            raise QuarantineError("only detected threats can be quarantined")
        if finding.container is not None or "::" in finding.path:
            raise QuarantineError(
                "files inside archives cannot be quarantined individually; "
                "quarantine or delete the archive itself")
        device = self.registry.get(finding.device_id)
        if device is None or not device.available:
            raise QuarantineError("device is not currently connected; "
                                  "reconnect it before quarantining")
        try:
            target = resolve_within(Path(device.mount_point), finding.path)
        except ValueError as exc:
            raise QuarantineError(f"invalid quarantine path: {exc}") from exc

        try:
            snap = snapshot_file(target, buffer_cap=256 * 1024 * 1024)
        except OSError as exc:
            raise QuarantineError(f"cannot read original file: "
                                  f"{exc.strerror or exc}") from exc
        if snap.body is None:
            raise QuarantineError("file too large to quarantine safely")
        if finding.sha256 and snap.sha256 and snap.sha256 != finding.sha256:
            raise QuarantineError(
                "file changed since it was scanned (hash mismatch); "
                "rescan before taking action")

        data = snap.body
        sha256 = snap.sha256 or hashlib.sha256(data).hexdigest()
        qid = uuid.uuid4().hex
        blob_name = f"{qid}.usq"
        payload = self._encrypt(data, self._aad(sha256, finding.path))
        self._write_blob(blob_name, payload)

        # Encrypted copy is durable; NOW remove the original from the device.
        try:
            os.remove(target)
        except OSError as exc:
            try:
                (self.dir / blob_name).unlink(missing_ok=True)
            except OSError:
                pass
            raise QuarantineError(
                f"could not remove original from device: {exc.strerror or exc}; "
                "the file has NOT been quarantined") from exc

        entry = QuarantineEntry(
            id=qid, finding_id=finding.id, scan_id=finding.scan_id,
            device_id=finding.device_id, device_label=device_label,
            original_path=finding.path, container=finding.container,
            detection_name=finding.detection_name,
            classification=finding.classification, severity=finding.severity,
            engine=finding.engine, sha256=sha256, size=len(data))
        self.store.save_quarantine(entry, blob_name)
        self.store.mark_finding_quarantined(finding.id)
        self.store.audit("quarantine.create", actor="agent",
                         detail=f"{finding.path} ({finding.detection_name})")
        return entry

    def restore(self, qid: str, destination: str = "original") -> QuarantineEntry:
        got = self.store.get_quarantine(qid)
        if not got:
            raise QuarantineError("quarantine entry not found")
        entry, blob_name = got
        if entry.status != QuarantineStatus.QUARANTINED:
            raise QuarantineError("only quarantined items can be restored")
        blob_path = self.dir / blob_name
        if not blob_path.exists():
            raise QuarantineError("quarantine blob is missing from the vault")
        data = self._decrypt(blob_path.read_bytes(),
                             self._aad(entry.sha256, entry.original_path))
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            raise QuarantineError("decrypted content failed hash verification; "
                                  "restore aborted")

        import time as _t
        if destination == "original":
            device = self.registry.get_anywhere(entry.device_id)
            if device is None or not os.path.isdir(device.mount_point):
                raise QuarantineError(
                    "original device is not connected; restore to the inbox instead "
                    "or reconnect the device")
            try:
                target = resolve_within(Path(device.mount_point), entry.original_path)
            except ValueError as exc:
                raise QuarantineError(f"unsafe restore path: {exc}") from exc
            if not target.parent.is_dir():
                raise QuarantineError("original folder no longer exists on the device")
            if target.exists():
                raise QuarantineError("a file already exists at the original location; "
                                      "refusing to overwrite")
        else:
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_"
                                for c in Path(entry.original_path).name)[:120]
            target = self.restore_inbox / f"{int(_t.time())}_{safe_name}"
            if target.exists():
                target = self.restore_inbox / f"{uuid.uuid4().hex[:8]}_{safe_name}"

        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.unlink(target)
            except OSError:
                pass
            raise
        entry.status = QuarantineStatus.RESTORED
        import time as _time
        entry.resolved_at = _time.time()
        entry.restored_to = str(target)
        self.store.save_quarantine(entry, blob_name)
        self.store.audit("quarantine.restore", actor="user",
                         detail=f"{entry.original_path} -> {target}")
        return entry

    def delete(self, qid: str) -> QuarantineEntry:
        got = self.store.get_quarantine(qid)
        if not got:
            raise QuarantineError("quarantine entry not found")
        entry, blob_name = got
        if entry.status == QuarantineStatus.DELETED:
            raise QuarantineError("already deleted")
        try:
            (self.dir / blob_name).unlink(missing_ok=True)
        except OSError as exc:
            raise QuarantineError(f"could not delete quarantine blob: "
                                  f"{exc.strerror or exc}") from exc
        import time as _time
        entry.status = QuarantineStatus.DELETED
        entry.resolved_at = _time.time()
        self.store.save_quarantine(entry, blob_name)
        self.store.audit("quarantine.delete", actor="user",
                         detail=f"{entry.original_path} ({entry.detection_name})")
        return entry
