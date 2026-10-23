"""Quarantine lifecycle: isolation, encryption at rest, restore, delete."""
import hashlib
import os
from pathlib import Path

import pytest

from usb_shield.engines.eicar import EICAR_SIGNATURE

from .conftest import add_eicar, add_clean, add_file, make_zip


def _finding_for(findings, path):
    return next(f for f in findings if f["path"] == path)


def quarantine_one(client, auth, device_dir, rel="Downloads/setup.exe"):
    add_eicar(device_dir, rel)
    from .conftest import start_scan, wait_scan, get_findings
    rec = start_scan(client, auth, _device_id(client, auth, device_dir), "full")
    done = wait_scan(client, auth, rec["id"])
    findings = get_findings(client, auth, rec["id"])
    f = _finding_for(findings, rel)
    r = client.post("/api/quarantine", headers=auth,
                    json={"finding_id": f["id"]})
    assert r.status_code == 201, r.text
    return r.json(), done, f


def _device_id(client, auth, device_dir):
    r = client.get("/api/drives", headers=auth)
    return next(d["id"] for d in r.json()["devices"]
                if Path(d["mount_point"]) == device_dir)


def test_quarantine_removes_original_and_encrypts(client, auth, device_dir):
    entry, _, f = quarantine_one(client, auth, device_dir)
    original = device_dir / "Downloads/setup.exe"
    assert not original.exists()                       # removed from device
    assert entry["status"] == "quarantined"
    assert entry["sha256"] == f["sha256"]
    vault = Path(entry["original_path"])               # API returns rel path
    r = client.get("/api/quarantine", headers=auth)
    assert r.status_code == 200
    listed = r.json()["entries"]
    assert any(e["id"] == entry["id"] for e in listed)
    # find the blob on disk: must be encrypted, random-named, 0600
    data_dir = Path(str(device_dir)).parent / "agent-data"
    blobs = list((data_dir / "quarantine").glob("*.usq"))
    assert len(blobs) == 1
    blob = blobs[0]
    content = blob.read_bytes()
    assert content[:4] == b"USQ1"
    assert EICAR_SIGNATURE not in content              # actually encrypted
    assert (blob.stat().st_mode & 0o777) == 0o600
    assert not (blob.stat().st_mode & 0o111)           # never executable
    # tampering with the blob breaks integrity verification
    blob.write_bytes(content[:20] + b"\x00" + content[21:])
    r = client.post(f"/api/quarantine/{entry['id']}/restore", headers=auth,
                    json={"confirm": True, "destination": "inbox"})
    assert r.status_code == 422
    assert "integrity" in r.json()["detail"].lower() or "tampered" in r.json()["detail"].lower()


def test_restore_to_inbox_and_original(client, auth, device_dir):
    entry, _, f = quarantine_one(client, auth, device_dir)
    # without confirm -> refused
    r = client.post(f"/api/quarantine/{entry['id']}/restore", headers=auth,
                    json={"confirm": False, "destination": "inbox"})
    assert r.status_code == 400
    # restore to original location
    r = client.post(f"/api/quarantine/{entry['id']}/restore", headers=auth,
                    json={"confirm": True, "destination": "original"})
    assert r.status_code == 200, r.text
    restored = device_dir / "Downloads/setup.exe"
    assert restored.exists()
    assert hashlib.sha256(restored.read_bytes()).hexdigest() == f["sha256"]
    assert (restored.stat().st_mode & 0o777) == 0o600   # restored non-executable
    # entry state updated; second restore refused
    r = client.post(f"/api/quarantine/{entry['id']}/restore", headers=auth,
                    json={"confirm": True, "destination": "inbox"})
    assert r.status_code == 422


def test_restore_refuses_overwrite(client, auth, device_dir):
    entry, _, _ = quarantine_one(client, auth, device_dir)
    (device_dir / "Downloads").mkdir(parents=True, exist_ok=True)
    (device_dir / "Downloads/setup.exe").write_bytes(b"replacement")
    r = client.post(f"/api/quarantine/{entry['id']}/restore", headers=auth,
                    json={"confirm": True, "destination": "original"})
    assert r.status_code == 422
    assert (device_dir / "Downloads/setup.exe").read_bytes() == b"replacement"


def test_delete_quarantined_requires_confirm(client, auth, device_dir):
    entry, _, _ = quarantine_one(client, auth, device_dir)
    r = client.post(f"/api/quarantine/{entry['id']}/delete", headers=auth,
                    json={"confirm": False})
    assert r.status_code == 400
    r = client.post(f"/api/quarantine/{entry['id']}/delete", headers=auth,
                    json={"confirm": True})
    assert r.status_code == 200
    data_dir = Path(str(device_dir)).parent / "agent-data"
    assert not list((data_dir / "quarantine").glob("*.usq"))
    r = client.post(f"/api/quarantine/{entry['id']}/delete", headers=auth,
                    json={"confirm": True})
    assert r.status_code == 422                       # already deleted


def test_hash_mismatch_blocks_quarantine(client, auth, device_dir, run_scan):
    p = add_eicar(device_dir, "Downloads/setup.exe")
    rec, findings = run_scan("full")
    f = _finding_for(findings, "Downloads/setup.exe")
    p.write_bytes(b"totally different content now")    # changed since scan
    r = client.post("/api/quarantine", headers=auth, json={"finding_id": f["id"]})
    assert r.status_code == 422
    assert "changed" in r.json()["detail"].lower()
    assert p.exists()                                  # untouched


def test_archive_member_cannot_be_quarantined(client, auth, device_dir, run_scan):
    from usb_shield.engines.eicar import EICAR_SIGNATURE as SIG
    add_file(device_dir, "arc.zip", make_zip({"evil.com": SIG}))
    rec, findings = run_scan("full")
    member = _finding_for(findings, "arc.zip::evil.com")
    r = client.post("/api/quarantine", headers=auth,
                    json={"finding_id": member["id"]})
    assert r.status_code == 422
    assert "archive" in r.json()["detail"].lower()


def test_clean_files_refused(client, auth, device_dir, run_scan):
    add_clean(device_dir, "docs/a.txt")
    rec, findings = run_scan("full")
    assert findings == []
    r = client.post("/api/quarantine", headers=auth,
                    json={"finding_id": "0" * 32})
    assert r.status_code == 404


def test_quarantine_actions_are_audited(client, auth, device_dir):
    entry, _, _ = quarantine_one(client, auth, device_dir)
    client.post(f"/api/quarantine/{entry['id']}/delete", headers=auth,
                json={"confirm": True})
    r = client.get("/api/audit", headers=auth)
    actions = {e["action"] for e in r.json()["events"]}
    assert "quarantine.create" in actions
    assert "quarantine.delete" in actions
