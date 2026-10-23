"""End-to-end scan behaviour through the HTTP API."""
import os
import time
from pathlib import Path

import pytest

from .conftest import (add_clean, add_eicar, add_file, get_findings, make_zip,
                       start_scan, wait_scan)


def build_rich_device(root: Path) -> None:
    add_clean(root, "Documents/readme.txt")
    add_clean(root, "a/b/c/d/e/f/deep-notes.txt")
    add_eicar(root, "Downloads/setup.exe")               # root-ish detection
    add_eicar(root, ".hidden/payload.com")               # hidden dir detection
    add_eicar(root, "System Volume Information/svi.dat") # system dir detection
    add_file(root, "autorun.inf", b"[autorun]\nopen=setup.exe\n")
    add_file(root, "photos/report.pdf.exe", b"double ext content")
    add_file(root, ".hidden/run.vbs",
             b'CreateObject("WScript.Shell").Run "powershell -enc AAAA"\n')


def test_full_scan_finds_hidden_and_system_detections(client, auth, device_dir,
                                                      run_scan):
    build_rich_device(device_dir)
    rec, findings = run_scan("full")
    assert rec["status"] == "completed"
    assert rec["outcome"] == "threats_found"
    paths = {f["path"] for f in findings}
    assert "Downloads/setup.exe" in paths
    assert ".hidden/payload.com" in paths                    # hidden covered
    assert "System Volume Information/svi.dat" in paths      # system covered
    assert any(f["detection_name"] == "Heur.Autorun.AutoStart" for f in findings)
    assert any(f["detection_name"] == "Heur.Name.DoubleExtension" for f in findings)
    by_path = {f["path"]: f for f in findings}
    eicar = by_path["Downloads/setup.exe"]
    assert eicar["classification"] == "malicious"
    assert eicar["is_test_detection"] is True
    assert eicar["sha256"]
    assert eicar["recommended_action"]
    c = rec["counters"]
    assert c["files_scanned"] >= 8
    assert c["entries_seen"] == c["estimate_total"]
    assert c["estimate_complete"] is True
    assert c["dirs_scanned"] >= 6
    assert rec["duration_seconds"] is not None
    assert "eicar-test-signature" in rec["engines"]


def test_heuristics_never_classified_malicious(client, auth, device_dir, run_scan):
    add_file(device_dir, "photo.jpg", b"MZ" + b"\x90" * 300)
    rec, findings = run_scan("full")
    suspicious = [f for f in findings if f["detection_name"].startswith("Heur.")]
    assert suspicious
    assert all(f["classification"] != "malicious" for f in suspicious)


def test_clean_device_outcome_clean(client, auth, device_dir, run_scan):
    add_clean(device_dir, "docs/a.txt")
    add_clean(device_dir, "docs/b/nested.txt")
    rec, findings = run_scan("full")
    assert rec["status"] == "completed"
    assert rec["outcome"] == "clean"
    assert findings == []


def test_quick_scan_is_scoped_and_honest(client, auth, device_dir, run_scan):
    add_eicar(device_dir, ".hidden/eicar.com")          # hidden → covered by quick
    add_clean(device_dir, "Deep/Folder/Many/boring.txt")  # low-risk → skipped
    add_clean(device_dir, "Deep/Folder/Many/boring2.txt")
    rec, findings = run_scan("quick")
    assert rec["status"] == "completed"
    assert rec["outcome"] in ("clean", "threats_found")
    paths = {f["path"] for f in findings}
    assert ".hidden/eicar.com" in paths            # high-risk content found
    assert rec["counters"]["files_skipped"] >= 2   # boring files were skipped
    assert rec["counters"]["files_scanned"] >= 1


def test_custom_scan_scopes_and_validates(client, auth, device_id, device_dir,
                                          run_scan):
    add_clean(device_dir, "wanted/a.txt")
    add_eicar(device_dir, "wanted/eicar.com")
    add_eicar(device_dir, "unrelated/eicar2.com")
    rec, findings = run_scan("custom", ["wanted"])
    paths = {f["path"] for f in findings}
    assert "wanted/eicar.com" in paths
    assert "unrelated/eicar2.com" not in paths     # out-of-scope not scanned
    # path traversal must be rejected
    r = start = None
    from .conftest import CSRF
    r = client.post("/api/scans", headers=auth,
                    json={"device_id": device_id, "mode": "custom",
                          "custom_paths": ["../../etc"]})
    assert r.status_code == 422
    r = client.post("/api/scans", headers=auth,
                    json={"device_id": device_id, "mode": "custom",
                          "custom_paths": ["missing/folder"]})
    assert r.status_code == 422


def test_scan_events_stream_progress_and_end(client, auth, device_id, device_dir):
    for i in range(30):
        add_clean(device_dir, f"folder{i%5}/file{i}.txt")
    rec = start_scan(client, auth, device_id, "full")
    done = wait_scan(client, auth, rec["id"])
    r = client.get(f"/api/scans/{rec['id']}/events", headers=auth,
                   params={"since": 0})
    assert r.status_code == 200
    payload = r.json()
    assert payload["done"] is True
    types = [e["type"] for e in payload["events"]]
    assert "phase" in types and "end" in types
    end = [e for e in payload["events"] if e["type"] == "end"][-1]
    assert end["data"]["outcome"] == done["outcome"]


def test_events_pagination_with_since(client, auth, device_id, device_dir):
    for i in range(10):
        add_clean(device_dir, f"f{i}.txt")
    rec = start_scan(client, auth, device_id, "full")
    wait_scan(client, auth, rec["id"])
    first = client.get(f"/api/scans/{rec['id']}/events", headers=auth).json()
    seen = {e["seq"] for e in first["events"]}
    second = client.get(f"/api/scans/{rec['id']}/events", headers=auth,
                        params={"since": first["next"]}).json()
    assert all(e["seq"] not in seen for e in second["events"])


def test_concurrent_scan_rejected(client, auth, device_id, device_dir):
    for i in range(400):
        add_file(device_dir, f"bulk/f{i}.bin", os.urandom(2048))
    rec = start_scan(client, auth, device_id, "full")
    r = client.post("/api/scans", headers=auth,
                    json={"device_id": device_id, "mode": "quick"})
    assert r.status_code == 409
    client.post(f"/api/scans/{rec['id']}/cancel", headers=auth)
    wait_scan(client, auth, rec["id"])


def test_unknown_scan_404(client, auth):
    r = client.get("/api/scans/doesnotexist", headers=auth)
    assert r.status_code == 404
    r = client.get("/api/scans/doesnotexist/events", headers=auth)
    assert r.status_code == 404
