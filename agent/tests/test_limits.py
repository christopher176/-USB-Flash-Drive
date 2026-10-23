"""Reliability: oversized files, unreadable files, changed files, limits,
device disconnect, cancellation. Incomplete scans must never read 'clean'."""
import os
import threading
import time
from pathlib import Path

import pytest

from .conftest import add_clean, add_file, start_scan, wait_scan, get_findings


def test_oversized_file_marked_partial_not_clean(client, auth, device_dir,
                                                 run_scan):
    client.patch("/api/config", headers=auth, json={"max_file_bytes": 4096})
    add_file(device_dir, "videos/big.iso", b"\x11" * (1024 * 1024))
    add_clean(device_dir, "docs/small.txt")
    rec, findings = run_scan("full")
    assert rec["status"] == "completed"
    assert rec["outcome"] == "no_threats_with_gaps"     # NOT clean
    partials = [f for f in findings if f["status"] == "partial"]
    assert any(f["path"] == "videos/big.iso" for f in partials)
    assert rec["counters"]["files_partial"] >= 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_permission_denied_file_reported_unable(client, auth, device_dir,
                                                run_scan):
    p = add_file(device_dir, "locked/secret.txt", b"content")
    p.chmod(0o000)
    try:
        rec, findings = run_scan("full")
    finally:
        p.chmod(0o644)
    assert rec["outcome"] == "no_threats_with_gaps"
    unables = [f for f in findings if f["classification"] == "unable_to_scan"]
    assert any(f["path"] == "locked/secret.txt"
               and "permission denied" in f["reason"] for f in unables)
    assert rec["counters"]["files_unable"] >= 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_permission_denied_directory_reported(client, auth, device_dir, run_scan):
    d = device_dir / "restricted"
    (d / "inner").mkdir(parents=True)
    (d / "inner" / "file.txt").write_bytes(b"x")
    d.chmod(0o000)
    add_clean(device_dir, "open/readme.txt")
    try:
        rec, findings = run_scan("full")
    finally:
        d.chmod(0o755)
    assert rec["counters"]["dirs_failed"] >= 1
    assert rec["outcome"] == "no_threats_with_gaps"


def test_symlinked_files_skipped_and_counted(client, auth, device_dir, run_scan):
    real = add_clean(device_dir, "real.txt")
    os.symlink(real, device_dir / "alias.txt")
    rec, findings = run_scan("full")
    assert rec["counters"]["symlinks_skipped"] == 1
    assert rec["outcome"] == "clean"
    assert not any(f["path"] == "alias.txt" for f in findings)


def test_file_modified_during_scan_not_certified(app, client, auth, device_dir,
                                                 run_scan):
    # patch snapshot to always report a change for a specific file
    import usb_shield.walker as walker
    original = walker.snapshot_file

    flaky = {"done": 0}

    def wrapped(path, buffer_cap, header_bytes=4096):
        snap = original(path, buffer_cap, header_bytes)
        if path.name == "flaky.txt" and flaky["done"] < 2:
            flaky["done"] += 1
            snap.changed = True
        return snap

    import usb_shield.scanner as scanner
    scanner.snapshot_file = wrapped
    try:
        add_file(device_dir, "flaky.txt", b"changing content")
        add_clean(device_dir, "stable.txt")
        rec, findings = run_scan("full")
    finally:
        scanner.snapshot_file = original
    assert rec["outcome"] == "no_threats_with_gaps"
    unables = [f for f in findings if f["path"] == "flaky.txt"]
    assert unables and "changed" in unables[0]["reason"]


def test_device_disconnected_mid_scan(app, client, auth, device_id, device_dir):
    import shutil
    for i in range(200):
        add_file(device_dir, f"bulk/f{i:04d}.bin", os.urandom(64 * 1024))
    import usb_shield.scanner as scanner_mod
    rec = start_scan(client, auth, device_id, "full")

    def rip_out():
        time.sleep(0.15)
        shutil.rmtree(device_dir, ignore_errors=True)

    t = threading.Thread(target=rip_out, daemon=True)
    t.start()
    done = wait_scan(client, auth, rec["id"], timeout=30)
    t.join()
    if done["status"] == "completed":
        # device was ripped after the scan finished; acceptable race outcome
        pytest.skip("scan finished before simulated removal took effect")
    assert done["status"] == "failed"
    assert done["error_code"] == "DEVICE_DISCONNECTED"
    assert done["outcome"] == "incomplete"


def test_cancel_scan(app, client, auth, device_id, device_dir):
    for i in range(300):
        add_file(device_dir, f"big/f{i:03d}.bin", os.urandom(1024 * 1024))
    rec = start_scan(client, auth, device_id, "full")
    time.sleep(0.2)
    r = client.post(f"/api/scans/{rec['id']}/cancel", headers=auth)
    assert r.status_code == 200
    done = wait_scan(client, auth, rec["id"], timeout=60)
    if done["status"] == "completed" and done["outcome"] != "incomplete":
        pytest.skip("scan completed before cancel landed (fast disk)")
    assert done["status"] == "cancelled"
    assert done["outcome"] == "incomplete"
    assert done["error_code"] == "CANCELLED"


def test_config_rejects_invalid_values(client, auth):
    r = client.patch("/api/config", headers=auth, json={"max_depth": 0})
    assert r.status_code == 422
    r = client.patch("/api/config", headers=auth, json={"nonsense_key": 1})
    assert r.status_code == 422
    r = client.patch("/api/config", headers=auth,
                     json={"archive_max_ratio": 1})
    assert r.status_code == 422
    ok = client.patch("/api/config", headers=auth, json={"max_depth": 40})
    assert ok.status_code == 200
    assert ok.json()["max_depth"] == 40


def test_fake_device_id_rejected(client, auth):
    r = client.post("/api/scans", headers=auth,
                    json={"device_id": "deadbeefdeadbeef", "mode": "full",
                          "custom_paths": []})
    assert r.status_code == 404
    assert "system drives" in r.json()["detail"]
