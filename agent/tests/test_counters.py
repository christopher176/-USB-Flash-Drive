"""Counter accounting: every discovered filesystem entry is accounted for,
so UI numbers can never silently hide unscanned content."""
import os
from pathlib import Path

from .conftest import add_clean, add_eicar, add_file


def counter_consistency(rec):
    c = rec["counters"]
    # entries = dirs + files + symlinks + special; every file lands in at
    # least one disposition (files can be counted in partial+unable together
    # when multiple independent failures occurred; scanned/skipped are exact)
    assert c["entries_seen"] >= (c["dirs_scanned"] + c["symlinks_skipped"]
                                 + c["special_skipped"])
    total_file_dispositions = (c["files_scanned"] + c["files_skipped"]
                               + c["files_partial"] + c["files_unable"])
    files_present = c["entries_seen"] - c["dirs_scanned"] - \
        c["symlinks_skipped"] - c["special_skipped"]
    assert total_file_dispositions >= files_present


def test_mixed_device_counter_consistency(client, auth, device_dir, run_scan):
    for i in range(20):
        add_clean(device_dir, f"docs/f{i}.txt")
    for i in range(10):
        add_clean(device_dir, f".hidden/h{i}.txt")
    add_eicar(device_dir, "Downloads/eicar.com")
    add_file(device_dir, "dup.jpg.exe", b"xx")
    real = add_clean(device_dir, "linktarget.txt")
    os.symlink(real, device_dir / "alias.lnk-file")
    try:
        os.mkfifo(device_dir / "pipe")
    except (AttributeError, OSError):
        pass
    rec, findings = run_scan("full")
    assert rec["outcome"] == "threats_found"
    counter_consistency(rec)
    c = rec["counters"]
    assert c["symlinks_skipped"] == 1
    est = c["estimate_total"]
    assert est == c["entries_seen"]


def test_progress_percent_reaches_complete(client, auth, device_dir, run_scan):
    add_clean(device_dir, "a.txt")
    rec, _ = run_scan("full")
    r = client.get(f"/api/scans/{rec['id']}/events", headers=auth)
    end = [e for e in r.json()["events"] if e["type"] == "end"][-1]
    assert end["data"]["percent"] == 100.0
