"""Device enumeration safety + demo endpoint behaviour."""
from pathlib import Path

from usb_shield.drives import _looks_system, list_devices
from usb_shield.engines.eicar import EICAR_SIGNATURE

from .conftest import CSRF


def test_system_paths_never_eligible():
    for p in ("/", "/home", "/boot", "/etc", "/usr", "/tmp", "/var",
              "/System/Library", "C:\\"):
        assert _looks_system(p), p
    assert not _looks_system("/media/user/FLASHDRIVE")
    assert not _looks_system("/media/user/FLASHDRIVE")


def test_extra_root_device_enumerated(settings, device_dir):
    devs = list_devices(settings)
    assert any(Path(d.mount_point) == device_dir and d.kind == "demo"
               for d in devs)
    for d in devs:
        assert not _looks_system(d.mount_point)


def test_drives_api_lists_only_safe_devices(client, auth):
    r = client.get("/api/drives", headers=auth)
    assert r.status_code == 200
    for d in r.json()["devices"]:
        assert not _looks_system(d["mount_point"])
        assert d["kind"] in ("removable", "demo")
        assert d["id"] and "total_bytes" in d


def test_demo_endpoint_creates_and_removes_device(client, auth, settings,
                                                  data_dir):
    r = client.post("/api/devices/demo", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] is True
    assert "Synthetic" in body["warning"]
    dev = body["device"]
    assert dev and Path(dev["mount_point"]).name == "demo-device"
    stats = body["stats"]
    assert stats["eicar"] >= 4 and stats["suspicious"] >= 5
    # demo device actually scannable and yields detections
    from .conftest import start_scan, wait_scan, get_findings
    rec = start_scan(client, auth, dev["id"], "full")
    done = wait_scan(client, auth, rec["id"])
    assert done["outcome"] == "threats_found"
    findings = get_findings(client, auth, rec["id"])
    assert any(f["is_test_detection"] for f in findings)
    assert any(f["detection_name"].startswith("Heur.") for f in findings)
    assert any("::" in f["path"] for f in findings)      # archive member finding
    # hidden + system dirs really were traversed
    paths = {f["path"] for f in findings}
    assert any(p.startswith("System Volume Information/") for p in paths)
    assert any(p.startswith(".hidden/") for p in paths)
    assert done["counters"]["files_scanned"] >= 100
    # teardown
    r = client.delete("/api/devices/demo", headers=auth)
    assert r.status_code == 200
    assert not (data_dir / "demo-device").exists()


def test_eject_demo_device_refused(client, auth, device_dir, device_id):
    r = client.post(f"/api/devices/{device_id}/eject", headers=auth)
    assert r.status_code == 200
    assert r.json()["ejected"] is False
    assert "Demo" in r.json()["message"]


def test_disconnected_device_scan_rejected(client, auth, device_dir):
    import shutil
    r = client.get("/api/drives", headers=auth)
    tmp_id = next(d["id"] for d in r.json()["devices"]
                  if Path(d["mount_point"]) == device_dir)
    shutil.rmtree(device_dir)
    r = client.post("/api/scans", headers=auth,
                    json={"device_id": tmp_id, "mode": "full",
                          "custom_paths": []})
    assert r.status_code in (404, 409)
