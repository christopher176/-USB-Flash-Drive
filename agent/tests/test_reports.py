"""Reports: JSON/TXT structure, HTML escaping, persistence, history."""
import json
from pathlib import Path

from .conftest import add_clean, add_eicar, add_file


def test_json_report_structure(client, auth, device_dir, run_scan):
    add_eicar(device_dir, "Downloads/setup.exe")
    add_clean(device_dir, "docs/a.txt")
    rec, findings = run_scan("full")
    r = client.get(f"/api/scans/{rec['id']}/report", headers=auth,
                   params={"format": "json"})
    assert r.status_code == 200
    doc = json.loads(r.text)
    assert doc["scan"]["id"] == rec["id"]
    assert doc["scan"]["outcome"] == "threats_found"
    assert doc["scan"]["engines"]
    assert doc["scan"]["counters"]["files_scanned"] >= 2
    assert doc["findings"][0]["path"] == "Downloads/setup.exe"
    assert doc["disclaimer"]
    assert "attachment" in r.headers["content-disposition"]


def test_html_report_escapes_malicious_filenames(client, auth, device_dir,
                                                 run_scan):
    evil_name = "<script>alert(1)</script>.png.exe"
    add_file(device_dir, evil_name, b"payload")
    rec, _ = run_scan("full")
    r = client.get(f"/api/scans/{rec['id']}/report", headers=auth,
                   params={"format": "html"})
    assert r.status_code == 200
    body = r.text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp


def test_text_report_notes_quick_scan_limit(client, auth, device_dir, run_scan):
    add_clean(device_dir, "docs/a.txt")
    rec, _ = run_scan("quick")
    r = client.get(f"/api/scans/{rec['id']}/report", headers=auth,
                   params={"format": "txt"})
    assert "QUICK scan" in r.text
    assert "does not provide the coverage" in r.text


def test_reports_saved_and_history_lifecycle(client, auth, device_dir, run_scan,
                                             data_dir):
    add_eicar(device_dir, "eicar.com")
    rec, _ = run_scan("full")
    client.get(f"/api/scans/{rec['id']}/report", headers=auth,
               params={"format": "json"})
    assert list((data_dir / "reports").glob("usb-shield-report-*.json"))
    h = client.get("/api/history", headers=auth)
    assert h.status_code == 200
    assert any(s["id"] == rec["id"] for s in h.json()["scans"])
    # deletion requires confirmation
    r = client.request("DELETE", "/api/history", headers=auth,
                       json={"confirm": False})
    assert r.status_code == 400
    r = client.request("DELETE", "/api/history", headers=auth,
                       json={"confirm": True})
    assert r.status_code == 200
    assert r.json()["deleted_scans"] >= 1
    assert not list((data_dir / "reports").glob("usb-shield-report-*.json"))
    h2 = client.get("/api/history", headers=auth)
    assert all(s["id"] != rec["id"] for s in h2.json()["scans"])


def test_report_unknown_scan_404(client, auth):
    r = client.get("/api/scans/zzz/report", headers=auth)
    assert r.status_code == 404
