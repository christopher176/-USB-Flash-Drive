"""Shared test fixtures: isolated agent app, synthetic devices, helpers.

All scanning tests use synthetic, harmless data - above all the EICAR
standard test string, which exists precisely for safely validating AV
pipelines. No live malware is ever used in this suite.
"""
from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from usb_shield.api.app import create_app
from usb_shield.config import Settings
from usb_shield.engines.eicar import EICAR_SIGNATURE

BASE_URL = "http://127.0.0.1:8765"
CSRF = {"X-USBShield-Client": "usb-shield-web"}


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "agent-data"


@pytest.fixture()
def device_dir(tmp_path: Path) -> Path:
    d = tmp_path / "test-device"
    d.mkdir()
    return d


@pytest.fixture()
def settings(data_dir: Path, device_dir: Path) -> Settings:
    return Settings(data_dir=str(data_dir),
                    extra_device_roots=str(device_dir),
                    allowed_hosts="testserver",
                    dev_demo=True,
                    accounts_enabled=False,
                    session_secure=False)


@pytest.fixture()
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    with TestClient(app, base_url=BASE_URL,
                    client=("127.0.0.1", 4321)) as c:
        yield c


@pytest.fixture()
def token(client: TestClient) -> str:
    r = client.post("/api/pair", headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture()
def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", **CSRF}


@pytest.fixture()
def device_id(client: TestClient, auth: dict, device_dir: Path) -> str:
    r = client.get("/api/drives", headers=auth)
    assert r.status_code == 200, r.text
    for d in r.json()["devices"]:
        if Path(d["mount_point"]) == device_dir:
            return d["id"]
    raise AssertionError(f"device not enumerated: {r.json()}")


# ------------------------------------------------------------------ builders
def add_file(root: Path, rel: str, data: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def add_clean(root: Path, rel: str, size: int = 256) -> Path:
    return add_file(root, rel, b"This is a benign document.\n" * (size // 27 + 1))


def add_eicar(root: Path, rel: str) -> Path:
    return add_file(root, rel, EICAR_SIGNATURE)


def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ------------------------------------------------------------------ scanning
def start_scan(client: TestClient, auth: dict, device_id: str,
               mode: str = "full", custom_paths: list[str] | None = None) -> dict:
    payload = {"device_id": device_id, "mode": mode,
               "custom_paths": custom_paths or []}
    r = client.post("/api/scans", json=payload, headers=auth)
    assert r.status_code == 201, r.text
    return r.json()


def wait_scan(client: TestClient, auth: dict, scan_id: str,
              timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/scans/{scan_id}", headers=auth)
        assert r.status_code == 200, r.text
        rec = r.json()
        if rec["status"] not in ("queued", "scanning"):
            return rec
        time.sleep(0.1)
    raise AssertionError(f"scan {scan_id} did not finish within {timeout}s")


def get_findings(client: TestClient, auth: dict, scan_id: str) -> list[dict]:
    r = client.get(f"/api/scans/{scan_id}/findings", headers=auth)
    assert r.status_code == 200, r.text
    return r.json()["findings"]


@pytest.fixture()
def run_scan(client, auth, device_id):
    def _go(mode: str = "full", custom_paths=None):
        rec = start_scan(client, auth, device_id, mode, custom_paths)
        done = wait_scan(client, auth, rec["id"])
        findings = get_findings(client, auth, rec["id"])
        return done, findings
    return _go
