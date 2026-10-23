"""API hardening: auth, CSRF, origin/host allowlists, rate limits, headers."""
import time

from fastapi.testclient import TestClient

from .conftest import BASE_URL, CSRF


def test_health_is_public_and_minimal(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "token" not in str(body).lower()


def test_no_debug_surface(client):
    for path in ("/docs", "/redoc", "/openapi.json",
                 "/api/docs", "/api/openapi.json"):
        r = client.get(path)
        assert r.status_code == 404, path


def test_missing_token_rejected(client):
    for r in (client.get("/api/drives"),
              client.get("/api/scans"),
              client.get("/api/quarantine"),
              client.get("/api/audit"),
              client.get("/api/info")):
        assert r.status_code == 401, (r.request.url, r.status_code)


def test_wrong_token_rejected(client):
    bad = {"Authorization": "Bearer wrong-token", **CSRF}
    r = client.get("/api/drives", headers=bad)
    assert r.status_code == 401


def test_wrong_token_is_audited(client, auth):
    client.get("/api/drives", headers={"Authorization": "Bearer nope"})
    r = client.get("/api/audit", headers=auth)
    assert any(e["action"] == "api.unauthorized" for e in r.json()["events"])


def test_csrf_header_required_on_mutations(client, token):
    bearer = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/scans", headers=bearer,
                    json={"device_id": "x", "mode": "full", "custom_paths": []})
    assert r.status_code == 403
    r = client.post("/api/scans", headers=bearer,
                    json={"device_id": "x", "mode": "full", "custom_paths": []},
                    params={})
    assert r.status_code == 403
    ok = client.post("/api/scans", headers={**bearer, **CSRF},
                     json={"device_id": "x", "mode": "full", "custom_paths": []})
    assert ok.status_code == 404      # CSRF passed; unknown device afterwards


def test_evil_origin_blocked(client, auth):
    r = client.get("/api/drives", headers={**auth, "Origin": "https://evil.example.com"})
    assert r.status_code == 403


def test_cors_preflight_denies_foreign_origin(client):
    r = client.options("/api/drives", headers={
        "Origin": "https://evil.example.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    })
    assert r.headers.get("access-control-allow-origin") != "https://evil.example.com"


def test_host_header_allowlist_blocks_dns_rebinding(client, token):
    signed_in = {"Authorization": f"Bearer {token}", **CSRF}
    ok = client.get("/api/drives", headers=signed_in)
    assert ok.status_code == 200
    r = client.get("/api/drives",
                   headers={**signed_in, "Host": "attacker-rebind.example:8765"})
    assert r.status_code == 403


def test_pairing_requires_loopback(app):
    with TestClient(app, base_url=BASE_URL, client=("10.9.9.9", 9999)) as remote:
        r = remote.post("/api/pair", headers=CSRF)
        assert r.status_code == 403


def test_pairing_rate_limited(client):
    for _ in range(5):
        r = client.post("/api/pair", headers=CSRF)
        assert r.status_code == 200
    r = client.post("/api/pair", headers=CSRF)
    assert r.status_code == 429
    assert "retry-after" in {k.lower(): v for k, v in r.headers.items()}


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in {k.lower() for k in r.headers} or \
           "uvicorn" in r.headers.get("server", "")


def test_get_requests_do_not_require_csrf_header(client, token):
    r = client.get("/api/drives", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_info_requires_auth_but_is_rich(client, auth):
    r = client.get("/api/info", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["version"]
    names = {e["name"] for e in body["engines"]}
    assert {"clamav", "usb-shield-heuristics", "eicar-test-signature"} <= names
    clam = next(e for e in body["engines"] if e["name"] == "clamav")
    assert isinstance(clam["available"], bool)
    if not clam["available"]:
        assert "not reachable" in clam["detail"] or "disabled" in clam["detail"]
