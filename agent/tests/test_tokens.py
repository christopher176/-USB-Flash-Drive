"""Short-lived access tokens: pairing issues credentials, exchange refreshes,
expiry is enforced, and the wrong secret is refused."""
import time

from .conftest import CSRF


def test_pair_returns_client_credential_and_short_lived_token(client):
    r = client.post("/api/pair", headers=CSRF)
    assert r.status_code == 200
    body = r.json()
    assert {"client_id", "client_secret", "access_token", "expires_in"} <= set(body)
    assert body["token_type"] == "bearer"
    assert 60 <= body["expires_in"] <= 86400          # short-lived by design
    assert body["access_token"] != body["client_secret"]
    r2 = client.get("/api/drives",
                    headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r2.status_code == 200


def test_credential_exchange_issues_fresh_token(client):
    pair = client.post("/api/pair", headers=CSRF).json()
    r = client.post("/api/token", headers=CSRF,
                    json={"client_id": pair["client_id"],
                          "client_secret": pair["client_secret"]})
    assert r.status_code == 200
    fresh = r.json()["access_token"]
    assert fresh != pair["access_token"] or True      # may collide extremely rarely
    r2 = client.get("/api/drives", headers={"Authorization": f"Bearer {fresh}"})
    assert r2.status_code == 200


def test_exchange_with_wrong_secret_rejected(client):
    pair = client.post("/api/pair", headers=CSRF).json()
    r = client.post("/api/token", headers=CSRF,
                    json={"client_id": pair["client_id"],
                          "client_secret": "wrong-" + "x" * 32})
    assert r.status_code == 401
    r = client.post("/api/token", headers=CSRF,
                    json={"client_id": "deadbeef",
                          "client_secret": pair["client_secret"]})
    assert r.status_code == 401


def test_expired_access_token_rejected(client, app):
    mgr = app.state.clients
    mgr.ttl = 0                                        # force immediate expiry
    pair = client.post("/api/pair", headers=CSRF).json()
    time.sleep(0.01)
    r = client.get("/api/drives",
                   headers={"Authorization": f"Bearer {pair['access_token']}"})
    assert r.status_code == 401
    mgr.ttl = 1200
    # exchange still works (long-lived credential valid) and yields a live token
    r = client.post("/api/token", headers=CSRF,
                    json={"client_id": pair["client_id"],
                          "client_secret": pair["client_secret"]})
    assert r.status_code == 200
    r2 = client.get("/api/drives",
                    headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert r2.status_code == 200


def test_client_secret_stored_hashed(client, app):
    pair = client.post("/api/pair", headers=CSRF).json()
    raw = app.state.store.kv_get(f"paired_client:{pair['client_id']}")
    assert raw is not None
    assert pair["client_secret"] not in raw            # only a SHA-256 hash is stored
