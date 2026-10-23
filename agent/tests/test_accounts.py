"""Optional accounts: Argon2id storage, MFA enforcement, sessions, cookies."""
import re
import time

import pytest
from fastapi.testclient import TestClient

from usb_shield.api.app import create_app
from usb_shield.auth import totp_code, totp_generate_secret, totp_verify
from usb_shield.config import Settings

from .conftest import BASE_URL, CSRF


@pytest.fixture()
def acc_client(tmp_path):
    settings = Settings(data_dir=str(tmp_path / "data"),
                        allowed_hosts="testserver",
                        accounts_enabled=True,
                        session_secure=True)
    app = create_app(settings)
    # https base URL so the Secure session cookie is actually sent back
    with TestClient(app, base_url="https://127.0.0.1:8765",
                    client=("127.0.0.1", 4321)) as c:
        c.post("/api/pair", headers=CSRF)
        yield c


def test_totp_rfc6238_vectors():
    # RFC 6238 Appendix B, SHA-1, 8 digits, secret "12345678901234567890"
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp_code(secret, when=59, digits=8) == "94287082"
    assert totp_code(secret, when=1111111109, digits=8) == "07081804"
    assert totp_code(secret, when=1234567890, digits=8) == "89005924"


def test_totp_window_and_format():
    secret = totp_generate_secret()
    code = totp_code(secret)
    assert re.fullmatch(r"\d{6}", code)
    assert totp_verify(secret, code)
    assert totp_verify(secret, totp_code(secret, when=time.time() - 30))
    assert not totp_verify(secret, "000000" if code != "000000" else "000001")
    assert not totp_verify(secret, "abcdef")
    assert not totp_verify(secret, "")


def test_register_first_user_is_admin_and_hashed_argon2id(acc_client):
    import string
    pw = "Tr0ub4dor&3-extra-long"
    r = acc_client.post("/api/auth/register", headers=CSRF,
                        json={"username": "admin@example.com", "password": pw})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"
    # second registration is closed
    r2 = acc_client.post("/api/auth/register", headers=CSRF,
                         json={"username": "second-user", "password": pw})
    assert r2.status_code == 403


def test_password_min_length_enforced(acc_client):
    r = acc_client.post("/api/auth/register", headers=CSRF,
                        json={"username": "shorty", "password": "short"})
    assert r.status_code == 422


def test_admin_must_enroll_totp_before_session(acc_client):
    pw = "correct horse battery staple!"
    acc_client.post("/api/auth/register", headers=CSRF,
                    json={"username": "adminuser", "password": pw})
    r = acc_client.post("/api/auth/login", headers=CSRF,
                        json={"username": "adminuser", "password": pw})
    assert r.status_code == 200
    body = r.json()
    assert body.get("mfa_setup_required") is True       # MFA: no session yet
    assert "usbshield_session" not in r.headers.get("set-cookie", "")
    setup_token = body["setup_token"]
    b = acc_client.post("/api/auth/mfa/enroll/begin", headers=CSRF,
                        json={"setup_token": setup_token})
    assert b.status_code == 200
    secret = b.json()["secret"]
    assert b.json()["uri"].startswith("otpauth://totp/")
    # wrong code rejected
    good_code = totp_code(secret)
    wrong_code = "000000" if good_code != "000000" else "111111"
    f_bad = acc_client.post("/api/auth/mfa/enroll/finish", headers=CSRF,
                            json={"setup_token": setup_token, "code": wrong_code})
    assert f_bad.status_code == 400
    f = acc_client.post("/api/auth/mfa/enroll/finish", headers=CSRF,
                        json={"setup_token": setup_token, "code": good_code})
    assert f.status_code == 200, f.text
    cookie = f.headers.get("set-cookie", "")
    assert "usbshield_session=" in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()
    assert "secure" in cookie.lower()
    # subsequent logins REQUIRE the TOTP code
    r2 = acc_client.post("/api/auth/login", headers=CSRF,
                         json={"username": "adminuser", "password": pw})
    assert r2.status_code == 401
    r3 = acc_client.post("/api/auth/login", headers=CSRF,
                         json={"username": "adminuser", "password": pw,
                               "totp_code": totp_code(secret)})
    assert r3.status_code == 200
    assert r3.json()["signed_in"] is True


def test_login_unknown_user_same_shape(acc_client):
    r = acc_client.post("/api/auth/login", headers=CSRF,
                        json={"username": "ghost", "password": "whatever-pass-12"})
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_rate_limited(acc_client):
    pw = "correct horse battery staple!"
    for _ in range(10):
        acc_client.post("/api/auth/login", headers=CSRF,
                        json={"username": "nosuchuser", "password": pw})
    r = acc_client.post("/api/auth/login", headers=CSRF,
                        json={"username": "nosuchuser", "password": pw})
    assert r.status_code == 429


def test_me_requires_session(acc_client):
    r = acc_client.get("/api/auth/me")
    assert r.status_code == 401
    pw = "correct horse battery staple!"
    acc_client.post("/api/auth/register", headers=CSRF,
                    json={"username": "adminuser", "password": pw})
    r = acc_client.post("/api/auth/login", headers=CSRF,
                        json={"username": "adminuser", "password": pw})
    b = acc_client.post("/api/auth/mfa/enroll/begin", headers=CSRF,
                        json={"setup_token": r.json()["setup_token"]})
    secret = b.json()["secret"]
    f = acc_client.post("/api/auth/mfa/enroll/finish", headers=CSRF,
                        json={"setup_token": r.json()["setup_token"],
                              "code": totp_code(secret)})
    assert f.status_code == 200
    me = acc_client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "adminuser"
    assert me.json()["user"]["totp_enabled"] is True
    # logout kills the session
    lo = acc_client.post("/api/auth/logout", headers=CSRF)
    assert lo.status_code == 200
    assert acc_client.get("/api/auth/me").status_code == 401


def test_argon2id_hash_format_stored(tmp_path):
    from usb_shield.auth import hash_password
    h = hash_password("some long password value")
    assert h.startswith("$argon2id$")
    assert "m=65536" in h and "t=3" in h and "p=4" in h
