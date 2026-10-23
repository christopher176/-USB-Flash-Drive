"""Unit-level engine & security-component tests."""
import hmac
import time

from usb_shield.config import Settings
from usb_shield.engines.clamav import ClamAvEngine
from usb_shield.scanner import quick_interested
from usb_shield.security import RateLimiter, TokenStore
from usb_shield.walker import WalkEntry


def entry(rel, hidden=False, system=False, name=None):
    return WalkEntry(abspath=None, rel=rel, name=name or rel.rsplit("/", 1)[-1],
                     kind="file", hidden=hidden, system=system)


def test_quick_filter_covers_high_risk():
    assert quick_interested(entry("setup.exe"))                    # root file
    assert quick_interested(entry("autorun.inf"))                  # root file
    assert quick_interested(entry(".hidden/x.txt", hidden=True))   # hidden
    assert quick_interested(entry("System Volume Information/s.dat",
                                  system=True))
    assert quick_interested(entry("deep/down/program.dll"))        # risky ext
    assert quick_interested(entry("a/b/photo.jpg.exe"))            # double ext
    assert quick_interested(entry("docs/Resume.doc.lnk"))
    assert quick_interested(entry("a/archive.zip"))


def test_quick_filter_skips_low_risk():
    assert not quick_interested(entry("Documents/report.txt"))
    assert not quick_interested(entry("media/photos/holiday.jpg"))
    assert not quick_interested(entry("a/b/c/data.csv"))


def test_clamav_unavailable_is_honest_not_error():
    eng = ClamAvEngine(socket_path="/nonexistent/clamd.sock",
                       tcp="127.0.0.1:1", timeout=1)
    assert eng.available() is False
    assert "not reachable" in eng.status_detail()
    assert eng.version() == "unavailable"
    # scanning silently defers - the scanner records unavailability elsewhere
    assert eng.scan_buffer(rel="x", name="x", data=b"data", size=4,
                           header=b"data", hidden=False, system=False) == []


def test_rate_limiter_window():
    rl = RateLimiter()
    for _ in range(3):
        assert rl.allow("k", 3, 60.0)
    assert not rl.allow("k", 3, 60.0)
    assert rl.allow("other", 3, 60.0)


def test_token_store_permissions_and_comparison(tmp_path):
    ts = TokenStore(tmp_path)
    assert len(ts.token) >= 32
    import stat
    mode = (tmp_path / "agent_token").stat().st_mode & 0o777
    assert mode == 0o600
    assert ts.verify(ts.token)
    assert not ts.verify(ts.token[:-1] + ("a" if ts.token[-1] != "a" else "b"))
    assert not ts.verify("")
    ts2 = TokenStore(tmp_path)
    assert ts2.token == ts.token        # stable across reloads


def test_settings_parsing(data_dir, device_dir):
    s = Settings(data_dir=str(data_dir),
                 allowed_origins="https://a.example, https://b.example",
                 extra_device_roots=str(device_dir))
    assert s.origins() == ["https://a.example", "https://b.example"]
    assert s.extra_roots()[0] == device_dir
    assert s.is_loopback_bind()
