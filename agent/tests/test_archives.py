"""Archive inspection: detection inside archives, bombs, limits, formats."""
import io
import struct
import tarfile
import zipfile

import pytest

from usb_shield.engines.eicar import EICAR_SIGNATURE

from .conftest import add_clean, add_eicar, add_file, make_zip


def paths_metas(findings):
    return {f["path"]: f for f in findings}


def test_eicar_inside_zip_detected(client, auth, device_dir, run_scan):
    add_file(device_dir, "pack/bundle.zip",
             make_zip({"docs/readme.txt": b"hello\n",
                       "bin/eicar.com": EICAR_SIGNATURE}))
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    key = "pack/bundle.zip::bin/eicar.com"
    assert key in pm
    f = pm[key]
    assert f["classification"] == "malicious"
    assert f["is_test_detection"] is True
    assert f["container"] == "pack/bundle.zip"
    assert "archive inspection" in f["method"]
    assert rec["counters"]["archives_inspected"] == 1


def test_nested_zip_within_limits_scanned(client, auth, device_dir, run_scan):
    inner = make_zip({"deep/eicar.com": EICAR_SIGNATURE})
    outer = make_zip({"inner.zip": inner, "ok.txt": b"fine\n"})
    add_file(device_dir, "outer.zip", outer)
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert "outer.zip::inner.zip::deep/eicar.com" in pm


def test_nesting_beyond_depth_limit_flagged(client, auth, device_dir, run_scan):
    level3 = make_zip({"eicar.com": EICAR_SIGNATURE})
    level2 = make_zip({"l3.zip": level3})
    level1 = make_zip({"l2.zip": level2})
    add_file(device_dir, "l1.zip", level1)
    # default depth = 3: l1(0) -> l2(1) -> l3(2) contents scanned at depth 3 ok
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert "l1.zip::l2.zip::l3.zip::eicar.com" in pm
    # now tighten the limit - rescan and expect a nesting-depth gap
    r = client.patch("/api/config", headers=auth,
                     json={"archive_max_depth": 1})
    assert r.status_code == 200, r.text
    rec2, findings2 = run_scan("full")
    assert any("nesting_depth" in f["reason"] or
               "nesting" in (f["reason"] or "")
               for f in findings2 if f["status"] in ("partial", "unscannable")), \
        findings2
    assert rec2["outcome"] in ("threats_found", "no_threats_with_gaps")


def test_declared_ratio_bomb_flagged(client, auth, device_dir, run_scan):
    # 6 MB of zeros compresses to ~6 KB: extreme ratio, classic bomb shape
    bomb = make_zip({"huge.bin": b"\x00" * 6_000_000})
    assert len(bomb) < 200_000
    r = client.patch("/api/config", headers=auth,
                     json={"archive_max_ratio": 10,
                           "archive_max_member_bytes": 8_000_000})
    assert r.status_code == 200
    add_file(device_dir, "bomb.zip", bomb)
    rec, findings = run_scan("full")
    bomb_hits = [f for f in findings
                 if f["detection_name"] == "Heur.Archive.PossibleBomb"]
    assert bomb_hits, findings
    assert bomb_hits[0]["classification"] == "suspicious"
    assert bomb_hits[0]["severity"] == "high"


def test_member_size_limit_gap_reported(client, auth, device_dir, run_scan):
    data = make_zip({"big.dat": b"A" * 3_000_000})
    client.patch("/api/config", headers=auth,
                 json={"archive_max_member_bytes": 1_000_000,
                       "archive_max_ratio": 100000})
    add_file(device_dir, "limited.zip", data)
    rec, findings = run_scan("full")
    assert any(f["classification"] == "unable_to_scan" and f["status"] == "partial"
               for f in findings), findings
    assert rec["outcome"] == "no_threats_with_gaps"   # never 'clean' with gaps


def _flip_zip_encryption_flag(zip_bytes: bytes) -> bytes:
    """Set the encrypted bit (0x1) in local + central headers of a normal zip,
    simulating an encrypted archive without needing an encryption library."""
    data = bytearray(zip_bytes)
    i = 0
    while True:
        i = data.find(b"PK\x03\x04", i)
        if i < 0:
            break
        data[i + 6] |= 0x01      # local header general-purpose flag
        i += 4
    i = 0
    while True:
        i = data.find(b"PK\x01\x02", i)
        if i < 0:
            break
        data[i + 8] |= 0x01      # central directory flag
        i += 4
    return bytes(data)


def test_encrypted_zip_members_reported_unscannable(client, auth, device_dir,
                                                    run_scan):
    enc = _flip_zip_encryption_flag(make_zip({"secret.txt": b"payload"}))
    add_file(device_dir, "locked.zip", enc)
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert pm["locked.zip::secret.txt"]["classification"] == "unable_to_scan"
    assert "encrypted" in pm["locked.zip::secret.txt"]["reason"].lower()
    assert rec["outcome"] != "clean"       # gaps mean the drive is not certified


def test_malformed_zip_reported(client, auth, device_dir, run_scan):
    add_file(device_dir, "broken.zip", b"PK\x03\x04" + b"\xff" * 40)
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert pm["broken.zip"]["classification"] == "unable_to_scan"
    assert pm["broken.zip"]["status"] == "unscannable"
    assert "malformed" in (pm["broken.zip"]["reason"] or "").lower()


def test_unsupported_archive_format_reported(client, auth, device_dir, run_scan):
    add_file(device_dir, "old.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 100)
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert pm["old.rar"]["classification"] == "unable_to_scan"
    assert "unsupported archive format" in pm["old.rar"]["reason"]


def test_targz_member_detection(client, auth, device_dir, run_scan):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in {"notes.txt": b"hi\n",
                           "bin/eicar.com": EICAR_SIGNATURE}.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    add_file(device_dir, "backup.tar.gz", buf.getvalue())
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert pm["backup.tar.gz::bin/eicar.com"]["classification"] == "malicious"


def test_tar_link_members_not_followed(client, auth, device_dir, run_scan):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("escape.txt")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)
        clean = tarfile.TarInfo("ok.txt")
        data = b"fine\n"
        clean.size = len(data)
        tf.addfile(clean, io.BytesIO(data))
    add_file(device_dir, "links.tar", buf.getvalue())
    rec, findings = run_scan("full")
    pm = paths_metas(findings)
    assert "non-regular member" in (pm["links.tar::escape.txt"]["reason"] or "")
