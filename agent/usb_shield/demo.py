"""Synthetic demo/test device builder.

Creates a directory tree full of *harmless* synthetic content - clean files,
the standard EICAR test string (the industry-accepted safe detection test),
and files with suspicious characteristics.  Used by the development demo
endpoint (never enabled in production) and by parts of the test-suite.
No live malware is ever used.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from .engines.eicar import EICAR_SIGNATURE

DEMO_LABEL = "USBSHIELD-DEMO"


def _w(root: Path, rel: str, data: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def build_demo_device(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    stats = {"eicar": 0, "suspicious": 0, "clean": 0}

    def clean(rel: str, data: bytes):
        _w(root, rel, data)
        stats["clean"] += 1

    def eicar(rel: str):
        _w(root, rel, EICAR_SIGNATURE)
        stats["eicar"] += 1

    def suspicious(rel: str, data: bytes):
        _w(root, rel, data)
        stats["suspicious"] += 1

    # ---- ordinary clean content -------------------------------------------
    clean("Documents/report.txt", b"Quarterly results. Nothing to see here.\n" * 40)
    clean("Documents/notes.txt", b"shopping list: apples, pears, drive adapters\n")
    clean("Pictures/vacation.jpg", b"\xff\xd8\xff\xe0" + b"JFIF" + b"\x00" * 600)
    clean("Pictures/family/beach.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 800)
    clean("Music/playlist.m3u", b"#EXTM3U\nsong1.mp3\nsong2.mp3\n")
    for i in range(60):  # filler so progress/counters are visible
        clean(f"Media/clips/clip-{i:03d}.mp4",
              b"\x00\x00\x00\x18ftypmp42" + bytes([(i * 37 + 11) % 256]) * 48 * 1024)
    for i in range(25):
        clean(f"Media/clips/thumbs/.thumbs/thumb-{i:03d}.jpg",
              b"\xff\xd8\xff" + bytes([(i * 13) % 256]) * 10 * 1024)
    deep = "Backups/2024/January/week2/day4/hour09"
    clean(f"{deep}/manifest.txt", b"backup manifest\n")

    # ---- clean zip-within-docx (opaque zip container) ----------------------
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document>Hello</w:document>")
    clean("Documents/Quarterly Report.docx", buf.getvalue())

    # ---- confirmed (test signature) detections ------------------------------
    eicar("Downloads/setup.exe")                                   # .exe, thrills
    eicar("System Volume Information/WPSettings.dat")              # hidden sys area
    eicar(".hidden/Recycle.Bin/desktop.ini")
    # nested archives: eicar inside inner zip inside outer zip (depth 2)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload/eicar.com", EICAR_SIGNATURE)
        zf.writestr("payload/readme.txt", b"benign readme\n")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("docs/invoice.pdf.txt", b"invoice #1234 total due 0.00\n")
        zf.writestr("eicar.txt", EICAR_SIGNATURE)
        zf.writestr("nested/inner.zip", inner.getvalue())
    _w(root, "Archives/bundle.zip", outer.getvalue())
    stats["eicar"] += 1

    # ---- suspicious characteristics -----------------------------------------
    suspicious("autorun.inf",
               b"[autorun]\nopen=setup.exe\nshellexecute=setup.exe\n"
               b"shell\\open\\command=setup.exe\n")
    suspicious("payment.pdf.exe", b"not really an executable, just badly named\n")
    suspicious(".hidden/update.vbs",
               b"Set sh = CreateObject(\"WScript.Shell\")\n"
               b"sh.Run \"powershell -enc AAAA\", 0\n")
    suspicious("Photos/New Folder .scr", b"MZ" + b"\x90" * 2000)   # PE at odd place
    suspicious("Drivers/netcard.jpg", b"MZ" + b"\x90" * 300)       # disguised PE
    lnk = (b"\x4c\x00\x00\x00" +
           bytes.fromhex("0114020000000000c000000000000046") +
           b"\x00" * 56 + b"C:\\Windows\\System32\\cmd.exe\x00")
    suspicious("Resume.doc.lnk", lnk)
    return stats
