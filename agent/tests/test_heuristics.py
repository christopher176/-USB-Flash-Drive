"""Heuristics engine unit tests."""
from usb_shield.engines.heuristics import HeuristicsEngine


def scan(name, data, rel=None, hidden=False, system=False):
    eng = HeuristicsEngine(True)
    return eng.scan_buffer(rel=rel or name, name=name, data=data, size=len(data),
                           header=data[:4096], hidden=hidden, system=system)


def detections(verdicts):
    return {v.detection_name for v in verdicts}


def test_clean_text_file_has_no_findings():
    assert scan("readme.txt", b"hello world\n" * 100) == []


def test_double_extension_flagged():
    v = scan("invoice.pdf.exe", b"nothing executable here")
    assert "Heur.Name.DoubleExtension" in detections(v)


def test_double_extension_photo_com():
    v = scan("family-photo.jpg.com", b"x")
    assert "Heur.Name.DoubleExtension" in detections(v)


def test_disguised_pe_flagged_high():
    v = scan("picture.jpg", b"MZ" + b"\x90" * 400)
    assert "Heur.Disguised.PE" in detections(v)
    assert next(x for x in v if x.detection_name ==
                "Heur.Disguised.PE").severity.value == "high"


def test_real_exe_extension_not_flagged_for_mismatch():
    v = scan("tools/setup.exe", b"MZ" + b"\x90" * 400, rel="tools/setup.exe")
    assert not any(x.detection_name.startswith("Heur.Disguised") for x in v)


def test_pe_at_device_root_flagged():
    v = scan("setup.exe", b"MZ" + b"\x90" * 400, rel="setup.exe")
    assert "Heur.Exec.AtypicalLocation" in detections(v)


def test_pe_hidden_dir_flagged():
    v = scan(".sys/drv.dll", b"MZ" + b"\x90" * 400, rel=".sys/drv.dll", hidden=True)
    assert "Heur.Exec.AtypicalLocation" in detections(v)


def test_autorun_with_launch_directive_flagged():
    data = b"[autorun]\nopen=evil.exe\n"
    v = scan("autorun.inf", data)
    d = detections(v)
    assert "Heur.Autorun.AutoStart" in d
    verdict = next(x for x in v if x.detection_name == "Heur.Autorun.AutoStart")
    assert verdict.severity.value == "high"
    assert any("open=evil.exe" in t for t in verdict.details["directives"])


def test_benign_autorun_is_pua_only():
    v = scan("autorun.inf", b"[autorun]\nlabel=My Drive\nicon=icon.ico\n")
    d = {x.detection_name: x for x in v}
    assert "Heur.Autorun.Config" in d
    assert d["Heur.Autorun.Config"].classification.value == "potentially_unwanted"


def test_lnk_shortcut_flagged_with_extracted_target():
    lnk = (b"\x4c\x00\x00\x00" +
           bytes.fromhex("0114020000000000c000000000000046") +
           b"\x00" * 56 + b"C:\\Windows\\System32\\cmd.exe\x00")
    v = scan("Resume.doc.lnk", lnk)
    d = detections(v)
    assert "Heur.Lnk.Shortcut" in d
    verdict = next(x for x in v if x.detection_name == "Heur.Lnk.Shortcut")
    assert any("cmd.exe" in s for s in verdict.details["embedded_strings"])


def test_suspicious_script_content_flagged():
    script = (b'Set s = CreateObject("WScript.Shell")\n'
              b's.Run "powershell -encodedcommand AAAA", 0\n')
    v = scan("update.vbs", script, hidden=True)
    d = detections(v)
    assert "Heur.Script.SuspiciousContent" in d


def test_single_benign_word_not_flagged():
    v = scan("notes.js", b"// this website uses eval() sparingly\n")
    assert "Heur.Script.SuspiciousContent" not in detections(v)


def test_bidi_override_in_name_flagged():
    # filename contains a RIGHT-TO-LEFT OVERRIDE that reverses display order
    v = scan("invoice\u202egpj.exe", b"content")
    assert "Heur.Name.BidiTrick" in detections(v)


def test_macro_doc_at_root_pua_but_deep_doc_clean():
    ole = bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 64
    v_root = scan("document.doc", ole, rel="document.doc")
    assert any(x.detection_name == "Heur.Doc.MacroCapable" for x in v_root)
    v_deep = scan("Documents/report.doc", ole, rel="Documents/report.doc")
    assert not any(x.detection_name == "Heur.Doc.MacroCapable" for x in v_deep)


def test_emoji_filename_not_flagged():
    v = scan("holiday-🎉-photo.jpg", b"\xff\xd8\xff" + b"\x00" * 100)
    assert not any(x.detection_name == "Heur.Name.BidiTrick" for x in v)
