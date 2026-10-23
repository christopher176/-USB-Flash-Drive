"""Structural / behavioural heuristics for USB-borne threat tradecraft.

IMPORTANT: heuristic output is intentionally capped at ``SUSPICIOUS`` - it
signals *indicators*, never confirmed infections (that needs a signature
backed engine).  Every verdict lists its indicators so users can judge.
"""
from __future__ import annotations

import re

from .base import Engine, Verdict
from ..models import Classification, Severity

PE_EXTS = {".exe", ".dll", ".scr", ".sys", ".com", ".ocx", ".cpl", ".drv",
           ".efi", ".mun", ".ax", ".acm", ".fon"}
SCRIPT_EXTS = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".bat",
               ".cmd", ".hta", ".php", ".pl"}
MSI_EXTS = {".msi"}
EXEC_LIKE = PE_EXTS | SCRIPT_EXTS | MSI_EXTS
CAMOUFLAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".doc",
                   ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".mp3",
                   ".mp4", ".avi", ".mov", ".zip", ".csv", ".htm", ".html",
                   ".mpg", ".wav"}

MAGIC_PE = b"MZ"
MAGIC_ELF = b"\x7fELF"
MAGIC_LNK_PREFIX = b"\x4c\x00\x00\x00"
MAGIC_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
MAGIC_OLE = bytes.fromhex("d0cf11e0a1b11ae1")

BIDI_MARKS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
              "\u2066", "\u2067", "\u2068", "\u2069"}

SCRIPT_MARKERS = [
    b"powershell", b"-encodedcommand", b"-enc ", b"frombase64string",
    b"createobject(", b"wscript.shell", b"activexobject", b"shell.application",
    b"scripting.filesystemobject", b"adodb.stream", b"msxml2.xmlhttp",
    b"winmgmts:", b"rundll32", b"regsvr32", b"bitsadmin", b"certutil -decode",
    b"downloadstring", b"invoke-expression", b"iex(", b"start-process",
    b"cmd.exe /c", b"mshta", b".downloadfile(",
]


def _ext_of(name: str) -> str:
    i = name.rfind(".")
    return name[i:].lower() if i > 0 else ""


def _stem_ext(name: str) -> str:
    base = name[:name.rfind(".")] if "." in name else name
    i = base.rfind(".")
    return base[i:].lower() if i > 0 else ""


def _extract_strings(data: bytes, min_len: int = 6, limit: int = 6) -> list[str]:
    out: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data[:65536]):
        out.append(m.group().decode("ascii", "replace")[:120])
        if len(out) >= limit:
            break
    # a couple of UTF-16LE strings (LNK targets are usually UTF-16)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data[:65536]):
        try:
            out.append(m.group().decode("utf-16-le", "replace")[:120])
        except Exception:
            pass
        if len(out) >= 2 * limit:
            break
    return out


class HeuristicsEngine(Engine):
    name = "usb-shield-heuristics"
    description = "Structural heuristics for disguise, autorun and script abuse"

    def __init__(self, enabled: bool = True) -> None:
        super().__init__()
        self._available = enabled

    # ------------------------------------------------------------------ rules
    def _rule_misleading_name(self, name: str) -> Verdict | None:
        # Explicit bidi-override/isolate marks only - generic Cf characters
        # (e.g. ZWJ in emoji filenames) are legitimate and must not flag.
        if any(c in BIDI_MARKS for c in name):
            return Verdict(Classification.SUSPICIOUS, "Heur.Name.BidiTrick",
                           Severity.HIGH,
                           "filename contains bidirectional/invisible control characters",
                           self.name, {"name_repr": repr(name)})
        if name != name.strip() or "  " in name:
            return Verdict(Classification.SUSPICIOUS, "Heur.Name.WhitespaceTrick",
                           Severity.LOW,
                           "filename uses padding whitespace to disguise its extension",
                           self.name, {"name_repr": repr(name)})
        return None

    def _rule_double_extension(self, name: str, at_root: bool) -> Verdict | None:
        last, prev = _ext_of(name), _stem_ext(name)
        if last in EXEC_LIKE and prev in CAMOUFLAGE_EXTS:
            return Verdict(Classification.SUSPICIOUS, "Heur.Name.DoubleExtension",
                           Severity.MEDIUM,
                           "executable hides behind a document/media extension "
                           f"('{prev}{last}')",
                           self.name, {"last_ext": last, "camouflage_ext": prev,
                                       "at_root": at_root})
        return None

    def _rule_disguised_executable(self, name: str, header: bytes, ext: str,
                                   hidden: bool, system: bool, at_root: bool,
                                   truncated: bool) -> Verdict | None:
        if len(header) < 2:
            return None
        indicators: list[str] = []
        sev = Severity.MEDIUM
        det = ""
        if header.startswith(MAGIC_PE):
            if ext not in PE_EXTS:
                det = "Heur.Disguised.PE"
                indicators.append(f"Windows executable (MZ header) with extension '{ext or '(none)'}'")
                sev = Severity.HIGH
            elif hidden or system or at_root:
                det = "Heur.Exec.AtypicalLocation"
                where = "hidden" if hidden else "system area" if system else "device root"
                indicators.append(f"executable located in {where} - classic USB-worm placement")
        elif header.startswith(MAGIC_ELF) and ext in CAMOUFLAGE_EXTS:
            det = "Heur.Disguised.ELF"
            indicators.append(f"Linux executable (ELF header) disguised as '{ext}'")
            sev = Severity.HIGH
        if not det:
            return None
        if ext == "" :
            indicators.append("file has no extension")
        if truncated:
            indicators.append("judged from header only (file exceeds buffer limit)")
        return Verdict(Classification.SUSPICIOUS, det, sev,
                       "; ".join(indicators), self.name,
                       {"indicators": indicators})

    def _rule_lnk(self, name: str, data: bytes, at_root: bool) -> Verdict | None:
        if not (data.startswith(MAGIC_LNK_PREFIX) and MAGIC_LNK_CLSID in data[:20]):
            if _ext_of(name) == ".lnk" and len(data) >= 76:
                det_note = "shortcut with unrecognised header (possibly obfuscated)"
            else:
                return None
        else:
            det_note = "Windows shortcut (.lnk) - a common USB malware launcher"
        strings = _extract_strings(data)
        sev = Severity.MEDIUM if at_root else Severity.LOW
        return Verdict(Classification.SUSPICIOUS, "Heur.Lnk.Shortcut", sev,
                       det_note + "; review its target before use",
                       self.name, {"embedded_strings": strings, "at_root": at_root})

    def _rule_autorun(self, name: str, data: bytes, at_root: bool) -> Verdict | None:
        if name.lower() != "autorun.inf":
            return None
        text = data[:16384].decode("utf-8", "replace").lower()
        triggers: list[str] = []
        for key in ("open=", "shellexecute=", "shell\\"):
            for line in text.splitlines():
                if key in line:
                    triggers.append(line.strip()[:160])
        if triggers:
            return Verdict(Classification.SUSPICIOUS, "Heur.Autorun.AutoStart",
                           Severity.HIGH,
                           "autorun.inf instructs Windows to launch content automatically",
                           self.name, {"directives": triggers[:8], "at_root": at_root})
        return Verdict(Classification.PUA, "Heur.Autorun.Config",
                       Severity.LOW,
                       "autorun.inf present (no auto-launch directive found)",
                       self.name, {"at_root": at_root})

    def _rule_script(self, name: str, data: bytes, ext: str, hidden: bool,
                     system: bool, at_root: bool, truncated: bool) -> Verdict | None:
        if ext not in SCRIPT_EXTS and not data[:2] == b"#!":
            return None
        sample = data[:262144].lower()
        hits = sorted({m.decode() for m in SCRIPT_MARKERS if m in sample})
        if not hits:
            return None
        risky_place = hidden or system or at_root
        if len(hits) >= 2 or (len(hits) >= 1 and risky_place):
            sev = Severity.MEDIUM if len(hits) >= 2 else Severity.LOW
            where = "hidden" if hidden else "system area" if system else "device root" if at_root else None
            indicators = [f"script references '{h}'" for h in hits[:6]]
            if where:
                indicators.append(f"script located in {where}")
            if truncated:
                indicators.append("only the first 256 KiB were inspected")
            return Verdict(Classification.SUSPICIOUS, "Heur.Script.SuspiciousContent",
                           sev, "; ".join(indicators), self.name,
                           {"markers": hits, "markers_shown": hits[:6]})
        return None

    def _rule_macro_container(self, name: str, header: bytes, ext: str,
                              hidden: bool, system: bool, at_root: bool) -> Verdict | None:
        # Only flagged in atypical locations - ordinary documents elsewhere
        # must not produce noise.
        if ext in {".doc", ".xls", ".ppt"} and header.startswith(MAGIC_OLE) and \
                (hidden or system or at_root):
            return Verdict(Classification.PUA, "Heur.Doc.MacroCapable",
                           Severity.INFO,
                           "macro-capable Office document in an atypical location; "
                           "contents require a full AV engine for certainty",
                           self.name, {"format": "OLE2"})
        return None

    # ------------------------------------------------------------------ main
    def scan_buffer(self, *, rel, name, data, size, header, hidden, system):
        ext = _ext_of(name)
        at_root = "/" not in rel
        body = data
        truncated = size > len(data)
        verdicts: list[Verdict] = []
        for rule in (self._rule_misleading_name(name),
                     self._rule_double_extension(name, at_root),
                     self._rule_disguised_executable(name, body[:4096], ext, hidden,
                                                     system, at_root, truncated),
                     self._rule_lnk(name, body, at_root),
                     self._rule_autorun(name, body, at_root),
                     self._rule_script(name, body, ext, hidden, system, at_root,
                                       truncated),
                     self._rule_macro_container(name, body[:8], ext, hidden,
                                             system, at_root)):
            if rule is not None:
                verdicts.append(rule)
        return verdicts
