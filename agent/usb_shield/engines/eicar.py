"""EICAR standard antivirus *test* signature engine.

This implements the official eicar.org test-file rule: the file must be at
most 128 bytes, begin with the 68-byte signature, and may be followed only
by whitespace.  It is the industry-standard safe way to prove an antivirus
pipeline actually works end-to-end, and it is what our automated tests use -
never live malware.

The engine is deliberately narrow: without a full ClamAV deployment it
proves the detection pipeline is wired correctly, and the UI labels its
output as a *test* detection.
"""
from __future__ import annotations

from .base import Engine, Verdict
from ..models import Classification, Severity

EICAR_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_MAX_LEN = 128
_WHITESPACE = b" \t\r\n\x00\x0b\x0c"


def is_eicar(data: bytes) -> bool:
    if len(data) > EICAR_MAX_LEN or not data.startswith(EICAR_SIGNATURE):
        return False
    rest = data[len(EICAR_SIGNATURE):]
    return all(b in _WHITESPACE for b in rest)


class EicarEngine(Engine):
    name = "eicar-test-signature"
    description = "EICAR standard antivirus test-signature check (harmless)"

    def __init__(self, enabled: bool = True) -> None:
        super().__init__()
        self._available = enabled

    def scan_buffer(self, *, rel, name, data, size, header, hidden, system):
        if is_eicar(data):
            return [Verdict(
                classification=Classification.MALICIOUS,
                detection_name="EICAR-Test-Signature",
                severity=Severity.HIGH,
                method="exact test-signature match (eicar.org rule)",
                engine=self.name,
                details={"standard": "https://www.eicar.org", "size": len(data)},
                is_test=True)]
        return []
