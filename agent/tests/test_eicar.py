"""EICAR standard test-signature engine: boundary behaviour."""
from usb_shield.engines.eicar import EICAR_SIGNATURE, is_eicar


def test_exact_signature_detected():
    assert is_eicar(EICAR_SIGNATURE)


def test_trailing_whitespace_allowed_up_to_128_bytes():
    assert is_eicar(EICAR_SIGNATURE + b"\r\n")
    assert is_eicar(EICAR_SIGNATURE + b" " * (128 - len(EICAR_SIGNATURE)))


def test_longer_than_128_bytes_not_detected():
    assert not is_eicar(EICAR_SIGNATURE + b"A" * 1000)


def test_prefixed_junk_not_detected():
    assert not is_eicar(b"xx" + EICAR_SIGNATURE)


def test_non_whitespace_suffix_not_detected():
    assert not is_eicar(EICAR_SIGNATURE + b"!")


def test_random_content_not_detected():
    assert not is_eicar(b"Just an ordinary text document.\n" * 3)


def test_engine_labels_test_detection():
    from usb_shield.engines.eicar import EicarEngine
    eng = EicarEngine(True)
    verdicts = eng.scan_buffer(rel="a.com", name="a.com", data=EICAR_SIGNATURE,
                               size=len(EICAR_SIGNATURE), header=EICAR_SIGNATURE,
                               hidden=False, system=False)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.classification.value == "malicious"
    assert v.is_test is True
    assert "EICAR" in v.detection_name
