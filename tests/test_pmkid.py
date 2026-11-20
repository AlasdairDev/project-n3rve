"""Tests for PMKID extraction and handshake-validity logic."""

from src.validator import extract_pmkid, ValidationResult, validate_all_handshakes


def _kde(pmkid_hex: str) -> bytes:
    """Wrap a PMKID in an RSN PMKID KDE (dd <len> 00 0f ac 04 <16 bytes>)."""
    pmkid = bytes.fromhex(pmkid_hex)
    return b"\xdd\x14\x00\x0f\xac\x04" + pmkid


def test_extract_pmkid_present():
    pm = "112233445566778899aabbccddeeff00"
    assert extract_pmkid(_kde(pm)) == pm


def test_extract_pmkid_after_rsn_ie():
    # A real M1's Key Data starts with a full RSN IE (tag 0x30) whose AKM/cipher
    # suite selectors contain the bytes 00-0f-ac-04. The PMKID KDE follows it.
    # A correct parser must skip the RSN IE by length and not match inside it.
    pm = "0011223344556677889900aabbccddee"
    rsn_ie = bytes.fromhex("30140100000fac040100000fac040100000fac020000")  # 22 bytes, len=0x14
    key_data = rsn_ie + _kde(pm)
    assert extract_pmkid(key_data) == pm


def test_extract_pmkid_not_fooled_by_rsn_ie():
    # RSN IE alone (contains 00-0f-ac-04 selectors) but no PMKID KDE -> None.
    rsn_ie = bytes.fromhex("30140100000fac040100000fac040100000fac020000")
    assert extract_pmkid(rsn_ie) is None


def test_extract_pmkid_absent():
    assert extract_pmkid(b"") is None
    assert extract_pmkid(None) is None
    assert extract_pmkid(bytes.fromhex("30140100000fac04")) is None  # RSN elt, no PMKID KDE


def test_extract_pmkid_all_zero_rejected():
    # Some APs advertise the KDE but leave the PMKID blank - treat as absent.
    assert extract_pmkid(_kde("00" * 16)) is None


def test_extract_pmkid_truncated_rejected():
    assert extract_pmkid(b"\xdd\x14\x00\x0f\xac\x04" + b"\x11" * 8) is None


def _mk(**kw) -> ValidationResult:
    r = ValidationResult(**kw)
    r.is_valid = r.has_pmkid or (r.has_m2 and (r.has_m1 or r.has_m3))
    return r


def test_validity_pmkid_only():
    assert _mk(has_pmkid=True).is_valid is True


def test_validity_m1_m2():
    assert _mk(has_m1=True, has_m2=True).is_valid is True


def test_validity_m2_m3_no_m1():
    # Crackable: M3 supplies the ANONCE. Previously (M1+M2 only) this was rejected.
    assert _mk(has_m2=True, has_m3=True).is_valid is True


def test_validity_m1_only_insufficient():
    assert _mk(has_m1=True).is_valid is False


def test_validity_m2_only_insufficient():
    assert _mk(has_m2=True).is_valid is False


def test_validate_all_handshakes_empty():
    assert validate_all_handshakes([]) == ({}, [])
