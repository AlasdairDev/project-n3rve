from src.hashcat.crack import _potfile_results
from src.hashcat.convert import _format_mac


def _pot(essid: str, password: str) -> str:
    return "deadbeef" * 8 + "*" + essid.encode().hex() + ":" + password


def test_potfile_result_valid():
    assert _potfile_results([_pot("MyNet", "mypassword1")]) == {"MyNet": "mypassword1"}


def test_potfile_result_too_short():
    assert _potfile_results([_pot("MyNet", "short")]) == {}


def test_potfile_result_too_long():
    assert _potfile_results([_pot("MyNet", "x" * 64)]) == {}


def test_potfile_result_empty():
    assert _potfile_results([]) == {}
    assert _potfile_results(["", "#comment", "no-colon-here"]) == {}


def test_potfile_result_keeps_passwords_containing_colons():
    # A passphrase may itself contain ':' - only the last one separates it.
    assert _potfile_results([_pot("MyNet", "pass:with:colons")]) == {"MyNet": "pass:with:colons"}


def test_format_mac_variants():
    assert _format_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert _format_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert _format_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert _format_mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"
    assert _format_mac("garbage") == "00:00:00:00:00:00"
    assert _format_mac(None) == "00:00:00:00:00:00"


def test_potfile_result_decodes_hex_encoded_password():
    # hashcat writes $HEX[..] when the plain contains a colon or stray whitespace.
    encoded = "$HEX[" + "pass:word1".encode().hex() + "]"
    assert _potfile_results([_pot("MyNet", encoded)]) == {"MyNet": "pass:word1"}
