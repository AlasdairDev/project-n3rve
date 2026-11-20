"""End-to-end tests for cap -> hc22000 conversion, focused on the PMKID path."""

import os

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL, EAPOL_KEY

from src.hashcat.convert import convert_cap_to_hc22000

AP = "aa:bb:cc:dd:ee:ff"
STA = "11:22:33:44:55:66"
ESSID = "TestNet"
PMKID = "00112233445566778899aabbccddeeff"


def _beacon():
    return (
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP)
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=ESSID.encode())
    )


def _m1_with_pmkid():
    kde = bytes.fromhex("dd14000fac04" + PMKID)  # RSN PMKID KDE
    return (
        Dot11(addr1=STA, addr2=AP, addr3=AP)
        / EAPOL(version=2, type=3)
        / EAPOL_KEY(
            key_descriptor_type=2,
            key_ack=1,
            has_key_mic=0,
            install=0,
            secure=0,
            key_data=kde,
            key_data_length=len(kde),
        )
    )


def test_convert_emits_pmkid_line(tmp_path):
    out = os.path.join(tmp_path, "pmkid.hc22000")
    ok = convert_cap_to_hc22000("ignored.pcap", out, packets=[_beacon(), _m1_with_pmkid()])
    assert ok is True

    lines = open(out).read().strip().splitlines()
    assert len(lines) == 1
    fields = lines[0].split("*")
    assert fields[0] == "WPA"
    assert fields[1] == "01"  # PMKID message-pair type
    assert fields[2] == PMKID
    assert fields[3] == AP.replace(":", "")
    assert fields[4] == STA.replace(":", "")
    assert bytes.fromhex(fields[5]).decode() == ESSID
    assert len(fields) == 9  # trailing anonce/eapol/messagepair are empty


def test_convert_no_crackable_material_fails(tmp_path):
    out = os.path.join(tmp_path, "empty.hc22000")
    # A lone beacon carries no PMKID and no handshake - nothing to crack.
    ok = convert_cap_to_hc22000("ignored.pcap", out, packets=[_beacon()])
    assert ok is False
    assert not os.path.exists(out)
