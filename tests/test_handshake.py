"""Tests for the capture -> per-network hash extraction (src/handshake.py).

The centrepiece is test_real_capture_hash_verifies_against_known_password: it
recomputes the EAPOL MIC from the passphrase we already recovered for the bundled
TP-Link capture. A hash that reproduces the MIC is provably crackable - every
field (ESSID, AP/STA order, ANONCE choice, EAPOL trimming, MIC zeroing) has to be
right for that to hold, which no amount of shape-checking can establish.
"""

import hashlib
import hmac
import os

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL, EAPOL_KEY

from src.handshake import (
    analyze_capture,
    analyze_packets,
    essid_from_filename,
    extract_pmkid,
)

HERE = os.path.dirname(os.path.abspath(__file__))
# Real-capture tests are OPT-IN and carry no real identifiers in this repo.
# To run them locally, place your own capture and set:
#   N3RVE_FIXTURE=<path>  N3RVE_FIXTURE_SSID=<ssid>
#   N3RVE_FIXTURE_BSSID=<bssid hex, no colons>  N3RVE_FIXTURE_PASSWORD=<passphrase>
FIXTURES = os.path.join(HERE, "fixtures")
TPLINK_CAP = os.environ.get("N3RVE_FIXTURE", "")
TPLINK_SSID = os.environ.get("N3RVE_FIXTURE_SSID", "")
TPLINK_BSSID = os.environ.get("N3RVE_FIXTURE_BSSID", "")
TPLINK_PASSWORD = os.environ.get("N3RVE_FIXTURE_PASSWORD", "")
_NEEDS_FIXTURE = pytest.mark.skipif(
    not (TPLINK_CAP and os.path.exists(TPLINK_CAP) and TPLINK_SSID and TPLINK_BSSID and TPLINK_PASSWORD),
    reason="set N3RVE_FIXTURE* env vars (and provide a capture) to run real-capture tests",
)


# helpers to build synthetic frames

def _beacon(ap: str, essid: str):
    return Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap) / Dot11Beacon() / Dot11Elt(ID=0, info=essid.encode())


def _key_frame(*, ap, sta, from_ap, ack, mic, install, secure, nonce, replay, ts, key_data=b""):
    dot11 = Dot11(
        addr1=sta if from_ap else ap,
        addr2=ap if from_ap else sta,
        addr3=ap,
        FCfield=0x2 if from_ap else 0x1,  # from-DS (AP->STA) / to-DS (STA->AP)
    )
    pkt = (
        dot11
        / EAPOL(version=2, type=3)
        / EAPOL_KEY(
            key_descriptor_type=2,
            key_descriptor_type_version=2,
            key_ack=ack,
            has_key_mic=mic,
            install=install,
            secure=secure,
            key_nonce=nonce,
            key_replay_counter=replay,
            key_data=key_data,
            key_data_length=len(key_data),
        )
    )
    pkt.time = ts
    return pkt


def _m1(ap, sta, nonce, replay=1, ts=0.0, key_data=b""):
    return _key_frame(ap=ap, sta=sta, from_ap=True, ack=1, mic=0, install=0, secure=0,
                      nonce=nonce, replay=replay, ts=ts, key_data=key_data)


def _m2(ap, sta, nonce, replay=1, ts=0.01):
    return _key_frame(ap=ap, sta=sta, from_ap=False, ack=0, mic=1, install=0, secure=0,
                      nonce=nonce, replay=replay, ts=ts)


def _m3(ap, sta, nonce, replay=2, ts=0.02):
    return _key_frame(ap=ap, sta=sta, from_ap=True, ack=1, mic=1, install=1, secure=1,
                      nonce=nonce, replay=replay, ts=ts)


def _m4(ap, sta, replay=2, ts=0.03):
    return _key_frame(ap=ap, sta=sta, from_ap=False, ack=0, mic=1, install=0, secure=1,
                      nonce=b"\x00" * 32, replay=replay, ts=ts)


# the real-capture cryptographic check

def _prf512(pmk: bytes, label: bytes, data: bytes) -> bytes:
    out = b""
    for i in range(4):
        out += hmac.new(pmk, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
    return out[:64]


def _expected_mic(passphrase: str, essid: str, ap: str, sta: str, anonce: bytes, eapol: bytes) -> str:
    """Recompute the EAPOL MIC the way an AP does, from the passphrase."""
    pmk = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), essid.encode(), 4096, 32)
    aa, spa = bytes.fromhex(ap), bytes.fromhex(sta)
    snonce = eapol[17:49]  # key_nonce field inside the EAPOL-Key body
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    ptk = _prf512(pmk, b"Pairwise key expansion", data)
    return hmac.new(ptk[:16], eapol, hashlib.sha1).digest()[:16].hex()


@_NEEDS_FIXTURE
def test_real_capture_hash_verifies_against_known_password():
    # The capture holds handshakes from two clients of the same AP. One is the
    # legitimate client (its MIC reproduces from TPLINK_PASSWORD); the other is a
    # foreign device that associated with the wrong key, so its hash can never
    # crack. The tool cannot know which is which up front and emits both - what
    # matters is that at least one emitted hash provably reproduces the MIC.
    analysis = analyze_capture(TPLINK_CAP)
    networks = analysis.valid_networks
    assert len(networks) == 1
    net = networks[0]
    assert net.essid == TPLINK_SSID
    assert net.hashes

    def verifies(h):
        return h.mic == _expected_mic(
            TPLINK_PASSWORD,
            net.essid,
            h.ap.replace(":", ""),
            h.sta.replace(":", ""),
            bytes.fromhex(h.anonce),
            bytes.fromhex(h.eapol_hex),
        )

    assert any(verifies(h) for h in net.hashes), (
        "no emitted hash reproduces the MIC for the known passphrase - none would crack"
    )


@_NEEDS_FIXTURE
def test_real_capture_line_shape():
    analysis = analyze_capture(TPLINK_CAP)
    lines = analysis.hc22000_lines()
    assert lines
    for line in lines:
        fields = line.split("*")
        assert fields[0] == "WPA" and fields[1] == "02"
        assert fields[3] == TPLINK_BSSID
        assert bytes.fromhex(fields[5]).decode() == TPLINK_SSID
        assert fields[8] in ("00", "01", "02", "03")


def test_mismatched_anonce_attempt_is_not_spliced():
    """One client, two handshake attempts: M1+M2 of the first, then M3+M4 of a
    second attempt 61 s later carrying a *different* ANONCE. Pairing that M2 with
    the later M3 would produce a well-formed hash that can never crack, so the
    tool must pair M1+M2 and take M1's ANONCE, never the unrelated M3's.

    (Reproduces the scenario the retired ConvergeExample_2.4GHz fixture captured;
    kept synthetic so it is committed and deterministic rather than a binary
    blob living in the gitignored handshakes/ directory.)"""
    ap, sta, essid = "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "ConvergeExample_2.4GHz"
    anonce_m1 = b"\x6d\xe5\x0d\xe9\x9b\x7e" + b"\x00" * 26
    anonce_m3 = b"\xff\xee\xdd\xcc" + b"\x11" * 28
    packets = [
        _beacon(ap, essid),
        _m1(ap, sta, anonce_m1, replay=1, ts=1.0),
        _m2(ap, sta, b"\xa5" * 32, replay=1, ts=1.02),
        _m3(ap, sta, anonce_m3, replay=2, ts=62.0),  # different attempt, 61 s later
        _m4(ap, sta, replay=2, ts=62.02),
    ]
    analysis = analyze_packets(packets, "HS_AABBCCDDEEFF_ConvergeExample_2.4GHz.pcap")
    net = analysis.valid_networks[0]
    assert net.essid == "ConvergeExample_2.4GHz"
    assert len(net.hashes) == 1
    assert net.hashes[0].source == "M1+M2"
    # The ANONCE must be M1's, not the unrelated M3's.
    assert net.hashes[0].anonce.startswith("6de50de99b7e")


# multi-network behaviour

AP_A, STA_A, ESSID_A = "aa:aa:aa:aa:aa:aa", "11:11:11:11:11:11", "PLDTHOMEFIBR_A"
AP_B, STA_B, ESSID_B = "bb:bb:bb:bb:bb:bb", "22:22:22:22:22:22", "Converge_B"


def test_two_networks_in_one_capture_each_get_their_own_essid():
    packets = [
        _beacon(AP_A, ESSID_A),
        _beacon(AP_B, ESSID_B),
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
        _m1(AP_B, STA_B, b"\xb1" * 32, ts=2.0),
        _m2(AP_B, STA_B, b"\xb2" * 32, ts=2.01),
    ]
    analysis = analyze_packets(packets)
    assert len(analysis.valid_networks) == 2
    by_essid = {n.essid: n for n in analysis.valid_networks}
    assert set(by_essid) == {ESSID_A, ESSID_B}
    assert by_essid[ESSID_A].hashes[0].anonce == "a1" * 32
    assert by_essid[ESSID_B].hashes[0].anonce == "b1" * 32

    lines = analysis.hc22000_lines()
    assert len(lines) == 2
    essids = {bytes.fromhex(ln.split("*")[5]).decode() for ln in lines}
    assert essids == {ESSID_A, ESSID_B}


def test_two_clients_on_one_ap_both_produce_hashes():
    sta2 = "33:33:33:33:33:33"
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
        _m1(AP_A, sta2, b"\xc1" * 32, ts=5.0),
        _m2(AP_A, sta2, b"\xc2" * 32, ts=5.01),
    ]
    analysis = analyze_packets(packets)
    net = analysis.valid_networks[0]
    assert net.clients == {STA_A, sta2}
    assert {h.sta for h in net.hashes} == {STA_A, sta2}


def test_replay_counter_mismatch_yields_no_hash():
    # M2 from a different exchange than the only M1 present: no ANONCE applies.
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, b"\xa1" * 32, replay=1, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, replay=9, ts=1.01),
    ]
    analysis = analyze_packets(packets)
    assert analysis.valid_networks == []
    net = analysis.all_networks[0]
    assert net.has_m1 and net.has_m2
    assert "replay counters" in net.reason()


def test_m2_m3_pair_without_m1_is_authorized():
    packets = [
        _beacon(AP_A, ESSID_A),
        _m2(AP_A, STA_A, b"\xa2" * 32, replay=1, ts=1.0),
        _m3(AP_A, STA_A, b"\xa1" * 32, replay=2, ts=1.01),
    ]
    net = analyze_packets(packets).valid_networks[0]
    assert [h.source for h in net.hashes] == ["M2+M3"]
    assert net.hashes[0].message_pair == "02"
    assert net.hashes[0].anonce == "a1" * 32


def test_identical_m1m2_and_m2m3_collapse_to_one_hash():
    # A clean exchange: M3 repeats M1's ANONCE, so both pairings describe the
    # same hash and only one line should be emitted.
    anonce = b"\xa1" * 32
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, anonce, replay=1, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, replay=1, ts=1.01),
        _m3(AP_A, STA_A, anonce, replay=2, ts=1.02),
    ]
    net = analyze_packets(packets).valid_networks[0]
    assert len(net.hashes) == 1


def test_hidden_ssid_without_beacon_is_reported_not_guessed():
    packets = [
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    analysis = analyze_packets(packets)  # no capture path -> no filename fallback
    assert analysis.valid_networks == []
    assert "ESSID unknown" in analysis.all_networks[0].reason()


def test_essid_recovered_from_filename_when_beacon_missing():
    packets = [
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    analysis = analyze_packets(packets, "HS_AAAAAAAAAAAA_WarehouseWiFi.pcap")
    net = analysis.valid_networks[0]
    assert net.essid == "WarehouseWiFi"
    assert net.essid_source == "filename"


def test_pmkid_and_eapol_both_emitted():
    kde = bytes.fromhex("dd14000fac04" + "aa" * 16)
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0, key_data=kde),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    net = analyze_packets(packets).valid_networks[0]
    kinds = [h.kind for h in net.hashes]
    assert "pmkid" in kinds and "eapol" in kinds
    pmkid_line = [ln for ln in analyze_packets(packets).hc22000_lines() if ln.split("*")[1] == "01"][0]
    assert pmkid_line.split("*")[2] == "aa" * 16
    assert extract_pmkid(kde) == "aa" * 16


# filename parsing

def test_essid_from_filename_variants():
    assert essid_from_filename("HS_AABBCCDDEEFF_MyNet.pcap", "aa:bb:cc:dd:ee:ff") == "MyNet"
    assert essid_from_filename("HS_AA-BB-CC-DD-EE-FF_MyNet.cap", "aa:bb:cc:dd:ee:ff") == "MyNet"
    # A MAC that belongs to a different AP must not name this one.
    assert essid_from_filename("HS_AABBCCDDEEFF_MyNet.pcap", "11:22:33:44:55:66") is None
    # airodump style
    assert essid_from_filename("WarehouseAP-01.cap", "aa:bb:cc:dd:ee:ff") == "WarehouseAP"


# merging an external extractor's output

def _hcx_line(essid: str, ap: str, sta: str, kind: str = "02") -> str:
    return "*".join(
        ["WPA", kind, "ff" * 16, ap.replace(":", ""), sta.replace(":", ""), essid.encode().hex(), "aa" * 32, "bb", "02"]
    )


def test_merge_adds_networks_our_parser_missed():
    from src.handshake import CaptureAnalysis, merge_external_lines

    analysis = CaptureAnalysis()
    added = merge_external_lines(analysis, [_hcx_line("HcxOnlyNet", AP_B, STA_B)])
    assert added == 1
    net = analysis.valid_networks[0]
    assert net.essid == "HcxOnlyNet"
    assert net.essid_source == "hcxpcapngtool"
    assert net.hashes[0].source == "hcxpcapngtool"
    # The line is emitted verbatim - we never rebuild what another tool parsed.
    assert analysis.hc22000_lines() == [_hcx_line("HcxOnlyNet", AP_B, STA_B)]


def test_merge_does_not_duplicate_a_hash_we_already_have():
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    from src.handshake import merge_external_lines

    analysis = analyze_packets(packets)
    ours = analysis.hc22000_lines()
    assert merge_external_lines(analysis, ours) == 0
    assert analysis.hc22000_lines() == ours


def test_merge_attaches_to_the_existing_network_by_bssid():
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    from src.handshake import merge_external_lines

    analysis = analyze_packets(packets)
    other_client = "44:44:44:44:44:44"
    assert merge_external_lines(analysis, [_hcx_line(ESSID_A, AP_A, other_client)]) == 1
    assert len(analysis.valid_networks) == 1  # same AP, not a second entry
    net = analysis.valid_networks[0]
    assert other_client in net.clients
    assert len(net.hashes) == 2


def test_merge_ignores_malformed_lines():
    from src.handshake import CaptureAnalysis, merge_external_lines

    analysis = CaptureAnalysis()
    assert merge_external_lines(analysis, ["", "not-a-hash", "WPA*02*tooshort", "PMKID*x*y"]) == 0
    assert analysis.all_networks == []


def test_external_essid_unlocks_our_own_pairing(monkeypatch):
    """hcxtools reading an SSID we couldn't must also let *our* hash be built -
    without the ESSID (the PBKDF2 salt) we skip hash generation entirely."""
    import src.handshake as hs

    packets = [
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    monkeypatch.setattr(hs, "hcxpcapngtool_lines", lambda p: [_hcx_line("RecoveredName", AP_A, STA_A)])
    analysis = hs.analyze_packets(packets, "/nonexistent/capture.pcap")

    net = analysis.valid_networks[0]
    assert net.essid == "RecoveredName"
    sources = {h.source for h in net.hashes}
    assert "M1+M2" in sources, "our own pairing should now be emitted too"
    assert "hcxpcapngtool" in sources


# security mode detection

def _rsn_ie(akm_types, group=b"\x00\x0f\xac\x04"):
    """Build an RSN information element advertising the given AKM suites."""
    body = b"\x01\x00" + group + b"\x01\x00" + b"\x00\x0f\xac\x04"
    body += len(akm_types).to_bytes(2, "little")
    for t in akm_types:
        body += b"\x00\x0f\xac" + bytes([t])
    body += b"\x00\x00"  # RSN capabilities
    return Dot11Elt(ID=48, info=body)


def _secured_beacon(ap, essid, ie=None, privacy=True):
    pkt = (
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap)
        / Dot11Beacon(cap="ESS+privacy" if privacy else "ESS")
        / Dot11Elt(ID=0, info=essid.encode())
    )
    return pkt / ie if ie is not None else pkt


def test_security_wpa2_psk():
    from src.handshake import security_from_beacon

    assert security_from_beacon(_secured_beacon(AP_A, ESSID_A, _rsn_ie([2]))) == "WPA2-PSK"


def test_security_wpa3_sae_and_transition_mode():
    from src.handshake import security_from_beacon

    assert security_from_beacon(_secured_beacon(AP_A, ESSID_A, _rsn_ie([8]))) == "WPA3-SAE"
    # Transition mode advertises both; the PSK half is still attackable.
    mixed = security_from_beacon(_secured_beacon(AP_A, ESSID_A, _rsn_ie([8, 2])))
    assert "WPA3-SAE" in mixed and "WPA2-PSK" in mixed


def test_security_enterprise_and_open():
    from src.handshake import security_from_beacon

    assert security_from_beacon(_secured_beacon(AP_A, ESSID_A, _rsn_ie([1]))) == "WPA2-Enterprise"
    assert security_from_beacon(_secured_beacon(AP_A, ESSID_A, None, privacy=False)) == "Open"
    # Privacy bit but no RSN/WPA element = WEP.
    assert security_from_beacon(_secured_beacon(AP_A, ESSID_A, None, privacy=True)) == "WEP"


def test_sae_only_network_is_reported_as_a_dead_end():
    """WPA3-SAE never exposes a crackable 4-way - say so instead of reporting a
    vague 'no handshake' and letting the user keep capturing."""
    packets = [_secured_beacon(AP_A, "WarehouseWPA3", _rsn_ie([8]))]
    net = analyze_packets(packets).all_networks[0]
    assert net.security == "WPA3-SAE"
    assert net.is_psk is False
    assert "SAE" in net.reason()


def test_enterprise_network_is_reported_as_a_dead_end():
    packets = [_secured_beacon(AP_A, "WarehouseCorp", _rsn_ie([1]))]
    net = analyze_packets(packets).all_networks[0]
    assert net.is_psk is False
    assert "no PSK to recover" in net.reason()


def test_transition_mode_network_is_still_attacked():
    packets = [
        _secured_beacon(AP_A, ESSID_A, _rsn_ie([8, 2])),
        _m1(AP_A, STA_A, b"\xa1" * 32, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, ts=1.01),
    ]
    net = analyze_packets(packets).valid_networks[0]
    assert net.is_psk is True
    assert net.hashes


def test_security_label_never_preempts_a_specific_pairing_reason():
    """A beacon we could not parse must not turn into 'Open - no WPA handshake'
    when the real problem is that the frames do not pair up."""
    packets = [
        _beacon(AP_A, ESSID_A),  # no RSN element -> reads as Open
        _m1(AP_A, STA_A, b"\xa1" * 32, replay=1, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, replay=9, ts=1.01),
    ]
    net = analyze_packets(packets).all_networks[0]
    assert "replay counters" in net.reason()


def test_frames_from_two_different_clients_are_not_spliced():
    """A real warehouse capture had M1/M3 from one station and M2/M4 from
    another. Pairing across stations gives a well-formed hash that can never
    crack - the PTK binds the client MAC."""
    sta_a, sta_b = "38:54:f5:c1:04:53", "d2:a7:57:20:79:db"
    packets = [
        _beacon(AP_A, "KID"),
        _m1(AP_A, sta_a, b"\xf0" * 32, replay=1, ts=3444.5),
        _m2(AP_A, sta_b, b"\x76" * 32, replay=1, ts=3748.2),
        _m3(AP_A, sta_a, b"\x57" * 32, replay=2, ts=4132.0),
    ]
    analysis = analyze_packets(packets)
    net = analysis.all_networks[0]
    assert net.hashes == [], "must not pair frames across different clients"
    # Every per-network flag can read OK while nothing usable was built, so the
    # reason has to name the actual problem.
    assert net.has_m1 and net.has_m2 and net.has_m3
    reason = net.reason()
    assert "different clients" in reason
    assert sta_a in reason and sta_b in reason
    assert "no M2" in reason  # names what station A is missing


def test_pairing_reason_stays_simple_for_a_single_client():
    packets = [
        _beacon(AP_A, ESSID_A),
        _m1(AP_A, STA_A, b"\xa1" * 32, replay=1, ts=1.0),
        _m2(AP_A, STA_A, b"\xa2" * 32, replay=9, ts=1.01),
    ]
    net = analyze_packets(packets).all_networks[0]
    assert "replay counters" in net.reason()
