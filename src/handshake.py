"""Turn a capture's 802.11 frames into crackable WPA hashes.

A capture is rarely one clean handshake. Airodump/Bruce/hcxdumptool dumps hold
several APs, several clients per AP, and repeated handshake attempts minutes
apart. Every EAPOL frame therefore has to be attributed to the (AP, STA) pair it
belongs to, and the messages of *one* exchange have to be matched by their key
replay counter - pairing an M2 with an M3 from a later attempt yields a hash that
looks perfectly well-formed and can never be cracked, because its ANONCE and
SNONCE come from different PTK derivations.

This module does that grouping once; both the validator (reporting) and the
hc22000 writer (cracking) consume its output, so what you are shown is exactly
what gets cracked.

Message pairs emitted (hc22000 ``message_pair`` field):

    00  M1+M2   ANONCE from M1, MIC/EAPOL from M2
    01  M1+M4   ANONCE from M1, MIC/EAPOL from M4 (only when M4 carries a SNONCE)
    02  M2+M3   ANONCE from M3, MIC/EAPOL from M2  (authorized: the AP accepted it)
    03  M3+M4   ANONCE from M3, MIC/EAPOL from M4 (only when M4 carries a SNONCE)

hashcat reads the SNONCE out of the EAPOL frame you give it. An M4 with the usual
all-zero nonce gives it nothing, so those frames are skipped. Emitting one would
only produce a hash that never cracks.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from scapy.all import PcapReader
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeResp,
    Dot11ReassoReq,
)
from scapy.layers.eap import EAPOL, EAPOL_KEY

from src.console import log_debug

# Vendor-specific element tag (0xDD) carrying an RSN PMKID KDE: OUI 00-0F-AC,
# data type 0x04, then the 16-byte PMKID. It shows up in the Key Data of a
# 4-way-handshake M1 when the AP supports PMKID caching, which lets us crack the
# network with no client (a "clientless"/PMKID attack).
_KDE_TAG = 0xDD
_PMKID_KDE_HEADER = b"\x00\x0f\xac\x04"  # OUI + KDE data type

_BROADCAST = "ff:ff:ff:ff:ff:ff"
_ZERO_MAC = "00:00:00:00:00:00"

# An EAPOL-Key frame is 4 (LLC-EAPOL header) + 95 (key descriptor) bytes at
# minimum; the MIC lives at offset 81..97 of that buffer.
_EAPOL_MIN_LEN = 99
_MIC_OFFSET = 81
_MIC_LEN = 16

# Cap on how many hashes we keep per (AP, STA) pair. A long capture can hold dozens
# of retried exchanges, but the first few carry all the information, and every
# extra line just costs GPU time on masks/rules for no extra chance of a hit.
_MAX_HASHES_PER_PAIR = 8


def classify_eapol(ek) -> str | None:
    """Which of the four handshake messages an EAPOL-Key frame is, or None."""
    ack = bool(ek.key_ack)
    mic = bool(ek.has_key_mic)
    ins = bool(ek.install)
    sec = bool(ek.secure)
    if ack and not mic and not ins and not sec:
        return "M1"
    if not ack and mic and not ins and not sec:
        return "M2"
    if ack and mic and ins and sec:
        return "M3"
    if not ack and mic and not ins and sec:
        return "M4"
    return None


def extract_pmkid(key_data: bytes | None) -> str | None:
    """Return the 32-hex-char PMKID from an EAPOL-Key frame's Key Data, or None.

    Walks the Key Data as a sequence of TLV elements rather than substring-
    matching: the bytes ``00 0f ac 04`` also appear inside an RSN information
    element (as an AKM/cipher suite selector), so a naive search would produce a
    bogus PMKID. Only a vendor-specific (0xDD) PMKID KDE counts. An all-zero
    PMKID is treated as absent, matching hcxtools' behaviour.
    """
    if not key_data:
        return None
    i, n = 0, len(key_data)
    while i + 2 <= n:
        tag, length = key_data[i], key_data[i + 1]
        val = key_data[i + 2:i + 2 + length]
        if len(val) < length:  # truncated element, stop
            break
        if tag == _KDE_TAG and length >= 20 and val[:4] == _PMKID_KDE_HEADER:
            pmkid = val[4:20]
            if pmkid != b"\x00" * 16:
                return pmkid.hex()
        i += 2 + length
    return None


def format_mac(mac) -> str:
    """Normalise anything MAC-shaped to ``aa:bb:cc:dd:ee:ff``."""
    if isinstance(mac, str):
        mac = mac.replace("-", ":").replace(" ", "")
        parts = mac.split(":")
        if len(parts) == 6:
            return ":".join(f"{p.lower():0>2s}" for p in parts)
        mac = mac.replace(":", "")
        try:
            return ":".join(f"{x:02x}" for x in bytes.fromhex(mac))
        except ValueError:
            return _ZERO_MAC
    if isinstance(mac, bytes) and len(mac) == 6:
        return ":".join(f"{x:02x}" for x in mac)
    return _ZERO_MAC


def _nc(mac: str) -> str:
    """MAC without separators, as hc22000 wants it."""
    return mac.replace(":", "")


@dataclass
class EapolFrame:
    """One EAPOL-Key frame, already attributed to an (AP, STA) pair."""

    msg: str
    ap: str
    sta: str
    ts: float
    replay: int
    nonce: bytes
    eapol: bytes
    key_ver: int
    pmkid: str | None = None

    @property
    def has_nonce(self) -> bool:
        return bool(self.nonce) and self.nonce != b"\x00" * len(self.nonce)


@dataclass
class WpaHash:
    """One crackable hc22000 line."""

    kind: str  # 'pmkid' | 'eapol'
    ap: str
    sta: str
    mic: str = ""
    pmkid: str = ""
    anonce: str = ""
    eapol_hex: str = ""
    message_pair: str = "00"
    source: str = ""  # e.g. "M1+M2", shown in reports
    raw: str = ""  # verbatim line, when it came from an external extractor

    def to_line(self, essid_hex: str) -> str:
        if self.raw:
            return self.raw
        if self.kind == "pmkid":
            return "*".join(["WPA", "01", self.pmkid, _nc(self.ap), _nc(self.sta), essid_hex, "", "", ""])
        return "*".join(
            [
                "WPA",
                "02",
                self.mic,
                _nc(self.ap),
                _nc(self.sta),
                essid_hex,
                self.anonce,
                self.eapol_hex,
                self.message_pair,
            ]
        )


@dataclass
class Network:
    """One AP seen in the capture, with everything crackable found for it."""

    bssid: str
    essid: str = ""
    essid_source: str = ""  # 'beacon' | 'assoc' | 'filename' | 'hcxpcapngtool' | ''
    security: str = ""  # 'WPA2-PSK' | 'WPA3-SAE' | 'WPA2-Enterprise' | 'Open' | ''
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    has_pmkid: bool = False
    hashes: list[WpaHash] = field(default_factory=list)
    clients: set = field(default_factory=set)
    # client MAC -> which handshake messages that client contributed. The four
    # messages only combine into a hash when they come from the same client, so
    # the per-network M1/M2/M3/M4 flags can all look fine while nothing is usable.
    client_msgs: dict = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """Crackable = at least one hash we can actually build."""
        return bool(self.hashes)

    @property
    def display_name(self) -> str:
        return self.essid or f"<hidden {self.bssid}>"

    @property
    def essid_hex(self) -> str:
        return self.essid.encode("utf-8", errors="replace").hex()

    @property
    def is_psk(self) -> bool:
        """Whether a passphrase exists to recover at all.

        Only a mode that is *definitively* not passphrase-based (SAE, 802.1X,
        OWE) counts as False. Open/WEP/undetermined stay True so they never
        preempt a more specific explanation - and a network showing EAPOL frames
        is plainly not open, whatever a truncated beacon suggested.
        """
        if not self.security or "PSK" in self.security:
            return True
        return not any(tag in self.security for tag in ("SAE", "Enterprise", "OWE"))

    def _pairing_reason(self) -> str:
        """Explain a network whose frames are present but never combine.

        Naming the per-client split is what makes this actionable: it says which
        station still needs to be re-captured, rather than leaving "M1..M4 all OK,
        0 hashes" looking like a tool fault.
        """
        if len(self.client_msgs) > 1:
            parts = []
            for sta, msgs in sorted(self.client_msgs.items()):
                have = ",".join(m for m in ("M1", "M2", "M3", "M4") if m in msgs)
                missing = "no M2" if "M2" not in msgs else "no ANONCE (needs its own M1/M3)"
                parts.append(f"{sta} has {have} ({missing})")
            return "frames come from different clients, none complete on its own: " + "; ".join(parts)
        return "handshake messages present but none pair up (replay counters differ)"

    def reason(self) -> str:
        """Why nothing crackable came out of this network."""
        if self.is_valid:
            return ""
        if not self.is_psk:
            if "SAE" in self.security:
                return f"{self.security} - SAE has no crackable 4-way handshake"
            if "Enterprise" in self.security:
                return f"{self.security} - 802.1X, there is no PSK to recover"
            return f"{self.security} - no passphrase to recover"
        if not self.essid:
            return "ESSID unknown (no beacon/assoc frame) - cannot build a hash"
        if self.has_m2 and not (self.has_m1 or self.has_m3):
            return "M2 present but no ANONCE (needs M1 or a replay-matched M3)"
        if self.has_m1 or self.has_m2 or self.has_m3 or self.has_m4:
            return self._pairing_reason()
        if self.security in (SEC_OPEN, SEC_WEP):
            return f"{self.security} - no WPA handshake exists to capture"
        return "no PMKID and no EAPOL frames"


@dataclass
class CaptureAnalysis:
    networks: dict[str, Network] = field(default_factory=dict)
    error: str | None = None
    eapol_seen: int = 0

    @property
    def valid_networks(self) -> list[Network]:
        return [n for n in self.networks.values() if n.is_valid]

    @property
    def all_networks(self) -> list[Network]:
        return list(self.networks.values())

    def hc22000_lines(self) -> list[str]:
        lines: list[str] = []
        for net in self.valid_networks:
            for h in net.hashes:
                lines.append(h.to_line(net.essid_hex))
        return lines


# frame walking


# AKM suite selectors (IEEE 802.11, OUI 00-0F-AC). What the AP accepts for
# authentication decides whether a 4-way-handshake capture is worth anything:
# only the PSK modes derive their PTK from a passphrase we can guess.
_AKM_OUI_RSN = b"\x00\x0f\xac"
_AKM_OUI_WPA1 = b"\x00\x50\xf2"
_AKM_PSK = {2, 4, 6}          # PSK, FT-PSK, PSK-SHA256
_AKM_SAE = {8, 9}             # SAE, FT-SAE (WPA3-Personal)
_AKM_ENTERPRISE = {1, 3, 5, 11, 12, 13}
_AKM_OWE = {18}

SEC_OPEN = "Open"
SEC_WEP = "WEP"
SEC_UNKNOWN = ""


def _akm_types(body: bytes, oui: bytes) -> set[int]:
    """AKM suite types from an RSN/WPA information element body."""
    try:
        i = 2  # version
        i += 4  # group cipher suite
        if len(body) < i + 2:
            return set()
        pair_count = int.from_bytes(body[i:i + 2], "little")
        i += 2 + 4 * pair_count
        if len(body) < i + 2:
            return set()
        akm_count = int.from_bytes(body[i:i + 2], "little")
        i += 2
        out: set[int] = set()
        for _ in range(akm_count):
            suite = body[i:i + 4]
            if len(suite) < 4:
                break
            if suite[:3] == oui:
                out.add(suite[3])
            i += 4
        return out
    except Exception:
        return set()


def security_from_beacon(pkt) -> str:
    """Short label for how a network authenticates ('WPA2-PSK', 'WPA3-SAE', …).

    A capture is only crackable this way when the AP accepts a *passphrase*.
    Naming the mode turns "no handshake found" into an answer: WPA3-SAE never
    exposes a crackable 4-way, and against Enterprise the PSK does not exist -
    both are dead ends worth reporting rather than grinding a GPU against.
    """
    rsn: set[int] = set()
    wpa1: set[int] = set()
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        info = bytes(elt.info or b"")
        if elt.ID == 48:
            rsn |= _akm_types(info, _AKM_OUI_RSN)
        elif elt.ID == 221 and info[:4] == _AKM_OUI_WPA1 + b"\x01":
            wpa1 |= _akm_types(info[4:], _AKM_OUI_WPA1)
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None

    parts: list[str] = []
    if rsn & _AKM_SAE:
        parts.append("WPA3-SAE")
    if rsn & _AKM_OWE:
        parts.append("OWE")
    if (rsn | wpa1) & _AKM_ENTERPRISE:
        parts.append("WPA2-Enterprise" if rsn else "WPA-Enterprise")
    if rsn & _AKM_PSK:
        parts.append("WPA2-PSK")
    if wpa1 & {1, 2} and not rsn:
        parts.append("WPA-PSK" if 2 in wpa1 else "WPA-Enterprise")
    if parts:
        return "/".join(dict.fromkeys(parts))

    if rsn or wpa1:
        return "WPA (unknown AKM)"
    try:
        if "privacy" in pkt[Dot11Beacon].cap:
            return SEC_WEP
    except Exception:
        pass
    return SEC_OPEN


def _ssid_from_elts(pkt) -> str | None:
    """SSID from the first (ID 0) information element, or None when hidden."""
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            info = bytes(elt.info or b"")
            # A hidden network beacons a zero-length SSID, or one padded with NULs.
            if not info or set(info) == {0}:
                return None
            return info.decode("utf-8", errors="replace")
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return None


def _ap_sta(pkt, msg: str) -> tuple[str, str]:
    """(AP, STA) for an EAPOL frame, from the DS bits when they're set.

    from-DS means AP -> STA (addr2 is the BSSID), to-DS means STA -> AP (addr1 is
    the BSSID). Ad-hoc captures and some firmware leave both bits clear, so we
    fall back to the message direction: M1/M3 come from the AP, M2/M4 from the STA.
    """
    d = pkt[Dot11]
    a1, a2 = format_mac(d.addr1), format_mac(d.addr2)
    fc = int(getattr(d, "FCfield", 0) or 0)
    to_ds, from_ds = bool(fc & 0x1), bool(fc & 0x2)
    if from_ds and not to_ds:
        return a2, a1
    if to_ds and not from_ds:
        return a1, a2
    return (a2, a1) if msg in ("M1", "M3") else (a1, a2)


def _eapol_bytes(pkt) -> bytes | None:
    """Raw EAPOL blob, trimmed of 802.11 padding using the EAPOL length field."""
    try:
        raw = bytes(pkt[EAPOL])
    except Exception:
        return None
    try:
        declared = 4 + int(pkt[EAPOL].len)
    except Exception:
        return raw
    # Only trust the length field when it describes a plausible key frame;
    # a malformed/zero length must not truncate a good frame to nothing.
    if declared >= _EAPOL_MIN_LEN and len(raw) > declared:
        return raw[:declared]
    return raw


def _zero_mic(eapol: bytes) -> str | None:
    """hc22000 wants the EAPOL frame with its MIC field zeroed out."""
    if len(eapol) < _MIC_OFFSET + _MIC_LEN:
        return None
    buf = bytearray(eapol)
    buf[_MIC_OFFSET:_MIC_OFFSET + _MIC_LEN] = b"\x00" * _MIC_LEN
    return bytes(buf).hex()


def _collect(packets) -> tuple[dict[str, str], dict[str, str], dict[tuple[str, str], list[EapolFrame]], int]:
    """Walk the frames once: per-BSSID ESSIDs and security modes, and EAPOL
    frames grouped per (AP, STA)."""
    essids: dict[str, str] = {}
    security: dict[str, str] = {}
    pairs: dict[tuple[str, str], list[EapolFrame]] = {}
    eapol_seen = 0

    for pkt in packets or []:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = _ssid_from_elts(pkt)
            if pkt.haslayer(Dot11):
                bssid = format_mac(pkt[Dot11].addr2)
                if bssid not in (_BROADCAST, _ZERO_MAC):
                    if ssid:
                        essids.setdefault(bssid, ssid)
                    # Read the AKM even from a hidden-SSID beacon: knowing the AP
                    # is SAE or Enterprise is what answers "why no handshake".
                    if bssid not in security:
                        mode = security_from_beacon(pkt)
                        if mode:
                            security[bssid] = mode
        elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            # An association request names the SSID it's joining and is addressed
            # to the AP, so it rescues captures that hold no beacon for the target.
            ssid = _ssid_from_elts(pkt)
            if ssid and pkt.haslayer(Dot11):
                bssid = format_mac(pkt[Dot11].addr1)
                if bssid not in (_BROADCAST, _ZERO_MAC):
                    essids.setdefault(bssid, ssid)

        if not pkt.haslayer(EAPOL_KEY) or not pkt.haslayer(Dot11):
            continue
        ek = pkt[EAPOL_KEY]
        msg = classify_eapol(ek)
        eapol_seen += 1
        if not msg:
            continue
        raw = _eapol_bytes(pkt)
        if raw is None:
            continue
        ap, sta = _ap_sta(pkt, msg)
        if ap in (_BROADCAST, _ZERO_MAC) or sta in (_BROADCAST, _ZERO_MAC) or ap == sta:
            continue
        pmkid = extract_pmkid(bytes(ek.key_data) if ek.key_data else None) if msg == "M1" else None
        pairs.setdefault((ap, sta), []).append(
            EapolFrame(
                msg=msg,
                ap=ap,
                sta=sta,
                ts=float(getattr(pkt, "time", 0.0) or 0.0),
                replay=int(getattr(ek, "key_replay_counter", 0) or 0),
                nonce=bytes(ek.key_nonce or b""),
                eapol=raw,
                key_ver=int(getattr(ek, "key_descriptor_type_version", 0) or 0),
                pmkid=pmkid,
            )
        )
    return essids, security, pairs, eapol_seen


# pairing


def _eapol_window() -> float:
    """Seconds within which two messages may still belong to one exchange.

    The four messages of a 4-way handshake are milliseconds apart. Two seconds is
    generous enough for a retried or congested exchange while still separating
    handshake attempts made minutes apart, which must never be spliced together.
    Override with ``HANDSHAKE_EAPOL_TIMEOUT`` (seconds).
    """
    raw = os.environ.get("HANDSHAKE_EAPOL_TIMEOUT")
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            log_debug(f"_eapol_window: invalid HANDSHAKE_EAPOL_TIMEOUT={raw!r}, using default")
    return 2.0


def _closest(frames: list[EapolFrame], replay: int, ts: float, window: float | None = None) -> EapolFrame | None:
    """The replay-counter-matching frame nearest in time to ``ts``.

    Frames inside the timing window win over frames outside it; when nothing is
    inside, the nearest match is still returned so a capture with unreliable
    timestamps (some firmware writes zeros) is not thrown away.
    """
    matches = [f for f in frames if f.replay == replay and f.has_nonce]
    if not matches:
        return None
    if window is not None:
        inside = [f for f in matches if abs(f.ts - ts) <= window]
        if inside:
            matches = inside
    return min(matches, key=lambda f: abs(f.ts - ts))


def _pair_hashes(frames: list[EapolFrame]) -> list[WpaHash]:
    """Build every hash the frames of one (AP, STA) pair support.

    Messages are matched on the key replay counter, which is what ties the four
    messages of a single exchange together: M1 and M2 share a counter, and the AP
    increments it for M3/M4. Frames from different attempts therefore never get
    spliced into one hash.
    """
    by_msg: dict[str, list[EapolFrame]] = {"M1": [], "M2": [], "M3": [], "M4": []}
    for f in frames:
        by_msg[f.msg].append(f)

    out: list[WpaHash] = []
    seen: set[tuple] = set()

    def _emit(anonce_src: EapolFrame, mic_src: EapolFrame, mp: str, label: str):
        eapol_hex = _zero_mic(mic_src.eapol)
        if not eapol_hex:
            log_debug(f"_pair_hashes: {label} skipped - EAPOL too short ({len(mic_src.eapol)} bytes)")
            return
        mic = mic_src.eapol[_MIC_OFFSET:_MIC_OFFSET + _MIC_LEN].hex()
        anonce = anonce_src.nonce.hex()
        key = (mic, anonce, eapol_hex)
        if key in seen:
            return
        seen.add(key)
        out.append(
            WpaHash(
                kind="eapol",
                ap=mic_src.ap,
                sta=mic_src.sta,
                mic=mic,
                anonce=anonce,
                eapol_hex=eapol_hex,
                message_pair=mp,
                source=label,
            )
        )

    window = _eapol_window()

    # M2-based hashes. Prefer the M2+M3 form (the AP clearly accepted this M2, so
    # the passphrase behind it is the live one), and also emit M1+M2, which is
    # what a deauth-driven capture usually gives you.
    for m2 in by_msg["M2"]:
        m1 = _closest(by_msg["M1"], m2.replay, m2.ts, window)
        m3 = _closest(by_msg["M3"], m2.replay + 1, m2.ts, window)
        if m1 is not None and m3 is not None and m1.nonce != m3.nonce:
            # M1 and M3 of one exchange carry the same ANONCE. Different values
            # mean these came from two separate attempts that just happen to have
            # consecutive counters, so only the one closer to this M2 can be its
            # partner. Pairing the other would give a hash that never cracks.
            log_debug(
                f"_pair_hashes: ANONCE mismatch between M1@{m1.ts:.3f} and M3@{m3.ts:.3f} "
                f"for M2@{m2.ts:.3f} - keeping the nearer frame"
            )
            if abs(m3.ts - m2.ts) > abs(m1.ts - m2.ts):
                m3 = None
            else:
                m1 = None
        if m3 is not None:
            _emit(m3, m2, "02", "M2+M3")
        if m1 is not None:
            _emit(m1, m2, "00", "M1+M2")

    # M4-based hashes only work when the client echoed its SNONCE instead of
    # zeroing it. hashcat reads the SNONCE out of the EAPOL blob we hand it.
    for m4 in by_msg["M4"]:
        if not m4.has_nonce:
            continue
        m3 = _closest(by_msg["M3"], m4.replay, m4.ts, window)
        if m3 is not None:
            _emit(m3, m4, "03", "M3+M4")
            continue
        m1 = _closest(by_msg["M1"], m4.replay - 1, m4.ts, window)
        if m1 is not None:
            _emit(m1, m4, "01", "M1+M4")

    return out[:_MAX_HASHES_PER_PAIR]


# filename fallback

_FILENAME_MAC_RE = re.compile(r"(?i)(?:^|[_\-])((?:[0-9a-f]{2}[:\-]?){5}[0-9a-f]{2})(?:[_\-]|$)")
_AIRODUMP_SUFFIX_RE = re.compile(r"-\d{2}$")


def essid_from_filename(path: str, bssid: str) -> str | None:
    """Recover an ESSID from the capture's own file name.

    Capture tools name their files after the network - Bruce writes
    ``HS_<BSSID>_<SSID>.pcap``, airodump ``<SSID>-01.cap``. When the capture holds
    no beacon and no association request (short handshake-only dumps do not), that
    name is the only surviving record of the SSID, and without it the hash cannot
    be built at all. Only used as a last resort, and only when the file name's MAC
    matches the AP we are naming.
    """
    base = os.path.basename(path or "")
    for ext in (".pcapng", ".pcap", ".cap"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    if not base:
        return None

    m = _FILENAME_MAC_RE.search(base)
    if m:
        found = format_mac(m.group(1))
        if found != bssid:
            return None
        rest = (base[: m.start(1)] + base[m.end(1):]).strip("_- ")
        rest = re.sub(r"(?i)^(hs|handshake|pmkid|capture)[_\-]+", "", rest).strip("_- ")
        return rest or None

    # No MAC in the name: only safe when the file describes a single network.
    cleaned = _AIRODUMP_SUFFIX_RE.sub("", base).strip("_- ")
    cleaned = re.sub(r"(?i)^(hs|handshake|pmkid|capture)[_\-]+", "", cleaned).strip("_- ")
    return cleaned or None


# external extractor (hcxpcapngtool)

_HCX_TIMEOUT = 300
_hcx_cache: dict[tuple, list[str]] = {}


def hcxpcapngtool_lines(cap_path: str) -> list[str]:
    """hc22000 lines from hcxpcapngtool, or [] when it isn't installed/usable.

    Cached per (path, size, mtime): the validator and the converter both analyse
    the same capture, and there is no reason to shell out twice for it.
    """
    exe = shutil.which("hcxpcapngtool")
    if not exe or not os.path.isfile(cap_path):
        return []
    try:
        st = os.stat(cap_path)
        key = (os.path.abspath(cap_path), st.st_size, st.st_mtime_ns)
    except OSError:
        return []
    if key in _hcx_cache:
        return _hcx_cache[key]

    tmp_out = None
    lines: list[str] = []
    try:
        with tempfile.NamedTemporaryFile(suffix=".hc22000", delete=False) as tmp:
            tmp_out = tmp.name
        proc = subprocess.run([exe, "-o", tmp_out, cap_path], capture_output=True, text=True, timeout=_HCX_TIMEOUT)
        with open(tmp_out, encoding="utf-8", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip().startswith("WPA*")]
        log_debug(f"hcxpcapngtool_lines: rc={proc.returncode} lines={len(lines)}")
    except Exception as e:
        log_debug(f"hcxpcapngtool_lines: skipped ({type(e).__name__}: {e})")
    finally:
        if tmp_out and os.path.exists(tmp_out):
            try:
                os.remove(tmp_out)
            except OSError:
                pass
    _hcx_cache[key] = lines
    return lines


def _parse_hc22000_line(line: str) -> tuple[str, str, str, str] | None:
    """(kind, essid, ap, sta) from an hc22000 line, or None when unparseable."""
    parts = line.split("*")
    if len(parts) < 6 or parts[0] != "WPA":
        return None
    kind = "pmkid" if parts[1] == "01" else "eapol"
    try:
        essid = bytes.fromhex(parts[5]).decode("utf-8", "replace")
    except ValueError:
        return None
    return kind, essid, parts[3], parts[4]


def external_essids(lines: list[str]) -> dict[str, str]:
    """BSSID -> ESSID as reported by an external extractor.

    Consulted *before* our own hashes are built: without an ESSID we cannot emit
    a hash at all (it is the PBKDF2 salt), so an SSID hcxtools recovered from a
    frame we don't parse unlocks our own pairings for that AP too, not just
    hcxtools' lines.
    """
    out: dict[str, str] = {}
    for line in lines:
        parsed = _parse_hc22000_line(line)
        if parsed is None:
            continue
        _kind, essid, ap_nc, _sta = parsed
        if essid:
            out.setdefault(format_mac(ap_nc), essid)
    return out


def merge_external_lines(analysis: "CaptureAnalysis", lines: list[str]) -> int:
    """Fold an external extractor's hc22000 lines into the analysis.

    Ours and hcxtools' parsers fail on different captures - hcxtools copes with
    malformed radiotap and vendor quirks we don't model, we recover an ESSID from
    the file name it never sees. Merging here rather than at write time means the
    validation report, the hash file and the attack plan all describe the same set
    of networks. Returns the number of lines added.
    """
    known = {h.to_line(net.essid_hex) for net in analysis.networks.values() for h in net.hashes}
    added = 0
    for line in lines:
        if line in known:
            continue
        parsed = _parse_hc22000_line(line)
        if parsed is None:
            continue
        kind, essid, ap_nc, sta_nc = parsed
        ap = format_mac(ap_nc)
        net = analysis.networks.get(ap)
        if net is None:
            net = Network(bssid=ap, essid=essid, essid_source="hcxpcapngtool")
            analysis.networks[ap] = net
        elif not net.essid:
            net.essid, net.essid_source = essid, "hcxpcapngtool"
        if net.essid != essid:
            # Same AP reported under a different SSID (multi-SSID radio): keep it
            # as its own entry rather than silently relabelling either one.
            log_debug(f"merge_external_lines: {ap} reported as {essid!r}, ours says {net.essid!r} - keeping both")
            continue
        sta = format_mac(sta_nc)
        net.clients.add(sta)
        if kind == "pmkid":
            net.has_pmkid = True
        net.hashes.append(WpaHash(kind=kind, ap=ap, sta=sta, source="hcxpcapngtool", raw=line))
        known.add(line)
        added += 1
    if added:
        log_debug(f"merge_external_lines: added {added} hash(es) hcxpcapngtool found and we did not")
    return added


# entry points


def analyze_packets(packets, capture_path: str = "") -> CaptureAnalysis:
    """Group a capture's frames into per-network crackable hashes."""
    analysis = CaptureAnalysis()
    essids, security, pairs, eapol_seen = _collect(packets)
    analysis.eapol_seen = eapol_seen

    external = hcxpcapngtool_lines(capture_path) if capture_path else []
    hcx_essids = external_essids(external)

    def _net(bssid: str) -> Network:
        net = analysis.networks.get(bssid)
        if net is None:
            essid = essids.get(bssid, "")
            source = "beacon"
            if not essid and bssid in hcx_essids:
                essid, source = hcx_essids[bssid], "hcxpcapngtool"
            net = Network(
                bssid=bssid,
                essid=essid,
                essid_source=source if essid else "",
                security=security.get(bssid, ""),
            )
            analysis.networks[bssid] = net
        return net

    for bssid in essids:
        _net(bssid)

    single_ap = len({ap for ap, _ in pairs}) == 1

    for (ap, sta), frames in pairs.items():
        net = _net(ap)
        net.clients.add(sta)
        for f in frames:
            setattr(net, f"has_{f.msg.lower()}", True)
            net.client_msgs.setdefault(sta, set()).add(f.msg)
            if f.pmkid:
                net.has_pmkid = True

        if not net.essid and capture_path:
            # Last resort: the file name. Requires a matching MAC in the name,
            # unless this capture describes exactly one AP.
            guessed = essid_from_filename(capture_path, ap)
            if guessed and (single_ap or _FILENAME_MAC_RE.search(os.path.basename(capture_path))):
                net.essid, net.essid_source = guessed, "filename"
                log_debug(f"analyze_packets: ESSID for {ap} recovered from filename: {guessed!r}")

        if not net.essid:
            log_debug(f"analyze_packets: {ap} has no ESSID - skipping hash generation")
            continue

        seen_pmkid: set[str] = set()
        for f in frames:
            if f.pmkid and f.pmkid not in seen_pmkid:
                seen_pmkid.add(f.pmkid)
                net.hashes.append(WpaHash(kind="pmkid", ap=ap, sta=sta, pmkid=f.pmkid, source="PMKID"))
        net.hashes.extend(_pair_hashes(frames))

    if external:
        merge_external_lines(analysis, external)

    log_debug(
        f"analyze_packets: {len(analysis.networks)} network(s), "
        f"{sum(len(n.hashes) for n in analysis.networks.values())} hash(es) from {eapol_seen} EAPOL frame(s)"
    )
    return analysis


def read_relevant_packets(filepath: str) -> list:
    """Load only the frames that matter, so big captures stay cheap to handle."""
    packets = []
    with PcapReader(filepath) as pcap:
        for pkt in pcap:
            if (
                pkt.haslayer(EAPOL_KEY)
                or pkt.haslayer(Dot11Beacon)
                or pkt.haslayer(Dot11ProbeResp)
                or pkt.haslayer(Dot11AssoReq)
                or pkt.haslayer(Dot11ReassoReq)
            ):
                packets.append(pkt)
    return packets


def analyze_capture(filepath: str) -> CaptureAnalysis:
    """Read a capture file and group it into per-network crackable hashes."""
    try:
        packets = read_relevant_packets(filepath)
    except Exception as e:
        analysis = CaptureAnalysis()
        analysis.error = f"cannot read pcap: {e}"
        return analysis
    return analyze_packets(packets, filepath)
