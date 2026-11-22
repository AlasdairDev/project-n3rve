"""Default-PSK candidate generation for ISP / router factory keys, worldwide.

Several ISP routers derive the factory Wi-Fi key deterministically from the BSSID
(AP MAC) or the SSID suffix. When they do, we can *compute* the handful of likely
default keys instead of brute-forcing - far more effective than any wordlist for a
factory-default router, and effectively instant (a few dozen candidates).

The derivable algorithms below are transcribed from the open RouterKeygen project
(routerkeygen/routerkeygenPC, GPL-3.0 - ported from its Qt C++ ``src/algorithms/*``
and ``WirelessMatcher.cpp``), the community reference for ISP default keys
worldwide, plus the PH ISP research already shipped (PLDT / HomeBro). References:

- https://github.com/routerkeygen/routerkeygenPC      (Arcadyan / EasyBox, Sky V1,
                                                       Wlan6, Zyxel, Bssid, HG824x,
                                                       PLDT keygens)
- https://github.com/andrewjlamarche/PSKracker         (keyspaces / masks reference)
- https://github.com/ebux/Cable-modems                 (Cisco UPC modem POC)

Only WPA-valid candidates (8..63 chars) are ever returned.
"""

import functools
import hashlib
import re

from src.console import log_debug

WPA_MIN, WPA_MAX = 8, 63
_HEX = "0123456789abcdefABCDEF"
_DEC = "0123456789"
_HEX_LOWER = "0123456789abcdef"

# How far to fan out from the exact BSSID tail when deriving PLDT keys. The label
# key is seeded from one specific interface MAC, but the BSSID we capture might be a
# sibling radio/guest BSSID offset by a bit, so we also try +/- this many values.
# Kept small so the computed stage stays a few dozen candidates (instant).
_MAC_SPAN = 6


def _nibble_complement(hexstr: str) -> str:
    """Per-nibble complement (15 - n) of a hex string. 'c5c4c9' -> '3a3b36'."""
    out = []
    for ch in hexstr:
        try:
            out.append(format(15 - int(ch, 16), "x"))
        except ValueError:
            return ""
    return "".join(out)


def _trailing_run(text: str, charset: str) -> str:
    """Longest trailing run of characters from charset."""
    s = (text or "").strip()
    i = len(s)
    while i > 0 and s[i - 1] in charset:
        i -= 1
    return s[i:]


def _clean_mac(bssid_hex: str) -> str:
    """Strip separators and lower-case a BSSID/MAC. Non-hex chars are dropped."""
    raw = (bssid_hex or "").replace(":", "").replace("-", "").replace(".", "").strip().lower()
    return "".join(c for c in raw if c in _HEX_LOWER)


def _tail6_neighbors(mac6: str, span: int = _MAC_SPAN) -> list[str]:
    """The 6-hex MAC tail plus its +/- span neighbours (24-bit wrap)."""
    if len(mac6) != 6 or any(c not in _HEX_LOWER for c in mac6):
        return []
    base = int(mac6, 16)
    offsets = [0]
    for k in range(1, span + 1):
        offsets += [k, -k]
    seen: set[str] = set()
    out: list[str] = []
    for d in offsets:
        h = format((base + d) & 0xFFFFFF, "06x")
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _pldt_from_tail(tail: str) -> list[str]:
    """All documented PLDT key forms derived from one 6-hex MAC tail."""
    cands: list[str] = []
    inv = _nibble_complement(tail)
    if inv:
        cands.append("wlan" + inv)              # Baudtec:  wlanXXXXXX
        cands.append("PLDTWIFI" + inv.upper())  # PLDTWIFI + complement (upper)
        cands.append("PLDTWIFI" + inv)          # PLDTWIFI + complement (lower)
    cands.append("wlan" + tail)                 # wlan + plain tail (some Baudtec)
    cands.append("PLDTWIFI" + tail.upper())     # Fiberhome: PLDTWIFI + last-6 MAC (upper)
    cands.append("PLDTWIFI" + tail)             # PLDTWIFI + last-6 MAC (lower)
    cands.append("HomeBro_" + tail.upper())     # HomeBro Ultera
    return cands


@functools.lru_cache(maxsize=512)
def pldt_candidates(essid: str, bssid_hex: str, mac_span: int = _MAC_SPAN) -> list[str]:
    """Candidate default keys for PLDT Home Fibr / DSL / HomeBro routers."""
    cands: list[str] = []
    mac = _clean_mac(bssid_hex)
    mac6 = mac[-6:] if len(mac) >= 6 else ""
    mac5 = mac[-5:] if len(mac) >= 5 else ""

    for tail in _tail6_neighbors(mac6, mac_span):
        cands.extend(_pldt_from_tail(tail))

    if len(mac5) == 5:
        cands.append("PLDTWIFI" + mac5.upper())        # PLDTHOMEDSL 5-hex variants
        inv5 = _nibble_complement(mac5)
        if inv5:
            # PLDTHOMEFIBR_xxxxx: key = PLDTWIFI + inverted last-5 MAC (upper)
            cands.append("PLDTWIFI" + inv5.upper())
            cands.append("wlan" + inv5)                # ... or wlan + inverted last-5

    # SSID-suffix-derived variants (the suffix usually mirrors the MAC tail).
    hex_suf = _trailing_run(essid, _HEX)
    if len(hex_suf) >= 6:
        tail = hex_suf[-6:].lower()
        inv = _nibble_complement(tail)
        if inv:
            cands.append("PLDTWIFI" + inv.upper())
            cands.append("wlan" + inv)
        cands.append("PLDTWIFI" + tail.upper())
    if len(hex_suf) >= 4 and all(c in _DEC for c in hex_suf):
        # Pure-numeric 4-6 suffix (PLDTHOMEDSL21354 / PLDTWIFI52374):
        # PLDTWIFI + decimal * 3. Also 6-digit numeric SSIDs get this alongside
        # the hex forms above, matching the documented x3 behaviour.
        cands.append("PLDTWIFI" + str(int(hex_suf) * 3))
    elif len(hex_suf) == 5 and any(c not in _DEC for c in hex_suf):
        # 5-hex-letter suffix: BOTH documented forms apply to different DSL lines.
        # PLDTHOMEDSL/b4870: nibble-complement of the last 5 -> PLDTWIFI4B78F.
        # PLDTHOMEDSL547AD: hex -> dec, x3 -> PLDTWIFI1038087.
        inv5 = _nibble_complement(hex_suf.lower())
        if inv5:
            cands.append("PLDTWIFI" + inv5.upper())
            cands.append("wlan" + inv5)
        try:
            cands.append("PLDTWIFI" + str(int(hex_suf, 16) * 3))
        except ValueError:
            pass
    return cands


def looks_like_pldt(essid: str, bssid_hex: str = "") -> bool:
    """True when the network looks like factory-default PLDT gear."""
    e = re.sub(r"[^A-Z0-9]", "", (essid or "").upper())
    return e.startswith("PLDT") or e.startswith("HOMEBRO") or "PLDTHOME" in e


def looks_like_converge(essid: str) -> bool:
    """True when the SSID belongs to Converge ICT gear.

    Converge broadcasts under several label styles: ``Converge_…``,
    ``Convergeics_…``, ``wlan…``/WLAN-prefixed, ``0FS_…``, and the
    Converge-deployed ``ZTE_2.4G_…`` dual-band routers (documented in the PH
    community). Their default Windows key is deriveable from the last 6 hex of the
    WPA/MAC (see converge_candidates) - they are NOT random label-printed keys.
    """
    e = (essid or "").strip()
    if not e:
        return False
    if re.match(r"(?i)converge|0fs", e):
        return True
    if re.match(r"(?i)ZTE[._-]?[0-9.]+[gGHz]", e):
        return True
    # legacy "wlan" SSIDs are ambiguous (both PLDT & Converge use them) but the
    # wlan+hex file is the same, so it's safe to include.
    return re.match(r"(?i)wlan[_0-9a-f]", e) is not None


@functools.lru_cache(maxsize=512)
def converge_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Converge ICT factory WPA keys - ``wlan`` + per-nibble complement of the
    last E6hex of the AP MAC (or, when the SSID carries a hex suffix, of the
    suffix, which mirrors the label). Documented derivation:
    https://www.phbreaker.com/2021/10/converge-wifi-password-hack-new-hex-code.html
    and the kleo.hak.dog / mkdirlove references.

    Gated to Converge-ish SSIDs so off-brand APs aren't polluted. Both the
    lower-case ``wlan`` form (canonical) and the PLDTWIFI-complement show up in
    the wild; both are produced.
    """
    if not looks_like_converge(essid):
        return []

    cands: list[str] = []

    mac = _clean_mac(bssid_hex)
    if len(mac) >= 6:
        for tail in _tail6_neighbors(mac[-6:], _MAC_SPAN):
            inv = _nibble_complement(tail)
            if inv:
                cands.append("wlan" + inv)
                cands.append("PLDTWIFI" + inv.upper())
            cands.append("wlan" + tail)
            cands.append("PLDTWIFI" + tail.upper())

    # SSID suffix mirrors the MAC tail for Converge fiber gear.
    hex_suf = _trailing_run(essid, _HEX)
    if len(hex_suf) >= 6:
        tail = hex_suf[-6:].lower()
        inv = _nibble_complement(tail)
        if inv:
            cands.append("wlan" + inv)
            cands.append("PLDTWIFI" + _clean_mac(inv).upper())
        cands.append("wlan" + tail)
        cands.append("PLDTWIFI" + tail.upper())
    elif len(hex_suf) == 5:
        # 5-hex suffix form (0FS_abcde) mirrors the last-5 MAC derivation.
        tail5 = hex_suf[-5:].lower()
        inv5 = _nibble_complement(tail5)
        if inv5:
            cands.append("wlan" + inv5)
            cands.append("PLDTWIFI" + inv5.upper())
        cands.append("wlan" + tail5)
        cands.append("PLDTWIFI" + tail5.upper())

    return _dedupe_valid(cands)


# Globe PROLiNK AT-Home routers build the WPA key by dropping the literal string
# "WIFI" into the middle of the last 6 hex chars of the AP MAC. So
# MAC ...A1B2C3 -> "A1B WIFI 2C3" -> A1BWIFI2C3. Documented in the PH community
# reference for Globe At Home (kleo.hak.dog). Gated on a Globe-ish SSID so it only
# fires on in-scope PH gear.
_GLOBE_WIFI = "WIFI"


@functools.lru_cache(maxsize=512)
def globe_wifi_mac_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Globe At Home PROLiNK keys: insert 'WIFI' in the middle of the last-6 MAC."""
    if not essid or not re.match(r"(?i)globe", (essid or "").strip()):
        return []
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12:
        return []
    tail = mac[-6:].upper()
    cand = tail[:3] + _GLOBE_WIFI + tail[3:]
    return [cand] if WPA_MIN <= len(cand) <= WPA_MAX else []


@functools.lru_cache(maxsize=512)
def mybro_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Smart MyBro Wimax / old PLDT-homefibr - myBROWWIFI + MAC-decrement forms.

    The WAN-bridged radio's key is documented as ``myBROWIFI`` + the *WAN* MAC tail
    decremented by 2 (the beaconing WLAN MAC is usually WAN + 2), or the plain
    last-5 MAC for old PLDT firmware. The captured BSSID may be offset, so the
    +/- tail neighbours are tried too. All documented upper/lower variants.
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) < 10 or not mac[:6]:
        return []
    if not re.match(r"(?i)mybro", (essid or "").strip()) and not looks_like_pldt(essid):
        return []

    out: list[str] = []

    def _emit(tail: str):
        try:
            d = (int(tail, 16) - 2) & 0xFFFFFF
        except ValueError:
            return
        up = format(d, "06X")
        lo = format(d, "06x")
        out.append("myBROWIFI" + up)
        out.append("mybrowifi" + up)
        out.append("myBROWIFI" + lo)

    for t in _tail6_neighbors(mac[-6:], _MAC_SPAN) + [mac[-5:].zfill(6)]:
        if len(t) == 6 and t not in ("", None):
            _emit(t)
    # my mbrowifi + plain last-5 (old PLDT firmware form)
    if len(mac) >= 11:
        out.append("myBROWIFI" + mac[-5:].upper())
        out.append("myBROWIFI" + mac[-5:])
    return _dedupe_valid(out)


@functools.lru_cache(maxsize=512)
def sagecom_candidates(essid: str, bssid_hex: str) -> list[str]:
    """PLDT Sagemcom - ``PLDTWIFI`` + the last 5 MAC hex, final octet incremented by 2.

    The nibble-offset slice is deliberate, not a transcription slip: the suffix is
    *five* hex characters (``mac[7:12]``), so three come from ``mac[7:10]`` and two
    from the incremented final octet. That octet has to be printed zero-padded -
    unpadded, every AP whose last octet is <= 0x0D (or wraps past 0xFF) yielded a
    four-character suffix, i.e. a key that cannot match. That was 16 of 256 last
    octets, ~6% of this family silently un-crackable.

    Both readings of the "+2" are emitted: increment the final octet alone, and
    increment the MAC as a whole so a carry propagates. They differ only when the
    last octet is >= 0xFE, and the extra candidate is free at this scale.
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12 or not looks_like_pldt(essid):
        return []
    try:
        last = int(mac[10:12], 16)
        whole = int(mac, 16)
    except ValueError:
        return []

    suffixes = [
        mac[7:10] + format((last + 2) & 0xFF, "02x"),          # final octet only
        format((whole + 2) & 0xFFFFFFFFFFFF, "012x")[7:12],    # whole MAC, with carry
    ]
    out: list[str] = []
    for suffix in suffixes:
        for form in (suffix.upper(), suffix.lower()):
            cand = "PLDTWIFI" + form
            if WPA_MIN <= len(cand) <= WPA_MAX and cand not in out:
                out.append(cand)
    return out


# International derivable default keys (RouterKeygen ports)

@functools.lru_cache(maxsize=512)
def arcadyan_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Arcadyan / Astoria WPA key (Vodafone / EasyBox / Arcor, DACH).

    Factory WPA key = 9 hex nibbles XORed from the decimal value of the last 4 MAC
    bytes and the final 4 MAC nibbles. Translated from ArcadyanKeygen.cpp. A variant
    that substitutes '1' for any '0' nibble is also produced. Matches
    ORIGINALAndroid's SSID gate (Arcor/EasyBox/Vodafone/WLAN + 6 hex, or Vodafone-net +4).
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12:
        return []
    if not re.fullmatch(r"(?:Arcor|EasyBox|Vodafone|WLAN)[- ][0-9a-fA-F]{6}", essid) and not re.search(
        r"Vodafone[0-9a-zA-Z]{4}", essid
    ):
        return []

    c1 = "%05d" % int(mac[8:12], 16)                      # decimal of last-4 MAC bytes
    s7, s8, s9, s10 = (int(ch, 16) for ch in c1[1:5])
    m9, m10, m11, m12 = (int(ch, 16) for ch in mac[8:12])

    k1 = (s7 + s8 + m11 + m12) & 0x0F
    k2 = (m9 + m10 + s9 + s10) & 0x0F
    x1 = k1 ^ s10
    x2 = k1 ^ s9
    x3 = k1 ^ s8
    y1 = k2 ^ m10
    y2 = k2 ^ m11
    y3 = k2 ^ m12
    z1 = m11 ^ s10
    z2 = m12 ^ s9
    z3 = k1 ^ k2
    key = "".join(format(v, "x") for v in (x1, y1, z1, x2, y2, z2, x3, y3, z3)).upper()
    out = [key]
    if "0" in key:
        out.append(key.replace("0", "1"))
    return out


def _bssid_mac_key(mac: str, length: int, offset: int, cut_left: bool = False) -> str:
    """BssidKeygen.cpp: MAC substring, trailing 24-bit value + offset, fixed width."""
    if len(mac) != 12 or length not in (8, 10, 12):
        return ""
    t = mac[:length] if cut_left else mac[12 - length:]
    value = format((int(t[-6:], 16) + offset) & 0xFFFFFF, "06x")
    return t[: length - 6] + value


_BSSID_RULES = [
    (r"^Reliance[ \t].*$|^YOTA$|^YOTAZ$|^YotaCPE[0-9A-F]{5}$|^Aztech110_[0-9A-F]{4}$|^HEXABYTE_[0-9A-F]{6}$|^BOLT! SUPER 4G-[0-9A-F]{4}$|^MBLAZE-AC3633-[0-9A-F]{4}$|^MBLAZE-AC3633R2-[0-9A-F]{4}$|^VodafoneNet-[0-9A-F]{4}$", [(8, 0, "U", False)]),
    (r"^netis$|^MGTS_GPON_[0-9A-F]{4}$|^MGTS[-_][0-9]+$|^mgts[0-9]{3}$|^HAME_([0-9A-Z]{2,4})_[0-9a-f]{4}$|^MBR[0-9]{2,4}-[0-9a-f]{3}$|^MIFI_[0-9A-Z]{2}_[0-9a-f]{4}$|^wi-fi[0-9]{4}$|^true_home2G_[0-9a-f]{3}$", [(8, 0, "L", False)]),
    (r"^Broadband Express$|^AER[0-9]{2,4}-[0-9a-f]{3}$", [(8, -1, "U", False)]),
    (r"^H2O[2]OLBTSpot|^CLEARSpot[0-9A-F]{5}$|^telew_[0-9a-f]{3}$", [(8, -1, "L", False)]),
    (r"^PTCL", [(8, -1, "L", False), (8, -1, "U", False)]),
    (r"^MAXNET-[0-9A-F]{4}$", [(8, -2, "U", False)]),
    (r"^MAXNET-[0-9a-f]{4}$", [(8, -2, "L", False)]),
    (r"^NET_2G[0-9A-F]{6}$|^NET_2G_[0-9]{3}$", [(8, -6, "U", False), (8, -5, "U", False), (12, -6, "U", False), (12, -5, "U", False)]),
    (r"^OPTIC[0-9a-fA-F]{4}$", [(8, -16, "U", False)]),
    (r"^TeleRed-[0-9A-F]{4}$|^Ubee[0-9A-F]{4}$", [(10, -4, "U", False)]),
    (r"^PTV[0-9]{4}$|^VIVO-[0-9A-F]{4}$", [(10, 0, "U", False)]),
    (r"^CTM-", [(10, 0, "L", False)]),
    (r"^AXTEL EXTREMO$|^VIVO-[0-9A-F]{4}$", [(10, 1, "U", False)]),
    (r"^Comtrend[0-9A-F]{4}$", [(10, -1, "U", False)]),
    (r"^D-Link$|^VIVOFIBRA-[0-9A-F]{4}$", [(10, -2, "L", False)]),
    (r"^D-Link$|^NetZero-[0-9A-F]{6}$", [(10, -1, "L", False)]),
    (r"^ORANGE-[0-9A-F]{4}$", [(12, -6, "L", False)]),
    (r"^Distributel_[0-9]{5}$", [(12, -3, "L", False), (12, -2, "L", False)]),
    (r"^FLOW[0-9]{4}$", [(12, -2, "U", False)]),
    (r"^Access[0-9]{3}$", [(12, 2, "U", False)]),
    (r"^Lukman_Wi_Fi_[0-9]{7}$", [(12, 1, "U", False)]),
    (r"^Upvel_?[0-9a-f]{4}$", [(12, 1, "L", False), (12, 2, "L", False), (12, 3, "L", False)]),
    (r"^Nemont|^TURBONET|^300NWLAN|^DJAWEB_|^Djaweb[0-9]{8}$|^MAXCOM[0-9a-zA-Z]{4}$|^(PTV-|ptv|ptv-)[0-9a-zA-Z]{6}$", [(12, 0, "U", False)]),
    (r"^MTNL$", [(12, 0, "U", False), (12, 1, "U", False), (12, 2, "U", False)]),
    (r"^Claro-[0-9A-F]{4}$", [(12, 0, "U", False), (12, 0, "L", False)]),
    (r"^CIK[0-9]{4}$", [(12, -1, "L", False)]),
    (r"^Slingshot Home WIFI [0-9]{3}$", [(12, -1, "U", False), (12, -1, "L", False)]),
    (r"^ElectronicBox", [(12, -2, "L", False)]),
    (r"^AKADO-[0-9A-F]{4}$", [(12, -6, "L", False)]),
    (r"^movistar_[0-9a-f]{6}$", [(12, -9, "L", False)]),
    (r"^OTE[0-9a-fA-F]{6}$|^conn-x[0-9a-f]{6}$|^Claro[0-9A-F]{4}$|^Wind WiFi [0-9a-zA-Z]{6}$|^Megared[0-9a-f]{4}$|^CIK1000M_2.4G_[0-9]{4}$|^CIK1000M_AC2.4G_[0-9]{4}$|^2KOM_[0-9a-f]{6}$", [(12, 0, "L", False)]),
    (r"^ZTE-[0-9a-f]{6}$", [(8, 0, "L", True), (8, 1, "L", True)]),
    (r"^LIME[0-9]{4}$", [(10, 0, "U", True), (12, -2, "U", False)]),
]

# A few families that also require a specific BSSID OUI (from RouterKeygen).
_BSSID_RULES_MAC = [
    (r"^HOTBOX-[0-9A-F]{4}$", [(12, -6, "L", False)], ("7cb733", "a0648f", "b4eeb4", "e0cec3")),
    (r"^TP-LINK_[0-9A-F]{6}$", [(8, 0, "U", False)], ("10feed", "30b5c2", "6466b3", "647002", "90f652", "a0f3c1", "c04a00", "f81a67")),
]


@functools.lru_cache(maxsize=512)
def _bssid_tail_candidates(essid: str, bssid_hex: str) -> list[str]:
    """'SSID suffix == last-of-MAC' family used by dozens of ISPs worldwide.

    For patterns like VIVO-, Orange-, NetZero-, Distributel_, FLOW, movistar … the
    factory key is simply the relevant slice of the BSSID (8/10/12 hex chars, upper
    or lower), often keyed off the MAC offset by a few units. Translated from
    BssidKeygen.cpp; mac_span/mask handled explicitly per-pattern below.
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12:
        return []
    out: list[str] = []

    def _push(cand: str, case: str):
        out.append(cand.upper() if case == "U" else cand.lower())

    for regex, flags in _BSSID_RULES:
        if re.match(regex, essid):
            for length, offset, case, cut_left in flags:
                cand = _bssid_mac_key(mac, length, offset, cut_left)
                if cand:
                    _push(cand, case)

    for regex, flags, ouis in _BSSID_RULES_MAC:
        if re.match(regex, essid) and mac.startswith(ouis):
            for length, offset, case, cut_left in flags:
                cand = _bssid_mac_key(mac, length, offset, cut_left)
                if cand:
                    _push(cand, case)

    # WIFI-XXXX: the SSID suffix must equal the AP's last 4 MAC hex.
    if re.fullmatch(r"WIFI-[0-9A-F]{4}", essid) and mac[-4:] == essid[5:].lower():
        cand = _bssid_mac_key(mac, 10, 0, False)
        if cand:
            _push(cand, "U")

    # OnLime_ reconstructs the MAC from the SSID suffix.
    if re.fullmatch(r"OnLime_[0-9A-F]{4}", essid):
        macfix = mac[:10] + essid[7:9].lower() + essid[9:].lower()
        cand = _bssid_mac_key(macfix, 12, 0, False)
        if cand:
            _push(cand, "L")
    return out


# HG824x WPA key (Huawei FTTH 'HG824KS' family). Gated to the source's OUI list.
_HG824X_OUIS = (
    "001882", "001e10", "0022a1", "002568", "00259e", "0034fe",
    "00464b", "00664b", "00e0fc", "00f81c", "0819a6", "086361",
    "087a4c", "08e84f", "101b54", "104780", "105172", "10c61f",
    "2008ed", "200bc7", "202bc1", "20f3a3", "283152", "283ce4",
    "285fdb", "286ed4", "4846fb", "486276", "7054f5", "70723c",
    "707be8", "70a8e3", "8038bc", "80717a", "80b686", "80d09b",
    "80fb06", "ac4e91", "ac856d", "ace215", "ace87b", "cc53b5",
    "cc96a0", "cca223", "cccc81", "d440f0", "d46aa8", "d46e5c",
    "d494e8", "d4b110", "d4f9a1", "e0191d", "e0247f", "e03676",
    "e09796", "f80113", "f83dff", "f84abf", "f898b9", "f8bf0d",
    "f8e811",
)

# HG824xKeygen.cpp: (first MAC byte -> last two PSK hex chars) known-map + fallback.
_HG824X_TAIL_MAP = {
    "00": "0d", "08": "05", "10": "0e", "20": "1f", "28": "03", "48": "24",
    "68": "39", "70": "20", "78": "04", "80": "06", "9c": "2a", "ac": "1a",
    "cc": "12", "d4": "23", "e0": "0c", "f8": "21",
}


@functools.lru_cache(maxsize=512)
def hg824x_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Huawei HG824x (classic FTTH ONT) WPA key, from HG824xKeygen.cpp.

    When the first MAC byte isn't in the known-output map, all 256 two-hex PSK
    tails are derived (the first 6 hex are computed exactly). Matches the source's
    OUI gate so off-brand APs aren't polluted.
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12 or not mac.startswith(_HG824X_OUIS):
        return []

    key = mac[6:8]
    last_pair = int(mac[10:12], 16)
    if last_pair <= 8:
        key += format((int(mac[8:10], 16) - 1) & 0xFF, "x")
    else:
        key += mac[8:10]
    last_char = int(mac[11], 16)
    if last_char <= 8:
        key += format((int(mac[10], 16) - 1) & 0xF, "x")
    else:
        key += mac[10]
    # Nibble rotation map: 8->F, 9->0, a->1 .. f->6, 0->7 .. 7->E  == (n+7)&0xF.
    key += format((last_char + 7) & 0xF, "x").upper()

    prefix = key.upper()
    tail = _HG824X_TAIL_MAP.get(mac[:2])
    if tail:
        return [prefix + tail.upper()]
    return [prefix + format(i, "02X") for i in range(256)]


@functools.lru_cache(maxsize=512)
def zyxel_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Zyxel / JAZZTEL / OTE - ZyxelKeygen.cpp.

    PSK = first 20 hex of MD5(mac-left-8 + ssid-right-4), uppercase. Gated to the
    documented Zyxel OUIs (00:1F:A4 / F4:3E:61 / 40:4A:03).
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12:
        return []
    if not re.fullmatch(r"(WLAN|JAZZTEL)_[0-9a-fA-F]{4}|OTE[0-9A-F]{6}", essid or ""):
        return []
    if not mac.startswith(("001fa4", "f43e61", "404a03")):
        return []
    mac_mod = mac[:8] + (essid or "")[-4:]
    return [hashlib.md5(mac_mod.lower().encode("ascii", "replace")).hexdigest()[:20].upper()]


def _wlan6_nibble(ch: str) -> int:
    """Wlan6Keygen.cpp nibble transform: hex char -> 0-15 (letters '-55' then &0xF)."""
    o = ord(ch)
    return ((o - 55) if o >= 65 else o) & 0xF


@functools.lru_cache(maxsize=512)
def wlan6_candidates(essid: str, bssid_hex: str) -> list[str]:
    """Wlan6 / WiFi6 / YaCom routers - the full 10 x 13-hex key set.

    Translated from Wlan6Keygen.cpp; the 'loop' parameter generates all 10 likely
    keys for the (intentionally undocumented) algorithm.
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12:
        return []
    if not re.fullmatch(r"(WLAN|WiFi|YaCom)[0-9a-zA-Z]{6}", essid or ""):
        return []

    ssid_part = [_wlan6_nibble(c) for c in (essid or "")[-6:]]
    bss_part = [_wlan6_nibble(c) for c in mac[-2:]]

    out: list[str] = []
    for _ in range(10):
        aux = ssid_part[3] + bss_part[0] + bss_part[1]
        aux1 = ssid_part[1] + ssid_part[2] + ssid_part[4] + ssid_part[5]
        b = [0] * 13
        b[1] = aux ^ ssid_part[5]
        b[5] = aux ^ ssid_part[4]
        b[9] = aux ^ ssid_part[3]
        b[2] = aux1 ^ ssid_part[2]
        b[6] = aux1 ^ bss_part[0]
        b[10] = aux1 ^ bss_part[1]
        b[3] = bss_part[0] ^ ssid_part[5]
        b[7] = bss_part[1] ^ ssid_part[4]
        b[11] = aux ^ aux1
        b[4] = b[1] ^ b[7]
        b[8] = b[6] ^ b[10]
        b[12] = b[2] ^ b[9]
        b[0] = b[11] ^ b[5]
        out.append("".join(format(v & 0xF, "x") for v in b).upper())
    return out


# Sky V1 (UK Sky Home Hub): MD5(mac) mapped onto A-Z at positions 1,3,..15.
_SKYV1_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_SKYV1_OUIS = (
    "c43dc7", "e0469a", "e091f5", "00095b", "000fb5", "00146c", "00184d",
    "0026f2", "c03f0e", "30469a", "001b2f", "a021b7", "001e2a", "001f33",
    "00223f", "0024b2",
)


@functools.lru_cache(maxsize=512)
def skyv1_candidates(essid: str, bssid_hex: str) -> list[str]:
    """UK Sky Home Hub v1 - MD5(BSSID) -> 8 uppercase letters (SkyV1Keygen.cpp)."""
    mac = _clean_mac(bssid_hex)
    if len(mac) != 12:
        return []
    if not re.fullmatch(r"SKY[0-9]{5}", essid or ""):
        return []
    if not mac.startswith(_SKYV1_OUIS):
        return []
    digest = hashlib.md5(mac.encode("ascii")).digest()
    return ["".join(_SKYV1_ALPHABET[digest[i] % 26] for i in range(1, 16, 2))]


# Static defaults seen in the wild across ISP consumer gear. WPA-valid only
# (>= 8 chars). Kept small and high-signal on purpose, not a dumping ground.
_STATIC_GLOBAL_DEFAULTS = [
    # all-common short keys
    "12345678", "123456789", "1234567890", "0123456789", "1234567891",
    "11223344", "1122334455", "12121212", "12341234",
    "1234567890123456", "1234567812345678",
    "0000000000", "1111111111", "00000000", "11111111", "88888888", "66666666",
    "987654321", "9876543210",
    # passwords / admin-ish
    "password", "password1", "password123", "password1234",
    "P@ssw0rd", "P@ssw0rd1", "p@ssw0rd123",
    "dragon123", "football123", "baseball123", "letmein123",
    "qwertyuiop", "qwerty123", "qwerty1234", "1qaz2wsx", "1qazxsw2",
    "qazwsxedc", "1q2w3e4r", "1q2w3e4r5",
    "admin1234", "admin12345", "admin123456", "adminadmin", "administrator",
    "root12345", "root1234", "toor1234", "changeme123",
    "user12345", "user1234",
    "default123", "default1234",
    "wireless", "wireless1", "wireless123",
    "internet", "internet123", "internet1234", "home12345", "home1234",
    "hello12345", "hello1234", "abcd1234", "abcd12345",
    "abc12345", "abc123456", "xyz12345", "a1b2c3d4", "a1b2c3d4e5",
    "1234abcd", "1234qwer", "qwer1234", "asdf1234", "zxcv1234",
    "wifi12345", "wifi1234", "wifipass123",
    "guest12345", "guest1234",
    "iloveyou123", "welcome123", "welcome12345", "monkey123",
    "1a2b3c4d",
    "pilipinas", "pinoy12345", "mahalkita",
# PH ISP label-printed WPA keys: the actual Wi-Fi keys printed on the device
# sticker (pldthome / smartbro). Converge's Wi-Fi key is derivable (wlan+hex
# complement) and handled by the computed candidates, not the admin-panel
# passwords (C0nv3rg3FH!, Converge@zte123, admintelecom...) which open the
# router web UI and aren't the Wi-Fi passphrase.
    "pldthome", "pldthome1", "pldthome123",
    "smartbro", "smartbro123", "smartbrother",
]


# Additional PH ISP label-printed Wi-Fi passphrases commonly seen on router
# stickers across Philippine ISPs. Factory defaults, not admin passwords.
_PH_STATIC_DEFAULTS = [
    # PLDT Home Fibr / DSL / HomeBro
    "pldthomefibr", "pldthomedsl", "pldtwifi123", "pldtwifi1234",
    "pldthomefibr123", "pldthomedsl123",
    "PLDTHOMEFIBR", "PLDTHOMEDSL", "PLDTWIFI123",
    # Converge ICT
    "converge123", "converge1234", "convergeics123",
    "Converge123", "Converge1234",
    # Globe At Home
    "globeathome123", "globeathome1234", "globehome123",
    "GlobeAtHome123", "GlobeAtHome1234",
    # Smart / Smart Bro
    "smartbro12345", "smartwifi123", "smartbro1234",
    "SmartBro12345", "SmartWifi123",
    # DITO
    "dito12345", "dito1234", "ditohome123",
    "DITO12345", "DITO1234",
    # Sky / Bayan / Eastern / Streamtech / Radius / Cablelink
    "skyfiber123", "skyfiber1234", "skybroadband123",
    "bayantel123", "eastern123", "streamtech123",
    "radius123", "cablelink123",
    # Common PH mobile-number prefixes used as Wi-Fi passwords
    "09171234567", "09181234567", "09191234567", "09201234567", "09211234567",
    "0917123456", "0918123456", "0919123456", "0920123456", "0921123456",
    # Common PH birthdate / simple defaults
    "123123", "01012000", "01011990", "01012000",
]


def _dedupe_valid(cands) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for c in cands:
        if WPA_MIN <= len(c) <= WPA_MAX and c not in seen:
            seen.add(c)
            out.append(c)
    return out


# Suffixes people most often tack onto an otherwise-stock default PSK, e.g. the
# sticker key "wlan3a3b36" turned into "wlan3a3b36" + "123" / "2024" / "!". Tried
# right after the exact derived keys so a hit still lands in the same near-instant
# vendor stage. Ordered most-common first.
_PSK_SUFFIXES = [
    "1", "2", "3", "12", "123", "1234", "12345", "12345678",
    "0", "00", "000", "0000", "00000000",
    "9", "99", "9999", "88888888", "77777777",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "123!", "1234!", "@", "!", "@!",
]


# Budget for the suffix expansion. Generous on purpose: these candidates go to
# the GPU as one tiny wordlist, and 20k of them is ~0.4 s at the ~48 kH/s an iGPU
# manages on WPA. The old 400 was tight enough that most derived keys never even
# got their most likely suffix.
_SUFFIX_BUDGET = 20_000


def passphrase_suffix_variants(cands: list[str], max_total: int = _SUFFIX_BUDGET) -> list[str]:
    """Expand a base candidate set with '<key><suffix>' variants.

    Real users keep the factory default-key shell and append a short digit
    sequence or year (``wlan3a3b36`` -> ``wlan3a3b36123``, ``12345678`` ->
    ``123456782024``). Applied to the computed derivable/short-default candidates
    (not the full dictionary), it stays near-instant.

    Every base survives: a computed factory key is high-value on its own, and
    dropping one to make room for a *variant* of another would trade a likely hit
    for an unlikely one. The expansion is then generated suffix-major - every base
    gets ``+1`` before any base gets ``+2024`` - so when the budget runs out it
    has been spent on the most probable variant of each key rather than on thirty
    variants of whichever key happened to be first. ``max_total`` bounds the
    expansion, not the bases.
    """
    bases = _dedupe_valid(cands)
    if max_total <= 0:
        return bases
    out = list(bases)
    seen = set(bases)
    budget = max_total - len(out)
    if budget <= 0:
        return out
    # Iterate suffix-major over a fixed base list. Appending to `out` while
    # looping over it would feed variants back in and produce doubled suffixes
    # (`wlan3a3b36` + `00000000` + `2024`).
    for suf in _PSK_SUFFIXES:
        if not suf:
            continue
        for base in bases:
            cand = base + suf
            if WPA_MIN <= len(cand) <= WPA_MAX and cand not in seen:
                seen.add(cand)
                out.append(cand)
                budget -= 1
                if budget <= 0:
                    return out
    return out


@functools.lru_cache(maxsize=512)
def ph_isp_candidates(essid: str, bssid_hex: str) -> list[str]:
    """WPA-valid PH default keys: PLDT-derivable + fixed PH/global defaults,
    plus 'derived key + digit/year suffix' personalizations."""
    cands = pldt_candidates(essid, bssid_hex)
    cands += mybro_candidates(essid, bssid_hex)
    cands += sagecom_candidates(essid, bssid_hex)
    cands += converge_candidates(essid, bssid_hex)
    cands += globe_wifi_mac_candidates(essid, bssid_hex)
    cands += _STATIC_GLOBAL_DEFAULTS
    cands += _PH_STATIC_DEFAULTS
    return passphrase_suffix_variants(cands)


@functools.lru_cache(maxsize=512)
def global_default_candidates(essid: str, bssid_hex: str) -> list[str]:
    """The full international default-key candidate set for one AP.

    Order is 'most-likely first': computed/derivable factory keys (PLDT first,
    then the international derivable algorithms), then the static known defaults.
    """
    mac = _clean_mac(bssid_hex)
    cands: list[str] = []
    cands += pldt_candidates(essid, mac)
    cands += mybro_candidates(essid, mac)
    cands += sagecom_candidates(essid, mac)
    cands += converge_candidates(essid, mac)
    cands += globe_wifi_mac_candidates(essid, mac)
    if mac:
        cands += arcadyan_candidates(essid, mac)
        cands += _bssid_tail_candidates(essid, mac)
        cands += hg824x_candidates(essid, mac)
        cands += zyxel_candidates(essid, mac)
        cands += wlan6_candidates(essid, mac)
        cands += skyv1_candidates(essid, mac)
        cands += brand_mac_variants(essid, mac)
    cands += _STATIC_GLOBAL_DEFAULTS
    out = _dedupe_valid(cands)
    out = passphrase_suffix_variants(out)
    log_debug(f"global_default_candidates: essid={essid!r} bssid={bssid_hex} -> {len(out)} candidate(s)")
    return out


# Human-pattern guesses (brand + common suffix). Works for ANY ISP.

_PH_BRAND_TOKENS = [
    # ISPs / brands. These go first so they survive the heuristic bound.
    "converge", "fiberx", "convergeics",
    "pldt", "pldthome", "pldthomefibr", "pldthomedsl", "pldtwifi", "pldtfibr", "homebro",
    "globe", "globeathome", "globefiber",
    "sky", "skyfiber", "skybroadband", "skycable",
    "dito", "ditohome", "ditotelecom",
    "smart", "smartbro", "smartwifi",
    "eastern", "streamtech", "rise", "redfiber", "royalcable", "infinivan",
    "cignal", "starlink", "parasat", "wecnet", "planet", "now", "nowfiber",
    "bayan", "bayantel", "radius", "cablelink", "comclark", "tierone", "gofiber",
    # PisoWiFi vendo units are everywhere in PH neighbourhoods and are usually
    # keyed to the operator's own brand word.
    "pisowifi", "piso", "vendo", "juanfi",
    # phone hotspot brands common on PH household/office SSIDs. People often key
    # these to something guessable, so the brand token carries weight.
    "android", "androidap", "xiaomi", "redmi", "realme", "oppo",
    "vivo", "huawei", "honor", "samsung", "infinix", "tecno", "lenovo",
    "samsung", "galaxy", "connectify", "wi-fi-direct",
    # router vendors seen on PH consumer gear
    "zte", "huawei", "nokia", "baudtec", "fiberhome", "prolink", "arcadyan",
    "tplink", "tenda", "dlink", "reyee", "ruijie",
    # generic terms + common Filipino habits
    "fiber", "fibr", "homewifi", "wifi", "wifiph", "internet", "home", "connect",
    "pinoy", "pilipinas", "philippines", "mahalkita", "iloveyou", "welcome",
    "admin", "user", "guest", "password", "changeme",
]

_INTL_BRAND_TOKENS = [
    # UK / IE
    "bt", "bthomehub", "btwifi", "plusnet", "ee", "o2wifi", "three", "talk",
    "talktalk", "virginmedia", "virgin", "eir", "eircom",
    # Europe / Nordic
    "vodafone", "telekom", "magenta", "tcom", "deutschetelekom", "tele2", "telia",
    "telenor", "unitymedia", "cablecom", "swisscom", "sunrise", "ureg", "ketio",
    # France / Iberia / Benelux
    "orange", "sfr", "neufbox", "freebox", "free", "alice", "bbox", "bouygues",
    "movistar", "telefonica", "livebox", "jazztel", "ono", "meo", "kpn", "ziggo",
    "telenet", "proximus", "orangebe",
    # DACH + Italy
    "t-mobile", "o2", "telecomitalia", "tim", "fastweb", "infostrada", "wind",
    # North America
    "comcast", "xfinity", "spectrum", "charter", "twc", "timewarner", "att",
    "attwifi", "verizon", "centurylink", "frontier", "cox", "optimum", "altice",
    "suddenlink", "brightbox", "videotron", "rogers", "bell", "shaw", "cogeco",
    "telmex", "infinitum", "provida", "cablevision",
    # LATAM
    "vivo", "claro", "oi", "movistar", "azteca", "megacable", "izzi", "totalplay",
    "fibertel", "personal",
    # Oceania
    "telstra", "optus", "tpg", "iinet", "aapt", "dodo",
    # India / Pakistan
    "reliance", "jio", "airtel", "bsnl", "mtnl", "tatado", "idea", "vi",
    "ptcl", "warid", "zong", "slt", "dialog", "mobitel",
    # SE Asia
    "singtel", "starhub", "m1", "myrepublic", "singnet", "unifi", "digi",
    "celcom", "maxis", "truehome", "ais", "dtac",
    # Indochina / Korea / Japan
    "vnpt", "viettel", "fpt", "mobifone", "vinaphone", "telkom", "indihome",
    "kt", "olleh", "yahoobb", "docomo", "au", "softbank",
    # Eurasia
    "beeline", "megafon", "ukrtelecom", "kyivstar", "tcell", "mobiuz",
    # Mobile-4G / pocket hotspots
    "mifi", "4glte", "lterouter", "wifirouter", "homewifi",
]


_HEURISTIC_SUFFIXES = [
    # Ordered by likelihood. The round-robin slice in heuristic_candidates only
    # reaches the first few dozen positions per token, so the highest-value keys
    # (bare, digit sequences, current-year family) have to live near the front.
    "", "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678",
    "2024", "2025", "2026", "2023", "2022", "2021", "2020",
    "123456789", "1234567890", "2019", "2018",
    "00000000", "0000000000", "11111111", "88888888",
    "12341234", "11223344", "1122334455", "12121212", "13572468", "147258369",
    "987654321", "77777777",
    # PH mobile-number prefixes (all major PH telcos)
    "0917", "0918", "0919", "0920", "0921", "0922", "0923", "0925", "0926",
    "0927", "0928", "0929", "0930", "0931", "0932", "0933", "0934", "0935",
    "0936", "0937", "0938", "0939", "0940", "0941", "0942", "0943", "0945",
    "0946", "0947", "0948", "0949", "0950", "0951", "0953", "0955", "0956",
    "0961", "0962", "0963", "0965", "0966", "0967", "0968", "0969", "0970",
    "0975", "0976", "0977", "0978", "0979", "0981", "0985", "0989", "0992",
    "0993", "0994", "0995", "0997", "0998", "0999",
    # PH birthdate short forms
    "0101", "0102", "0103", "1225", "1231", "010123", "010124", "122523", "122524",
    # Filipino / PH terms
    "pinoy", "pilipinas", "mahalkita", "ibigka", "ganda", "gwapo", "pogi",
    "sarap", "alamo", "ano", "sige", "okay", "oko", "mabuhay",
    # Common PH special-char suffixes
    "123!", "!123", "@123", "1234!", "@2024", "@2025",
    "#2024", "#2023", "!2024", "!2023",
]

_MAX_HEURISTIC = 8000


def _ssid_alpha_tokens(essid: str) -> list[str]:
    """Alphabetic words (>=3 letters) inside an SSID, e.g. 'Converge_2.4GHz' -> ['Converge','GHz']."""
    return re.findall(r"[A-Za-z]{3,}", essid or "")


@functools.lru_cache(maxsize=512)
def brand_mac_variants(essid: str, bssid_hex: str, max_n: int = 40) -> list[str]:
    """'brand + MAC-tail' guesses: the ISP-brand word from the SSID (or the generic
    'wifi/home/router' words) glued to the last 2-4 hex of the BSSID, upper or
    lower - e.g. ConvergeC4C9, BT-AABB, wifi1a2b. Covers the common worldwide
    habit of keying the router to brand + last-MAC-digits. Bounded and deduped.
    """
    mac = _clean_mac(bssid_hex)
    if len(mac) < 4:
        return []
    tail4 = mac[-4:].upper()
    tail2 = mac[-2:]

    # A list, not a set: set iteration order depends on PYTHONHASHSEED, so which
    # four brands survived the cap changed from run to run, and the same capture
    # got attacked with different candidates each time. PH tokens lead, since
    # that's the estate this is aimed at.
    pooled_brands: list[str] = []
    for t in _PH_BRAND_TOKENS + _INTL_BRAND_TOKENS + ["wifi", "home", "router", "net", "fiber"]:
        tl = t.lower()
        if tl not in pooled_brands:
            pooled_brands.append(tl)

    brands: list[str] = []
    essid_l = (essid or "").lower()
    for b in pooled_brands:
        if b in essid_l:
            brands.append(b)
            if len(brands) == 4:
                break
    if not brands:
        brands = ["wifi"]  # blind-shot the most common prefix

    out: list[str] = []
    seen: set[str] = set()
    for b in brands:
        for piece in (tail4, tail4.lower(), tail4.lower() + tail2, tail2):
            for cand in (b + piece, b + "-" + piece, b.lower() + piece):
                if WPA_MIN <= len(cand) <= WPA_MAX and cand not in seen:
                    seen.add(cand)
                    out.append(cand)
                    if len(out) >= max_n:
                        return out
    return out


@functools.lru_cache(maxsize=512)
def heuristic_candidates(essid: str, max_n: int = _MAX_HEURISTIC) -> list[str]:
    """Bounded human-pattern guesses: brand/SSID word + common suffix, a few case
    variants. The SSID's own words are tried first so the guesses most specific to
    *this* network survive the bound. Covers the worldwide 'ISP-name + numbers'
    habit (Converge2024, GlobeAtHome123, BT12345678, VirginMedia1 ...).

    Candidates are consumed round-robin: every token (PH and INTL alike) gets an
    equal slice of the budget instead of the first tokens greedily absorbing it,
    so a BT/Virgin/Telstra network isn't starved just by having a long brand list.
    SSID-derived tokens get a triple slice because they are network-specific.
    """
    ssid_words = _ssid_alpha_tokens(essid)
    # The space/underscore-stripped join of the SSID's own words is one of the most
    # common home passphrases ("Example Home" -> examplehome). The spaced SSID is
    # rarely the key; the joined form often is. Added as its own token so it also
    # gets the suffix family (examplehome2024, …).
    joined = "".join(ssid_words) if len(ssid_words) >= 2 else ""
    tokens: list[str] = []
    for t in ([joined] if joined else []) + ssid_words + _PH_BRAND_TOKENS + _INTL_BRAND_TOKENS:
        tl = t.lower()
        if tl not in tokens:
            tokens.append(tl)

    seen: set[str] = set()
    out: list[str] = []

    def _add(cand: str) -> bool:
        if WPA_MIN <= len(cand) <= WPA_MAX and cand not in seen:
            seen.add(cand)
            out.append(cand)
        return len(out) < max_n

    base = (essid or "").strip()
    if base:
        for v in (base, base.lower(), base.upper()):
            if not _add(v):
                return out
        # Per-word CamelCase join ("ExampleHome") - the pool
        # machinery below only produces flat lower/Capitalize/UPPER of the joined
        # token, so this is the one case variant it would otherwise miss.
        if joined:
            camel = "".join(w.capitalize() for w in ssid_words)
            if not _add(camel):
                return out

    ssid_set = {w.lower() for w in ssid_words}
    if joined:
        ssid_set.add(joined.lower())
    ph_set = {t.lower() for t in _PH_BRAND_TOKENS}
    remaining = max_n - len(out)
    n_tokens = max(1, len(tokens))
    budget = max(1, remaining // n_tokens)

    # Weighted slices: the network's own SSID words are the most specific evidence
    # we have, then Philippine ISP/vendor brands, then the worldwide list. With
    # equal shares, ~150 international brands would crowd out the PH ones on exactly
    # the estate this is aimed at.
    def _slice(tok: str) -> int:
        if tok in ssid_set:
            return budget * 3
        if tok in ph_set:
            return budget * 2
        return budget

    alloc = {tok: _slice(tok) for tok in tokens}

    pools: dict[str, list[str]] = {}
    for tok in tokens:
        pool: list[str] = []
        for suf in _HEURISTIC_SUFFIXES:
            for v in (tok, tok.capitalize(), tok.upper()):
                cand = v + suf
                if WPA_MIN <= len(cand) <= WPA_MAX and cand not in pool:
                    pool.append(cand)
        pools[tok] = pool

    for rnd in range(max(alloc.values())):
        for tok in tokens:
            if rnd >= alloc[tok] or rnd >= len(pools[tok]):
                continue
            if not _add(pools[tok][rnd]):
                return out
    log_debug(f"heuristic_candidates: essid={essid!r} -> {len(out)} candidate(s)")
    return out


# Common Filipino names + realistic birthdates (network-independent stage)
# Many Philippine home networks key their Wi-Fi to a name, nickname, or a
# birthday. A generic dictionary misses those because the exact string is
# personal. These two small sets are cheap (a few tens of thousands of
# candidates) and are tried as one dedicated stage, so they don't have to
# compete for the heuristic budget with ISP brand words.

# Common Filipino given names and surnames, lower-case.
_PH_FIRST_NAMES = [
    "juan", "jose", "maria", "jesus", "antonio", "pedro", "pablo", "francisco",
    "carlos", "manuel", "miguel", "angel", "raphael", "gabriel", "michael",
    "john", "paul", "peter", "james", "mark", "daniel", "david", "joshua",
    "christian", "angelo", "jerome", "jhun", "jun", "ronald", "robert", "richard",
    "rollie", "rodel", "rodrigo", "rolando", "ramon", "reynaldo", "renato",
    "roberto", "ricardo", "eduardo", "ernesto", "ernie", "elmer", "eduardo",
    "emmanuel", "arlene", "analyn", "annalyn", "angelica", "andrea", "bea",
    "cristina", "catherine", "cathy", "diana", "donna", "elaine", "eleanor",
    "erica", "fatima", "grace", "gloria", "hazel", "irene", "isabel", "jasmin",
    "jennifer", "jessica", "joanna", "joy", "joyce", "julie", "karen", "kathleen",
    "kim", "liza", "lorna", "luz", "mae", "maria", "maricel", "marilou", "marites",
    "marjorie", "mary", "melanie", "melissa", "michelle", "monica", "nancy",
    "nena", "nora", "patricia", "paula", "princess", "rachel", "rebecca",
    "regina", "rose", "rosalie", "ruby", "sandra", "sarah", "shiela", "sophia",
    "stephanie", "teresa", "trisha", "vanessa", "veronica", "vicky", "virginia",
    "yesha", "zara", "bea", "nia", "kai", "lia", "mika", "ella", "lucy",
]
_PH_SURNAMES = [
    "dela cruz", "delacruz", "delrosario", "delosreyes", "delossantos",
    "santos", "reyes", "cruz", "bautista", "oropeza", "garcia", "mendoza",
    "torres", "ramos", "aquino", "castillo", "flores", "villar", "gonzales",
    "robles", "lopez", "perez", "fernandez", "martinez", "lim", "tan", "sy",
    "chua", "co", "uymatiao", "yap", "lee", "go", "ong", "chan", "dizon",
    "navarro", "salazar", "mercado", "domingo", "bacani", "santiago", "aguilar",
    "alcantara", "alfonso", "angeles", "arellano", "baltazar", "bernal",
    "briones", "cabrera", "caluag", "camacho", "carpio", "cortez", "david",
    "de guzman", "deguzman", "delgado", "diaz", "evangelista", "fajardo",
    "gatchalian", "hernandez", "ignacio", "javier", "lagman", "lazaro",
    "macaraeg", "magbanua", "manalo", "marcelo", "marquez", "medina",
    "miranda", "molina", "morales", "nepomuceno", "ocampo", "pascual",
    "panganiban", "quirino", "rivera", "romero", "roxas", "salvador",
    "samson", "soriano", "tabora", "tamayo", "tomas", "valdez", "vargas",
    "velasco", "ventura", "villaflor", "villanueva", "yulo", "zamora",
]

# Suffixes people append to a name: digits, years, phone prefixes.
_NAME_SUFFIXES = [
    "1", "12", "123", "1234", "12345", "01", "07", "24", "123456",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "0917", "0918", "0919", "0920", "0921", "88", "99", "!",
]


def _ph_birthdate_candidates(year_lo: int = 1955, year_hi: int = 2012) -> list[str]:
    """Realistic 8-digit birthdates in three common layouts.

    The generic '8 digits' mask would enumerate all 10^8 values; the real space
    of plausible birthdays is ~17k, so generating them directly is ~6000x cheaper
    and can be tried early instead of being skipped for budget reasons.
    """
    out: list[str] = []
    days_in_month = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    for year in range(year_lo, year_hi + 1):
        yyyy = f"{year:04d}"
        for month in range(1, 13):
            mm = f"{month:02d}"
            for day in range(1, days_in_month[month - 1] + 1):
                dd = f"{day:02d}"
                out.append(mm + dd + yyyy)   # MMDDYYYY
                out.append(dd + mm + yyyy)   # DDMMYYYY
                out.append(yyyy + mm + dd)   # YYYYMMDD
    return out


@functools.lru_cache(maxsize=4)
def ph_common_candidates() -> list[str]:
    """Network-independent PH guesses: common names and real birthdays.

    These do not depend on the SSID, so they are pooled once across the whole
    batch. Kept small (~a few tens of thousands) so the stage runs in seconds on
    an integrated GPU while covering the name/nickname/birthday passwords a
    generic wordlist almost never contains.
    """
    cands: list[str] = []

    # Birthdates (already WPA-valid at 8 chars).
    cands.extend(_ph_birthdate_candidates())

    # Names: bare if long enough, plus common numeric/year/phone suffixes, in
    # lower / Capitalized / UPPER forms.
    names = list(dict.fromkeys(_PH_FIRST_NAMES + _PH_SURNAMES))
    for name in names:
        forms = [name, name.capitalize(), name.upper()]
        for form in forms:
            cands.append(form)
            for suf in _NAME_SUFFIXES:
                cands.append(form + suf)

    out = _dedupe_valid(cands)
    log_debug(f"ph_common_candidates: {len(out)} candidate(s)")
    return out
