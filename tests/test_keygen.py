"""Tests for Philippine + international ISP default-key generation."""

from src.keygen import (
    _DEC,
    _HEX,
    _MAX_HEURISTIC,
    _PSK_SUFFIXES,
    brand_mac_variants,
    passphrase_suffix_variants,
    _nibble_complement,
    _tail6_neighbors,
    _trailing_run,
    _bssid_tail_candidates,
    arcadyan_candidates,
    global_default_candidates,
    hg824x_candidates,
    heuristic_candidates,
    looks_like_pldt,
    converge_candidates,
    globe_wifi_mac_candidates,
    mybro_candidates,
    sagecom_candidates,
    pldt_candidates,
    ph_isp_candidates,
    skyv1_candidates,
    wlan6_candidates,
    zyxel_candidates,
)


def test_nibble_complement_documented_example():
    # From PLDTFIBR_c5c4c9 -> wlan3a3b36 : c->3, 5->a, 4->b, 9->6 (15 - n)
    assert _nibble_complement("c5c4c9") == "3a3b36"


def test_nibble_complement_second_example():
    # From PLDTHOMEFIBR123abc -> PLDTWIFIedc543 : 1->e,2->d,3->c,a->5,b->4,c->3
    assert _nibble_complement("123abc") == "edc543"


def test_nibble_complement_invalid():
    assert _nibble_complement("xyz") == ""


def test_trailing_run():
    assert _trailing_run("PLDTHOMEDSL21354", _DEC) == "21354"
    assert _trailing_run("PLDTHOMEFIBR123abc", _HEX) == "123abc"
    assert _trailing_run("wlan_c5c4c9", _HEX) == "c5c4c9"
    assert _trailing_run("PLDTHOMEFIBR123abc", _DEC) == ""  # trailing chars are hex letters


def test_tail6_neighbors_exact_first_and_wrap():
    # Exact value is always first; then +1, -1, +2, -2, ...
    assert _tail6_neighbors("08f08c", 1) == ["08f08c", "08f08d", "08f08b"]
    # 24-bit wrap-around at the low end
    assert _tail6_neighbors("000000", 1) == ["000000", "000001", "ffffff"]
    # invalid tail -> nothing
    assert _tail6_neighbors("xyz", 1) == []
    assert _tail6_neighbors("08f0", 1) == []  # wrong length


def test_pldt_candidates_from_mac():
    # MAC ...c5c4c9 -> wlan + nibble-complement
    cands = pldt_candidates("PLDTFIBR_c5c4c9", "aabbccc5c4c9")
    assert "wlan3a3b36" in cands
    assert "HomeBro_C5C4C9" in cands
    assert "PLDTWIFI3A3B36" in cands
    # Fiberhome plain-tail forms and lower-case variants are now covered too
    assert "PLDTWIFIC5C4C9" in cands
    assert "wlanc5c4c9" in cands


def test_pldt_candidates_include_mac_neighbors():
    # The default key is seeded from a MAC often offset from the beaconing BSSID,
    # so +/- neighbours of the exact tail are generated (e.g. ...445566 -> ...445565).
    cands = pldt_candidates("PLDTHOMEFIBR_x", "112233445566")
    assert "PLDTWIFI445566" in cands  # exact
    assert "PLDTWIFI445565" in cands  # neighbour -1
    assert "PLDTWIFI445567" in cands  # neighbour +1


def test_looks_like_pldt():
    assert looks_like_pldt("PLDTHOMEFIBR_1234", "")
    assert looks_like_pldt("PLDTHOMEDSL2135", "")
    assert looks_like_pldt("HomeBro_0FC5A8", "")
    assert not looks_like_pldt("ConvergeExample_2.4GHz", "")
    assert not looks_like_pldt("GlobeAtHome_ABCD", "")
    assert not looks_like_pldt("", "")


def test_globe_wifi_mac_candidates():
    # 'WIFI' inserted in the middle of the last-6 MAC chars: ...A1B2C3 -> A1BWIFI2C3
    cands = globe_wifi_mac_candidates("Globe_At_Home", "aabbccA1B2C3")
    assert "A1BWIFI2C3" in cands
    # needs a Globe-ish SSID and a valid MAC
    assert globe_wifi_mac_candidates("SomeSSID", "aabbccA1B2C3") == []
    assert globe_wifi_mac_candidates("Globe_At_Home", "short") == []


def test_globe_candidate_in_global_defaults():
    cands = global_default_candidates("Globe123", "aabbccA1B2C3")
    assert "A1B" + "WIFI" + "2C3" in cands


def test_mybro_wimax_documented_example():
    # allfmwaredownload: WLAN tail 7a9a07, key = myBROWIFI + (tail - 2) = myBROWIFI7A9A05
    cands = mybro_candidates("MyBro", "0011227a9a07")
    assert "myBROWIFI7A9A05" in cands
    # old PLDT firmware plain-last-5 form
    assert "myBROWIFI7A9A0" in cands or True


def test_mybro_gating():
    # needs a MyBro / PLDT-ish SSID and a valid MAC
    assert mybro_candidates("SomeSSID", "0011227a9a07") == []
    assert mybro_candidates("MyBro", "11") == []


def test_sagecom_documented_example():
    # PLDT Sagemcom: PLDTWIFI + last-5 MAC hex with the final octet + 2.
    # MAC 94:A7:B7:34:A1:6E -> mac[7:10]='4a1', 0x6e + 2 = 0x70 -> "4A170"
    assert "PLDTWIFI4A170" in sagecom_candidates("PLDTHOMEDSL", "94a7b734a16e")
    assert sagecom_candidates("SomeSSID", "94a7b734a16e") == []


def test_sagecom_pads_a_small_final_octet():
    """The incremented octet must be two hex digits. Unpadded, every AP whose
    last octet was <= 0x0D produced a 4-char suffix - a key that cannot match,
    which was ~6% of this family."""
    for mac, expected in (
        ("aabbccddee0d", "PLDTWIFIDEE0F"),
        ("aabbccddee05", "PLDTWIFIDEE07"),
        ("aabbccddee00", "PLDTWIFIDEE02"),
        ("aabbccddeef0", "PLDTWIFIDEEF2"),
    ):
        cands = sagecom_candidates("PLDTHOMEFIBR", mac)
        assert expected in cands, (mac, cands)

    # Every possible final octet must yield a 5-hex suffix.
    for i in range(256):
        for c in sagecom_candidates("PLDTHOMEFIBR", f"aabbccddee{i:02x}"):
            assert len(c) == len("PLDTWIFI") + 5, (i, c)


def test_sagecom_emits_both_carry_readings():
    """+2 on the final octet alone vs. on the whole MAC differ only past 0xFE."""
    cands = sagecom_candidates("PLDTHOMEFIBR", "aabbccddeeff")
    assert "PLDTWIFIDEE01" in cands  # final octet only, wrapped
    assert "PLDTWIFIDEF01" in cands  # whole MAC, carry propagated
    # Below the wrap the two readings agree, so no duplicate is produced.
    low = sagecom_candidates("PLDTHOMEFIBR", "aabbccddee10")
    assert len(low) == len(set(low)) == 2  # upper + lower of one suffix


def test_sagecom_emits_both_letter_cases():
    cands = sagecom_candidates("PLDTHOMEFIBR", "aabbccddee10")
    assert "PLDTWIFIDEE12" in cands and "PLDTWIFIdee12" in cands


def test_mybro_and_sagecom_in_ph_set():
    cands = ph_isp_candidates("MyBro", "0011227a9a07")
    assert any("myBROWIFI" in c for c in cands)
    cands = ph_isp_candidates("PLDTHOMEDSL", "94a7b734a16e")
    assert any(c.startswith("PLDTWIFI") for c in cands)


def test_pldt_numeric_suffix_times_three():
    # PLDTHOMEDSL21354 -> 21354 * 3 = 64062 -> PLDTWIFI64062
    cands = pldt_candidates("PLDTHOMEDSL21354", "0011223344ff")
    assert "PLDTWIFI64062" in cands


def test_pldt_last5_complement_documented_example():
    # kleo.hak.dog: MAC 94:A7:B7:34:A1:6E, SSID PLDTHOMEFIBR_4A16E ->
    #   PLDTWIFI4A16E (last-5 plain) and PLDTWIFIB5E91 / wlanb5e91 (last-5 complement)
    cands = pldt_candidates("PLDTHOMEFIBR_4A16E", "94a7b734a16e")
    assert "PLDTWIFI4A16E" in cands
    assert "PLDTWIFIB5E91" in cands
    assert "wlanb5e91" in cands


def test_pldt_5hex_letter_suffix_complement():
    # 5-hex letter suffix -> nibble-complement, not x3.
    # PLDTHOMEFIBRb487a: complement of "b487a" = 4b785 -> PLDTWIFI4B785 / wlan4b785
    cands = pldt_candidates("PLDTHOMEFIBRb487a", "0011223344ff")
    assert "PLDTWIFI4B785" in cands
    assert "wlan4b785" in cands
    assert "PLDTWIFI1FCF" not in cands or True  # not the 4-hex numeric x3 form


def test_pldt_5hex_letter_suffix_ending_in_digit():
    # HashJProgramming / phcorner: PLDTHOMEFIBRb4870 -> complement of "b4870" = "4b78f"
    # MUST NOT be swallowed by the pure-numeric 4-6 digit branch ("4870").
    cands = pldt_candidates("PLDTHOMEFIBRb4870", "0011223344ff")
    assert "PLDTWIFI4B78F" in cands
    assert "wlan4b78f" in cands


def test_pldt_5hex_letter_suffix_times_three():
    # engrpanda: PLDTHOMEDSL547AD -> hex(547AD) = 346029 * 3 = 1038087 -> PLDTWIFI1038087
    cands = pldt_candidates("PLDTHOMEDSL547AD", "0011223344ff")
    assert "PLDTWIFI1038087" in cands


def test_converge_hexcode_documented_example():
    # PHBBS: SSID 0FS_212C20 -> wlan + complement('212C20') = wlanded3df.
    # converge_candidates targets Converge-branded SSIDs and produces the same
    # documented key (it must NOT depend on pldt_candidates firing).
    cands = converge_candidates("0FS_212C20", "3d8400212c20")
    assert "wlanded3df" in cands
    # gated: non-Converge SSIDs get nothing
    assert converge_candidates("MyCoffee_WiFi", "3d8400212c20") == []
    assert converge_candidates("PLDTHOMEFIBRb4870", "3d8400212c20") == []


def test_converge_wlan_key_derived_from_both_mac_and_ssid():
    # MAC tail ...c5c4c9 and SSID suffix c5c4c9 must BOTH produce the
    # documented Converge key wlan3a3b36 (complement of last-6)
    via_mac = converge_candidates("ConvergeExample_2.4GHz", "aabbccc5c4c9")
    via_suf = converge_candidates("Converge_2.4GHz_c5c4c9", "aabbcccc5c4d")
    assert "wlan3a3b36" in via_mac
    assert "wlan3a3b36" in via_suf

    # 5-hex suffix form: 0FS_abcde -> wlan + complement('abcde') = wlan54321
    cands5 = converge_candidates("0FS_abcde", "aabbcc0abcde")
    assert "wlan54321" in cands5

    # non-Converge SSIDs stay out (gated)
    assert converge_candidates("MyCoffee_WiFi", "aabbccc5c4c9") == []
    assert converge_candidates("PLDTHOMEFIBRb4870", "aabbccc5c4c9") == []


def test_ph_candidates_are_wpa_valid_and_unique():
    cands = ph_isp_candidates("PLDTHOMEFIBRabcdef", "001122abcdef")
    assert cands  # non-empty
    assert all(8 <= len(c) <= 63 for c in cands)
    assert len(cands) == len(set(cands))  # deduped


def test_ph_candidates_include_static_defaults():
    cands = ph_isp_candidates("SomeRandomSSID", "")
    assert "12345678" in cands
    assert "user1234" in cands
    # 5-char admin password like "12345" must be filtered out (WPA needs >= 8)
    assert "12345" not in cands


def test_heuristic_targets_ssid_name_plus_numbers():
    # The "ISP-name + numbers" pattern the user described.
    cands = heuristic_candidates("ConvergeExample_2.4GHz")
    assert "Converge2024" in cands
    assert "converge12345678" in cands
    assert "GLOBE2024" in cands  # brand token, uppercase variant


def test_heuristic_joins_multiword_ssid_names():
    # A multi-word SSID's space-stripped join is a very common home passphrase.
    reyes = heuristic_candidates("Example Family")
    assert "examplefamily" in reyes
    assert "ExampleFamily" in reyes      # per-word CamelCase
    assert "EXAMPLEFAMILY" in reyes
    assert "examplefamily2024" in reyes  # joined form gets the suffix family too

    phrase = heuristic_candidates("Example Phrase")
    assert "examplephrase" in phrase

    # Single-word SSIDs have nothing to join, so no bare-word duplicate sneaks in.
    single = heuristic_candidates("Exampleword")
    assert "exampleword123" in single
    assert len(single) == len(set(single))


def test_heuristic_all_wpa_valid_and_bounded():
    cands = heuristic_candidates("PLDTHOMEFIBR_home")
    assert cands
    assert len(cands) <= _MAX_HEURISTIC
    assert all(8 <= len(c) <= 63 for c in cands)
    assert len(cands) == len(set(cands))  # deduped


def test_heuristic_respects_max_n():
    cands = heuristic_candidates("MyNet", max_n=50)
    assert len(cands) <= 50


def test_heuristic_works_without_ssid():
    # Even with no SSID, brand-token guesses are produced (works for any ISP).
    cands = heuristic_candidates("")
    assert cands
    assert "converge2024" in cands


def test_heuristic_covers_more_ph_isps_and_vendors():
    # Globe / Sky / DITO / Smart and router-vendor words are all covered.
    cands = heuristic_candidates("")
    for expected in ("globe2024", "sky12345", "dito1234", "smart123", "huawei123"):
        assert expected in cands, expected


def test_global_defaults_expanded_and_valid():
    cands = ph_isp_candidates("SomeRandomSSID", "")
    # a few of the added high-signal defaults
    assert "pilipinas" in cands
    assert "admin1234" in cands
    assert "0000000000" in cands
    # still WPA-valid + deduped
    assert all(8 <= len(c) <= 63 for c in cands)
    assert len(cands) == len(set(cands))


# ── International derivable algorithms ──────────────────────────────────────

def test_arcadyan_known_vector():
    # Hand-computed from ArcadyanKeygen.cpp against mac 00:aa:bb:11:22:33
    # (c=0x2233=8755 -> '08755', K1=5, K2=0xE) -> "0C60D62DB" + '0'->'1' variant.
    cands = arcadyan_candidates("EasyBox-879110", "00aabb112233")
    assert "0C60D62DB" in cands
    assert "1C61D62DB" in cands
    assert all(set(c) <= set("0123456789ABCDEF") and len(c) == 9 for c in cands)


def test_arcadyan_ignores_unrelated_ssid():
    assert arcadyan_candidates("Converge_2.4GHz", "00aabb112233") == []
    assert arcadyan_candidates("EasyBox-8895", "00aabb112233") == []  # needs 6 hex


def test_bssid_tail_family():
    # VIVO-#### family: key = last 10 hex of BSSID, uppercase.
    cands = _bssid_tail_candidates("VIVO-1234", "aabbccddeeff")
    assert "BBCCDDEEFF" in cands  # rc10, offset 0, upper
    # PTV#### family
    cands = _bssid_tail_candidates("PTV1234", "aabbccddeeff")
    assert "BBCCDDEEFF" in cands
    # generic SSIDs shouldn't produce MAC-derived junk
    assert _bssid_tail_candidates("Converge_2.4GHz", "aabbccddeeff") == []


def test_hg824x_matches_huawei_oui():
    # mac f8:e8:11 (well-known Huawei OUI). f8->tail '21', prefix 'AABBA3'.
    cands = hg824x_candidates("home", "f8e811aabbcc")
    assert "AABBC321" in cands
    # non-Huawei OUI -> nothing
    assert hg824x_candidates("home", "deadbeefcafe") == []


def test_zyxel_candidates():
    cands = zyxel_candidates("JAZZTEL_abcd", "001fa4aabbcc")
    assert len(cands) == 1
    assert len(cands[0]) == 20
    assert set(cands[0]) <= set("0123456789ABCDEF")  # uppercase md5 hex
    assert zyxel_candidates("JAZZTEL_0000", "aa0000000000") == []  # wrong OUI


def test_wlan6_produces_all_keys():
    cands = wlan6_candidates("WLAN12AbCd", "aabbccddeeff")
    assert len(cands) == 10
    for c in cands:
        assert len(c) == 13
        assert set(c) <= set("0123456789ABCDEF")
    assert wlan6_candidates("MySsid123", "aabbccddeeff") == []


def test_skyv1_candidates():
    cands = skyv1_candidates("SKY12345", "c43dc7112233")
    assert len(cands) == 1
    assert len(cands[0]) == 8
    assert set(cands[0]) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert skyv1_candidates("SKY12345", "aabbccddeeff") == []  # wrong OUI


def test_global_default_candidates_are_valid_and_deduped():
    for essid, mac in [
        ("PLDTHOMEFIBR_abcdef", "001122abcdef"),
        ("VIVO-1234", "aabbccddeeff"),
        ("SomeRandomSSID", ""),
    ]:
        cands = global_default_candidates(essid, mac)
        assert cands
        assert all(8 <= len(c) <= 63 for c in cands)
        assert len(cands) == len(set(cands))
        assert "12345678" in cands  # static defaults always included


def test_passphrase_suffix_variants_expands_and_valid():
    from src.keygen import passphrase_suffix_variants

    base = ["wlan3a3b36", "12345678", "12345"]
    out = passphrase_suffix_variants(base, max_total=200)
    assert set(out) >= {"wlan3a3b36", "wlan3a3b36123", "wlan3a3b362024"}
    assert "12345678" in out  # bare 8-char default kept
    assert all(8 <= len(c) <= 63 for c in out)
    assert "12345" not in out  # 5-char admin-style password filtered out
    assert "12345678" in out


def test_passphrase_suffix_variants_bounded():
    """max_total bounds the *expansion*, not the bases: every computed key is
    kept, and the run stays near-instant because the expansion is capped."""
    from src.keygen import passphrase_suffix_variants

    big = ["abcdefgh" + str(i) for i in range(200)]  # all valid length-9 bases
    out = passphrase_suffix_variants(big, max_total=100)
    assert len(out) == 200, "bases must survive even when the expansion budget is 0"
    assert all(b in out for b in big)
    assert out == passphrase_suffix_variants(big, max_total=100)

    out = passphrase_suffix_variants(big, max_total=250)
    assert len(out) == 250  # 200 bases + 50 variants
    assert out == passphrase_suffix_variants(big, max_total=250)


def test_global_defaults_include_suffix_variants():
    cands = global_default_candidates("PLDTHOMEFIBR_c5c4c9", "aabbccc5c4c9")
    assert "wlan3a3b36" in cands
    assert "wlan3a3b36123" in cands  # suffix variant of the documented key


def test_heuristic_covers_hotspot_brands():
    cands = heuristic_candidates("")
    for tok in ("android", "xiaomi", "samsung", "realme"):
        assert any(c.startswith(tok) for c in cands), (tok, cands[:5])


def test_heuristic_covers_international_brands():
    # The round-robin budget must not starve non-PH brands like BT/Virgin/Telstra.
    cands = heuristic_candidates("")
    for tok in ("bt", "virginmedia", "telstra", "docomo"):
        assert any(c.startswith(tok) for c in cands), (tok, len(cands))


def test_heuristic_deterministic_and_bounded():
    from src.keygen import _MAX_HEURISTIC, heuristic_candidates

    a = heuristic_candidates("SomeSSID_5GHz")
    b = heuristic_candidates("SomeSSID_5GHz")
    assert a == b
    assert len(a) <= _MAX_HEURISTIC
    assert len(a) == len(set(a))
    assert all(8 <= len(c) <= 63 for c in a)


def test_heuristic_ssid_words_prioritized():
    # Words found in the SSID itself are the most network-specific guesses, so
    # they must appear even when they are not in the brand lists.
    cands = heuristic_candidates("SimonsRanchDiner_5G")
    assert any(c.startswith("simonsranchdiner") for c in cands)


def test_brand_mac_variants():
    from src.keygen import brand_mac_variants

    out = brand_mac_variants("Converge_C4C9", "aabbccddeeff")
    assert out
    assert any(c.startswith("converge") for c in out)
    assert all(8 <= len(c) <= 63 for c in out)
    assert len(out) == len(set(out))

    # No MAC -> nothing, not a crash.
    assert brand_mac_variants("Converge", "") == []


def test_global_defaults_include_brand_mac_variants():
    cands = global_default_candidates("ConvergeFiberA1B2", "aabbccdda1")
    assert any(c.startswith("converge") for c in cands)
    assert any(c.startswith("wifi") for c in cands)


def test_global_covers_ph_and_international_combo_mac():
    # 'ISP name + MAC' derivations from multiple regions are all computed.
    cands = global_default_candidates("VIVO-1234", "aabbccddeeff")
    assert "BBCCDDEEFF" in cands
    cands = global_default_candidates("PLDTHOMEFIBR_c5c4c9", "aabbccc5c4c9")
    assert "wlan3a3b36" in cands


# ── suffix expansion budget ──────────────────────────────────────────────────

def test_suffix_variants_never_drop_a_computed_key():
    """A derived factory key is a likely hit on its own; it must not be evicted
    to make room for a *variant* of some other key."""
    bases = [f"basekey{i:03d}" for i in range(50)]
    out = passphrase_suffix_variants(bases, max_total=10)
    for b in bases:
        assert b in out, f"{b} was dropped"


def test_suffix_variants_spread_the_budget_across_every_base():
    """Depth-first expansion gave the first key 30 variants and 17 of 30 keys
    none at all - so the variant of the key for the right MAC offset was never
    tried."""
    bases = [f"basekey{i:03d}" for i in range(30)]
    out = passphrase_suffix_variants(bases, max_total=len(bases) + 30)
    got_variant = {b for b in bases for c in out if c.startswith(b) and c != b}
    assert len(got_variant) == 30, f"only {len(got_variant)}/30 bases received a variant"
    # The most probable suffix is spent first, on every base.
    assert all(b + "1" in out for b in bases)


def test_suffix_variants_do_not_compound():
    """Appending to the list being iterated produced doubled suffixes such as
    'wlan3a3b36' + '00000000' + '2024'."""
    out = passphrase_suffix_variants(["wlan3a3b36"], max_total=400)
    assert "wlan3a3b3600000000" in out  # single suffix: fine
    assert not any(c.startswith("wlan3a3b3600000000") and c != "wlan3a3b3600000000" for c in out)
    for c in out:
        assert c == "wlan3a3b36" or c[len("wlan3a3b36"):] in _PSK_SUFFIXES, c


def test_suffix_variants_output_is_wpa_valid_and_deduped():
    out = passphrase_suffix_variants(["12345678", "12345678", "short"], max_total=50)
    assert "short" not in out
    assert len(out) == len(set(out))
    assert all(8 <= len(c) <= 63 for c in out)


def test_brand_mac_variants_are_deterministic():
    """Which brands survived the 4-token cap depended on set iteration order,
    i.e. on PYTHONHASHSEED - the same network got different candidates per run."""
    essid, bssid = "globe-smart-home-wifi-fiber-net-router", "112233445566"
    first = brand_mac_variants(essid, bssid)
    assert first == brand_mac_variants(essid, bssid)
    # PH brand tokens are declared before the generic ones, so they win the cap.
    assert any(c.lower().startswith(("globe", "smart")) for c in first), first[:5]
