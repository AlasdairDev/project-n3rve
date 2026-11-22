"""Tests for the speed-gated hashcat attack plan."""

import os

from src.config import PH_WORDLIST_NAME
from src.hashcat.crack import (
    _DEFAULT_MASKS,
    _has_derivable_hex_suffix,
    _PLDT_MASKS,
    _build_attack_plan,
    _count_rules,
    _isp_family,
    _isp_mask_stages,
    ph_random_key_isp,
    _isp_mask_stages_for_networks,
    _parse_hc22000_meta,
    _parse_hc22000_networks,
    _potfile_results,
    _stage_budget_seconds,
    _vendor_stages,
)


def test_default_masks_well_formed():
    for label, mask, extra, keyspace in _DEFAULT_MASKS:
        assert isinstance(label, str) and label
        assert mask.count("?") >= 8  # at least 8 positions
        assert isinstance(extra, list)
        assert isinstance(keyspace, int) and keyspace > 0
    # custom-charset masks must ship their charset definition
    for label, mask, extra, _ in _DEFAULT_MASKS:
        if "?1" in mask:
            assert "-1" in extra


def test_default_masks_ordered_cheapest_first():
    keyspaces = [ks for *_, ks in _DEFAULT_MASKS]
    assert keyspaces == sorted(keyspaces)


def test_build_attack_plan_shape(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("password1\npassword2\npassword3\n")
    plan = _build_attack_plan(str(tmp_path), str(wl))

    # PH default-keys stage (when the wordlist is available) leads, then dictionary.
    ph_stages = [a for a in plan if a["label"].startswith("PH default passwords")]
    dict_stages = [a for a in plan if a["label"] == "dictionary"]
    assert dict_stages and dict_stages[0]["optional"] is False and dict_stages[0]["keyspace"] == 3
    for s in ph_stages:
        assert s["optional"] is False and s["keyspace"] and s["keyspace"] > 0
    assert plan[0]["keyspace"] == 3 or (ph_stages and plan[0]["label"].startswith("PH"))

    masks = [a for a in plan if a["label"].startswith("mask")]
    assert masks
    assert all(a["optional"] and a["keyspace"] for a in masks)


def test_build_attack_plan_includes_rules_stage(tmp_path):
    # The bundled project rule file exists, so a dictionary+rules stage is added
    # with keyspace = wordlist_lines * rule_count, and the PH default-password
    # list gets its own rules mutation stage.
    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\nc\nd\n")
    plan = _build_attack_plan(str(tmp_path), str(wl))
    rules_stages = [a for a in plan if a["label"].startswith("dictionary + rules")]
    assert len(rules_stages) == 1
    stage = rules_stages[0]
    assert stage["optional"] is True
    assert stage["keyspace"] and stage["keyspace"] % 4 == 0  # 4 wordlist lines
    ph_rules = [a for a in plan if a["label"].startswith("PH defaults + rules")]
    assert len(ph_rules) == 1
    assert ph_rules[0]["optional"] is True and ph_rules[0]["keyspace"] > 0


def test_hybrid_wraps_digit_suffix_onto_ph_wordlist(tmp_path):
    # Hybrid -a 6 stages must carry (wordlist, mask) as a list, in that order,
    # so hashcat receives wordlist + mask right after the hash file path.
    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\n")
    plan = _build_attack_plan(str(tmp_path), str(wl))
    hybrids = [a for a in plan if a["mode"] == "6"]
    assert hybrids, "expected hybrid -a 6 stages"
    for h in hybrids:
        assert isinstance(h["arg"], list) and len(h["arg"]) == 2
        assert os.path.basename(h["arg"][0]) == PH_WORDLIST_NAME
        assert h["arg"][1].startswith("?d")
        assert h["optional"] is True and h["keyspace"] > 0


def test_prefix_stages_use_prepend_rules_not_a7(tmp_path):
    """Digits-before-word used to be a -a 7 hybrid, which makes the tiny mask the
    attack's base and starves the GPU - measured ~8x slower than its keyspace
    predicted. As prepend rules the wordlist stays the base."""
    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\n")
    plan = _build_attack_plan(str(tmp_path), str(wl))

    assert not [a for a in plan if a["mode"] == "7"], "-a 7 starves the GPU; use rules"
    prefix = [a for a in plan if "prefix" in a["label"]]
    assert len(prefix) >= 1
    for h in prefix:
        assert h["mode"] == "0"
        assert os.path.basename(h["arg"]) == PH_WORDLIST_NAME
        assert h["extra"][0] == "-r" and os.path.isfile(h["extra"][1])
        assert h["optional"] is True and h["keyspace"] > 0


def test_prefix_rule_file_prepends_in_the_right_order():
    """hashcat applies rules left to right and ^X prepends, so "09" must be
    written ^9^0 - the reverse order produces "90word"."""
    from src.hashcat.crack import _prefix_rule_file

    path = _prefix_rule_file(2)
    rules = [ln.strip() for ln in open(path, encoding="utf-8") if ln.strip()]
    assert len(rules) == 100
    assert rules[0] == "^0^0"    # prefix "00"
    assert rules[9] == "^9^0"    # prefix "09"  -> ^9 then ^0 == "09" + word
    assert rules[17] == "^7^1"   # prefix "17"
    assert len(set(rules)) == 100


def test_count_rules(tmp_path):
    r = tmp_path / "r.rule"
    r.write_text("# a comment\n\nc\nu\n$1\n")
    assert _count_rules(str(r)) == 3


def test_stage_budget_default(monkeypatch):
    monkeypatch.delenv("HANDSHAKE_MAX_STAGE_MIN", raising=False)
    assert _stage_budget_seconds() == 120 * 60


def test_stage_budget_env_override(monkeypatch):
    monkeypatch.setenv("HANDSHAKE_MAX_STAGE_MIN", "15")
    assert _stage_budget_seconds() == 15 * 60


def test_stage_budget_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("HANDSHAKE_MAX_STAGE_MIN", "not-a-number")
    assert _stage_budget_seconds() == 120 * 60


def test_parse_hc22000_meta():
    essid_hex = b"PLDTHOMEFIBR".hex()
    line = f"WPA*02*aabb*aabbccddeeff*112233445566*{essid_hex}*dd*ee*02"
    essid, bssid = _parse_hc22000_meta(line)
    assert essid == "PLDTHOMEFIBR"
    assert bssid == "aabbccddeeff"


def test_isp_mask_stages_pldt_only():
    # PLDT networks get targeted hex masks; so does Converge (shared wlan+hex
    # shape, previously skipped because it's not a PLDT-lookalike SSID).
    pldt = _isp_mask_stages("PLDTHOMEFIBR_abcd", "aabbccddeeff")
    assert pldt, "expected PLDT mask stages"
    converge = _isp_mask_stages("Converge_2.4GHz_c5c4c9", "aabbccc5c4c9")
    assert converge, "expected Converge wlan+hex mask stages"
    # ISPs whose gear uses random label keys still get nothing - no shape to brute
    assert not _isp_mask_stages("SkyFiber_1234", "aabbccddeeff")
    assert not _isp_mask_stages("DITO_Home_99", "aabbccddeeff")

    for stage in pldt + converge:
        assert stage["mode"] == "3"          # brute-force mask mode
        assert stage["optional"] is True     # speed-gated like other masks
        assert stage["keyspace"] > 0
        assert stage["label"].startswith("ISP mask:")
        # custom-charset masks must ship their charset definition
        if "?1" in stage["arg"]:
            assert "-1" in stage["extra"]


def test_isp_masks_cover_mybro_and_converge_shapes():
    # the full myBROWIFI space and the shared wlan+hex shape (Converge) are
    # swept, not just the PLDTWIFI family
    labels = [s["label"] for s in _isp_mask_stages("PLDTHOMEFIBR_abcd", "aabbccddeeff")]
    assert any("myBROWIFI" in label for label in labels), labels
    masks = [mask for (_label, mask, _extra, _ks) in _PLDT_MASKS]
    assert "wlan?1?1?1?1?1?1" in masks           # PLDT + Converge wlan shape
    assert "myBROWIFI?1?1?1?1?1?1" in masks
    assert "mybrowifi?1?1?1?1?1?1" in masks


def test_has_derivable_hex_suffix():
    assert _has_derivable_hex_suffix("wlan_c5c4c9")
    assert _has_derivable_hex_suffix("Converge_2.4GHz_c5c4c9")
    assert _has_derivable_hex_suffix("PLDTHOMEFIBR_c5c4c9")
    assert not _has_derivable_hex_suffix("GlobeAtHome_1234")
    assert not _has_derivable_hex_suffix("SkyBroadband")
    assert not _has_derivable_hex_suffix("")


def test_converge_ssid_matches_mask_autai():
    # Converge broadcasts under Converge/0FS/ZTE-branded SSIDs whose key space is
    # the enumerable 'wlan+6hex' shape - all must get the ISP mask stages,
    # including the non-hex-suffixed 5GHz and ZTE-branded ones.
    for ssid in (
        "Converge_2.4GHz_2fPDHp",
        "Converge_5GHz_a1b2c3",
        "0FS_212C20",
        "0FS_abcde",
        "ZTE_2.4G_2fPDHp",
        "Converge_FiberHome_port",
    ):
        assert _isp_mask_stages(ssid, "aabbccddeeff"), f"expected ISP masks for {ssid}"


def test_vendor_stages_include_suffix_variants():
    essid_hex = b"Converge_2.4GHz".hex()
    content = f"WPA*02*aabb*112233445566*112233445566*{essid_hex}*dd*ee*02"
    stages, temp_paths = _vendor_stages(content)
    try:
        labels = [s["label"] for s in stages]
        assert any("suffix" in x.lower() for x in labels), labels
        for p in temp_paths:
            assert os.path.isfile(p)
    finally:
        for p in temp_paths:
            try:
                os.remove(p)
            except OSError:
                pass


def test_vendor_stages_builds_and_cleans_up():
    essid_hex = b"Converge_2.4GHz".hex()
    content = f"WPA*02*aabb*112233445566*112233445566*{essid_hex}*dd*ee*02"
    stages, temp_paths = _vendor_stages(content)
    try:
        labels = [s["label"] for s in stages]
        assert any("ISP default keys" in x for x in labels)
        assert any("ISP/SSID pattern keys" in x for x in labels)
        # All vendor stages are plain wordlist (mode-0) runs now; the SSID-word
        # digit stages are optional, the deterministic ones always run.
        for s in stages:
            assert s["mode"] == "0" and s["keyspace"] > 0
            assert isinstance(s["arg"], str)
        assert any(s["optional"] is False for s in stages)
        assert any(s["optional"] is True for s in stages)
        for p in temp_paths:
            assert os.path.isfile(p)
    finally:
        for p in temp_paths:
            try:
                os.remove(p)
            except OSError:
                pass


# multi-network hash files

def _line(essid: str, bssid: str, mic: str = "aabb") -> str:
    return f"WPA*02*{mic}*{bssid}*112233445566*{essid.encode().hex()}*dd*ee*02"


def test_parse_hc22000_networks_lists_every_ap():
    content = "\n".join(
        [
            _line("ConvergeExample_2.4GHz", "112233445566"),
            _line("ConvergeExample_2.4GHz", "112233445566", mic="ccdd"),  # 2nd hash, same AP
            _line("PLDTHOMEFIBR_abc123", "aabbccddeeff"),
        ]
    )
    nets = _parse_hc22000_networks(content)
    assert nets == [
        ("ConvergeExample_2.4GHz", "112233445566"),
        ("PLDTHOMEFIBR_abc123", "aabbccddeeff"),
    ]
    # The legacy single-network helper still reports the first line.
    assert _parse_hc22000_meta(content) == ("ConvergeExample_2.4GHz", "112233445566")


def test_vendor_stages_cover_every_network_in_the_file():
    """A second AP in the same capture must get its own computed factory keys."""
    pldt_bssid = "aabbccddc5c4c9"[-12:]
    content = "\n".join([_line("ConvergeExample_2.4GHz", "112233445566"), _line("PLDTHOMEFIBR", pldt_bssid)])
    stages, temp_paths = _vendor_stages(content)
    try:
        defaults = [s for s in stages if "ISP default keys" in s["label"]][0]
        words = set(open(defaults["arg"], encoding="utf-8").read().split())
        # Derived from the *second* network's BSSID (nibble complement of c5c4c9).
        assert "wlan3a3b36" in words
        # ...and the first network's SSID still drives the pattern stage.
        patterns = [s for s in stages if "pattern" in s["label"].lower()][0]
        pattern_words = open(patterns["arg"], encoding="utf-8").read()
        assert "Converge" in pattern_words and "PLDTHOMEFIBR" in pattern_words
    finally:
        for p in temp_paths:
            try:
                os.remove(p)
            except OSError:
                pass


def test_isp_masks_fire_when_any_network_matches():
    content = "\n".join([_line("SomeRandomOffice", "001122334455"), _line("PLDTHOMEFIBR_abc123", "aabbccddeeff")])
    assert _isp_mask_stages_for_networks(_parse_hc22000_networks(content))
    only_generic = _line("SomeRandomOffice", "001122334455")
    assert _isp_mask_stages_for_networks(_parse_hc22000_networks(only_generic)) == []


def test_potfile_results_attributes_passwords_to_their_network():
    lines = [
        "9a141217ccd8be6c55981acc6df25c549563493df052c34f393196b413afde71"
        "*" + b"ExampleNet".hex() + ":ExamplePass1",
        "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990"
        "*" + b"ExampleISP_2.4GHz".hex() + ":ExampleKey99",
        "#comment",
        "malformed-line-without-colon",
        "shorthash*" + b"TooShort".hex() + ":123",  # password under 8 chars
    ]
    assert _potfile_results(lines) == {
        "ExampleNet": "ExamplePass1",
        "ExampleISP_2.4GHz": "ExampleKey99",
    }


def test_isp_masks_run_after_every_dictionary_stage():
    """The ISP hex masks sweep 16^6 each - minutes of GPU. They must never be
    ordered ahead of the dictionary, which is orders of magnitude cheaper per hit."""
    from src.hashcat.crack import _build_attack_plan

    plan = _build_attack_plan(".", "wifi-wordlist.txt")
    isp_masks = _isp_mask_stages_for_networks([("PLDTHOMEFIBR_abc123", "aabbccddeeff")])
    assert isp_masks
    brute_at = next(
        (i for i, a in enumerate(plan) if a.get("kind") in ("hybrid", "mask", "rules")),
        len(plan),
    )
    plan[brute_at:brute_at] = isp_masks

    kinds = [a.get("kind") for a in plan]
    first_isp = kinds.index("isp_mask")
    last_dict = max(i for i, k in enumerate(kinds) if k == "dict")
    assert last_dict < first_isp, f"dictionary must precede the ISP masks: {[a['label'] for a in plan]}"
    for later in ("hybrid", "mask", "rules"):
        if later in kinds:
            assert first_isp < kinds.index(later), f"ISP masks must precede the {later} stages"


def test_every_plan_stage_is_tagged_with_a_kind():
    from src.hashcat.crack import _build_attack_plan

    for stage in _build_attack_plan(".", "wifi-wordlist.txt"):
        assert stage.get("kind") in ("dict", "hybrid", "mask", "rules"), stage["label"]


# throughput estimation

def test_speed_estimate_ignores_tiny_stages():
    """A 3-word dictionary stage once measured 91 H/s on a GPU doing ~48 kH/s,
    which made the gate skip a 22-second stage as '3 hours'."""
    from src.hashcat.crack import _update_speed_estimate

    est = _update_speed_estimate(None, [48_458, 48_000], 16**6)
    assert est == 48_458
    # A sub-second stage must not drag the estimate down.
    assert _update_speed_estimate(est, [91], 3) == 48_458
    assert _update_speed_estimate(est, [91, 88], 8108) == 48_458


def test_speed_estimate_keeps_the_best_qualifying_measurement():
    from src.hashcat.crack import _update_speed_estimate

    est = _update_speed_estimate(None, [18_425], 10**7)
    assert est == 18_425
    # A faster qualifying stage raises it; a slower one does not lower it.
    est = _update_speed_estimate(est, [48_458], 16**6)
    assert est == 48_458
    assert _update_speed_estimate(est, [20_000], 16**6) == 48_458


def test_speed_estimate_handles_no_measurement():
    from src.hashcat.crack import _update_speed_estimate

    assert _update_speed_estimate(None, [], 10**8) is None
    assert _update_speed_estimate(None, [0], 10**8) is None
    assert _update_speed_estimate(5000, [], None) == 5000


# PH ISP family targeting

def _mask_labels(essid, bssid="aabbccddeeff"):
    return [s["label"] for s in _isp_mask_stages(essid, bssid)]


def test_converge_does_not_sweep_pldt_only_key_spaces():
    """A Converge AP cannot carry a HomeBro (PLDT Ultera) or myBROWIFI (Smart
    Wimax) key - sweeping 16^6 of each costs ~40 min on an iGPU for nothing."""
    labels = _mask_labels("ConvergeExample_2.4GHz", "112233445566")
    assert any("wlan+6hex" in x for x in labels), labels
    assert not any("HomeBro" in x for x in labels), labels
    assert not any("myBRO" in x.lower() or "mybro" in x.lower() for x in labels), labels
    assert not any("8digits" in x for x in labels), labels


def test_pldt_tries_the_cheap_5hex_shapes_first():
    """16^5 is 16x cheaper than 16^6 - ~20 s versus ~6 min per stage."""
    stages = _isp_mask_stages("PLDTHOMEFIBR_abcd", "aabbccddeeff")
    assert stages[0]["keyspace"] == 16**5
    assert "PLDTWIFI+5hex" in stages[0]["label"]
    # PLDT still sweeps its whole product family, HomeBro and myBRO included.
    labels = [s["label"] for s in stages]
    assert any("myBROWIFI" in x for x in labels)
    assert any("HomeBro" in x for x in labels)


def test_homebro_and_mybro_get_their_own_shapes():
    homebro = _mask_labels("HomeBro_A1B2C3")
    assert homebro and "HomeBro_+6hex" in homebro[0]

    mybro = _mask_labels("myBRO_1234")
    assert mybro, "a myBRO SSID must still get its own mask family"
    assert any("myBROWIFI" in x or "mybrowifi" in x for x in mybro), mybro
    assert any("PH mobile" in x or "PH birthdate" in x for x in mybro), mybro


def test_unidentified_hex_suffixed_ssid_falls_back_to_every_shape():
    labels = _mask_labels("SomeOffice_aabbcc")
    assert len(labels) == len(_PLDT_MASKS)


def test_random_key_isps_get_no_isp_masks():
    """Sky/DITO/Streamtech ship a random per-device label key: there is no key
    space to sweep, so an hour of masks would prove only that."""
    for essid in ("SkyBroadband", "SkyFiber_1234", "DITO_Home_99", "Streamtech_AB", "RISE_Fiber", ""):
        assert _mask_labels(essid) == [], essid
        if essid:
            assert ph_random_key_isp(essid) or essid == "RISE_Fiber"


def test_globe_gets_its_own_derivable_family():
    """Globe At Home PROLiNK inserts 'WIFI' into the last-6 MAC hex - that IS
    enumerable, so Globe is not a dead end like Sky/DITO."""
    labels = _mask_labels("GlobeAtHome_1234")
    assert labels, "Globe has a derivable key shape and should get masks"
    assert any("WIFI" in x for x in labels), labels
    assert any("PH mobile" in x or "PH birthdate" in x for x in labels), labels
    assert ph_random_key_isp("GlobeAtHome_1234") == ""


def test_ph_random_key_isp_names_the_provider():
    assert ph_random_key_isp("SkyFiber_1234") == "Sky Broadband/Fiber"
    assert ph_random_key_isp("DITO_Home") == "DITO"
    assert ph_random_key_isp("Streamtech_9") == "Streamtech"
    assert ph_random_key_isp("PLDTHOMEFIBR_abc") == ""
    assert ph_random_key_isp("") == ""


def test_isp_family_gate_regex_has_no_typos():
    """'pltdhwifi' was a transposition of 'pldtwifi', and 'homeultrera' of
    'homeultera' - neither ever matched a real SSID."""
    assert _has_derivable_hex_suffix("PLDTWIFI_abc")
    assert _has_derivable_hex_suffix("HomeUltera_xyz")


def test_isp_family_classification():
    assert _isp_family("ConvergeExample_2.4GHz") == "converge"
    assert _isp_family("0FS_abcdef") == "converge"
    assert _isp_family("ZTE_2.4G_A1B2") == "converge"
    assert _isp_family("wlan1a2b3c") == "converge"
    assert _isp_family("PLDTHOMEFIBR_abc123") == "pldt"
    assert _isp_family("PLDTWIFI123456") == "pldt"
    assert _isp_family("HomeBro_A1B2C3") == "homebro"
    assert _isp_family("HomeUltera_1234") == "homebro"
    assert _isp_family("myBRO_1234") == "mybro"
    assert _isp_family("SmartBro_99") == "mybro"
    assert _isp_family("GlobeAtHome_1234") == "globe"
    assert _isp_family("SkyFiber_1234") == ""
    assert _isp_family("DITO_Home") == ""
    assert _isp_family("") == ""


def test_mutation_rules_run_before_the_generic_brute_force_masks():
    """On a human-named network ("Example Family", "ExampleNet-K") the passphrase is
    human-chosen, so 8.5M words x ~25 mutations beats an exhaustive sweep of
    every 9- or 10-digit string. Rules were dead last and never ran."""
    plan = _build_attack_plan(".", "wifi-wordlist.txt")
    kinds = [a.get("kind") for a in plan]
    assert "rules" in kinds and "mask" in kinds
    assert kinds.index("rules") < kinds.index("mask"), [a["label"] for a in plan]
    # ...but still after the cheap dictionary and hybrid stages.
    assert max(i for i, k in enumerate(kinds) if k == "dict") < kinds.index("rules")


def test_default_budget_admits_rules_but_not_the_hopeless_sweeps():
    budget = _stage_budget_seconds()
    speed = 49_000  # measured on the target iGPU
    rules_keyspace = 8_513_588 * 25          # dictionary x wifi-rules.rule
    assert rules_keyspace / speed <= budget, "the highest-yield stage must fit"
    for hopeless in (10**9, 16**8, 10**10):  # 9-digit, 8-hex, 10-digit
        assert hopeless / speed > budget, "exhaustive sweeps must still be skipped"


# salt-aware runtime estimates

def test_salt_count_is_distinct_essids():
    from src.hashcat.crack import _salt_count

    nets = [("A", "aa" * 6), ("B", "bb" * 6), ("A", "cc" * 6)]  # A twice, two APs
    assert _salt_count(nets) == 2
    assert _salt_count([]) == 1          # never divide by zero
    assert _salt_count([("", "aa" * 6)]) == 1


def test_estimates_scale_with_the_number_of_networks():
    """A WPA PMK is PBKDF2(passphrase, ESSID), so each candidate is derived once
    per SSID. Ignoring that made every batch estimate N times too optimistic -
    an 8-digit mask advertised as ~49 min really took ~9 hours over 11 networks."""
    from src.hashcat.crack import _salt_count

    speed = 49_000
    keyspace = 10**8                       # mask: 8 digits
    one = keyspace * _salt_count([("Solo", "aa" * 6)]) / speed
    eleven = keyspace * _salt_count([(f"N{i}", "aa" * 6) for i in range(11)]) / speed
    assert round(eleven / one) == 11
    assert one < 2 * 3600 <= eleven, "the gate must admit it solo and reject it for 11 networks"


# family masks only run against their own family

def _line(essid, bssid="aa" * 6, mic="bb" * 16):
    return f"WPA*02*{mic}*{bssid}*112233445566*{essid.encode().hex()}*dd*ee*02"


def test_isp_mask_carries_the_networks_it_applies_to():
    nets = [("ConvergeExample_2.4GHz", "c6" * 6), ("ExampleNet-K", "7c" * 6), ("Example Family", "f8" * 6)]
    stages = _isp_mask_stages_for_networks(nets)
    assert stages
    for st in stages:
        assert st["targets"] == {"ConvergeExample_2.4GHz"}, st["label"]


def test_two_networks_of_one_family_share_a_single_stage():
    nets = [("Converge_2.4GHz_aaaa", "c6" * 6), ("Converge_2.4GHz_bbbb", "c7" * 6)]
    stages = _isp_mask_stages_for_networks(nets)
    masks = [s["arg"] for s in stages]
    assert len(masks) == len(set(masks)), "no duplicate shapes"
    for st in stages:
        assert st["targets"] == {"Converge_2.4GHz_aaaa", "Converge_2.4GHz_bbbb"}


def test_stage_hash_file_narrows_to_the_target_networks(tmp_path, monkeypatch):
    """A Converge key shape cannot crack a TP-Link, so pointing the mask at all
    eleven salts multiplied its cost by ten networks it could never solve."""
    from src.hashcat import crack as crack_mod

    monkeypatch.setattr(crack_mod, "HCOV_DIR", str(tmp_path))
    lines = [_line("ConvergeExample_2.4GHz"), _line("ExampleNet-A"), _line("ExampleNet-K"), _line("Example Family")]
    full = str(tmp_path / "full.hc22000")
    open(full, "w").write("\n".join(lines) + "\n")

    stage = {"targets": {"ConvergeExample_2.4GHz"}}
    path, salts = crack_mod._stage_hash_file(stage, lines, full)
    assert path != full and salts == 1
    written = open(path).read().strip().splitlines()
    assert len(written) == 1
    assert bytes.fromhex(written[0].split("*")[5]).decode() == "ConvergeExample_2.4GHz"


def test_stage_without_targets_uses_every_hash(tmp_path, monkeypatch):
    from src.hashcat import crack as crack_mod

    monkeypatch.setattr(crack_mod, "HCOV_DIR", str(tmp_path))
    lines = [_line("A"), _line("B"), _line("C")]
    full = str(tmp_path / "full.hc22000")
    open(full, "w").write("\n".join(lines) + "\n")

    path, salts = crack_mod._stage_hash_file({}, lines, full)
    assert path == full and salts == 3


# up-front timing

def test_benchmark_parses_hashcat_machine_readable_output():
    """Format is device:mode:?:?:ms:H/s - reading the wrong fields silently
    produced a nonsense speed and therefore nonsense estimates."""
    from src.hashcat.crack import _parse_benchmark

    assert _parse_benchmark("1:22000:4294967295:4294967295:93.41:32848") == 32848
    # Other modes must be ignored.
    assert _parse_benchmark("1:2500:0:0:1.0:999\n1:22000:0:0:93.41:32848") == 32848
    # Multiple devices sum.
    assert _parse_benchmark("1:22000:0:0:93:30000\n2:22000:0:0:93:20000") == 50000
    assert _parse_benchmark("") is None
    assert _parse_benchmark("garbage") is None


def test_benchmark_is_cached(tmp_path, monkeypatch):
    """A benchmark costs seconds; paying it on every run is a tax on every job."""
    from src.hashcat import crack as crack_mod

    monkeypatch.setattr(crack_mod, "HCOV_DIR", str(tmp_path))
    calls = []

    def _fake_run(cmd, **kw):
        calls.append(cmd)
        out = type("R", (), {"stdout": "1:22000:0:0:93.41:32848", "stderr": ""})()
        return out

    monkeypatch.setattr(crack_mod.subprocess, "run", _fake_run)
    assert crack_mod._benchmark_speed("hashcat", str(tmp_path)) == 32848
    assert crack_mod._benchmark_speed("hashcat", str(tmp_path)) == 32848
    assert len(calls) == 1, "the second call must come from the cache"


def test_compact_counts_stay_readable():
    """Full digit groups pushed the plan table past a normal terminal width, so
    every row wrapped and the at-a-glance shape was lost."""
    from src.hashcat.crack import _fmt_count

    assert _fmt_count(999) == "999"
    assert _fmt_count(35_681) == "35.7k"
    assert _fmt_count(16_777_216) == "16.8M"
    assert _fmt_count(1_070_430_000) == "1.1B"
    assert _fmt_count(107_043_000_000) == "107B"      # >=100 drops the decimal
    assert _fmt_count(35_681_000_000_000) == "35.7T"
    assert all(len(_fmt_count(n)) <= 6 for n in (999, 35_681, 16_777_216, 10**13))
