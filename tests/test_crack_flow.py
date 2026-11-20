"""Tests for crack_with_hashcat's control flow that don't need a GPU."""

import os

import pytest

from src.hashcat import crack as crack_mod

ESSID_A = "ExampleNet-A"
ESSID_B = "ConvergeExample_2.4GHz"


def _hash_line(essid: str, bssid: str, mic: str) -> str:
    return f"WPA*02*{mic}*{bssid}*112233445566*{essid.encode().hex()}*dd*ee*02"


def _pot_line(essid: str, password: str) -> str:
    return "deadbeef" * 8 + "*" + essid.encode().hex() + ":" + password


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """Point the cracker at a temp potfile and a stub hashcat binary."""
    hc_dir = tmp_path / "hc"
    hc_dir.mkdir()
    hc_exe = hc_dir / "hashcat"
    hc_exe.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(hc_exe, 0o755)

    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password123\n")

    monkeypatch.setattr(crack_mod, "HCOV_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(crack_mod, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(crack_mod, "get_hashcat_path", lambda: str(hc_exe))
    monkeypatch.setattr(crack_mod, "ensure_ph_wordlist", lambda: None)
    os.makedirs(str(tmp_path / "cache"), exist_ok=True)
    return tmp_path, str(wordlist)


def test_networks_already_in_the_potfile_are_reported_not_recracked(rig, monkeypatch):
    """hashcat exits immediately when every hash is in the potfile, writing
    nothing - so watching only for new entries would call a known password a
    failure, and would re-run the whole plan to get there."""
    tmp_path, wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(_hash_line(ESSID_A, "aabbccddeeff", "aa" * 16) + "\n")
    potfile = tmp_path / "cache" / "hashcat.potfile"
    potfile.write_text(_pot_line(ESSID_A, "ExamplePass1") + "\n")

    def _boom(*args, **kwargs):
        raise AssertionError("hashcat must not run when the answer is already known")

    monkeypatch.setattr(crack_mod, "_run_hashcat_attack", _boom)

    assert crack_mod.crack_with_hashcat(str(hashes), wordlist, ESSID_A) == {ESSID_A: "ExamplePass1"}


def test_partially_known_capture_still_runs_for_the_unsolved_network(rig, monkeypatch):
    tmp_path, wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(
        _hash_line(ESSID_A, "aabbccddeeff", "aa" * 16) + "\n" + _hash_line(ESSID_B, "112233445566", "bb" * 16) + "\n"
    )
    potfile = tmp_path / "cache" / "hashcat.potfile"
    potfile.write_text(_pot_line(ESSID_A, "ExamplePass1") + "\n")

    ran: list[str] = []

    def _fake_attack(hc_exe, hc_dir, hc22000, attack, pot, essid, discrete, i, n, before, time_limit=None, run_started=None):
        ran.append(attack["label"])
        return "exhausted", []

    monkeypatch.setattr(crack_mod, "_run_hashcat_attack", _fake_attack)

    result = crack_mod.crack_with_hashcat(str(hashes), wordlist, ESSID_A)
    assert result == {ESSID_A: "ExamplePass1"}  # the known one is still reported
    assert ran, "the plan must still run for the network that is not yet cracked"


def test_potfile_entries_for_other_captures_are_ignored(rig, monkeypatch):
    tmp_path, wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(_hash_line(ESSID_B, "112233445566", "bb" * 16) + "\n")
    potfile = tmp_path / "cache" / "hashcat.potfile"
    potfile.write_text(_pot_line("SomeOtherNetwork", "notourpassword") + "\n")

    monkeypatch.setattr(
        crack_mod, "_run_hashcat_attack", lambda *a, **k: ("exhausted", [])
    )
    assert crack_mod.crack_with_hashcat(str(hashes), wordlist, ESSID_B) == {}


def test_stages_that_error_are_reported_not_silently_dropped(rig, monkeypatch, capsys):
    """A stage that exits abnormally used to appear in neither the completed nor
    the skipped list, so a 54-minute run reported only ~21 minutes of work."""
    tmp_path, wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(_hash_line(ESSID_B, "112233445566", "bb" * 16) + "\n")

    def _attack(hc_exe, hc_dir, hc22000, attack, pot, essid, discrete, i, n, before, time_limit=None, run_started=None):
        # First stage runs fine so the caller does not bail out to aircrack.
        return ("exhausted", [1000]) if i == 1 else ("error", [])

    monkeypatch.setattr(crack_mod, "_run_hashcat_attack", _attack)
    crack_mod.crack_with_hashcat(str(hashes), wordlist, ESSID_B)

    out = capsys.readouterr().out
    assert "did not finish" in out, out[-800:]


def test_hashcat_is_launched_with_stdin_detached(rig, monkeypatch):
    """hashcat reads the terminal for its [b]ypass/[q]uit keys; inheriting stdin
    lets a stray keystroke abort a stage mid-run."""
    tmp_path, _wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(_hash_line(ESSID_B, "112233445566", "bb" * 16) + "\n")
    seen = {}

    class _Proc:
        stdout = iter(())
        pid = 1
        returncode = 1

        def wait(self, timeout=None):
            return 1

    def _popen(cmd, **kwargs):
        seen.update(kwargs)
        return _Proc()

    monkeypatch.setattr(crack_mod.subprocess, "Popen", _popen)
    crack_mod._run_hashcat_attack(
        "hashcat", str(tmp_path), str(hashes),
        {"label": "x", "mode": "0", "arg": "wl", "extra": []},
        str(tmp_path / "pot"), ESSID_B, False, 1, 1, set(),
    )
    assert seen.get("stdin") is crack_mod.subprocess.DEVNULL


def test_ctrl_c_stops_the_program_instead_of_skipping_one_capture(rig, monkeypatch):
    """Swallowing KeyboardInterrupt made the caller's loop advance to the next
    capture, so stopping an 11-capture run took eleven presses."""
    tmp_path, wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(_hash_line(ESSID_B, "112233445566", "bb" * 16) + "\n")

    def _interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(crack_mod, "_run_hashcat_attack", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        crack_mod.crack_with_hashcat(str(hashes), wordlist, ESSID_B)


def test_interrupt_still_saves_what_was_already_recovered(rig, monkeypatch):
    tmp_path, wordlist = rig
    hashes = tmp_path / "t.hc22000"
    hashes.write_text(
        _hash_line(ESSID_A, "aabbccddeeff", "aa" * 16) + "\n" + _hash_line(ESSID_B, "112233445566", "bb" * 16) + "\n"
    )
    potfile = tmp_path / "cache" / "hashcat.potfile"

    calls = {"n": 0}

    def _attack(hc_exe, hc_dir, hc22000, attack, pot, essid, discrete, i, n, before, time_limit=None, run_started=None):
        calls["n"] += 1
        if calls["n"] == 1:
            potfile.write_text(_pot_line(ESSID_A, "ExamplePass1") + "\n")
            return "found", [1000]
        raise KeyboardInterrupt

    monkeypatch.setattr(crack_mod, "_run_hashcat_attack", _attack)
    with pytest.raises(KeyboardInterrupt):
        crack_mod.crack_with_hashcat(str(hashes), wordlist, ESSID_A)

    saved = tmp_path / "results" / f"{ESSID_A}_cracked_password.txt"
    assert saved.is_file(), "a recovered password must survive the interrupt"
    assert "ExamplePass1" in saved.read_text()


def test_no_blanket_process_kill():
    """A global `pkill -9 -x hashcat` killed every hashcat on the machine,
    including a concurrent run's - six stages of a real run died that way. Only
    comments may mention it now; no executable line may kill by name."""
    import inspect

    for line in inspect.getsource(crack_mod).splitlines():
        code = line.split("#", 1)[0]
        assert "pkill" not in code and "taskkill" not in code, line.strip()


def test_deep_pass_attacks_each_network_alone(rig, monkeypatch):
    """Cost scales with distinct SSIDs, so a stage that cannot fit across a dozen
    networks fits against one. The deep pass must hand hashcat a single salt."""
    from src.hashcat.crack import crack_networks_individually

    _tmp, wordlist = rig
    lines = [
        _hash_line(ESSID_A, "aabbccddeeff", "aa" * 16),
        _hash_line(ESSID_B, "112233445566", "bb" * 16),
        _hash_line(ESSID_B, "112233445566", "cc" * 16),  # 2nd hash, same SSID
    ]
    seen = []

    def _fake(path, wl, essid, discrete=False):
        content = open(path).read().strip().splitlines()
        salts = {ln.split("*")[5] for ln in content}
        seen.append((essid, len(content), len(salts)))
        return {essid: "cracked!!"} if essid == ESSID_B else {}

    monkeypatch.setattr(crack_mod, "crack_with_hashcat", _fake)
    found = crack_networks_individually(lines, [ESSID_A, ESSID_B], wordlist)

    assert found == {ESSID_B: "cracked!!"}
    assert [s[0] for s in seen] == [ESSID_A, ESSID_B]
    assert all(salts == 1 for _e, _n, salts in seen), "each pass must carry one salt"
    assert seen[1][1] == 2, "both hashes for that SSID should be included"


def test_effort_record_accumulates_and_dedupes():
    """Stage outcomes from several crack passes merge into one report-ready record.

    A stage that ran in the shared pass and again in a per-network deep pass is
    one searched candidate set to the reader, and a stage skipped on the shared
    pass but searched later no longer counts as "not searched".
    """
    crack_mod.reset_effort()
    assert crack_mod.last_effort() == {"searched": [], "skipped": []}

    # Shared pass: dictionary searched, the 9-digit mask skipped on budget.
    crack_mod.record_effort(
        ["dictionary (8.5M)"],
        [("mask: 9 digits", "~5h 40m exceeds the 2h budget")],
    )
    # Deep pass on one network: dictionary runs again, and the mask now fits.
    crack_mod.record_effort(["dictionary (8.5M)", "mask: 9 digits"], [])

    effort = crack_mod.last_effort()
    assert effort["searched"] == ["dictionary (8.5M)", "mask: 9 digits"]
    assert effort["skipped"] == []  # the mask moved from skipped to searched

    # The getter returns a copy - mutating it must not corrupt the record.
    effort["searched"].append("tampered")
    assert "tampered" not in crack_mod.last_effort()["searched"]

    crack_mod.reset_effort()
    assert crack_mod.last_effort() == {"searched": [], "skipped": []}
