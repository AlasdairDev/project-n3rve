"""The progress file: how a run is observed when its terminal isn't showing it."""

import os

from src.hashcat import crack as crack_mod


def _rig(tmp_path, monkeypatch):
    monkeypatch.setattr(crack_mod, "HCOV_DIR", str(tmp_path))
    return tmp_path


def test_progress_round_trips(tmp_path, monkeypatch):
    _rig(tmp_path, monkeypatch)
    crack_mod.write_progress(state="running", stage="10/19", label="hybrid", recovered="2/9")
    info = crack_mod.read_progress()
    assert info["state"] == "running"
    assert info["stage"] == "10/19"
    assert info["label"] == "hybrid"
    assert info["recovered"] == "2/9"
    assert int(info["pid"]) == os.getpid()
    assert info["updated"]


def test_labels_containing_equals_survive(tmp_path, monkeypatch):
    """Stage labels carry things like 'a=b'; splitting on every '=' would
    silently truncate them."""
    _rig(tmp_path, monkeypatch)
    crack_mod.write_progress(state="running", label="mask: ?d?d = digits")
    assert crack_mod.read_progress()["label"] == "mask: ?d?d = digits"


def test_missing_progress_reads_empty(tmp_path, monkeypatch):
    _rig(tmp_path, monkeypatch)
    assert crack_mod.read_progress() == {}


def test_status_command_reports_each_state(tmp_path, monkeypatch, capsys):
    import main as main_mod

    _rig(tmp_path, monkeypatch)

    # Nothing recorded yet.
    assert main_mod.print_run_status() == 1
    assert "No run has been recorded" in capsys.readouterr().out

    # A finished run whose process is gone.
    crack_mod.write_progress(state="finished", stage="19/19", label="complete", recovered="2/9", pid=os.getpid())
    monkeypatch.setattr("src.utils._pid_alive", lambda pid: False)
    assert main_mod.print_run_status() == 0
    assert "Finished" in capsys.readouterr().out

    # A live run.
    crack_mod.write_progress(state="running", stage="10/19", label="hybrid: PH + 2 digits", recovered="2/9")
    monkeypatch.setattr("src.utils._pid_alive", lambda pid: True)
    main_mod.print_run_status()
    out = capsys.readouterr().out
    assert "Running" in out and "10/19" in out and "hybrid: PH + 2 digits" in out

    # A run that died mid-stage.
    monkeypatch.setattr("src.utils._pid_alive", lambda pid: False)
    main_mod.print_run_status()
    assert "Stopped" in capsys.readouterr().out
