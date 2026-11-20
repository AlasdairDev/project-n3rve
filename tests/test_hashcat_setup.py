import subprocess
from unittest.mock import Mock

import pytest

from src.hashcat.setup import _hashcat_device_available


@pytest.fixture(autouse=True)
def _clear_backend_cache():
    """The probe result is cached per binary in production; each test wants a
    fresh probe."""
    from src.hashcat import setup as hc_setup

    hc_setup._backend_info_cache.clear()
    yield
    hc_setup._backend_info_cache.clear()


def test_device_probe_positive_on_device_listing(monkeypatch):
    fake = Mock()
    fake.returncode = 0
    fake.stdout = "* Device #1: NVIDIA GeForce RTX 3080, 10240/10240 MB\n"
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
    assert _hashcat_device_available(["hashcat"], "/tmp") is True


def test_device_probe_negative_on_no_devices(monkeypatch):
    fake = Mock()
    fake.returncode = 0
    fake.stdout = "hashcat (v7.1.2) starting in backend information mode\n\nNo devices found/left.\n"
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
    assert _hashcat_device_available(["hashcat"], "/tmp") is False


def test_device_probe_negative_on_probe_error(monkeypatch):
    def boom(*a, **k):
        raise OSError("no cl cracker")

    monkeypatch.setattr(subprocess, "run", boom)
    assert _hashcat_device_available(["hashcat"], "/tmp") is False


def test_backend_info_is_cached_per_binary(monkeypatch):
    """The probe runs once per binary - but a different binary must not be
    answered with the first one's device list."""
    from src.hashcat import setup as hc_setup

    hc_setup._backend_info_cache.clear()
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(cmd[0])
        out = Mock()
        out.returncode = 0
        out.stdout = f"Name...........: GPU-for-{cmd[0]}\n    Type...........: GPU\n"
        out.stderr = ""
        return out

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert "GPU-for-a" in hc_setup._backend_info(["a"], "/tmp")
    assert "GPU-for-a" in hc_setup._backend_info(["a"], "/tmp")
    assert calls == ["a"], "second call for the same binary should hit the cache"
    assert "GPU-for-b" in hc_setup._backend_info(["b"], "/tmp")
    assert calls == ["a", "b"]
    hc_setup._backend_info_cache.clear()


def test_gpu_devices_parsed_from_backend_info(monkeypatch):
    from src.hashcat import setup as hc_setup

    hc_setup._backend_info_cache.clear()
    # Real hashcat -I shape: the *platform* block carries a "Name....:" line of
    # its own before any device block.
    info = """
OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: Intel(R) Corporation
  Name....: Intel(R) OpenCL Graphics
  Version.: OpenCL 3.0

  Backend Device ID #01
    Type...........: CPU
    Vendor.........: Intel(R) Corporation
    Name...........: 11th Gen Intel(R) Core(TM) i5-1135G7

  Backend Device ID #02
    Type...........: GPU
    Vendor.........: Intel(R) Corporation
    Name...........: Intel(R) Iris(R) Xe Graphics
    Processor(s)...: 16
"""
    monkeypatch.setattr(hc_setup, "get_hashcat_path", lambda: "/usr/bin/hashcat")
    monkeypatch.setattr(hc_setup, "_backend_info", lambda e, c: info)
    assert hc_setup.hashcat_gpu_devices() == ["Intel(R) Iris(R) Xe Graphics"]
    hc_setup._backend_info_cache.clear()
