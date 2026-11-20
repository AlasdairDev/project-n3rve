"""Discrete GPU detection for hashcat routing."""

import re
import shutil
import platform
import subprocess

from src.console import log_debug


def _clean_gpu_name(lspci_line: str) -> str:
    """Turn a raw `lspci -vnn` line into a readable GPU name.

    e.g. "00:02.0 VGA compatible controller [0300]: Intel Corporation
    TigerLake-LP GT2 [Iris Xe Graphics] [8086:9a49] (rev 01)"
      -> "Intel Corporation TigerLake-LP GT2 [Iris Xe Graphics]"
    """
    name = lspci_line.split("]:", 1)[1] if "]:" in lspci_line else lspci_line
    name = re.sub(r"\[[0-9a-fA-F]{4}:[0-9a-fA-F]{4}\]", "", name)  # drop [vendor:device] ids
    name = re.sub(r"\((?:rev|prog-if)[^)]*\)", "", name)  # drop (rev ..)/(prog-if ..)
    name = re.sub(r"\s+", " ", name).strip()
    return name or lspci_line.strip()


_KNOWN_DISCRETE = ["rtx", "gtx", "quadro", "tesla", "rx", "firepro", "pro wx", "arc"]
_SKIP = ["intel", "microsoft", "basic display", "vmware", "virtualbox", "parsec", "remote"]
# Intel "Arc" is always a discrete dGPU; "Intel Iris/UHD/HD" are iGPUs, so the
# skip-list keeps them out while "arc" still gets classified discrete.

# Matched on word boundaries, not as bare substrings: "rx" and "arc" occur inside
# unrelated vendor names ("Matrox", "Arcturus"), and a mis-classified iGPU would
# be driven at the discrete workload profile.
_DISCRETE_RE = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in _KNOWN_DISCRETE) + r")\b")
_NVIDIA_RE = re.compile(r"\b(?:nvidia|geforce)\b")


def _looks_discrete(name: str) -> bool:
    low = (name or "").lower()
    return bool(_DISCRETE_RE.search(low) or _NVIDIA_RE.search(low))


def _get_gpu_list_powershell() -> list[dict]:
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_VideoController | "
        "Where-Object { $_.ConfigManagerErrorCode -eq 0 } | "
        "Select-Object Name, AdapterRAM | "
        "ConvertTo-Csv -NoTypeInformation",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
    method = "PowerShell (Get-CimInstance)"
    if r.returncode != 0 or not r.stdout.strip():
        cmd[2] = (
            "Get-WmiObject Win32_VideoController | "
            "Where-Object { $_.ConfigManagerErrorCode -eq 0 } | "
            "Select-Object Name, AdapterRAM | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
        method = "PowerShell (Get-WmiObject)"

    log_debug(f"GPU detection: queried via {method}")

    gpus = []
    lines = r.stdout.strip().splitlines()
    for line in lines[1:]:  # skip CSV header
        parts = [x.strip('"') for x in line.split(",")]
        if len(parts) >= 2 and parts[0]:
            name = parts[0].strip()
            ram_str = parts[1].strip() if parts[1] else "0"
            try:
                ram_bytes = int(ram_str) if ram_str.isdigit() else 0
            except ValueError:
                ram_bytes = 0
            gpus.append({"name": name, "ram_bytes": ram_bytes})
            log_debug(f'GPU detection: found "{name}" (VRAM: {ram_bytes / (1024**3):.2f} GB)')
    return gpus


def _get_gpu_list_wmic() -> list[dict]:
    r = subprocess.run(
        ["wmic", "path", "win32_videocontroller", "get", "name", "/format:csv"],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    gpus = []
    for line in r.stdout.splitlines():
        parts = line.split(",")
        if len(parts) >= 2:
            name = parts[-1].strip()
            if name and name.lower() != "name":
                gpus.append({"name": name, "ram_bytes": 0})
                log_debug(f'GPU detection (wmic): found "{name}" (VRAM: N/A)')
    return gpus


def _is_discrete(gpu: dict) -> bool:
    name = gpu["name"].lower()

    if _looks_discrete(name):
        log_debug(f'GPU detection: "{gpu["name"]}" -> discrete')
        return True

    if any(x in name for x in _SKIP):
        log_debug(f'GPU detection: "{gpu["name"]}" -> skipped (matched skip list)')
        return False

    log_debug(f'GPU detection: "{gpu["name"]}" -> integrated (no matching pattern)')
    return False


def _select_gpu(gpus: list[dict]) -> tuple[str | None, bool]:
    """Pick the GPU hashcat will effectively be judged on: a discrete card if one
    is present, otherwise the first real display adapter.

    A laptop enumerates its iGPU first, so taking the first entry would report
    "integrated" on a machine that has a dGPU and quietly run hashcat at the
    conservative workload profile.
    """
    for gpu in gpus:
        if _is_discrete(gpu):
            log_debug(f'GPU detection: selected discrete "{gpu["name"]}"')
            return gpu["name"], True
    for gpu in gpus:
        if not any(x in gpu["name"].lower() for x in _SKIP):
            log_debug(f'GPU detection: selected integrated (fallback) "{gpu["name"]}"')
            return gpu["name"], False
    if gpus:
        return gpus[0]["name"], False
    return None, False


def detect_gpu() -> tuple[str | None, bool]:
    """Return the name of the first GPU and whether it is discrete."""
    system = platform.system()
    log_debug(f"GPU detection: OS={system}")
    try:
        if system == "Windows":
            gpus = _get_gpu_list_powershell()
            method = "PowerShell"
            if not gpus:
                gpus = _get_gpu_list_wmic()
                method = "WMIC"
            log_debug(f"GPU detection: {method} returned {len(gpus)} GPU(s)")
            name, discrete = _select_gpu(gpus)
            if name:
                return name, discrete

        elif system == "Linux":
            if not shutil.which("lspci"):
                # GPU naming is informational only; hashcat enumerates its own
                # devices. No lspci (e.g. minimal container) => skip quietly.
                log_debug("GPU detection: lspci not available, skipping")
                return None, False
            r = subprocess.run(["lspci", "-vnn"], capture_output=True, text=True, check=False, timeout=5)
            log_debug(f"GPU detection (lspci):\n{r.stdout.strip()[:500]}")
            gpus = [
                {"name": _clean_gpu_name(line.strip()), "ram_bytes": 0}
                for line in r.stdout.splitlines()
                if any(kw in line.lower() for kw in ["vga", "3d controller", "display controller"])
            ]
            log_debug(f"GPU detection: lspci returned {len(gpus)} display adapter(s)")
            name, discrete = _select_gpu(gpus)
            if name:
                return name, discrete

    except Exception as e:
        # Non-critical: GPU name is only shown for info, so never alarm the user.
        log_debug(f"GPU detection: skipped ({type(e).__name__}: {e})")
    return None, False
