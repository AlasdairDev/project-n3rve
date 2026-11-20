import os
import re
import sys
import time
import platform
import subprocess
from src.console import console, colored_log, log_debug
from src.config import BIN_DIR, HASHCAT_VERSION, HCOV_DIR

_SYSTEM = platform.system()

_hashcat_path_cache = None


def _find_in_path(name: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d.strip('"'), name)
        if os.path.isfile(p):
            return p
    return None


def _get_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_hashcat_path() -> str | None:
    global _hashcat_path_cache
    if _hashcat_path_cache:
        return _hashcat_path_cache
    # Windows ships hashcat.exe; the Linux release binary is hashcat.bin (a plain
    # "hashcat" only exists when installed via a package manager wrapper).
    names = ["hashcat.exe"] if _SYSTEM == "Windows" else ["hashcat", "hashcat.bin"]
    for exe in names:
        found = _find_in_path(exe)
        if found:
            log_debug(f"get_hashcat_path: found in PATH: {found}")
            _hashcat_path_cache = found
            return found
    root = _get_root()
    hc_dir = os.path.join(root, BIN_DIR, f"hashcat-{HASHCAT_VERSION}")
    for exe in names:
        local = os.path.join(hc_dir, exe)
        if os.path.isfile(local):
            log_debug(f"get_hashcat_path: found locally: {local}")
            _hashcat_path_cache = local
            return local
    log_debug(f"get_hashcat_path: not found (checked PATH and {hc_dir})")
    return None


_DEVICE_BLOCK_RE = re.compile(r"Backend Device ID")
_DEVICE_NAME_RE = re.compile(r"^\s*Name\.*:\s*(.+?)\s*$", re.MULTILINE)
_DEVICE_TYPE_RE = re.compile(r"^\s*Type\.*:\s*(.+?)\s*$", re.MULTILINE)

# Keyed by the binary probed, so a second hashcat (portable build in bin/) is not
# answered with the first one's device list.
_backend_info_cache: dict[tuple, str] = {}


def _backend_info(executable: list[str], cwd: str) -> str:
    """Cached output of ``hashcat -I`` (backend information mode)."""
    key = (tuple(executable), cwd)
    if key in _backend_info_cache:
        return _backend_info_cache[key]
    try:
        r = subprocess.run(list(executable) + ["-I"], capture_output=True, text=True, timeout=30, cwd=cwd or ".")
        out = (r.stdout + r.stderr).strip()
        log_debug(f"_backend_info: rc={r.returncode} out={out[:160]!r}")
    except Exception as e:
        log_debug(f"_backend_info: probe failed ({type(e).__name__}: {e})")
        out = ""
    _backend_info_cache[key] = out
    return out


def hashcat_gpu_devices() -> list[str]:
    """Names of the GPU devices hashcat can actually use.

    Asking hashcat beats inspecting the host: inside a container ``lspci`` is
    usually absent, and it is hashcat's view of the hardware - not the host's -
    that determines how the run performs.
    """
    exe = get_hashcat_path()
    if not exe:
        return []
    info = _backend_info([exe], os.path.dirname(exe))
    if not info:
        return []
    # Parse per device block. A platform header carries its own "Name....:" line
    # ("Intel(R) OpenCL Graphics") before any device, so scanning the whole output
    # for Name/Type in parallel would report the platform as the device.
    devices: list[str] = []
    for block in _DEVICE_BLOCK_RE.split(info)[1:]:
        name = _DEVICE_NAME_RE.search(block)
        dev_type = _DEVICE_TYPE_RE.search(block)
        if name and dev_type and dev_type.group(1).strip().upper() == "GPU":
            devices.append(name.group(1).strip())
    log_debug(f"hashcat_gpu_devices: {devices}")
    return devices


def _hashcat_device_available(executable: list[str], cwd: str) -> bool:
    """Return True if hashcat can enumerate at least one compute device.

    ``-I`` (backend information mode) prints 'No devices found/left.' when there
    is no OpenCL/CUDA device present - exactly what breaks in containers - so we
    treat that string as "unavailable" regardless of the exit code.
    """
    out = _backend_info(executable, cwd)
    if not out:
        return False
    low = out.lower()
    return "no devices found" not in low and "no device" not in low and "no devices" not in low


def _gpu_vendor() -> str:
    """Rough GPU vendor for OpenCL advice: 'intel' | 'amd' | 'nvidia' | ''."""
    try:
        from src.gpu import detect_gpu

        name = (detect_gpu()[0] or "").lower()
    except Exception:
        name = ""
    if not name and _SYSTEM == "Linux":
        try:
            r = subprocess.run(["lspci"], capture_output=True, text=True, timeout=5)
            name = " ".join(ln for ln in r.stdout.splitlines() if "VGA" in ln or "3D" in ln).lower()
        except Exception:
            name = ""
    if "nvidia" in name or "geforce" in name or "rtx" in name or "gtx" in name:
        return "nvidia"
    if "amd" in name or "radeon" in name:
        return "amd"
    if "intel" in name or "iris" in name or "uhd graphics" in name:
        return "intel"
    return ""


def _linux_distro_hint() -> tuple[str, bool]:
    """(package manager, is-atomic) for install advice."""
    atomic = os.path.exists("/run/ostree-booted")
    for pm in ("dnf", "apt-get", "pacman", "zypper"):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            if os.path.isfile(os.path.join(d.strip('"'), pm)):
                return pm, atomic
    return "", atomic


def opencl_advice() -> list[str]:
    """Concrete commands that would give this machine an OpenCL device.

    Without one, hashcat exits with "No devices found/left" on every stage and
    the whole run silently degrades to the CPU path - on an integrated GPU that
    is typically a 10-20x slowdown, which is worth naming explicitly instead of
    leaving the user to wonder why cracking crawls.
    """
    if _SYSTEM != "Linux":
        if _SYSTEM == "Windows":
            return ["Install the vendor GPU driver (NVIDIA/AMD/Intel) - it ships the OpenCL runtime."]
        return ["macOS: hashcat uses the built-in Metal/OpenCL backend; update to the latest hashcat."]

    vendor = _gpu_vendor()
    pm, atomic = _linux_distro_hint()
    pkgs = {
        "intel": {"dnf": "intel-compute-runtime", "apt-get": "intel-opencl-icd", "pacman": "intel-compute-runtime", "zypper": "intel-opencl"},
        "amd": {"dnf": "rocm-opencl", "apt-get": "mesa-opencl-icd", "pacman": "opencl-mesa", "zypper": "ocl-icd-devel"},
        "nvidia": {"dnf": "xorg-x11-drv-nvidia-cuda", "apt-get": "nvidia-opencl-icd", "pacman": "opencl-nvidia", "zypper": "nvidia-computeG06"},
    }.get(vendor, {})
    pkg = pkgs.get(pm, "")

    lines: list[str] = []
    if pkg:
        label = {"intel": "Intel iGPU", "amd": "AMD GPU", "nvidia": "NVIDIA GPU"}[vendor]
        if atomic:
            lines.append(f"{label} detected. On an atomic host this needs layering (one reboot):")
            lines.append(f"  sudo rpm-ostree install {pkg} && systemctl reboot")
        else:
            sudo = "" if os.geteuid() == 0 else "sudo "
            install = f"{pm} install -y {pkg}" if pm != "pacman" else f"pacman -S {pkg}"
            lines.append(f"{label} detected. Install its OpenCL runtime:")
            lines.append(f"  {sudo}{install}")
    else:
        lines.append("Install your GPU vendor's OpenCL runtime (intel-compute-runtime / rocm-opencl / CUDA).")
    lines.append("No GPU runtime available? A CPU OpenCL backend still beats nothing: brew install pocl")
    return lines


def _warn_no_opencl() -> None:
    colored_log(
        "warning",
        "hashcat found, but no OpenCL/CUDA compute device is visible - falling back to aircrack-ng (CPU).",
    )
    for line in opencl_advice():
        colored_log("info", line)


def ensure_hashcat() -> bool:
    """Make hashcat available: use it if already installed, else install it via the
    OS package manager (Linux) or point the user at an install command.

    Availability means the binary *exists AND can see a compute device* - a
    portable hashcat inside a container without an OpenCL/CUDA backend would
    otherwise be reported as "available" and then fail every stage with
    "No devices found/left".
    """
    found = get_hashcat_path()
    log_debug(f"ensure_hashcat: get_hashcat_path() returned {found!r}")
    if found:
        probe_dir = os.path.dirname(found)
        has_dev = _hashcat_device_available([found], probe_dir)
        log_debug(f"ensure_hashcat: device probe {'OK' if has_dev else 'NO DEVICE'}")
        if has_dev:
            log_debug("ensure_hashcat: hashcat available with usable device")
            return True
        _warn_no_opencl()
        return False

    if _SYSTEM == "Linux":
        try:
            from src.setup import _linux_install  # lazy import: avoids an import cycle

            pkg_map = {"brew": "hashcat", "apt-get": "hashcat", "dnf": "hashcat", "pacman": "hashcat", "zypper": "hashcat"}
            if _linux_install(pkg_map, "hashcat"):
                installed = get_hashcat_path()  # not found earlier => no stale cache to clear
                if installed:
                    # A fresh install is useless without a compute device, so probe
                    # before promising the GPU path. That way we degrade at setup
                    # time instead of failing every stage later.
                    if _hashcat_device_available([installed], os.path.dirname(installed)):
                        return True
                    _warn_no_opencl()
                    return False
        except Exception as e:
            log_debug(f"ensure_hashcat: package-manager install failed ({e})")

    colored_log("warning", "hashcat not found and could not be installed automatically.")
    if _SYSTEM == "Windows":
        colored_log("info", "Install it: winget install hashcat  (or unzip hashcat.net into bin/)")
    elif _SYSTEM == "Darwin":
        colored_log("info", "Install it: brew install hashcat")
    else:
        colored_log("info", "Install it: brew install hashcat  /  sudo apt install hashcat  /  sudo dnf install hashcat")
    return False


def _kernel_cache_exists(hc_dir: str) -> bool:
    """Return True if hashcat has compiled kernels cached anywhere it looks.

    Portable installs keep them under ``<hc_dir>/kernels``; package-manager
    installs (e.g. /usr/bin/hashcat) cache them under ``~/.cache/hashcat``.
    """
    search_dirs = [os.path.join(hc_dir, "kernels"), os.path.expanduser("~/.cache/hashcat")]
    for base in search_dirs:
        if not os.path.isdir(base):
            continue
        for _root, _dirs, files in os.walk(base):
            if any(f.endswith((".kernel", ".bin")) for f in files):
                return True
    return False


def warmup_hashcat_kernel(hc22000_path: str | None = None) -> bool:
    """Pre-compile GPU kernel for mode 22000 using the real handshake hash.

    Requires a valid *hc22000_path* to a converted .hc22000 file - no
    synthetic/dummy hashes are used (see Testing Policy in AGENTS.md).
    """
    hc_exe = get_hashcat_path()
    if not hc_exe:
        return False
    hc_dir = os.path.dirname(hc_exe)
    if _kernel_cache_exists(hc_dir):
        log_debug("warmup_hashcat_kernel: kernel cache found, skipping compilation")
        colored_log("info", "GPU kernel cache found - compilation not required.")
        return True
    if not hc22000_path or not os.path.isfile(hc22000_path):
        log_debug("warmup_hashcat_kernel: no real hash file available, skipping warmup")
        return False
    os.makedirs(HCOV_DIR, exist_ok=True)
    warmup_hash = os.path.abspath(hc22000_path)
    dummy_wordlist = os.path.abspath(os.path.join(HCOV_DIR, "_warmup_wl.txt"))
    cleanup_files: list[str] = [dummy_wordlist]
    log_debug(f"warmup_hashcat_kernel: using real hash: {hc22000_path}")
    with open(dummy_wordlist, "w") as f:
        f.write("testpassword\n")
    potfile = os.path.abspath(os.path.join(HCOV_DIR, "_warmup.potfile"))
    # -O so the compiled/cached kernel matches the optimized one used for cracking.
    cmd = [hc_exe, "-m", "22000", "-a", "0", "-w", "1", "-O", "--potfile-path", potfile, warmup_hash, dummy_wordlist]
    cleanup_files.append(potfile)
    try:
        log_debug("warmup_hashcat_kernel: no kernel cache found, running first-time compilation")
        console.rule("[bold yellow]GPU Kernel Compilation (First Run)[/bold yellow]", style="yellow")
        colored_log("info", "Compiling GPU kernel for WPA/WPA2 cracking...")
        console.print("  [dim]This one-time step prepares your GPU for faster cracking.[/dim]")
        console.print("  [dim]Time: ~30-90 seconds depending on GPU and driver.[/dim]")
        console.print("")
        start = time.time()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=hc_dir,
        )
        if proc.stdout is None:
            raise RuntimeError("stdout pipe not created")
        output_lines: list[str] = []
        device_name = ""
        import threading

        _spin_stop = threading.Event()

        def _spin():
            chars = ["-", "\\", "|", "/"]
            c = 0
            while not _spin_stop.is_set():
                sys.stdout.write(f"\r  {chars[c % 4]} Compiling GPU kernel...")
                sys.stdout.flush()
                c += 1
                time.sleep(0.25)

        spin_thread = threading.Thread(target=_spin, daemon=True)
        spin_thread.start()
        for line in proc.stdout:
            line_str = line.rstrip("\n\r")
            output_lines.append(line_str)
            if line_str.startswith("* Device #"):
                device_name = line_str.split(",")[0].replace("* Device #1: ", "").strip()
        try:
            proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            log_debug("warmup_hashcat_kernel: timed out after 300s, process killed")
            colored_log("warning", "GPU kernel compilation timed out (>5 min). Skipping warmup.")
            return False
        finally:
            _spin_stop.set()
            spin_thread.join(timeout=2)
            sys.stdout.write("\r" + " " * 40 + "\r")
            sys.stdout.flush()
        elapsed = time.time() - start
        log_debug(f"warmup_hashcat_kernel: finished in {elapsed:.2f}s (rc={proc.returncode})")
        console.print("")
        kernel_cached = _kernel_cache_exists(hc_dir)
        if kernel_cached:
            colored_log(
                "success",
                f"GPU kernel ready{(' on ' + device_name if device_name else '')} ({int(elapsed)}s). Cached for next run.",
            )
        else:
            colored_log("warning", "GPU kernel compilation skipped - will use hashcat with default kernels.")
        console.rule(style="yellow")
        return kernel_cached
    except Exception as e:
        log_debug(f"warmup_hashcat_kernel: failed ({e})")
        return False
    finally:
        for f in cleanup_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass


def add_bin_to_path() -> None:
    hc = get_hashcat_path()
    if hc:
        parent = os.path.dirname(hc)
        if parent not in os.environ.get("PATH", ""):
            old = os.environ.get("PATH", "")
            os.environ["PATH"] = parent + os.pathsep + old
            log_debug(f"add_bin_to_path: prepended {parent} to PATH")
        else:
            log_debug(f"add_bin_to_path: {parent} already in PATH")
    else:
        log_debug("add_bin_to_path: hashcat not found, nothing to add")
