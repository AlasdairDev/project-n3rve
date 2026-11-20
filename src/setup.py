import os
import platform
import subprocess

from rich.panel import Panel
from rich.text import Text

from src.console import console, colored_log, log_error, log_debug
from src.config import (
    HANDSHAKES_DIR,
    RESULTS_DIR,
    WORDLIST_NAME,
    AIRCRACK_WIN_URL,
    BIN_DIR,
    DEPS_DIR,
    AIRCRACK_ZIP_NAME,
    AIRCRACK_WIN_SHA256,
    HCOV_DIR,
)
from src.utils import CAPTURE_EXTENSIONS, download_and_extract_zip, extract_local_zip
from src.bootstrap import pip_install_requirements


def _find_exe_in_path(exe: str) -> str | None:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path.strip('"'), exe)
        if os.path.isfile(candidate):
            return candidate
    return None


# Native package managers we know how to drive, in preference order.
_LINUX_PM_ORDER = ["apt-get", "dnf", "pacman", "zypper"]


def _is_atomic() -> bool:
    """Detect an immutable/atomic host (Fedora Silverblue/Kinoite, Aurora, Bazzite…)."""
    return os.path.exists("/run/ostree-booted")


def _run_install(cmd: list[str], display: str) -> bool:
    """Run an install command interactively; return True on success."""
    colored_log("info", f"Installing {display}: {' '.join(cmd)}")
    try:
        # No capture_output: let brew stream progress / sudo prompt for a password.
        subprocess.run(cmd, check=True, timeout=1800)
        colored_log("success", f"{display} installed.")
        return True
    except subprocess.TimeoutExpired:
        colored_log("error", f"Installation timed out. Run manually: {' '.join(cmd)}")
        return False
    except (subprocess.CalledProcessError, FileNotFoundError):
        colored_log("error", f"Could not install {display} automatically.")
        colored_log("info", f"Install manually: {' '.join(cmd)}")
        return False


def _linux_install(pkg_map: dict[str, str], display: str) -> bool:
    """Install a package on Linux, preferring Homebrew where it makes sense.

    ``pkg_map`` maps an installer name (``brew`` or a native package manager) to
    the package name it uses. Homebrew is preferred on atomic/immutable hosts
    (Aurora, uBlue, Silverblue): it's user-scoped, needs no sudo, and doesn't
    require a reboot the way rpm-ostree layering does. On a mutable host we use
    the native package manager, falling back to brew if there isn't one.
    """
    if os.environ.get("HANDSHAKE_NO_AUTOINSTALL"):
        colored_log("info", f"HANDSHAKE_NO_AUTOINSTALL set - skipping the {display} install.")
        return False

    brew = _find_exe_in_path("brew")
    native = next((p for p in _LINUX_PM_ORDER if _find_exe_in_path(p)), None)
    atomic = _is_atomic()

    # Homebrew first on atomic hosts (or when no native pm is usable).
    if brew and (atomic or native is None):
        return _run_install(["brew", "install", pkg_map.get("brew", display)], display)

    if native is None:
        colored_log("error", f"No supported installer found (brew/apt/dnf/pacman/zypper). Install manually: {display}")
        return False

    pkg = pkg_map.get(native, display)

    if atomic:
        # Native pm exists but the base image is read-only and brew is absent.
        colored_log("warning", f"Atomic host with no Homebrew - can't cleanly auto-install {display}.")
        colored_log("info", "Recommended (Aurora/uBlue):  brew install " + pkg_map.get("brew", display))
        colored_log("info", f"Or use a container:          distrobox enter  ->  {native} install {pkg}")
        colored_log("info", f"Last resort (needs reboot):  sudo rpm-ostree install {pkg}")
        return False

    # Only prepend sudo when we aren't already root (e.g. inside a container).
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    if native == "pacman":
        cmd = sudo + ["pacman", "-S", "--noconfirm", pkg]
    else:
        cmd = sudo + [native, "install", "-y", pkg]
    return _run_install(cmd, display)


_aircrack_path_cache = None


def _find_aircrack_anywhere() -> str | None:
    global _aircrack_path_cache
    if _aircrack_path_cache:
        return _aircrack_path_cache

    system = platform.system()
    exe = "aircrack-ng.exe" if system == "Windows" else "aircrack-ng"
    found = _find_exe_in_path(exe)
    if found:
        _aircrack_path_cache = found
        return found

    root = os.path.dirname(os.path.abspath(__file__))
    local_paths = [
        os.path.join(root, "..", exe),
        os.path.join(root, "..", BIN_DIR, exe),
    ]

    if system == "Windows":
        local_paths += [
            os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "aircrack-ng", "bin", exe),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"), "aircrack-ng", "bin", exe),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "aircrack-ng", "bin", exe),
        ]

    for p in local_paths:
        resolved = os.path.abspath(p)
        if os.path.isfile(resolved):
            _aircrack_path_cache = resolved
            return resolved
    return None


def _add_parent_to_path(found_path: str):
    parent = os.path.dirname(os.path.abspath(found_path))
    if parent not in os.environ.get("PATH", ""):
        os.environ["PATH"] = parent + os.pathsep + os.environ.get("PATH", "")


def ensure_aircrack() -> bool:
    try:
        found = _find_aircrack_anywhere()
        if found:
            _add_parent_to_path(found)
            return True

        system = platform.system()
        if system == "Windows":
            root = os.path.dirname(os.path.abspath(__file__))
            bin_path = os.path.abspath(os.path.join(root, "..", BIN_DIR))

            local_zip = os.path.abspath(os.path.join(root, "..", DEPS_DIR, AIRCRACK_ZIP_NAME))
            if os.path.isfile(local_zip):
                colored_log("info", "Found local aircrack-ng ZIP.")
                if extract_local_zip(local_zip, bin_path, "aircrack-ng-1.7-win/bin"):
                    found = _find_aircrack_anywhere()
                    if found:
                        _add_parent_to_path(found)
                        return True
                colored_log("warning", "Local ZIP extraction failed - trying download.")

            if download_and_extract_zip(AIRCRACK_WIN_URL, bin_path, "aircrack-ng-1.7-win/bin", AIRCRACK_WIN_SHA256):
                found = _find_aircrack_anywhere()
                if found:
                    _add_parent_to_path(found)
                    return True
            colored_log("error", "Could not download aircrack-ng.")
            return False

        elif system == "Linux":
            pkg_map = {
                "brew": "aircrack-ng",
                "apt-get": "aircrack-ng",
                "dnf": "aircrack-ng",
                "pacman": "aircrack-ng",
                "zypper": "aircrack-ng",
            }
            if _linux_install(pkg_map, "aircrack-ng"):
                found = _find_aircrack_anywhere()
                if found:
                    _add_parent_to_path(found)
                    return True
            return False

        else:
            colored_log("error", f"Unsupported OS: {system}. Install aircrack-ng manually.")
            return False

    except Exception as e:
        log_error("Error during aircrack-ng setup", e)
        colored_log("error", "Could not set up aircrack-ng.")
        return False


def ensure_hcxtools() -> bool:
    """Make ``hcxpcapngtool`` available if we cheaply can (optional).

    It is the reference capture->hc22000 converter; when present, its output is
    merged with this project's own parser so hashes either extractor finds are
    cracked. Everything still works without it, so a failure here is silent.
    Set ``HANDSHAKE_NO_AUTOINSTALL=1`` to skip the install attempt.
    """
    if _find_exe_in_path("hcxpcapngtool") or _find_exe_in_path("hcxpcapngtool.exe"):
        log_debug("ensure_hcxtools: hcxpcapngtool already present")
        return True
    if os.environ.get("HANDSHAKE_NO_AUTOINSTALL"):
        return False
    if platform.system() != "Linux":
        return False
    colored_log("info", "Installing hcxtools (optional: improves handshake extraction)...")
    pkg_map = {
        "brew": "hcxtools",
        "apt-get": "hcxtools",
        "dnf": "hcxtools",
        "pacman": "hcxtools",
        "zypper": "hcxtools",
    }
    try:
        if _linux_install(pkg_map, "hcxtools"):
            return bool(_find_exe_in_path("hcxpcapngtool"))
    except Exception as e:
        log_debug(f"ensure_hcxtools: install failed ({e})")
    colored_log("info", "Continuing without hcxtools - the built-in parser handles the capture.")
    return False


def show_banner(quiet: bool = False):
    # Fixed width: a full-width panel on a 200-column terminal is mostly empty
    # box, which reads as noise rather than a header.
    if quiet:
        return
    console.print()
    console.print(
        Panel(
            Text("n3rve", justify="center", style="bold"),
            subtitle="[dim]WPA/WPA2 passphrase recovery[/dim]",
            border_style="cyan",
            width=52,
            padding=(0, 2),
        )
    )


def ensure_directories() -> bool:

    for directory in [RESULTS_DIR, HANDSHAKES_DIR, BIN_DIR, HCOV_DIR]:
        try:
            os.makedirs(directory, exist_ok=True)
        except (OSError, PermissionError):
            if directory == RESULTS_DIR:
                colored_log("error", f"Cannot create results directory: {RESULTS_DIR}")
                return False
            else:
                colored_log("warning", f"Cannot create directory: {directory}")

    try:
        has_cap = any(f.lower().endswith(CAPTURE_EXTENSIONS) for f in os.listdir(HANDSHAKES_DIR))
    except OSError:
        has_cap = False
    if not has_cap:
        colored_log("warning", f"No .cap/.pcap/.pcapng files found in '{HANDSHAKES_DIR}'.")

    return True


def ensure_wordlist() -> bool:
    """Check the bundled default wordlist is present (no network fetch)."""
    wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", WORDLIST_NAME)
    if os.path.exists(wordlist_path):
        return True

    colored_log("warning", f"Default wordlist '{WORDLIST_NAME}' not found in the project root.")
    colored_log("info", "Add your own wordlist there, or choose a custom wordlist (option 2) at the prompt.")
    return False


def ensure_python_dependencies() -> bool:
    """Install required Python packages from requirements.txt if missing."""
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "requirements.txt")
    if not os.path.isfile(req_path):
        colored_log("warning", "requirements.txt not found, skipping Python dependency check.")
        return True

    try:
        import rich  # noqa: F401
        import prompt_toolkit  # noqa: F401
        import scapy  # noqa: F401

        return True
    except ImportError:
        pass

    colored_log("info", "Installing Python dependencies from requirements.txt...")

    if pip_install_requirements(req_path):
        colored_log("success", "Python dependencies installed.")
        return True

    log_error("Failed to install Python dependencies")
    colored_log("error", "Install manually: pip install --user -r requirements.txt")
    colored_log("info", "Or if blocked by PEP 668: pip install --break-system-packages -r requirements.txt")
    return False


def auto_setup(quiet: bool = False) -> dict:
    """Run full auto-setup. Returns dict with availability flags."""
    show_banner(quiet=quiet)

    ensure_python_dependencies()

    aircrack_ok = ensure_aircrack()
    dirs_ok = ensure_directories()
    wordlist_ok = ensure_wordlist()
    hcxtools_ok = ensure_hcxtools()

    # Hashcat setup (preferred over aircrack-ng when available)
    try:
        from src.hashcat import ensure_hashcat

        hashcat_ok = ensure_hashcat()
    except Exception as e:
        log_debug(f"auto_setup: hashcat setup skipped ({e})")
        hashcat_ok = False

    # GPU detection. We ask hashcat for its own device list, since that decides
    # how the run performs. Inside a container the host probes (lspci / WMI)
    # usually see nothing.
    gpu_name: str | None = None
    gpu_is_discrete = False
    if hashcat_ok:
        try:
            from src.gpu import _looks_discrete, detect_gpu
            from src.hashcat import hashcat_gpu_devices

            devices = hashcat_gpu_devices()
            discrete = next((d for d in devices if _looks_discrete(d)), None)
            if discrete:
                gpu_name, gpu_is_discrete = discrete, True
            elif devices:
                gpu_name, gpu_is_discrete = devices[0], False
            else:
                gpu_name, gpu_is_discrete = detect_gpu()
        except Exception as e:
            log_debug(f"auto_setup: GPU detection skipped ({e})")

    if not aircrack_ok and not hashcat_ok:
        colored_log("error", "No cracking tool available (aircrack-ng or hashcat).")
        return {"aircrack_available": False, "hashcat_available": False}

    return {
        "aircrack_available": aircrack_ok,
        "hashcat_available": hashcat_ok,
        "gpu_name": gpu_name,
        "gpu_is_discrete": gpu_is_discrete,
        "directories_ready": dirs_ok,
        "wordlist_ready": wordlist_ok,
        "hcxtools_available": hcxtools_ok,
    }
