import os
import tempfile

# Application version, surfaced by `--version`. Keep in sync with pyproject.toml.
__version__ = "1.0.0"


def _find_writable_dir(preferred: str) -> str:
    if os.path.isabs(preferred):
        base = preferred
    else:
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), preferred)

    parent = os.path.dirname(base) or "."
    if os.access(parent, os.W_OK):
        return base

    return os.path.join(tempfile.gettempdir(), "n3rve", preferred.lstrip("./\\"))


AIRCRACK_WIN_URL = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
# Anchored to the project directory, not the process's cwd: the program often
# gets launched from elsewhere (`python3 /work/main.py`, a container entrypoint,
# a desktop shortcut), and a relative path would just scan an empty directory and
# report "no handshakes found".
HANDSHAKES_DIR = _find_writable_dir("handshakes")
RESULTS_DIR = _find_writable_dir("cracked_results")
WORDLIST_NAME = "wifi-wordlist.txt"
BIN_DIR = _find_writable_dir("bin")

# Version used only to locate a manually-placed binary at bin/hashcat-<version>/.
# hashcat itself is installed via the OS package manager (see src/hashcat/setup.py).
HASHCAT_VERSION = "7.1.2"
HCOV_DIR = _find_writable_dir("hc22000_cache")

DEPS_DIR = "dependencies"
AIRCRACK_ZIP_NAME = "aircrack-ng-1.7-win.zip"

# Optional PH-focused wordlist (real captured Philippine default passwords). Fetched
# once on first run (small, ~370 KB), then used as a high-priority dictionary stage.
PH_WORDLIST_NAME = "wifi-wordlist-ph.txt"
PH_WORDLIST_URL = "https://raw.githubusercontent.com/unrealistic-reality/wifi-wordlists/main/ph-wordlist.txt"
PH_WORDLIST_SHA256 = "284690B67BE8DA1F36BFA5EBD44B3BA32A4A16B5ADFFF54BA2D5CD1B0120C8C8"

AIRCRACK_WIN_SHA256 = "767A456BF0675032D37D3C8CAF05E2E5DCB105C218614B2E4E42B51370D05205"
