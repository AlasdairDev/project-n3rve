# ruff: noqa: E402
import os
import re
import sys
import tempfile
import urllib.request
import zipfile
import ctypes
import platform

from src.console import colored_log, log_error


CAPTURE_EXTENSIONS = (".cap", ".pcap", ".pcapng")

# WPA passphrase length bounds, used when merging/filtering wordlists.
_WPA_MIN, _WPA_MAX = 8, 63


def strip_capture_extension(path: str) -> str:
    base = os.path.basename(path)
    low = base.lower()
    for ext in (".pcapng", ".pcap", ".cap"):  # longest first so ".pcapng" wins over ".cap"
        if low.endswith(ext):
            return base[: -len(ext)]
    return base


def _pid_alive(pid: int) -> bool:
    """Whether a process id is still running, without signalling it."""
    if pid <= 0:
        return False
    if platform.system() == "Windows":
        try:
            PROCESS_QUERY_LIMITED_INFORMATION, STILL_ACTIVE = 0x1000, 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return bool(ok) and code.value == STILL_ACTIVE
        except Exception:
            return False
    try:
        os.kill(pid, 0)  # signal 0 only probes; it does not touch the process
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def acquire_run_lock(lock_path: str) -> int | None:
    """Claim the single-instance lock, or return the PID already holding it.

    Two concurrent runs are worse than useless: they contend for the same GPU,
    write the same potfile, and each one's "kill any lingering hashcat" step
    destroys the other's in-flight stage, which is then recorded as a failure. A
    lock naming the live PID makes that impossible to do by accident, and a stale
    lock (holder no longer running) is simply taken over.
    """
    try:
        if os.path.exists(lock_path):
            with open(lock_path, encoding="utf-8") as f:
                holder = int((f.read().strip() or "0"))
            if holder != os.getpid() and _pid_alive(holder):
                return holder
        os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
        with open(lock_path, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except (OSError, ValueError):
        return None  # never block a run over a broken lock file
    return None


def release_run_lock(lock_path: str) -> None:
    """Drop the lock, but only if this process still owns it."""
    try:
        with open(lock_path, encoding="utf-8") as f:
            if int((f.read().strip() or "0")) != os.getpid():
                return
        os.remove(lock_path)
    except (OSError, ValueError):
        pass


def lower_process_priority(pid: int) -> None:
    system = platform.system()
    if system == "Windows":
        try:
            # 0x1F0FFF = PROCESS_ALL_ACCESS, 0x00004000 = IDLE_PRIORITY_CLASS
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            ctypes.windll.kernel32.SetPriorityClass(handle, 0x00004000)
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass
    else:
        try:
            os.setpriority(os.PRIO_PROCESS, pid, 19)
        except Exception:
            pass


def sanitize_ssid(ssid: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "", ssid).strip().replace(" ", "_")


# Cache: abspath -> (mtime, size, line_count). Keyed on size+mtime so a wordlist
# that changes on disk is recounted, but the common case - the same list scanned
# again - is answered without touching the file.
_line_count_cache: dict[str, tuple[float, int, int]] = {}


def count_wordlist_lines(path: str) -> int:
    """Count lines in a wordlist file efficiently (1 MB buffer chunks).

    A final line with no trailing newline still counts - it is a password
    hashcat will try, and the count feeds the runtime estimates that decide
    whether a stage fits in the time budget.

    The result is memoised per (path, size, mtime): the deep pass rebuilds the
    attack plan once per unsolved network, and without a cache each rebuild
    re-scanned the whole ~93 MB main list (plus rockyou at ~130 MB when present)
    - hundreds of megabytes of pointless I/O per network.
    """
    try:
        st = os.stat(path)
    except OSError:
        return 0
    key = os.path.abspath(path)
    cached = _line_count_cache.get(key)
    if cached is not None and cached[0] == st.st_mtime and cached[1] == st.st_size:
        return cached[2]
    try:
        total = 0
        last = b""
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                total += chunk.count(b"\n")
                last = chunk[-1:]
        if last and last != b"\n":
            total += 1
    except OSError:
        return 0
    _line_count_cache[key] = (st.st_mtime, st.st_size, total)
    return total


def scan_default_directory(directory_path: str) -> list[str]:
    found_files = []
    if not os.path.exists(directory_path):
        colored_log("error", f"Default directory {directory_path} not found.")
        return []

    colored_log("info", f"Scanning {directory_path}/ for .cap/.pcap/.pcapng files...")
    # NOTE: Only scans the DIRECT directory, NOT sub-folders.
    # Handshake files in sub-folders are intentionally ignored.
    try:
        for entry in os.scandir(directory_path):
            if entry.is_file() and entry.name.lower().endswith(CAPTURE_EXTENSIONS):
                found_files.append(entry.path)
    except OSError as e:
        log_error(f"Failed to scan {directory_path}", e)
    return found_files


import hashlib


def download_with_progress(url: str, dest: str, label: str = "Downloading", expected_sha256: str | None = None) -> bool:
    try:

        def report(block_count, block_size, total_size):
            downloaded = block_count * block_size / (1024 * 1024)
            total = total_size / (1024 * 1024)
            sys.stdout.write(f"\r{label}: {downloaded:.1f}MB / {total:.1f}MB")
            sys.stdout.flush()

        urllib.request.urlretrieve(url, dest, report)
        sys.stdout.write("\n")

        if expected_sha256:
            sys.stdout.write(f"Verifying checksum for {label}...\n")
            hasher = hashlib.sha256()
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            actual_sha256 = hasher.hexdigest().upper()
            if actual_sha256 != expected_sha256.upper():
                colored_log(
                    "error",
                    f"Checksum verification failed for {label}! Expected {expected_sha256}, got {actual_sha256}.",
                )
                os.unlink(dest)
                return False
            colored_log("success", "Checksum verified successfully.")

        return True
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        colored_log("warning", f"{label} interrupted by user.")
        return False
    except Exception as e:
        log_error(f"Failed to download {url}", e)
        return False


def extract_local_zip(zip_path: str, extract_to: str, subdir: str | None = None) -> bool:
    try:
        colored_log("info", f"Extracting {os.path.basename(zip_path)}...")
        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                if subdir and not member.startswith(subdir):
                    continue
                rel_path = member[len(subdir) :].lstrip("/") if subdir else member
                if not rel_path:
                    continue
                target = os.path.join(extract_to, rel_path)
                if member.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())

        colored_log("success", f"Extracted '{os.path.basename(zip_path)}'.")
        return True
    except KeyboardInterrupt:
        colored_log("warning", "Extraction interrupted by user.")
        return False
    except Exception as e:
        log_error(f"Failed to extract {zip_path}", e)
        return False


def download_and_extract_zip(
    url: str, extract_to: str, subdir: str | None = None, expected_sha256: str | None = None
) -> bool:
    tmp_path = None
    try:
        colored_log("info", "Downloading aircrack-ng for Windows...")
        colored_log("info", "The aircrack-ng server can be slow; this may take a few minutes.")
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name

        if not download_with_progress(url, tmp_path, "Downloading aircrack-ng", expected_sha256):
            return False

        colored_log("info", "Extracting...")
        return extract_local_zip(tmp_path, extract_to, subdir)

    except Exception as e:
        log_error("Failed to download/extract aircrack-ng", e)
        colored_log("error", "Failed to set up aircrack-ng. Check your internet connection.")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# Recovered UI Functions

import time
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.completion import PathCompleter
from src.console import console


class PcapValidator(Validator):
    def validate(self, document):
        text = document.text
        if text.lower() in ("q", "done"):
            return
        if not os.path.exists(text):
            raise ValidationError(message=f"File not found: {text}", cursor_position=len(text))
        if not text.lower().endswith(CAPTURE_EXTENSIONS):
            raise ValidationError(
                message=f"Not a .cap/.pcap/.pcapng file: {text}",
                cursor_position=len(text),
            )


class WordlistValidator(Validator):
    def validate(self, document):
        text = document.text.strip().strip("\"'")
        if not text:
            raise ValidationError(message="Path cannot be empty.", cursor_position=0)
        if not os.path.isfile(text):
            raise ValidationError(message=f"File not found: {text}", cursor_position=len(text))


def choose_wordlist(session: PromptSession, default_path: str) -> str:
    """Prompt user to pick default or custom wordlist. Returns chosen path."""
    console.print("\n[bold cyan]Wordlist Selection[/bold cyan]")
    console.print(f"  1. Use default wordlist ({os.path.basename(default_path)})")
    console.print("  2. Use custom wordlist file")

    while True:
        try:
            choice = input("  Choose [1/2] (default: 1): ").strip()
        except EOFError:
            # Non-interactive run (piped/cron): take the default rather than dying.
            choice = ""
        if choice in ("", "1", "2"):
            break
        colored_log("error", "Invalid choice. Enter 1 for default or 2 for custom.")

    if choice == "2":
        console.print("  Example: C:\\Users\\You\\wordlist.txt  or  /home/user/wordlist.txt")
        console.print("  Press TAB for auto-completion.")
        while True:
            try:
                raw_path = session.prompt(
                    "  Custom wordlist path: ",
                    completer=PathCompleter(only_directories=False, expanduser=True),
                    validator=WordlistValidator(),
                    validate_while_typing=True,
                ).strip()
                custom_path = raw_path.strip("\"'")
                break
            except ValidationError as e:
                colored_log("error", str(e))
            except (EOFError, KeyboardInterrupt):
                colored_log("warning", "Falling back to default wordlist.")
                return default_path

        lines = count_wordlist_lines(custom_path)
        if lines:
            colored_log("info", f"Custom wordlist loaded: {lines:,} passwords.".replace(",", "."))

        return custom_path

    # Default: count lines if available
    lines = count_wordlist_lines(default_path)
    if lines:
        colored_log("info", f"{lines:,} passwords loaded.".replace(",", "."))

    return default_path


def get_manual_handshake_paths(session: PromptSession) -> list[str]:
    manual_queue = []
    console.print("\nPlease enter handshake file paths (.cap/.pcap) one by one.")
    console.print("(Type 'done' or 'q' to finish adding files. Use TAB for auto-completion.)")

    while True:
        try:
            current_input_path = session.prompt(
                f"Handshake {len(manual_queue) + 1} Path: ",
                completer=PathCompleter(only_directories=False, expanduser=True),
                validator=PcapValidator(),
                validate_while_typing=True,
            ).strip()

            if current_input_path.lower() in ("done", "q"):
                break

            manual_queue.append(current_input_path)
            colored_log(
                "info",
                f"Added: {os.path.basename(current_input_path)} to queue.",
            )

        except ValidationError as e:
            colored_log("error", str(e))
        except EOFError:
            colored_log("info", "Exiting program.")
            sys.exit(0)
        except Exception as e:
            log_error("Error during manual handshake file input.", e)
            colored_log(
                "error",
                "An error occurred during file path input. Please try again or restart.",
            )
            time.sleep(1)


def merge_wordlists(output_path: str, *input_paths: str) -> int:
    """Merge multiple wordlist files into one deduplicated, WPA-valid output file.

    Lines are stripped, blank lines dropped, duplicates removed (first occurrence
    wins), and only 8-63 character entries are kept. Returns the number of unique
    passwords written.
    """
    seen: set[str] = set()
    total = 0
    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", errors="replace") as out:
        for path in input_paths:
            if not path or not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        pw = line.strip()
                        if not pw or pw in seen:
                            continue
                        if not (_WPA_MIN <= len(pw) <= _WPA_MAX):
                            continue
                        seen.add(pw)
                        out.write(pw + "\n")
                        total += 1
            except OSError:
                continue
    return total


def _wordlist_priority_score(pw: str) -> int:
    """Score a wordlist entry for cracking priority. Higher = tried first.

    PH ISP passwords tend to follow predictable patterns. We score entries so
    that high-probability candidates (PH ISP names, mobile prefixes, short
    numeric sequences, common years) are tried before long random strings.
    """
    score = 0
    low = pw.lower()

    # PH ISP / brand names are high-value
    ph_brands = (
        "converge", "pldt", "globe", "smart", "dito", "sky", "homebro",
        "mybro", "sagemcom", "fiberhome", "zte", "huawei", "tplink",
        "bayantel", "eastern", "streamtech", "radius", "cablelink",
        "parasat", "comclark", "infinivan", "starlink", "pisowifi",
    )
    for brand in ph_brands:
        if brand in low:
            score += 1000

    # Short numeric / year sequences are common in PH
    if pw.isdigit():
        if len(pw) <= 8:
            score += 500
        if pw in ("12345678", "123456789", "00000000", "11111111", "88888888"):
            score += 200
        # Years are very common
        if pw in ("2020", "2021", "2022", "2023", "2024", "2025", "2026"):
            score += 300

    # PH mobile prefixes
    if low.startswith(("0917", "0918", "0919", "0920", "0921")):
        score += 400

    # Filipino terms
    filipino_terms = ("pinoy", "pilipinas", "mahalkita", "mabuhay", "ganda",
                      "gwapo", "pogi", "sarap", "ibigka", "alamo")
    for term in filipino_terms:
        if term in low:
            score += 300

    # Shorter words tried first (faster to compute PBKDF2)
    score += max(0, 70 - len(pw)) * 5

    return score


def preprocess_wordlist(input_path: str, output_path: str | None = None) -> int:
    """Preprocess a wordlist: dedupe, filter WPA-valid, sort by cracking priority.

    Entries are sorted by _wordlist_priority_score so high-probability PH
    passwords are tried first. Returns the number of entries written.
    If output_path is None, overwrites input_path in place (via temp file).
    """
    if output_path is None:
        output_path = input_path + ".sorted"

    entries: list[tuple[int, str]] = []
    seen: set[str] = set()

    try:
        with open(input_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                pw = line.strip()
                if not pw or pw in seen:
                    continue
                if not (_WPA_MIN <= len(pw) <= _WPA_MAX):
                    continue
                seen.add(pw)
                entries.append((_wordlist_priority_score(pw), pw))
    except OSError as e:
        log_error(f"Failed to read wordlist {input_path}", e)
        return 0

    # Sort by score descending (highest priority first), then alphabetically
    # for stable ordering within the same score.
    entries.sort(key=lambda x: (-x[0], x[1]))

    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8", errors="replace") as out:
            for _, pw in entries:
                out.write(pw + "\n")
    except OSError as e:
        log_error(f"Failed to write wordlist {output_path}", e)
        return 0

    return len(entries)
