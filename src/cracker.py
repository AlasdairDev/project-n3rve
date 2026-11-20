import os
import re
import sys
import time
import math
import atexit
import tempfile
import threading
import subprocess

from src.console import console, log_error
from src.config import RESULTS_DIR
from src.utils import sanitize_ssid, strip_capture_extension, lower_process_priority
from src.backend import CrackerBackend


def get_already_cracked_essids() -> set[str]:
    cracked_essids = set()
    if not os.path.exists(RESULTS_DIR):
        return cracked_essids

    try:
        for filename in os.listdir(RESULTS_DIR):
            if filename.endswith("_cracked_password.txt"):
                essid_part = filename.replace("_cracked_password.txt", "")
                cracked_essids.add(essid_part)
    except Exception as e:
        log_error(f"Error scanning results directory {RESULTS_DIR} for cracked ESSIDs.", e)

    return cracked_essids


def get_known_passwords() -> dict[str, str]:
    """Network name -> passphrase recovered by an earlier run.

    A network cracked previously is skipped this time, which meant it dropped out
    of the count entirely: a run could report "0 of 9 recovered" for an estate
    where two passphrases were already in hand. The standing total is what the
    engagement is actually about.
    """
    known: dict[str, str] = {}
    if not os.path.exists(RESULTS_DIR):
        return known
    try:
        for filename in os.listdir(RESULTS_DIR):
            if not filename.endswith("_cracked_password.txt"):
                continue
            name = filename.replace("_cracked_password.txt", "")
            try:
                with open(os.path.join(RESULTS_DIR, filename), encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("Password Found:"):
                            known[name] = line.split(":", 1)[1].strip()
                            break
            except OSError:
                continue
    except Exception as e:
        log_error(f"Error reading recovered passwords from {RESULTS_DIR}.", e)
    return known


_SPINNER = ["-", "\\", "|", "/"]
_active_procs: list[subprocess.Popen] = []
_active_procs_lock = threading.Lock()
_cached_chunks: dict[str, list[str]] = {}
# Bound concurrent aircrack-ng processes so a large wordlist split into many
# chunks doesn't launch dozens of CPU-bound processes at once.
_PROC_SEMAPHORE = threading.Semaphore(os.cpu_count() or 2)


def _terminate_all():
    with _active_procs_lock:
        for proc in _active_procs[:]:
            try:
                if proc.poll() is None:
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            except Exception:
                pass
        _active_procs.clear()


def _cleanup_chunks():
    for paths in _cached_chunks.values():
        if not paths:
            continue
        chunk_dir = os.path.dirname(paths[0])
        for p in paths:
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(chunk_dir)
        except OSError:
            pass
    _cached_chunks.clear()


atexit.register(_terminate_all)
atexit.register(_cleanup_chunks)


def _write_status(spin_char: str, msg: str):
    sys.stdout.write(f"\r  {spin_char} {msg}".ljust(110) + "\r")
    sys.stdout.flush()


def _clear_status():
    sys.stdout.write("\r" + " " * 110 + "\r")
    sys.stdout.flush()


def _crack_worker(
    chunk_path: str,
    handshake_path: str,
    results: list,
    launch_errors: list | None = None,
    bssid: str = "",
):
    # -b pins the target AP. Without it, aircrack-ng stops and prompts for an
    # index when a capture holds more than one network, which would hang the run.
    cmd = ["aircrack-ng", "-w", chunk_path]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(handshake_path)
    try:
        with _PROC_SEMAPHORE:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
    except OSError as e:
        if launch_errors is not None:
            launch_errors.append(e)
        if getattr(e, "winerror", None) == 225:
            _clear_status()
            console.print(
                "  Windows Defender blocked aircrack-ng.exe. Add an exclusion in Windows Security, then re-run."
            )
        else:
            _clear_status()
            console.print(f"  Failed to launch aircrack-ng: {e}")
        return
    with _active_procs_lock:
        _active_procs.append(proc)

    lower_process_priority(proc.pid)

    try:
        stdout, _ = proc.communicate()
        if "KEY FOUND!" in stdout:
            results.append(stdout)
    finally:
        with _active_procs_lock:
            if proc in _active_procs:
                _active_procs.remove(proc)


class AircrackBackend(CrackerBackend):
    def __init__(self, candidate_keys: dict | None = None, networks_map: dict | None = None):
        # (handshake_path, essid) -> [computed default keys]. Tried first, before
        # the full wordlist, so a factory-default router is cracked almost
        # instantly even in the CPU fallback path. A bare handshake_path key is
        # accepted too, for callers that don't know the networks.
        self.candidate_keys = candidate_keys or {}
        # handshake_path -> [(essid, bssid)] for every network in that capture.
        self.networks_map = networks_map or {}

    def _keys_for(self, handshake_path: str, essid: str) -> list:
        return self.candidate_keys.get((handshake_path, essid)) or self.candidate_keys.get(handshake_path) or []

    def crack(self, handshake_path: str, wordlist_path: str, display_essid: str) -> dict[str, str] | None:
        """Crack every network in one capture on CPU.

        aircrack-ng handles a single AP per run, so each network in the capture
        gets its own pass, pinned with -b. Returns {essid: password} for what was
        recovered, {} when nothing was, or None when aircrack-ng could not run.
        """
        targets = self.networks_map.get(handshake_path) or [(display_essid, "")]
        results: dict[str, str] = {}
        backend_failed = False
        for essid, bssid in targets:
            if len(targets) > 1:
                console.print(f"  Network: {essid}")
            outcome = self._crack_one(handshake_path, wordlist_path, essid, bssid)
            if outcome is None:
                backend_failed = True
                break
            results.update(outcome)
        if backend_failed and not results:
            return None
        return results

    def _write_candidate_chunk(self, handshake_path: str, chunk_dir: str, essid: str = "") -> str | None:
        keys = self._keys_for(handshake_path, essid)
        if not keys:
            return None
        cp = os.path.join(chunk_dir, "chunk_defaults.txt")
        try:
            with open(cp, "w", encoding="utf-8") as f:
                f.write("\n".join(keys) + "\n")
        except OSError as e:
            log_error(f"AircrackBackend: failed to write candidate chunk ({e}).")
            return None
        return cp

    def _crack_one(
        self, handshake_path: str, wordlist_path: str, display_essid: str, bssid: str = ""
    ) -> dict[str, str] | None:
        chunk_paths: list[str] = []
        launch_errors: list = []
        try:
            messages = [
                f"Cracking {display_essid}... Initializing packet analyzer...",
                f"Cracking {display_essid}... Extracting handshake from capture...",
                f"Cracking {display_essid}... Loading wordlist into memory...",
                f"Cracking {display_essid}... Brute-forcing PMK computation...",
                f"Cracking {display_essid}... Testing key combinations...",
                f"Cracking {display_essid}... Almost there, checking matches...",
            ]
            msg_idx = 0
            spin_idx = 0
            iter_count = 0
            start_time = time.time()
            last_switch = start_time

            _write_status(_SPINNER[spin_idx % 4], messages[msg_idx])
            spin_idx += 1

            wl_size = os.path.getsize(wordlist_path)
            found_results: list[str] = []

            if wordlist_path not in _cached_chunks:
                n = max(1, (os.cpu_count() or 2) // 2)
                chunk_dir = tempfile.mkdtemp(prefix="hs_crack_")
                paths = []

                chunk_size_bytes = math.ceil(wl_size / n)

                with open(wordlist_path, "rb") as f:
                    for i in range(n):
                        cp = os.path.join(chunk_dir, f"chunk_{i}.txt")
                        with open(cp, "wb") as cf:
                            bytes_read = 0
                            while bytes_read < chunk_size_bytes:
                                chunk = f.read(min(1024 * 1024, chunk_size_bytes - bytes_read))
                                if not chunk:
                                    break
                                bytes_read += len(chunk)
                                cf.write(chunk)

                            # Read until the next newline so we don't break passwords
                            if bytes_read > 0 and chunk and not chunk.endswith(b"\n"):
                                remainder = f.readline()
                                cf.write(remainder)
                        paths.append(cp)
                _cached_chunks[wordlist_path] = paths

            chunk_paths = _cached_chunks[wordlist_path]

            # Computed ISP/PH default keys go first: a tiny chunk that finishes in
            # milliseconds and cracks factory-default routers immediately.
            candidate_chunk = None
            if self._keys_for(handshake_path, display_essid):
                candidate_chunk = self._write_candidate_chunk(
                    handshake_path, os.path.dirname(chunk_paths[0]), display_essid
                )

            threads = []

            if candidate_chunk:
                t = threading.Thread(
                    target=_crack_worker,
                    args=(candidate_chunk, handshake_path, found_results, launch_errors, bssid),
                    daemon=True,
                )
                t.start()
                threads.append(t)
                console.print("  Trying computed ISP default keys first...")

            for i, cp in enumerate(chunk_paths):
                t = threading.Thread(
                    target=_crack_worker,
                    args=(cp, handshake_path, found_results, launch_errors, bssid),
                    daemon=True,
                )
                t.start()
                threads.append(t)

            while len(found_results) == 0 and any(t.is_alive() for t in threads):
                iter_count += 1
                if iter_count % 6 == 0:
                    _write_status(_SPINNER[spin_idx % 4], messages[msg_idx])
                    spin_idx += 1
                now = time.time()
                if now - last_switch >= 6:
                    msg_idx = (msg_idx + 1) % len(messages)
                    last_switch = now
                time.sleep(0.1)

            _clear_status()

            # If we return early or finish, make sure to join threads
            for t in threads:
                if t.is_alive():
                    t.join(timeout=2)

            if launch_errors and not found_results:
                # aircrack-ng never started, so that's a backend failure, not a miss.
                return None

            if not found_results:
                console.print("  Password not found in wordlist. Try a larger wordlist.")
                return {}

            result_stdout = found_results[0]
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result_stdout)
            if not match:
                console.print("  Password not found in wordlist. Try a larger wordlist.")
                return {}

            password = match.group(1)
            elapsed = time.time() - start_time
            m, s = divmod(int(elapsed), 60)
            time_str = f"{m:02d}:{s:02d}"

            final_essid = display_essid
            if not final_essid or final_essid == "<hidden>":
                essid_match = re.search(r"SSID:\s*(.*)", result_stdout)
                if essid_match and essid_match.group(1).strip() not in ("", "<hidden>"):
                    final_essid = essid_match.group(1).strip()
                else:
                    final_essid = strip_capture_extension(handshake_path)

            _clear_status()
            console.print(f"  Password: {password}")
            console.print(f"  Time: {time_str}")

            os.makedirs(RESULTS_DIR, exist_ok=True)
            safe_essid = sanitize_ssid(final_essid)
            result_file = os.path.join(RESULTS_DIR, f"{safe_essid}_cracked_password.txt")
            with open(result_file, "w") as f:
                f.write(f"Network (ESSID): {final_essid}\n")
                f.write(f"Handshake File: {os.path.basename(handshake_path)}\n")
                f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
                f.write(f"Password Found: {password}\n")
                f.write(f"Time Taken: {time_str}\n")

            if sys.platform != "win32":
                try:
                    os.chmod(result_file, 0o600)
                except OSError:
                    pass

            console.print(f"  Saved to: {result_file}")
            return {final_essid: password}

        except Exception as e:
            log_error(f"Critical error during cracking process for {handshake_path}", e)
            console.print("  Cracking terminated due to an unexpected error.")
            return None
