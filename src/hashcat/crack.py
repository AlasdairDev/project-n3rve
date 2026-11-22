from .setup import get_hashcat_path, warmup_hashcat_kernel
from .convert import convert_capture
import os
import sys
import time
import platform
import subprocess
import threading
import re
from src.console import console, colored_log, log_error, log_debug
from src.config import HCOV_DIR, RESULTS_DIR, PH_WORDLIST_NAME, PH_WORDLIST_URL, PH_WORDLIST_SHA256
from src.utils import sanitize_ssid, strip_capture_extension, lower_process_priority, count_wordlist_lines, download_with_progress, merge_wordlists
from src.keygen import (
    global_default_candidates,
    heuristic_candidates,
    looks_like_pldt,
    passphrase_suffix_variants,
    ph_common_candidates,
    brand_mac_variants,
)
from rich import box
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import ProgressBar
from rich.align import Align
from rich.live import Live

_SYSTEM = platform.system()

_SPEED_RE = re.compile(r"Speed\.#[0-9*]+[.\s]*:\s+([\d.]+)\s*([kMGT]?)H/s")
_PROGRESS_RE = re.compile(r"Progress\.+:\s*(\d+)/(\d+)\s*\(([\d.]+)%\)")
_SPEED_MULT = {"": 1, "k": 1_000, "M": 1_000_000, "G": 1_000_000_000, "T": 1_000_000_000_000}
_HEX_SUFFIX_RE = re.compile(r"[0-9a-fA-F]{6,}$")

# Brute-force masks for common default-router PSK shapes, cheapest first.
# Each entry is (label, mask, extra_hashcat_args, keyspace).
# Anything whose estimate blows past the per-stage budget (HANDSHAKE_MAX_STAGE_MIN)
# gets skipped, so the big masks only run on a GPU quick enough to finish them.
# A slow iGPU just skips what a fast card would sweep.
_DEFAULT_MASKS = [
    ("8 digits", "?d?d?d?d?d?d?d?d", [], 10**8),
    ("9 digits", "?d?d?d?d?d?d?d?d?d", [], 10**9),
    ("11-digit PH mobile (09…)", "09?d?d?d?d?d?d?d?d?d", [], 10**9),
    ("8 hex (uppercase)", "?1?1?1?1?1?1?1?1", ["-1", "0123456789ABCDEF"], 16**8),
    ("10 digits", "?d?d?d?d?d?d?d?d?d?d", [], 10**10),
    ("PH landline (area+7-8 digits)", "?d?d?d?d?d?d?d?d?d?d", [], 10**10),
]

# Default per-stage time budget, in minutes. Optional stages get skipped when
# their estimated runtime (at the measured speed) goes over this. Override with
# the HANDSHAKE_MAX_STAGE_MIN env var.
#
# Why 120 and not 60: all networks in the queue crack in one shared pass now, so
# a stage costs the same whether it's one capture or the whole batch. At 60 we
# always skipped "dictionary + rules" (~85 min for 8.5M words x ~25 rules), which
# is the stage most likely to land a human-chosen password. 120 lets it run and
# still leaves out the hopeless sweeps (9-digit ~5.5h, 8-hex ~24h, 10-digit ~55h).
_DEFAULT_STAGE_BUDGET_MIN = 120


# Only sample GPU speed from stages with at least this many candidates. A stage
# that's over in a fraction of a second (the computed-key lists, a small
# wordlist) never hits steady state, and hashcat's reported rate for it can be
# off by 1000x. Trusting that number would make the budget gate skip stages that
# really only take seconds.
_SPEED_SAMPLE_MIN_KEYSPACE = 1_000_000


PROGRESS_FILE = ".progress"


def _progress_path() -> str:
    return os.path.join(HCOV_DIR, PROGRESS_FILE)


def write_progress(**fields) -> None:
    """Record what the run is doing, for anyone who cannot see its terminal.

    A long run is normally watched through a terminal pane, and when that pane
    stops repainting - or the run was started detached - there is no way to tell
    a working stage from a hung one. A file on disk answers it from anywhere.
    """
    try:
        os.makedirs(HCOV_DIR, exist_ok=True)
        fields.setdefault("pid", os.getpid())
        fields.setdefault("updated", time.strftime("%Y-%m-%d %H:%M:%S"))
        with open(_progress_path(), "w", encoding="utf-8") as f:
            for key, value in fields.items():
                f.write(f"{key}={value}\n")
    except OSError as e:
        log_debug(f"write_progress: {e}")


def read_progress() -> dict:
    """The last recorded progress, or {} when there is none."""
    try:
        with open(_progress_path(), encoding="utf-8") as f:
            return dict(
                line.rstrip("\n").split("=", 1) for line in f if "=" in line
            )
    except OSError:
        return {}


# The stages a run actually searched, and the ones it skipped and why. Populated
# by crack_with_hashcat on every call and accumulated across them (the shared
# batch pass plus any per-network deep pass), so the engagement report can show
# "effort expended" - the part that turns a negative result into a finding
# ("searched these candidate sets, found nothing") rather than just "no hit".
# In-process only, mirroring write_progress/read_progress but without the file.
_RUN_EFFORT: dict[str, list] = {"searched": [], "skipped": []}


def reset_effort() -> None:
    """Clear the accumulated effort record. Call once before a run's cracking."""
    _RUN_EFFORT["searched"] = []
    _RUN_EFFORT["skipped"] = []


def record_effort(searched: list[str], skipped: list[tuple[str, str]]) -> None:
    """Merge one crack_with_hashcat call's stage outcomes into the run record.

    Deduped by label: a stage can run in the shared pass and again per network in
    the deep pass, but to the reader it is one candidate set that was searched.
    A label that was searched anywhere wins over a skip recorded for it elsewhere.
    """
    for label in searched:
        if label not in _RUN_EFFORT["searched"]:
            _RUN_EFFORT["searched"].append(label)
    for label, reason in skipped:
        already = {lbl for lbl, _ in _RUN_EFFORT["skipped"]}
        if label not in already:
            _RUN_EFFORT["skipped"].append((label, reason))
    # A stage searched on one network is no longer "not searched" overall.
    _RUN_EFFORT["skipped"] = [
        (lbl, reason) for lbl, reason in _RUN_EFFORT["skipped"] if lbl not in _RUN_EFFORT["searched"]
    ]


def last_effort() -> dict[str, list]:
    """A copy of the accumulated effort record for report building."""
    return {
        "searched": list(_RUN_EFFORT["searched"]),
        "skipped": list(_RUN_EFFORT["skipped"]),
    }


def _salt_count(networks: list[tuple[str, str]]) -> int:
    """Distinct PBKDF2 salts in the hash file.

    A WPA PMK is PBKDF2(passphrase, ESSID), so every distinct SSID is a separate
    salt and each candidate is derived once per salt. hashcat's Progress counter
    reflects this (candidates x salts). An estimate that ignores it is off by the
    number of networks loaded, so the per-stage budget would be wrong in batch
    mode.
    """
    return max(1, len({essid for essid, _bssid in networks if essid}))


def _update_speed_estimate(current: int | None, speeds: list[int], keyspace: int | None) -> int | None:
    """Fold one stage's measurements into the throughput estimate.

    Takes the best rate seen across qualifying stages rather than the latest:
    under-reporting is systematic (ramp-up, I/O-bound starts, short runs) while
    over-reporting is not. The estimate stays approximate - mask attacks run
    faster than dictionary attacks on the same GPU - but it is only ever used to
    decide whether a stage fits in the time budget.
    """
    if not speeds or not keyspace or keyspace < _SPEED_SAMPLE_MIN_KEYSPACE:
        return current
    stage_median = sorted(speeds)[len(speeds) // 2]
    if stage_median <= 0:
        return current
    return max(current or 0, stage_median)


def _stage_budget_seconds() -> int:
    raw = os.environ.get("HANDSHAKE_MAX_STAGE_MIN")
    if raw:
        try:
            return max(1, int(float(raw))) * 60
        except ValueError:
            log_debug(f"_stage_budget_seconds: invalid HANDSHAKE_MAX_STAGE_MIN={raw!r}, using default")
    return _DEFAULT_STAGE_BUDGET_MIN * 60


def _count_rules(path: str) -> int:
    """Count active (non-comment, non-blank) rules in a hashcat rule file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip() and not line.startswith("#"))
    except OSError:
        return 0


def _parse_hashcat_progress(line: str) -> float | None:
    """Percent complete from a hashcat 'Progress....: X/Y (Z%)' status line."""
    m = _PROGRESS_RE.search(line)
    if not m:
        return None
    try:
        return float(m.group(3))
    except ValueError:
        return None


def _parse_hashcat_speed(line: str) -> int | None:
    """Parse a hashcat 'Speed.#N...: <value> [kMGT]H/s' line into H/s."""
    m = _SPEED_RE.search(line)
    if not m:
        return None
    try:
        return int(float(m.group(1)) * _SPEED_MULT[m.group(2)])
    except (ValueError, KeyError):
        return None


def _fmt_speed(spd: int) -> str:
    """Throughput with a unit, e.g. '41.3 kH/s'.

    The previous form printed 41265 as '41.265', which reads as forty-one on any
    locale that uses '.' as the decimal point - a number the user has to act on
    should not be ambiguous by three orders of magnitude.
    """
    if spd >= 1_000_000_000:
        return f"{spd / 1_000_000_000:.1f} GH/s"
    if spd >= 1_000_000:
        return f"{spd / 1_000_000:.1f} MH/s"
    if spd >= 1_000:
        return f"{spd / 1_000:.1f} kH/s"
    return f"{spd} H/s"


def _fmt_duration(elapsed: float) -> str:
    """Compact, uniform duration: '3d 4h', '2h 55m', '44m 59s', '9s'.

    One format everywhere: the old code mixed 'MM:SS' with '2 Hours, 54 Minutes,
    59 Seconds' in the same report, which made two stage estimates impossible to
    compare at a glance.
    """
    total = max(0, int(elapsed))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


_HEX_PLAIN_RE = re.compile(r"^\$HEX\[([0-9a-fA-F]*)\]$")


def _decode_plain(password: str) -> str:
    """Decode hashcat's ``$HEX[..]`` form, used for passwords it can't write raw.

    hashcat hex-encodes a recovered password whose plaintext would confuse the
    potfile format - one containing a colon, or leading/trailing whitespace.
    Reporting the literal ``$HEX[...]`` string back would hand over something that
    is not the Wi-Fi key.
    """
    m = _HEX_PLAIN_RE.match(password)
    if not m:
        return password
    try:
        return bytes.fromhex(m.group(1)).decode("utf-8", "replace")
    except ValueError:
        return password


def _potfile_results(lines) -> dict[str, str]:
    """Map ESSID -> password from hashcat potfile lines.

    A mode-22000 potfile line reads ``<hash>*<essid-hex>:<password>``, so a
    capture holding several networks can be attributed back to the right SSID
    instead of guessing from the file name. The hash half never contains a colon,
    so the *first* colon is the separator - splitting on the last one would
    truncate any password that contains one.
    """
    out: dict[str, str] = {}
    for pot_line in lines:
        if not pot_line or pot_line.startswith("#") or ":" not in pot_line:
            continue
        hash_part, _, password = pot_line.partition(":")
        password = _decode_plain(password.strip())
        if not (8 <= len(password) <= 63):
            continue
        essid_hex = hash_part.rsplit("*", 1)[-1] if "*" in hash_part else ""
        try:
            essid = bytes.fromhex(essid_hex).decode("utf-8", "replace") if essid_hex else ""
        except ValueError:
            essid = ""
        out.setdefault(essid, password)
    return out


def _read_potfile(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return set(f.read().splitlines())
    except Exception:
        return set()


def _log_hashcat_output(heading: str, lines: list[str]):
    log_debug(f"=== {heading} ===")
    for line in lines:
        if line.strip():
            log_debug(f"  {line}")


def _parse_hc22000_line(line: str) -> tuple[str, str]:
    """(essid, bssid_hex) from one hc22000 line: WPA*TYPE*..*AP*STA*ESSIDHEX*.."""
    parts = line.split("*")
    if len(parts) >= 6:
        bssid = parts[3]
        try:
            essid = bytes.fromhex(parts[5]).decode("utf-8", "replace")
        except ValueError:
            essid = ""
        return essid, bssid
    return "", ""


def _parse_hc22000_meta(content: str) -> tuple[str, str]:
    """Pull (essid, bssid_hex) from the first hc22000 line."""
    return _parse_hc22000_line(content.splitlines()[0] if content else "")


def _parse_hc22000_networks(content: str) -> list[tuple[str, str]]:
    """Every distinct (essid, bssid_hex) in a hash file, in file order.

    A capture can hold several APs, and each needs its *own* computed factory keys
    - deriving them from the first line only would leave every other network in
    the file with nothing but the generic dictionary.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (content or "").splitlines():
        if not line.strip():
            continue
        meta = _parse_hc22000_line(line)
        if meta != ("", "") and meta not in seen:
            seen.add(meta)
            out.append(meta)
    return out


def _vendor_stages(content: str) -> tuple[list[dict], list[str]]:
    """Build near-instant 'try the likely keys first' stages from hash metadata.

    Returns (stages, temp_paths). Mode-0 stages over tiny generated wordlists:
    computed factory keys (high confidence, worldwide), the same keys with a
    digit/year suffix, then human-pattern guesses across any ISP. Candidates are
    pooled over *every* network in the hash file, so one pass covers them all.
    temp_paths are removed by the caller after cracking.
    """
    networks = _parse_hc22000_networks(content)
    stages: list[dict] = []
    temp_paths: list[str] = []
    os.makedirs(HCOV_DIR, exist_ok=True)

    def _pool(fn) -> list[str]:
        seen: set[str] = set()
        pooled: list[str] = []
        for essid, bssid in networks:
            for cand in fn(essid, bssid):
                if cand not in seen:
                    seen.add(cand)
                    pooled.append(cand)
        return pooled

    def _emit(label: str, candidates: list[str], filename: str):
        if not candidates:
            return
        path = os.path.join(HCOV_DIR, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(candidates) + "\n")
        except OSError as e:
            log_debug(f"_vendor_stages: failed to write {filename} ({e})")
            return
        temp_paths.append(path)
        stages.append(
            {
                "label": f"{label} ({len(candidates)})",
                "mode": "0",
                "arg": path,
                "extra": [],
                "keyspace": len(candidates),
                "optional": False,
                "kind": "vendor",
            }
        )

    def _emit_ssid_digits(label: str, bases: list[str], digits: int, filename: str, max_total: int = 300_000):
        """Write '<base><n>' for every base and every n, as a plain wordlist.

        Done as a straight dictionary (mode 0), NOT a -a 6 hybrid: a tiny hybrid
        base (a dozen words) makes hashcat starve the GPU - measured ~400 H/s
        versus ~40 kH/s for the same 140k candidates as a flat wordlist. We cap
        the total so the file (and the stage) stays small.
        """
        if not bases:
            return
        per = min(len(bases), max(1, max_total // (10 ** digits)))
        written = 0
        path = os.path.join(HCOV_DIR, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                for b in bases[:per]:
                    for n in range(10 ** digits):
                        cand = f"{b}{n:0{digits}d}"
                        if 8 <= len(cand) <= 63:
                            f.write(cand + "\n")
                            written += 1
        except OSError as e:
            log_debug(f"_vendor_stages: failed to write {filename} ({e})")
            return
        if not written:
            return
        temp_paths.append(path)
        stages.append(
            {
                "label": f"{label} ({written})",
                "mode": "0",
                "arg": path,
                "extra": [],
                "keyspace": written,
                "optional": True,
                "kind": "hybrid",
            }
        )

    computed = _pool(global_default_candidates)
    _emit("Computed ISP default keys", computed, "_vendor_defaults.txt")
    # Same derivation, but people usually tweak the sticker key with an appended
    # digit, year, or "!". Cheap to try right after the exact forms.
    _emit(
        "Computed ISP keys + digit/year suffix",
        passphrase_suffix_variants(computed),
        "_vendor_suffixed.txt",
    )
    _emit("ISP/SSID pattern keys", _pool(lambda e, _b: heuristic_candidates(e)), "_vendor_patterns.txt")
    # Common Filipino names and realistic birthdates - network-independent, so
    # pooled once. Cheap (a few tens of thousands) and covers the name/nickname/
    # birthday passwords a generic dictionary almost never contains.
    _emit("Common PH names + birthdates", ph_common_candidates(), "_vendor_ph_common.txt")

    # SSID-derived base words for "the network's own name/nickname + a short
    # number" passwords ('examplenet0428', 'examplenet123'). The generic
    # pattern stage only tries a handful of fixed suffixes; this covers arbitrary
    # 3-4 digit tails. Bases are pooled and capped so the keyspace stays tiny.
    def _ssid_bases(essid: str, bssid: str) -> list[str]:
        base = (essid or "").strip()
        if not base:
            return []
        tokens = re.findall(r"[A-Za-z0-9]{2,}", base)
        alpha_words = re.findall(r"[A-Za-z]{2,}", base)
        num_runs = re.findall(r"\d+", base)
        joined = "".join(tokens)
        alpha_join = "".join(alpha_words)
        title_join = "".join(w.capitalize() for w in tokens)
        title_sp = " ".join(w.capitalize() for w in tokens)
        out: list[str] = []
        variants = [
            base, base.lower(), base.upper(),
            joined, joined.lower(), joined.upper(), title_join, title_sp,
            "_".join(tokens), "-".join(tokens), ".".join(tokens),
            "_".join(tokens).lower(), "-".join(tokens).lower(), "_".join(tokens).upper(),
            title_sp.replace(" ", "_"), title_sp.replace(" ", "-"),
            alpha_join, alpha_join.lower(), alpha_join.upper(), alpha_join.capitalize(),
            "_".join(alpha_words), "-".join(alpha_words),
            "".join(w.capitalize() for w in alpha_words),
            re.sub(r"[^A-Za-z0-9]", "", base), re.sub(r"[^A-Za-z0-9]", "", base).lower(),
        ]
        for v in variants:
            if 2 <= len(v) <= 55:
                out.append(v)
        # Expand short numeric runs to likely years: "08" -> 2008 / 1908.
        # Catches SSIDs like Example08 whose key is "example2008".
        years: list[str] = []
        for n in num_runs:
            if len(n) in (1, 2):
                y = n.zfill(2)
                years += ["20" + y, "19" + y]
            elif len(n) == 4 and n[:2] in ("19", "20"):
                years.append(n)
        for w in alpha_words:
            out.extend([w, w.lower(), w.capitalize(), w.upper()])
            for y in years:
                out.extend([w + y, w.lower() + y, w.capitalize() + y])
        out.extend(brand_mac_variants(essid, bssid, max_n=20))
        return out

    seen_bases: set[str] = set()
    ssid_bases: list[str] = []
    for essid, bssid in networks:
        for b in _ssid_bases(essid, bssid):
            if b not in seen_bases:
                seen_bases.add(b)
                ssid_bases.append(b)
                if len(ssid_bases) >= 500:
                    break
        if len(ssid_bases) >= 500:
            break
    _emit("SSID name variants", ssid_bases, "_vendor_ssid_names.txt")
    _emit_ssid_digits("SSID words + 3 digits", ssid_bases, 3, "_ssid_hybrid3.txt")
    _emit_ssid_digits("SSID words + 4 digits", ssid_bases, 4, "_ssid_hybrid4.txt", max_total=300_000)

    log_debug(f"_vendor_stages: networks={networks} stages={[s['label'] for s in stages]}")
    return stages, temp_paths


# Brute-force masks for the PH ISPs whose key space has a known shape. If we miss
# the exact computed key (unknown MAC offset, odd firmware), these sweep the
# whole family. Optional and speed-gated like any other mask.
_M_WLAN6 = ("wlan+6hex (PLDT/Converge)", "wlan?1?1?1?1?1?1", ["-1", "0123456789abcdef"], 16**6)
_M_PLDT6 = ("PLDTWIFI+6hex", "PLDTWIFI?1?1?1?1?1?1", ["-1", "0123456789ABCDEF"], 16**6)
_M_PLDT5 = ("PLDTWIFI+5hex", "PLDTWIFI?1?1?1?1?1", ["-1", "0123456789ABCDEF"], 16**5)
_M_PLDT5L = ("PLDTWIFI+5hex (lower)", "PLDTWIFI?2?2?2?2?2", ["-2", "0123456789abcdef"], 16**5)
_M_MYBRO = ("myBROWIFI+6hex", "myBROWIFI?1?1?1?1?1?1", ["-1", "0123456789ABCDEF"], 16**6)
_M_MYBROL = ("mybrowifi+6hex (lower)", "mybrowifi?1?1?1?1?1?1", ["-1", "0123456789abcdef"], 16**6)
_M_HBRO_US = ("HomeBro_+6hex", "HomeBro_?1?1?1?1?1?1", ["-1", "0123456789ABCDEF"], 16**6)
_M_HBRO = ("HomeBro+6hex (no underscore)", "HomeBro?1?1?1?1?1?1", ["-1", "0123456789ABCDEF"], 16**6)
_M_PLDT8D = ("PLDTWIFI+8digits", "PLDTWIFI?d?d?d?d?d?d?d?d", [], 10**8)
# Globe At Home PROLiNK: the key is the last 6 MAC hex digits with "WIFI" stuck
# in the middle (A1B WIFI 2C3). It's enumerable, so this still works when the
# BSSID we captured is offset from the MAC printed on the label.
_M_GLOBE = ("Globe 3hex+WIFI+3hex", "?1?1?1WIFI?1?1?1", ["-1", "0123456789ABCDEF"], 16**6)
_M_GLOBEL = ("globe 3hex+WIFI+3hex (lower)", "?2?2?2WIFI?2?2?2", ["-2", "0123456789abcdef"], 16**6)

# PH-specific masks that apply broadly across ISPs. PH passwords often follow
# local patterns: 11-digit mobile numbers (09xx). These are cheap enough to run
# on most GPUs.
#
# Operator prefixes are swept one at a time: an 11-digit number is
# <prefix> + 7 digits = 10^7 candidates, which is 100x cheaper than one blanket
# 11-digit sweep (10^9) and covers the prefixes people actually use. The keyspace
# MUST stay honest - 10^8 made each prefix look 10x costlier than it is and the
# budget gate skipped them all.
_PH_MOBILE_PREFIXES = [
    "0917", "0918", "0919", "0920", "0921", "0927", "0939", "0949",
]

_PH_BROAD_MASKS = [
    (f"PH mobile {p}…", f"{p}?d?d?d?d?d?d?d", [], 10**7)
    for p in _PH_MOBILE_PREFIXES
]

# All masks, in the order we use when we can't identify the ISP.
_PLDT_MASKS = [
    _M_WLAN6, _M_PLDT6, _M_PLDT5, _M_PLDT5L,
    _M_MYBRO, _M_MYBROL, _M_HBRO_US, _M_HBRO, _M_PLDT8D,
]

# Masks per ISP family, cheapest and likeliest first. Firing all nine at every PH
# network costs ~70 min on an iGPU, most of it on shapes that network's ISP never
# ships: a Converge AP can't have a HomeBro (PLDT Ultera) or myBROWIFI (Smart
# Wimax) key, so sweeping those is pure waste. PLDT keeps the HomeBro/myBRO shapes
# because both are PLDT-family products (see mybro_candidates() in src/keygen.py).
_ISP_MASK_FAMILIES: dict[str, list[tuple]] = {
    # Converge ICT: the label key is wlan + nibble-complement hex. The uppercase
    # PLDTWIFI form also turns up on Converge-deployed ZTE units.
    "converge": [_M_WLAN6, _M_PLDT6] + _PH_BROAD_MASKS,
    "pldt": [_M_PLDT5, _M_PLDT5L, _M_PLDT6, _M_WLAN6, _M_PLDT8D, _M_MYBRO, _M_MYBROL, _M_HBRO_US, _M_HBRO] + _PH_BROAD_MASKS,
    "homebro": [_M_HBRO_US, _M_HBRO, _M_WLAN6, _M_PLDT6] + _PH_BROAD_MASKS,
    "mybro": [_M_MYBRO, _M_MYBROL] + _PH_BROAD_MASKS,
    "globe": [_M_GLOBE, _M_GLOBEL] + _PH_BROAD_MASKS,
}

# PH ISPs that ship a random per-device key printed on the label. There's no key
# space to sweep, so we don't offer a mask family. Saying so up front beats
# burning an hour to prove it. The dictionary, PH wordlist, pattern, and rule
# stages still run against them, which is where a changed password gets caught.
_PH_RANDOM_KEY_ISPS = {
    "sky": "Sky Broadband/Fiber",
    "dito": "DITO",
    "streamtech": "Streamtech",
    "rise": "RISE",
    "infinivan": "InfiniVAN",
    "eastern": "Eastern Communications",
    "radius": "Radius Telecoms",
    "cablelink": "Cablelink",
    "royalcable": "Royal Cable",
    "parasat": "Parasat",
    "comclark": "ComClark",
    "starlink": "Starlink",
}


def ph_random_key_isp(essid: str) -> str:
    """Name of the PH ISP when its gear uses random label keys, else ''."""
    e = re.sub(r"[^a-z]", "", (essid or "").lower())
    for token, name in _PH_RANDOM_KEY_ISPS.items():
        if e.startswith(token):
            return name
    return ""


def _isp_family(essid: str) -> str:
    """Which PH ISP key-space family an SSID belongs to, or '' when unclear."""
    e = (essid or "").strip()
    if not e:
        return ""
    if re.match(r"(?i)homebro|homeultera", e):
        return "homebro"
    if re.match(r"(?i)mybro|smartbro", e):
        return "mybro"
    if re.match(r"(?i)globe", e):
        return "globe"
    if looks_like_pldt(e):
        return "pldt"
    if re.match(r"(?i)converge|0fs", e) or re.match(r"(?i)ZTE[._-]?[0-9.]+[gGHz]", e):
        return "converge"
    if re.match(r"(?i)wlan[_0-9a-f]", e):
        return "converge"  # bare wlan+hex SSIDs are the Converge/PLDT shared shape
    return ""


def _has_derivable_hex_suffix(essid: str) -> bool:
    """True when the SSID tail looks like the derivable-key hex families.

    Covers Converge routers (``wlan..`` + 6 hex, ``Converge_2.4GHz_…``,
    ``0FS_…``, Converge-deployed ``ZTE_2.4G_…`` whose label key uses the
    ``wlan+complement-hex`` shape) and the PLDT family, which are the PH ISPs
    with an enumerable factory key space. Non-hex-suffixed, non-branded networks
    (Globe/Sky/DITO label-printed random keys) correctly return False.
    """
    e = (essid or "").strip()
    if not e:
        return False
    tail = _HEX_SUFFIX_RE.search(e)
    if tail and len(tail.group(0)) >= 6:
        return True
    # Word tokens can be followed by '_' (a word char), so match loosely instead
    # of using \b. Converge routers broadcast under Converge/0FS/ZTE-branded SSIDs.
    return bool(
        re.search(r"(?i)converge|0FS|wlan|pldtwifi|homebro|homeultera", e)
        or re.match(r"(?i)ZTE[._-]?[0-9.]+[gGHz]", e)
    )


def _isp_mask_stages(essid: str, bssid: str) -> list[dict]:
    """Mask stages for this network's ISP key space, or [] when it isn't a match.

    Only the identified family's shapes are swept. An unidentified but
    hex-suffixed SSID falls back to the full set, since there is nothing to
    narrow it with.
    """
    family = _isp_family(essid)
    if not family and not looks_like_pldt(essid, bssid) and not _has_derivable_hex_suffix(essid):
        return []
    masks = _ISP_MASK_FAMILIES.get(family, _PLDT_MASKS)
    log_debug(f"_isp_mask_stages: essid={essid!r} family={family or 'unknown'} masks={len(masks)}")
    return [
        {
            "label": f"ISP mask: {label}",
            "mode": "3",
            "arg": mask,
            "extra": extra,
            "keyspace": ks,
            "optional": True,
            "kind": "isp_mask",
            # Only this network's family can carry this key shape, so testing it
            # against unrelated SSIDs is wasted work (see _stage_hash_file).
            "targets": {essid} if essid else set(),
        }
        for (label, mask, extra, ks) in masks
    ]


def _isp_mask_stages_for_networks(networks: list[tuple[str, str]]) -> list[dict]:
    """The union of every ISP family present in the hash file, deduplicated.

    A mask sweeps a whole key space and is checked against every hash in the file
    at once, so a batch holding PLDT *and* Converge *and* Globe APs needs each
    family's shapes exactly once - not one family's, and not the same shape
    repeated per network. Cheapest first, so a hit costs the least it can.
    """
    by_mask: dict[str, dict] = {}
    for essid, bssid in networks:
        for stage in _isp_mask_stages(essid, bssid):
            key = stage["arg"] + "".join(stage["extra"])
            if key in by_mask:
                # Same shape from another network in that family, so just widen
                # the targets instead of adding a duplicate stage.
                by_mask[key]["targets"] |= stage["targets"]
            else:
                by_mask[key] = stage
    stages = sorted(by_mask.values(), key=lambda s: s["keyspace"])
    return stages


_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ph_wordlist_path: str | None = None


_combined_rule_cache: dict[tuple, tuple[str, int]] = {}


def _combined_rule_file(rule_files: list[str]) -> tuple[str, int]:
    """Concatenate rule files into ONE file and return (path, rule_count).

    hashcat's keyspace for a rules attack is ``words × rules`` only when a single
    ``-r`` is used. Passing several ``-r`` files makes the true runtime and our
    budget estimate diverge badly (observed ~16x slower than predicted, so the
    per-stage budget gate could no longer protect the run). Writing one combined
    rule file keeps the estimate honest.
    """
    key = tuple(rule_files)
    if key in _combined_rule_cache:
        return _combined_rule_cache[key]

    os.makedirs(HCOV_DIR, exist_ok=True)
    path = os.path.join(HCOV_DIR, "_rules_combined.rule")
    count = 0
    try:
        with open(path, "w", encoding="utf-8") as out:
            for rf in rule_files:
                try:
                    with open(rf, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            s = line.rstrip("\n")
                            if not s.strip() or s.lstrip().startswith("#"):
                                continue
                            out.write(s + "\n")
                            count += 1
                except OSError:
                    continue
    except OSError as e:
        log_debug(f"_combined_rule_file: could not write ({e})")
        _combined_rule_cache[key] = ("", 0)
        return "", 0

    result = (path, count) if count else ("", 0)
    _combined_rule_cache[key] = result
    return result


def ensure_ph_wordlist() -> str | None:
    """Fetch (once) the small PH-focused default-password wordlist into the project
    root, then merge it with any additional PH wordlist files found locally
    (wifi-wordlist-ph-*.txt). Returns the merged wordlist path, or None when
    unavailable so the caller skips the stage.
    """
    global _ph_wordlist_path
    if _ph_wordlist_path is not None:
        return _ph_wordlist_path or None

    src_paths: list[str] = []
    dest = os.path.join(_PROJECT_ROOT, PH_WORDLIST_NAME)

    # Always include the downloaded PH wordlist if present.
    if os.path.isfile(dest) and os.path.getsize(dest) > 0:
        src_paths.append(dest)
    else:
        colored_log("info", f"Fetching Philippine default-password wordlist ({PH_WORDLIST_NAME}, ~370 KB)...")
        if download_with_progress(PH_WORDLIST_URL, dest, "Downloading PH wordlist", PH_WORDLIST_SHA256):
            src_paths.append(dest)
        else:
            _ph_wordlist_path = ""
            return None

    # Also merge any additional PH wordlist files the user has placed in the
    # project root (e.g. wifi-wordlist-ph-custom.txt).
    for extra in sorted(os.listdir(_PROJECT_ROOT)):
        if extra.startswith("wifi-wordlist-ph-") and extra.endswith(".txt") and extra != PH_WORDLIST_NAME:
            p = os.path.join(_PROJECT_ROOT, extra)
            if os.path.isfile(p) and p not in src_paths:
                src_paths.append(p)

    if len(src_paths) == 1:
        _ph_wordlist_path = src_paths[0]
        return src_paths[0]

    merged = os.path.join(_PROJECT_ROOT, "wifi-wordlist-ph-merged.txt")
    n = merge_wordlists(merged, *src_paths)
    if n > 0:
        colored_log("success", f"Merged {n} unique PH passwords into {os.path.basename(merged)}")
        _ph_wordlist_path = merged
        return merged
    _ph_wordlist_path = src_paths[0]
    return src_paths[0]


def _find_rule_files(hc_dir: str) -> list[str]:
    """Locate wordlist-mutation rule files, keeping the rules stage runnable.

    The bundled compact rule set is always used, plus one moderate general set
    (best66/best64, ~78 rules). The big sets (rockyou-30000, d3ad0ne) are
    deliberately excluded: with an 8.5M wordlist, 30,000 rules is ~2.5x10^14
    candidates, which can never fit a sane per-stage budget - so including it
    silently turned the whole rules stage into a no-op. Set
    ``HANDSHAKE_FULL_RULES=1`` to opt back into the large sets when you have days
    to spend.
    """
    full = bool(os.environ.get("HANDSHAKE_FULL_RULES"))

    # Always start with the project's curated wifi rules.
    candidates = [os.path.join(_PROJECT_ROOT, "rules", "wifi-rules.rule")]

    # Add exactly one moderate general set (first one present wins), so we don't
    # stack overlapping supersets and multiply the keyspace for no coverage gain.
    for moderate in (
        os.path.join(hc_dir, "rules", "best66.rule"),
        os.path.join(hc_dir, "rules", "best64.rule"),
        "/usr/share/hashcat/rules/best66.rule",
        "/usr/share/hashcat/rules/best64.rule",
    ):
        if os.path.isfile(moderate):
            candidates.append(moderate)
            break

    if full:
        candidates += [
            os.path.join(hc_dir, "rules", "rockyou-30000.rule"),
            "/usr/share/hashcat/rules/rockyou-30000.rule",
        ]

    seen: set[str] = set()
    found: list[str] = []
    for candidate in candidates:
        if os.path.isfile(candidate) and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found


_prefix_rule_cache: dict[int, str] = {}

def _prefix_rule_file(digits: int) -> str | None:
    """A rule file that prepends every `digits`-long decimal string.

    hashcat's ``^X`` prepends one character, and rules apply left to right, so the
    prefix has to be written in reverse: "09" becomes ``^9^0``. Generated once per
    length and cached in the hc22000 working directory.
    """
    if digits in _prefix_rule_cache:
        return _prefix_rule_cache[digits] or None
    try:
        os.makedirs(HCOV_DIR, exist_ok=True)
        path = os.path.join(HCOV_DIR, f"_prefix{digits}.rule")
        with open(path, "w", encoding="utf-8") as f:
            for n in range(10**digits):
                prefix = f"{n:0{digits}d}"
                f.write("".join(f"^{c}" for c in reversed(prefix)) + "\n")
        _prefix_rule_cache[digits] = path
        log_debug(f"_prefix_rule_file: wrote {10**digits} prepend rules to {path}")
        return path
    except OSError as e:
        log_debug(f"_prefix_rule_file: could not write rules ({e})")
        _prefix_rule_cache[digits] = ""
        return None


def _build_attack_plan(hc_dir: str, wordlist_path: str) -> list[dict]:
    """Ordered attack plan, cheapest + most-likely first, stopping on first hit:

    1. PH default-password wordlist   (optional; Philippine factory/user keys)
    2. straight dictionary            (always runs; broad coverage)
    3. default-format masks           (brute force of common default PSKs)
    4. dictionary + rules             (thorough; mutates each word - most expensive)

    Every stage carries its ``keyspace`` (candidate count) so the runner can
    estimate runtime and skip stages that can't finish within the time budget.
    The dictionary stage is the only non-optional one.
    """
    wl_lines = count_wordlist_lines(wordlist_path) or None
    plan: list[dict] = []
    ph_wordlist = ensure_ph_wordlist()
    if ph_wordlist:
        ph_lines = count_wordlist_lines(ph_wordlist) or None
        plan.append({"label": f"PH default passwords ({os.path.basename(ph_wordlist)})", "mode": "0", "arg": ph_wordlist, "extra": [], "keyspace": ph_lines, "optional": False, "kind": "dict"})
    plan.append({"label": "dictionary", "mode": "0", "arg": wordlist_path, "extra": [], "keyspace": wl_lines, "optional": False, "kind": "dict"})
    # Pick up any extra wordlists already on the system (Kali's rockyou.txt, etc).
    # Cheap to add, and they widen coverage past the one bundled list.
    for extra_wl in (
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    ):
        if os.path.isfile(extra_wl):
            extra_lines = count_wordlist_lines(extra_wl) or None
            plan.append(
                {
                    "label": f"dictionary: {os.path.basename(extra_wl)}",
                    "mode": "0",
                    "arg": extra_wl,
                    "extra": [],
                    "keyspace": extra_lines,
                    "optional": True,
                    "kind": "dict",
                }
            )
    # Any .txt wordlists the operator drops into <project>/wordlists/ are used
    # automatically (rockyou, seclists extracts, a client-specific list, ...).
    # This is the easiest way to widen coverage far past the bundled 8.5M list
    # without editing code: just copy the file in.
    extra_wl_dir = os.path.join(_PROJECT_ROOT, "wordlists")
    if os.path.isdir(extra_wl_dir):
        for name in sorted(os.listdir(extra_wl_dir)):
            if not name.lower().endswith(".txt"):
                continue
            path = os.path.join(extra_wl_dir, name)
            if not os.path.isfile(path):
                continue
            lines = count_wordlist_lines(path) or None
            plan.append(
                {
                    "label": f"dictionary: {name}",
                    "mode": "0",
                    "arg": path,
                    "extra": [],
                    "keyspace": lines,
                    "optional": True,
                    "kind": "dict",
                }
            )
    # Hybrid attacks. When someone changes the password it's usually a word plus
    # digits (name+birthday, family+year, phone+1). Base these on the PH wordlist
    # to keep the keyspace bounded; optional, so slow GPUs skip them.
    if ph_wordlist and ph_lines:
        for suf_label, mask, ks in (
            ("4 digits", "?d?d?d?d", 10**4),
            ("6 digits (MMDDYY)", "?d?d?d?d?d?d", 10**6),
            ("2 digits", "?d?d", 100),
        ):
            plan.append(
                {
                    "label": f"hybrid: {os.path.basename(ph_wordlist)} + {suf_label}",
                    "mode": "6",
                    "arg": [ph_wordlist, mask],
                    "extra": [],
                    "keyspace": ph_lines * ks,
                    "optional": True,
                    "kind": "hybrid",
                }
            )
        # Digits before a word (0917 + <name>). The obvious way is a -a 7 hybrid,
        # but that makes the tiny mask the base and leaves the GPU mostly idle: on
        # an Iris Xe, "?d?d" + a 35k wordlist ran ~8x longer than the keyspace
        # predicted (10 min for what should've been 76 s). Doing it as prepend
        # rules over the wordlist keeps the wordlist as the base, so the stage runs
        # at full speed for the same keyspace.
        for pre_label, digits in (("2 digits prefix", 2), ("4 digits prefix", 4)):
            rule_path = _prefix_rule_file(digits)
            if not rule_path:
                continue
            plan.append(
                {
                    "label": f"hybrid: {pre_label} + {os.path.basename(ph_wordlist)}",
                    "mode": "0",
                    "arg": ph_wordlist,
                    "extra": ["-r", rule_path],
                    "keyspace": (10**digits) * ph_lines,
                    "optional": True,
                    "kind": "hybrid",
                }
            )
    # Fast mutation rules: a ~10-rule tier that fits a small budget even on a
    # slow GPU and with many salts. Runs before the full rule set so the
    # highest-value mutations (capitalise, append 1/123/1234/2024/!) are still
    # tried even when the full 60-rule set is skipped for time. This is the
    # difference between "rules never ran" and "the common mutations ran".
    fast_rule = os.path.join(_PROJECT_ROOT, "rules", "wifi-rules-fast.rule")
    if os.path.isfile(fast_rule) and wl_lines:
        fast_count = _count_rules(fast_rule)
        if fast_count:
            plan.append(
                {
                    "label": f"dictionary + fast rules ({os.path.basename(fast_rule)})",
                    "mode": "0",
                    "arg": wordlist_path,
                    "extra": ["-r", fast_rule],
                    "keyspace": wl_lines * fast_count,
                    "optional": True,
                    "kind": "rules",
                }
            )
            if ph_wordlist and ph_lines:
                plan.append(
                    {
                        "label": f"PH defaults + fast rules ({os.path.basename(fast_rule)})",
                        "mode": "0",
                        "arg": ph_wordlist,
                        "extra": ["-r", fast_rule],
                        "keyspace": ph_lines * fast_count,
                        "optional": True,
                        "kind": "rules",
                    }
                )
    # Medium mutation tier: ~40 rules - a middle ground between the tiny fast set
    # and the full ~161-rule set. It covers most real human mutations (2-6 digit
    # suffixes, years 2018-2025, leet, capitalise+digit) while still fitting a
    # generous per-stage budget on a single network. Without this, a weak GPU can
    # only ever run the 11-rule fast set or skip rules entirely.
    medium_rule = os.path.join(_PROJECT_ROOT, "rules", "wifi-rules-medium.rule")
    if os.path.isfile(medium_rule) and wl_lines:
        medium_count = _count_rules(medium_rule)
        if medium_count:
            plan.append(
                {
                    "label": f"dictionary + medium rules ({os.path.basename(medium_rule)})",
                    "mode": "0",
                    "arg": wordlist_path,
                    "extra": ["-r", medium_rule],
                    "keyspace": wl_lines * medium_count,
                    "optional": True,
                    "kind": "rules",
                }
            )
            if ph_wordlist and ph_lines:
                plan.append(
                    {
                        "label": f"PH defaults + medium rules ({os.path.basename(medium_rule)})",
                        "mode": "0",
                        "arg": ph_wordlist,
                        "extra": ["-r", medium_rule],
                        "keyspace": ph_lines * medium_count,
                        "optional": True,
                        "kind": "rules",
                    }
                )
    # Mutation rules run before the generic digit/hex masks. On a home or office
    # network the passphrase is human-chosen, so a dictionary word put through
    # capitalisation/leet/append-year rules is a much better bet than sweeping
    # every 9- or 10-digit string. The masks still run after.
    rule_files = _find_rule_files(hc_dir)
    combined_rule, rule_count = _combined_rule_file(rule_files) if rule_files else ("", 0)
    if combined_rule and rule_count:
        rules_arg = ["-r", combined_rule]
        ks = wl_lines * rule_count if wl_lines else None
        plan.append(
            {
                "label": f"dictionary + rules ({rule_count} rules)",
                "mode": "0",
                "arg": wordlist_path,
                "extra": rules_arg,
                "keyspace": ks,
                "optional": True,
                "kind": "rules",
            }
        )
        # The PH default-password list gains from rule mutation too (S->$, a->@,
        # append '!'/year, leet casing). Cheap, and it leans toward local defaults.
        if ph_wordlist and ph_lines:
            ph_ks = ph_lines * rule_count
            plan.append(
                {
                    "label": f"PH defaults + rules ({rule_count} rules)",
                    "mode": "0",
                    "arg": ph_wordlist,
                    "extra": rules_arg,
                    "keyspace": ph_ks,
                    "optional": True,
                    "kind": "rules",
                }
            )
    for label, mask, extra, keyspace in _DEFAULT_MASKS:
        plan.append({"label": f"mask: {label}", "mode": "3", "arg": mask, "extra": extra, "keyspace": keyspace, "optional": True, "kind": "mask"})
    return plan


_KIND_LABEL = {
    "vendor": "keys",
    "dict": "dict",
    "isp_mask": "ISP mask",
    "hybrid": "hybrid",
    "rules": "rules",
    "mask": "brute",
}


def _fmt_count(n: int) -> str:
    """Candidate counts in compact units: 16.8M rather than 16,777,216.

    Fifteen digits of precision is not information at a glance, and the full
    forms pushed the table past a normal terminal width so every row wrapped.
    """
    for limit, suffix in ((1_000_000_000_000, "T"), (1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if n >= limit:
            value = n / limit
            return f"{value:.1f}{suffix}" if value < 100 else f"{value:.0f}{suffix}"
    return str(n)


def _stage_hash_file(attack: dict, all_lines: list, full_path: str) -> tuple[str, int]:
    """(hash file to use for this stage, number of salts it carries).

    A family mask only fits the ISP that ships that key shape, so running it
    against every SSID in the batch multiplies its cost by networks it can never
    crack - on a mixed estate that turned a 6-minute Converge sweep into an hour.
    Stages without targets keep the full file.
    """
    targets = attack.get("targets") or set()
    # ESSID hex is field index 5 of the '*'-delimited hc22000 line. Split each
    # line once here rather than three times per line further down.
    lines_with_essid = [
        (ln, parts[5]) for ln in all_lines if len(parts := ln.split("*")) > 5
    ]
    if not targets:
        return full_path, max(1, len({essid for _ln, essid in lines_with_essid}))

    wanted = {e.encode("utf-8", errors="replace").hex() for e in targets}
    lines = [ln for ln, essid in lines_with_essid if essid in wanted]
    if not lines:
        return full_path, max(1, len(wanted))
    path = os.path.join(HCOV_DIR, "_stage.hc22000")
    try:
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        log_debug(f"_stage_hash_file: falling back to the full file ({e})")
        return full_path, max(1, len(wanted))
    return path, max(1, len({e for _ln, e in lines_with_essid if e in wanted}))


BENCH_FILE = ".benchmark"


def _parse_benchmark(output: str) -> int | None:
    """Best WPA rate from ``hashcat -b --machine-readable`` output.

    Each line is ``device:mode:?:?:ms:H/s`` - e.g.
    ``1:22000:4294967295:4294967295:93.41:32848``. Summed across devices, since
    a machine with two GPUs reports one line each.
    """
    per_device: dict[str, int] = {}
    for line in (output or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 6 and parts[1] == "22000":
            try:
                per_device[parts[0]] = max(per_device.get(parts[0], 0), int(parts[5]))
            except ValueError:
                continue
    total = sum(per_device.values())
    return total or None


def _benchmark_speed(hc_exe: str, hc_dir: str) -> int | None:
    """Measured WPA throughput in H/s, cached so it costs one run, not every run."""
    cache = os.path.join(HCOV_DIR, BENCH_FILE)
    try:
        with open(cache, encoding="utf-8") as f:
            cached = int(f.read().strip())
        if cached > 0:
            log_debug(f"_benchmark_speed: cached {cached} H/s")
            return cached
    except (OSError, ValueError):
        pass

    colored_log("info", "Benchmarking WPA throughput once (a few seconds) to cost the plan...")
    try:
        proc = subprocess.run(
            [hc_exe, "-b", "-m", "22000", "--quiet", "--machine-readable"],
            capture_output=True, text=True, timeout=300, cwd=hc_dir,
        )
        speed = _parse_benchmark(proc.stdout + proc.stderr)
        log_debug(f"_benchmark_speed: measured {speed} H/s")
        if speed:
            try:
                os.makedirs(HCOV_DIR, exist_ok=True)
                with open(cache, "w", encoding="utf-8") as f:
                    f.write(str(speed))
            except OSError:
                pass
        return speed
    except Exception as e:
        log_debug(f"_benchmark_speed: skipped ({type(e).__name__}: {e})")
        return None


def _print_attack_plan(plan: list[dict], salts: int, budget_seconds: int, speed: int | None = None) -> None:
    """Show the plan as a table rather than one long arrow-chain.

    The chain wrapped over several terminal lines and buried the one thing worth
    knowing up front: which stages will actually run. Cost here is candidates x
    salts, so the same plan against more networks shifts stages from run to skip.
    """
    console.print()
    console.rule("[bold cyan]Attack plan[/bold cyan]", style="cyan", align="left")
    table = Table(
        show_header=True, header_style="bold", box=box.SIMPLE_HEAD,
        pad_edge=False, show_edge=False, border_style="dim",
    )
    table.add_column("#", justify="right", style="dim")
    # One row per stage. Wrapping the label would turn a 19-stage plan into 50
    # lines and lose the at-a-glance shape that makes the table worth printing.
    table.add_column("Stage", max_width=46, no_wrap=True, overflow="ellipsis")
    table.add_column("Type", style="dim")
    table.add_column("Candidates", justify="right")
    table.add_column("Work", justify="right")
    table.add_column("Est.", justify="right")

    for i, attack in enumerate(plan, 1):
        keyspace = attack.get("keyspace") or 0
        # A targeted stage only gets its own family's hashes, so scale its cost by
        # those networks, not by everything loaded.
        stage_salts = len(attack.get("targets") or ()) or salts
        work = keyspace * stage_salts
        scope = f" [dim]({stage_salts}/{salts})[/dim]" if stage_salts != salts else ""
        # A raw candidate count doesn't tell you much at a glance. The time it
        # implies is what decides whether a stage is worth waiting for.
        will_skip = False
        if work and speed:
            est = work / speed
            will_skip = bool(attack.get("optional")) and est > budget_seconds
            # Say "skip" in words, not just colour: this output often gets piped
            # to a file or log, where the colour is lost.
            est_text = (
                f"[yellow]{_fmt_duration(est)} skip[/yellow]"
                if will_skip
                else f"[green]{_fmt_duration(est)}[/green]"
            )
        else:
            est_text = "[dim]-[/dim]"

        # A stage that won't run is just context, so dim it. That way the eye
        # lands on the work that's actually going to happen.
        def _cell(text: str) -> str:
            return f"[dim]{text}[/dim]" if will_skip else text

        table.add_row(
            _cell(str(i)),
            _cell(attack["label"]),
            _cell(_KIND_LABEL.get(attack.get("kind", ""), attack.get("kind", ""))),
            _cell(_fmt_count(keyspace)) if keyspace else "[dim]-[/dim]",
            _cell(_fmt_count(work) + scope) if work else "[dim]-[/dim]",
            est_text,
        )

    console.print("")
    console.print(table)
    console.print()
    if speed:
        total = sum(
            (a.get("keyspace") or 0) * (len(a.get("targets") or ()) or salts) / speed
            for a in plan
            if not (a.get("optional") and (a.get("keyspace") or 0) * (len(a.get("targets") or ()) or salts) / speed > budget_seconds)
        )
        runnable = sum(
            1
            for a in plan
            if not (a.get("optional") and (a.get("keyspace") or 0) * (len(a.get("targets") or ()) or salts) / speed > budget_seconds)
        )
        console.print(
            f"  [bold]{runnable}[/bold] stage(s) will run, estimated [bold cyan]{_fmt_duration(total)}[/bold cyan] total"
        )
    optional = sum(1 for a in plan if a.get("optional"))
    if optional:
        console.print(
            f"\n  [dim]{optional} of {len(plan)} stages are optional: each is skipped if its measured "
            f"runtime would exceed {_fmt_duration(budget_seconds)} "
            f"(HANDSHAKE_MAX_STAGE_MIN={budget_seconds // 60}).[/dim]"
        )


class _StatusLine:
    """A single in-place status line for a running stage.

    rich's Progress starts a new live region per stage, and each one left a blank
    line behind - nineteen stages meant nineteen blank lines. Writing the line
    ourselves keeps one line per stage and no residue.

    It repaints on its own timer rather than only when new data arrives. hashcat
    reports every 5 seconds and a mask stage runs for minutes, so a line that
    changed only on new data sat visually motionless long enough to look hung -
    and some terminals do not reliably repaint a bare carriage-return update at
    all. A spinner that advances several times a second makes progress obvious
    and forces the repaint.
    """

    _FRAMES = "|/-\\"
    _INTERVAL = 0.2
    # How often to drop a permanent, newline-terminated line. An in-place update
    # is useless if the terminal stops repainting: a stalled pane just shows a
    # snapshot from minutes ago and the run looks hung. A line that scrolls proves
    # progress in any terminal, and gives piped output something between stages.
    _CHECKPOINT = 120.0

    def __init__(self, prefix: str, run_started: float | None = None):
        self.prefix = prefix
        self.run_started = run_started
        self.enabled = sys.stdout.isatty()
        self._detail = "starting..."
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._last_checkpoint = time.monotonic()

    def _paint(self) -> None:
        with self._lock:
            detail = self._detail
            spin = self._FRAMES[self._frame % len(self._FRAMES)]
        try:
            sys.stdout.write(f"\r  {spin} {self.prefix} {detail}".ljust(118)[:118])
            sys.stdout.flush()
        except Exception:
            pass

    def _checkpoint(self) -> None:
        """Leave a permanent line, so progress is visible even without repaints.

        Carries the whole-run clock too: a stage percentage alone does not answer
        "how long has this been going and when will it end", which is the question
        being asked when a run looks stuck.
        """
        with self._lock:
            detail = self._detail
        run = f"  |  run {_fmt_duration(time.time() - self.run_started)}" if self.run_started else ""
        try:
            sys.stdout.write(f"\r  {self.prefix} {detail}{run}".ljust(126)[:126] + "\n")
            sys.stdout.flush()
        except Exception:
            pass

    def _run(self) -> None:
        while not self._stop.wait(self._INTERVAL):
            now = time.monotonic()
            if now - self._last_checkpoint >= self._CHECKPOINT:
                self._last_checkpoint = now
                self._checkpoint()
                continue
            if self.enabled:
                with self._lock:
                    self._frame += 1
                self._paint()

    def start(self) -> None:
        # Run the heartbeat even when stdout isn't a terminal: those periodic
        # checkpoint lines are the only progress a piped or logged run ever sees.
        self._last_checkpoint = time.monotonic()
        if self.enabled:
            self._paint()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def update(self, detail: str) -> None:
        # Always record the detail, even with no terminal. The checkpoint lines
        # are all a piped or logged run shows, and without this they'd report
        # "starting..." forever.
        with self._lock:
            self._detail = detail
        if self.enabled:
            self._paint()

    def clear(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None
        if self.enabled:
            sys.stdout.write("\r" + " " * 118 + "\r")
            sys.stdout.flush()


# Focus mode: a single-network live dashboard
#
# When the user runs `--focus <capture>`, one network gets the whole spotlight:
# instead of one scrolling status line per stage, a single rich.Live panel stays
# pinned to the bottom showing the target, the current stage, live speed, an ETA
# extrapolated from real progress, and a result banner when it falls. The crack
# loop talks to it through the module-level _active_focus handle so the existing
# batch/deep code paths (which leave it None) are completely unaffected.

_active_focus: "FocusUI | None" = None


class FocusUI:
    """Live single-network dashboard driven by the crack loop.

    Rendered by rich.Live via ``__rich__``, so it repaints on Live's own timer -
    the elapsed clock and ETA keep ticking between hashcat's 5-second status
    reports instead of sitting frozen and looking hung.
    """

    _BAR_WIDTH = 44

    def __init__(self, essid: str, bssid: str, hash_count: int, run_started: float | None = None):
        self.essid = essid or "(unknown SSID)"
        self.bssid = bssid or "??:??:??:??:??:??"
        self.hash_count = hash_count
        self.run_started = run_started or time.time()
        self.plan_len = 0
        self.stage_idx = 0
        self.stage_label = "preparing…"
        self.speed = 0
        self.percent: float | None = None
        self.stage_started = time.monotonic()
        self.recovered = 0
        self.result: tuple[str, str | None] | None = None  # (kind, password)

    # -- state updates the crack loop pushes in --------------------------------
    def set_plan(self, labels: list[str]) -> None:
        self.plan_len = len(labels)

    def set_stage(self, idx: int, label: str) -> None:
        self.stage_idx = idx
        self.stage_label = label
        self.speed = 0
        self.percent = None
        self.stage_started = time.monotonic()

    def set_metrics(self, speed: int | None = None, percent: float | None = None) -> None:
        if speed is not None:
            self.speed = speed
        if percent is not None:
            self.percent = percent

    def set_recovered(self, n: int) -> None:
        self.recovered = n

    def set_result(self, kind: str, password: str | None = None) -> None:
        self.result = (kind, password)

    # -- rendering -------------------------------------------------------------
    def _eta_text(self) -> str:
        elapsed = time.monotonic() - self.stage_started
        if self.percent and self.percent > 1.0 and elapsed > 5:
            remaining = elapsed * (100.0 - self.percent) / self.percent
            return f"~{_fmt_duration(remaining)} left"
        return "estimating…"

    def __rich__(self) -> Panel:
        title = Text.assemble(
            (">  ", "bold"),
            (self.essid, "bold white"),
            (f"   {self.bssid}", "dim"),
            (f"   ·  {self.hash_count} hash{'es' if self.hash_count != 1 else ''}", "dim"),
        )

        if self.result is not None:
            kind, pw = self.result
            if kind == "cracked":
                banner = Align.center(
                    Text.assemble(
                        ("✔  CRACKED\n", "bold green"),
                        (pw or "", "bold white on green"),
                    ),
                    vertical="middle",
                )
                return Panel(banner, title=title, border_style="green", box=box.HEAVY, padding=(1, 2))
            banner = Align.center(
                Text("✘  not recovered - plan exhausted", style="bold yellow"),
                vertical="middle",
            )
            return Panel(banner, title=title, border_style="yellow", box=box.HEAVY, padding=(1, 2))

        stage_no = f"{self.stage_idx}/{self.plan_len}" if self.plan_len else "…"
        rows = Table.grid(padding=(0, 2))
        rows.add_column(justify="right", style="dim", no_wrap=True)
        rows.add_column(justify="left")

        rows.add_row("Stage", Text.assemble((f"{stage_no}  ", "bold cyan"), (self.stage_label, "white")))

        pct = self.percent if self.percent is not None else 0.0
        bar = ProgressBar(total=100, completed=pct, width=self._BAR_WIDTH,
                          complete_style="cyan", finished_style="green")
        pct_txt = f"{pct:5.1f}%" if self.percent is not None else "  -  "
        prog_cell = Table.grid(padding=(0, 1))
        prog_cell.add_column(no_wrap=True)
        prog_cell.add_column(no_wrap=True)
        prog_cell.add_row(bar, Text(pct_txt, style="bold"))
        rows.add_row("Progress", prog_cell)

        speed_txt = _fmt_speed(self.speed) if self.speed else "warming up…"
        stage_elapsed = _fmt_duration(time.monotonic() - self.stage_started)
        rows.add_row("Speed", Text.assemble((speed_txt, "bold magenta"), (f"    {self._eta_text()}", "dim")))
        rows.add_row("Elapsed", Text.assemble((stage_elapsed, "white"),
                                              (f"    run {_fmt_duration(time.time() - self.run_started)}", "dim")))
        recovered_style = "bold green" if self.recovered else "dim"
        rows.add_row("Recovered", Text(f"{self.recovered}/1", style=recovered_style))

        return Panel(rows, title=title, border_style="cyan", box=box.ROUNDED, padding=(1, 2))


def run_focus_capture(
    handshake_path: str,
    wordlist_path: str,
    gpu_is_discrete: bool = False,
    packets: list | None = None,
) -> dict[str, str] | None:
    """Crack a single capture with the live focus dashboard.

    Converts the one capture, then runs the normal attack plan against it with
    _active_focus wired up so the whole run renders as one pinned panel.
    """
    global _active_focus
    hc_exe = get_hashcat_path()
    if not hc_exe:
        colored_log("error", "hashcat is not available - focus mode needs the GPU backend.")
        return None
    colored_log("info", "Converting capture to hashcat format (hc22000)…")
    hc22000_path = os.path.join(HCOV_DIR, strip_capture_extension(handshake_path) + ".hc22000")
    analysis = convert_capture(handshake_path, hc22000_path, packets)
    if analysis is None:
        colored_log("error", "Nothing crackable in this capture - no PMKID and no pairable handshake.")
        return None
    try:
        with open(hc22000_path, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
    except OSError as e:
        log_error("Failed to read converted hashes", e)
        return None
    networks = _parse_hc22000_networks(content)
    essid, bssid = (networks[0] if networks else ("", ""))
    display_essid = essid or strip_capture_extension(handshake_path)
    hash_count = len([ln for ln in content.splitlines() if ln.strip()])

    if not warmup_hashcat_kernel(hc22000_path):
        log_debug("run_focus_capture: warmup failed, continuing anyway")

    focus = FocusUI(display_essid, bssid, hash_count)
    result: dict[str, str] | None = None
    _active_focus = focus
    try:
        with Live(focus, console=console, refresh_per_second=8, transient=False):
            result = crack_with_hashcat(hc22000_path, wordlist_path, display_essid, gpu_is_discrete)
            if result:
                pw = next(iter(result.values()))
                focus.set_result("cracked", pw)
            else:
                focus.set_result("exhausted")
            # Let the final banner render before Live tears down.
            time.sleep(0.4)
    except KeyboardInterrupt:
        colored_log("warning", "Focus run interrupted by user.")
    finally:
        _active_focus = None
        try:
            os.remove(hc22000_path)
        except OSError:
            pass
    return result


def _run_hashcat_attack(
    hc_exe: str,
    hc_dir: str,
    hc22000_path: str,
    attack: dict,
    potfile: str,
    display_essid: str,
    gpu_is_discrete: bool,
    stage_idx: int,
    stage_count: int,
    potfile_before: set[str],
    time_limit: float | None = None,
    run_started: float | None = None,
) -> tuple[str, list[int]]:
    """Run one hashcat attack. Returns (status, speeds).

    status is 'found' (this stage added at least one entry to the potfile) |
    'exhausted' | 'timeout' | 'error'. Which network was cracked is resolved by
    the caller from the potfile, since one run covers every hash in the file.

    ``time_limit`` stops a stage that runs far past what its keyspace predicted.
    The estimate assumes throughput scales with candidate count, which some attack
    shapes break badly (a hybrid whose *base* is a two-digit mask leaves the GPU
    mostly idle and can run an order of magnitude longer than predicted). Without
    a stop, one such stage silently eats the whole run. Raises KeyboardInterrupt
    on Ctrl+C.
    """
    workload = "4" if gpu_is_discrete else "2"
    session = f"{sanitize_ssid(display_essid)}_s{stage_idx}"
    # -O (optimized kernels) roughly doubles WPA speed. It caps candidate length at
    # 31 chars, which covers almost every real Wi-Fi password. --status makes
    # hashcat print periodic speed lines so we can show live progress.
    cmd = [hc_exe, "-m", "22000", "-a", attack["mode"], "-w", workload, "-O", "--status", "--status-timer", "5"]
    cmd += ["--session", session, "--potfile-path", potfile]
    cmd += attack["extra"]
    cmd += [hc22000_path]
    if isinstance(attack["arg"], list):
        cmd += attack["arg"]  # hybrid (-a 6/7): wordlist + mask, in that order
    else:
        cmd.append(attack["arg"])
    label = f"[{stage_idx}/{stage_count}] {attack['label']}"
    _log_hashcat_output(f"COMMAND [{label}]", [" ".join(cmd)])

    speeds: list[int] = []
    hashcat_output: list[str] = []
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            # hashcat watches the terminal for its [s]tatus/[p]ause/[b]ypass/[q]uit
            # keys. If it inherits stdin, a stray keystroke in the window can abort
            # a stage mid-run, which then shows up in the report as an "error".
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=hc_dir,
        )
        if proc.stdout is None:
            raise RuntimeError("stdout pipe not created")
        log_debug(f"_run_hashcat_attack[{label}]: pid={proc.pid}")
        kernel_init_done = False
        have_speed = False
        timed_out = False
        started = time.monotonic()
        last_speed = 0
        percent: float | None = None
        # In focus mode the live panel is the display; the scrolling status line
        # would fight rich.Live for the cursor, so hand progress to the panel.
        focus = _active_focus
        status = None if focus is not None else _StatusLine(
            f"[{stage_idx:>2}/{stage_count}] {attack['label']}", run_started
        )

        def _describe() -> str:
            elapsed = time.monotonic() - started
            bits = []
            if last_speed:
                bits.append(_fmt_speed(last_speed))
            if percent is not None:
                bits.append(f"{percent:5.1f}%")
            bits.append(_fmt_duration(elapsed))
            # Extrapolate from actual progress instead of the keyspace estimate.
            # This is measured reality, and it's what answers "how much longer".
            if percent and percent > 1.0 and elapsed > 5:
                remaining = elapsed * (100.0 - percent) / percent
                bits.append(f"~{_fmt_duration(remaining)} left")
            return "  ".join(bits)

        try:
            if status is not None:
                status.start()
            for raw_line in proc.stdout:
                line = raw_line.rstrip()
                hashcat_output.append(line)
                spd = _parse_hashcat_speed(line)
                if spd is not None:
                    speeds.append(spd)
                    have_speed = True
                    last_speed = spd
                    if focus is not None:
                        focus.set_metrics(speed=spd)
                    else:
                        status.update(_describe())
                pct = _parse_hashcat_progress(line)
                if pct is not None:
                    percent = pct
                    if focus is not None:
                        focus.set_metrics(percent=pct)
                    else:
                        status.update(_describe())
                if time_limit and (time.monotonic() - started) > time_limit:
                    timed_out = True
                    log_debug(f"_run_hashcat_attack[{label}]: over time limit ({time_limit:.0f}s), stopping stage")
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break
                if not kernel_init_done and line and not line.startswith("WPA*02*"):
                    kernel_init_done = True
                    if not have_speed and status is not None:
                        status.update("running...")
                    try:
                        lower_process_priority(proc.pid)
                    except Exception as e:
                        log_debug("_run_hashcat_attack: failed to set priority", str(e))
        finally:
            if status is not None:
                status.clear()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        hashcat_output.append(f"[EXIT CODE: {proc.returncode}]")
        _log_hashcat_output(f"HASHCAT OUTPUT [{label}]", hashcat_output)

        potfile_after = _read_potfile(potfile)
        if potfile_after - potfile_before:
            return "found", speeds
        if timed_out:
            return "timeout", speeds
        if proc.returncode not in (0, 1):
            log_debug(f"_run_hashcat_attack[{label}]: unexpected rc={proc.returncode}")
            return "error", speeds
        return "exhausted", speeds
    except KeyboardInterrupt:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        raise
    except Exception as e:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        log_error(f"Hashcat attack failed [{label}]", e)
        return "error", speeds


def crack_with_hashcat(
    hc22000_path: str, wordlist_path: str, display_essid: str, gpu_is_discrete: bool = False
) -> dict[str, str] | None:
    """Run the attack plan against every hash in ``hc22000_path``.

    Returns ``{essid: password}`` for what was recovered - empty when the plan ran
    to exhaustion without a hit - or ``None`` when hashcat itself could not run,
    which tells the caller to fall back to aircrack-ng.
    """
    start_time = time.time()
    hc22000_path = os.path.abspath(hc22000_path)
    wordlist_path = os.path.abspath(wordlist_path)
    hc_exe = get_hashcat_path()
    log_debug(f"crack_with_hashcat: start hc_exe={hc_exe!r} hc22000={hc22000_path} wordlist={wordlist_path}")
    if not hc_exe:
        log_error("crack_with_hashcat: hashcat binary not found")
        return None
    hc_dir = os.path.dirname(hc_exe)
    os.makedirs(HCOV_DIR, exist_ok=True)
    potfile = os.path.join(HCOV_DIR, "hashcat.potfile")

    try:
        with open(hc22000_path, "r") as _f:
            content = _f.read().strip()
        log_debug(f"crack_with_hashcat: hc22000 length={len(content)} starts_with={content[:80]}")
    except Exception as e:
        log_error("Failed to read hc22000 file", e)
        return None

    # NOTE: this used to run `pkill -9 -x hashcat` / `taskkill /im hashcat.exe`
    # to clear "lingering" processes. Problem is that kills every hashcat on the
    # machine, including one from another run of this same program. That actually
    # bit us on a 13-capture estate: a second instance killed six of this run's
    # stages mid-flight (the dictionary and both ISP masks included), each showing
    # up as "did not finish". The single-instance lock in main() now stops the
    # concurrent run that made this seem necessary, and every hashcat we start is
    # a child we already wait on.

    potfile_before = _read_potfile(potfile)
    networks = _parse_hc22000_networks(content)
    target_essids = [e for e, _ in networks if e]
    # A network cracked in an earlier run is already in the potfile. hashcat then
    # says "All hashes found in potfile" and exits without writing anything, so if
    # we only watched for new entries we'd report a known password as a failure.
    found: dict[str, str] = {}  # essid -> password
    found_via: dict[str, str] = {}  # essid -> winning stage label
    for essid, pw in _potfile_results(potfile_before).items():
        if essid in target_essids:
            found[essid] = pw
            found_via[essid] = "previous run (potfile)"
            colored_log("success", f"{essid}: already recovered - {pw}")
    if target_essids and all(e in found for e in target_essids):
        log_debug("crack_with_hashcat: every network already in the potfile, nothing to run")
        return found

    # Flag up front when a network's ISP ships random label keys: no computed key
    # or mask can reach it, only a changed password is in range.
    for essid, _bssid in networks:
        isp = ph_random_key_isp(essid)
        if isp:
            colored_log(
                "info",
                f"{essid}: {isp} gear uses a random per-device key - no derivable "
                f"shape, so only the dictionary/pattern stages can hit it.",
            )

    hash_lines = [ln for ln in content.splitlines() if ln.strip()]
    salts = _salt_count(networks)
    if salts > 1:
        colored_log(
            "info",
            f"{salts} distinct SSIDs = {salts} PBKDF2 salts: every candidate is derived "
            f"once per network, so stage times scale by {salts}x.",
        )

    plan = _build_attack_plan(hc_dir, wordlist_path)
    # ISP-family hex masks (PLDT/Converge) slot in after every dictionary stage
    # and before the generic brute force. They're the most targeted of the brute
    # stages, but each still sweeps 16^6 candidates (minutes on an iGPU), so we
    # can't let them delay the dictionary, which is far cheaper per hit.
    isp_masks = _isp_mask_stages_for_networks(networks)
    if isp_masks:
        brute_at = next(
            (i for i, a in enumerate(plan) if a.get("kind") in ("hybrid", "mask", "rules")),
            len(plan),
        )
        plan[brute_at:brute_at] = isp_masks
    # Try computed ISP keys + human-pattern guesses first: tiny keyspaces,
    # near-instant, and a direct hit on any router still on a predictable key.
    vendor_stages, vendor_temp_paths = _vendor_stages(content)
    plan[0:0] = vendor_stages
    budget_seconds = _stage_budget_seconds()
    # Benchmark first so we can show the plan in minutes instead of candidate
    # counts. A few seconds here buys an up-front answer to "how long will this
    # take", which otherwise only emerges stage by stage.
    measured = _benchmark_speed(hc_exe, hc_dir)
    _print_attack_plan(plan, salts, budget_seconds, measured)
    log_debug(f"crack_with_hashcat: plan={[a['label'] for a in plan]} budget={budget_seconds}s")
    if _active_focus is not None:
        _active_focus.set_plan([a["label"] for a in plan])

    all_speeds: list[int] = []
    speed_estimate: int | None = None  # measured H/s, used to gate later stages
    ran_ok = False  # a stage reached 'exhausted' or 'found' => hashcat works
    attempted: list[str] = []
    skipped: list[tuple[str, str]] = []
    errored: list[str] = []
    stage_potfile = potfile_before

    try:
        for i, attack in enumerate(plan, 1):
            keyspace = attack.get("keyspace")
            stage_path, stage_salts = _stage_hash_file(attack, hash_lines, hc22000_path)
            # Real work is candidates x salts: every network in the file gets its
            # own PBKDF2 pass over each candidate.
            work = keyspace * stage_salts if keyspace else None
            if attack.get("optional") and speed_estimate and work:
                est = work / speed_estimate
                if est > budget_seconds:
                    console.print(
                        f"  [dim]- [{i:>2}/{len(plan)}] {attack['label']} - skipped, ~{_fmt_duration(est)} "
                        f"at {_fmt_speed(speed_estimate)}[/dim]"
                    )
                    log_debug(f"crack_with_hashcat: skip stage {i} est={est:.0f}s > budget={budget_seconds}s")
                    skipped.append(
                        (attack["label"], f"~{_fmt_duration(est)} exceeds the {_fmt_duration(budget_seconds)} budget")
                    )
                    continue
            stage_started = time.time()
            write_progress(
                state="running",
                stage=f"{i}/{len(plan)}",
                label=attack["label"],
                recovered=f"{len(found)}/{len(target_essids) or 1}",
                run_elapsed=_fmt_duration(time.time() - start_time),
                stage_started=time.strftime("%H:%M:%S"),
            )
            if _active_focus is not None:
                _active_focus.set_stage(i, attack["label"])
            # Optional stages got admitted on an estimate, so hold them to it. The
            # mandatory dictionary stages have no cap; they're the core attack.
            time_limit = budget_seconds * 1.5 if attack.get("optional") else None
            status, speeds = _run_hashcat_attack(
                hc_exe, hc_dir, stage_path, attack, potfile, display_essid, gpu_is_discrete, i, len(plan),
                stage_potfile, time_limit, start_time,
            )
            all_speeds += speeds
            speed_estimate = _update_speed_estimate(speed_estimate, speeds, work)
            took = _fmt_duration(time.time() - stage_started)
            run_so_far = _fmt_duration(time.time() - start_time)
            if status == "found":
                ran_ok = True
                console.print(
                    f"  [bold green]+[/bold green] [{i:>2}/{len(plan)}] {attack['label']} "
                    f"[dim]- hit after {took}[/dim]"
                )
                stage_potfile = _read_potfile(potfile)
                for essid, pw in _potfile_results(stage_potfile).items():
                    if essid in found:
                        continue
                    if target_essids and essid not in target_essids:
                        continue  # an older entry for some other capture
                    found[essid] = pw
                    found_via[essid] = attack["label"]
                    console.print(f"  [green]+[/green] {essid}: [bold green]{pw}[/bold green]")
                    if _active_focus is not None:
                        _active_focus.set_recovered(len(found))
                # Keep going while any network in this capture is still unsolved.
                # A shared run costs the same as just cracking the one that fell.
                if not target_essids or all(e in found for e in target_essids):
                    break
                remaining = [e for e in target_essids if e not in found]
                console.print(f"  [dim]{len(remaining)} still unsolved - continuing the plan[/dim]")
                continue
            if status == "exhausted":
                ran_ok = True
                attempted.append(attack["label"])
                console.print(
                    f"  [green]·[/green] [{i:>2}/{len(plan)}] {attack['label']} "
                    f"[dim]- no match ({took}, run {run_so_far})[/dim]"
                )
                continue
            if status == "timeout":
                ran_ok = True
                console.print(
                    f"  [yellow]![/yellow] [{i:>2}/{len(plan)}] {attack['label']} "
                    f"[dim]- stopped after {took}, its estimate did not hold[/dim]"
                )
                skipped.append((attack["label"], f"stopped after {took}, estimate did not hold"))
                continue
            # status == "error"
            if i == 1 and not ran_ok:
                # hashcat itself can't run (e.g. no device) => let caller fall back to aircrack.
                log_debug("crack_with_hashcat: first stage errored, aborting for fallback")
                return None
            errored.append(attack["label"])
            console.print(
                f"  [red]x[/red] [{i:>2}/{len(plan)}] {attack['label']} "
                f"[dim]- did not finish, hashcat exited abnormally[/dim]"
            )
            log_debug(f"crack_with_hashcat: stage {i} errored, continuing")
    except KeyboardInterrupt:
        colored_log("warning", "Hashcat cracking interrupted by user.")
        interrupted = True
    else:
        interrupted = False
    finally:
        # The generated candidate lists and the per-stage hash subset are all
        # temporary, so clean them up on every exit path, including the early
        # return that hands over to aircrack-ng.
        for _vp in (*vendor_temp_paths, os.path.join(HCOV_DIR, "_stage.hc22000")):
            try:
                os.remove(_vp)
            except OSError:
                pass

    # Hand the stage outcomes to the run-level record so a later report can state
    # exactly what was searched and what was left out of budget.
    record_effort(attempted, skipped)

    write_progress(
        state="finished",
        stage=f"{len(plan)}/{len(plan)}",
        label="complete",
        recovered=f"{len(found)}/{len(target_essids) or 1}",
    )
    duration_str = _fmt_duration(time.time() - start_time)
    avg_speed = sum(all_speeds) // len(all_speeds) if all_speeds else 0
    avg_speed_str = _fmt_speed(avg_speed)
    console.print(
        f"\n  [dim]Duration[/dim] [bold]{duration_str}[/bold]"
        f"    [dim]Average[/dim] [bold]{avg_speed_str}[/bold]"
        f"    [dim]Recovered[/dim] [bold]{len(found)}/{len(target_essids) or 1}[/bold]\n"
    )

    if interrupted:
        # Save what we recovered, then re-raise the interrupt. If we swallowed it
        # here, Ctrl+C only cancelled the current capture: the caller's loop just
        # moved on to the next one, so stopping an 11-capture run took eleven
        # presses and usually left the process alive.
        for essid, password in found.items():
            _write_result_file(
                essid or display_essid, password, found_via.get(essid, ""),
                wordlist_path, duration_str, avg_speed_str,
            )
        raise KeyboardInterrupt

    for essid, password in found.items():
        label = found_via.get(essid, "")
        log_debug(f"crack_with_hashcat: FOUND essid={essid!r} password={password!r} via {label!r} time={duration_str}")
        _write_result_file(
            essid or display_essid,
            password,
            label,
            wordlist_path,
            duration_str,
            avg_speed_str,
        )

    unsolved = [e for e in target_essids if e not in found]
    if found and not unsolved:
        return found

    if not ran_ok and not found:
        # Every stage errored, so hashcat isn't usable. Tell the caller to fall back.
        log_debug("crack_with_hashcat: no stage ran successfully, returning None")
        return None
    if interrupted:
        return found

    if unsolved:
        # Show the stage detail even on a partial success. The networks that didn't
        # fall are exactly the ones whose skipped stages the user may want back.
        console.print(f"\n[bold yellow]Not recovered ({len(unsolved)}):[/bold yellow]")
        for name in unsolved:
            console.print(f"  [dim]- {name}[/dim]")
    else:
        console.print("\n[bold yellow]Attack exhausted - password not found.[/bold yellow]")
    if attempted:
        console.print(f"[bold]Searched and exhausted ({len(attempted)}):[/bold]")
        for label in attempted:
            console.print(f"  [dim]- {label}[/dim]")
    if errored:
        console.print(
            "[bold red]Stages that did not finish:[/bold red] " + ", ".join(errored)
        )
        console.print("  [dim]These were not searched. See logs/ for hashcat's exit code.[/dim]")
    if skipped:
        console.print("[bold]Stages not searched:[/bold]")
        for label, reason in skipped:
            console.print(f"  [dim]- {label} - {reason}[/dim]")
        console.print(
            "\n  [dim]To search them anyway, raise the per-stage budget:  "
            "python main.py -b 240[/dim]"
        )
    if all_speeds:
        log_debug(
            f"crack_with_hashcat: exhausted stages={attempted!r} "
            f"skipped={skipped!r} avg_speed={sum(all_speeds)//max(1,len(all_speeds))} H/s"
        )
    log_debug(f"crack_with_hashcat: stages exhausted, unsolved={unsolved!r}")
    return found


def _write_result_file(
    essid: str,
    password: str,
    winning_label: str,
    wordlist_path: str,
    duration_str: str,
    avg_speed_str: str,
) -> None:
    """Persist one cracked network to ``cracked_results/`` (mode 0600)."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    result_file = os.path.join(RESULTS_DIR, f"{sanitize_ssid(essid)}_cracked_password.txt")
    try:
        with open(result_file, "w") as f:
            f.write(f"Network (ESSID): {essid}\n")
            f.write(f"Wordlist Used: {os.path.basename(wordlist_path)}\n")
            f.write(f"Found Via: {winning_label}\n")
            f.write(f"Password Found: {password}\n")
            f.write(f"Time Taken: {duration_str}\n\n")
            f.write("--- Cracking Statistics ---\n")
            f.write(f"Total Duration : {duration_str}\n")
            f.write(f"Avg Speed      : {avg_speed_str}\n")
        if sys.platform != "win32":
            try:
                os.chmod(result_file, 0o600)
            except OSError:
                pass
        console.print(f"  Saved to: {result_file}")
    except OSError as e:
        log_error("Failed to write result file", e)


def hashcat_crack_handshake(
    handshake_path: str,
    wordlist_path: str,
    display_essid: str,
    gpu_is_discrete: bool = False,
    packets: list | None = None,
) -> dict[str, str] | None:
    log_debug(
        f"hashcat_crack_handshake: start handshake={handshake_path} wordlist={wordlist_path} essid={display_essid!r}"
    )
    hc_exe = get_hashcat_path()
    if not hc_exe:
        log_debug("hashcat_crack_handshake: hashcat path not cached, aborting")
        return None
    colored_log("info", "Converting capture to hashcat format (hc22000)...")
    hc22000_path = os.path.join(HCOV_DIR, strip_capture_extension(handshake_path) + ".hc22000")
    log_debug(f"hashcat_crack_handshake: hc22000 output path: {hc22000_path}")
    analysis = convert_capture(handshake_path, hc22000_path, packets)
    if analysis is None:
        colored_log("error", "Nothing crackable in this capture - no PMKID and no pairable handshake.")
        log_debug("hashcat_crack_handshake: convert_capture found nothing")
        return None
    if not warmup_hashcat_kernel(hc22000_path):
        log_debug("hashcat_crack_handshake: warmup failed, continuing anyway")
    log_debug("hashcat_crack_handshake: conversion OK, calling crack_with_hashcat")
    result = crack_with_hashcat(hc22000_path, wordlist_path, display_essid, gpu_is_discrete)
    log_debug(f"hashcat_crack_handshake: crack_with_hashcat returned {result!r}")
    try:
        os.remove(hc22000_path)
        log_debug(f"hashcat_crack_handshake: cleaned up temp file {hc22000_path}")
    except OSError:
        pass
    return result


def hashcat_crack_batch(
    captures: dict, wordlist_path: str, gpu_is_discrete: bool = False, return_lines: bool = False
):
    """Crack every network from every capture in a single pass.

    hashcat checks each candidate against all hashes loaded, so a stage costs the
    same whether the file holds one network or fifty. Running the plan per capture
    therefore repeats the expensive generic stages (the 8.5M dictionary, the digit
    masks) once per file - on a real estate of a dozen captures that is hours of
    duplicated work for no extra coverage.

    ``captures`` maps capture path -> parsed packets (or None to re-read).
    """
    merged_lines: list[str] = []
    seen: set[str] = set()
    for path, packets in captures.items():
        tmp = os.path.join(HCOV_DIR, strip_capture_extension(path) + ".hc22000")
        if convert_capture(path, tmp, packets) is None:
            colored_log("warning", f"Nothing crackable in {os.path.basename(path)} - skipped.")
            continue
        try:
            with open(tmp, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        merged_lines.append(line)
        except OSError as e:
            log_error(f"Failed to read converted hashes for {path}", e)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    if not merged_lines:
        colored_log("error", "No crackable hashes in any capture.")
        return (None, []) if return_lines else None

    os.makedirs(HCOV_DIR, exist_ok=True)
    batch_path = os.path.join(HCOV_DIR, "_batch.hc22000")
    with open(batch_path, "w") as f:
        f.write("\n".join(merged_lines) + "\n")

    networks = _parse_hc22000_networks("\n".join(merged_lines))
    colored_log(
        "info",
        f"Cracking {len(networks)} network(s) from {len(captures)} capture(s) in one pass "
        f"({len(merged_lines)} hashes) - every stage is shared.",
    )
    if not warmup_hashcat_kernel(batch_path):
        log_debug("hashcat_crack_batch: warmup failed, continuing anyway")
    try:
        result = crack_with_hashcat(batch_path, wordlist_path, "all networks", gpu_is_discrete)
    finally:
        try:
            os.remove(batch_path)
        except OSError:
            pass
    return (result, merged_lines) if return_lines else result


def crack_networks_individually(
    hash_lines: list, targets: list, wordlist_path: str, gpu_is_discrete: bool = False
) -> dict[str, str]:
    """Second pass: attack each unsolved network on its own.

    Cost scales with the number of distinct SSIDs, because each is a separate
    PBKDF2 salt. A stage that cannot fit the time budget across a dozen networks
    fits comfortably against one - "dictionary + rules" over an 8.5M list is ~16 h
    for eleven networks and ~1.4 h for one. Breadth first to catch anything on a
    factory key, then depth on whatever is left.
    """
    found: dict[str, str] = {}
    os.makedirs(HCOV_DIR, exist_ok=True)
    for idx, essid in enumerate(targets, 1):
        wanted = essid.encode("utf-8", errors="replace").hex()
        lines = [ln for ln in hash_lines if ln.split("*")[5:6] == [wanted]]
        if not lines:
            continue
        console.print(f"\n{'-' * 60}")
        colored_log("info", f"Deep pass {idx}/{len(targets)}: {essid} (alone, so the heavy stages fit)")
        path = os.path.join(HCOV_DIR, "_deep.hc22000")
        try:
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            result = crack_with_hashcat(path, wordlist_path, essid, gpu_is_discrete)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        if result:
            found.update(result)
    return found


class HashcatBackend:
    def __init__(self, gpu_is_discrete: bool = False, packets_map: dict | None = None):
        self.gpu_is_discrete = gpu_is_discrete
        self.packets_map = packets_map or {}
        # Merged hc22000 lines from the last batch, so a later deep pass can
        # re-slice them per network without re-reading every capture.
        self.last_batch_lines: list = []

    def crack(self, handshake_path: str, wordlist_path: str, display_essid: str) -> dict[str, str] | None:
        packets = self.packets_map.get(handshake_path)
        return hashcat_crack_handshake(handshake_path, wordlist_path, display_essid, self.gpu_is_discrete, packets)

    def crack_all(self, handshake_paths: list, wordlist_path: str) -> dict[str, str] | None:
        """Crack every capture in one shared pass. See hashcat_crack_batch."""
        captures = {p: self.packets_map.get(p) for p in handshake_paths}
        result, self.last_batch_lines = hashcat_crack_batch(
            captures, wordlist_path, self.gpu_is_discrete, return_lines=True
        )
        return result
