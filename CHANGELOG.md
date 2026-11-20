# Changelog

All notable changes to **n3rve** are documented here. This project is a derivative
of [handshakeCracker](https://github.com/Mysteriza/handshakeCracker) by
[Mysteriza](https://github.com/Mysteriza); the original architecture and design
are theirs. See the Crediting section below.

## [1.0.0] - 2026-11-19

First public release of the `n3rve` derivative.

### Crediting / attribution
- `handshakeCracker` by **Mysteriza** is credited prominently in the README, with
  links to the original project.
- Additional credit for ISP default-key derivations to **RouterKeygen** and
  **PSKracker**, and to **hashcat**, **aircrack-ng** and **hcxtools**.

### Added
- **rockyou.txt (14.3M) support** - auto-detected from `/usr/share/wordlists/`
  and from a new `wordlists/` drop-in folder; the container image installs it.
- **`wordlists/` drop-in directory** - any `*.txt` is used automatically
  (deduplicated, WPA-valid only).
- **SSID-derived attack stages**: SSID name variants (letter/digit split, year
  expansion such as `name08` → `name2008`), plus SSID + 2/3/4-digit attacks,
  implemented as flat wordlists (not `-a 6` hybrids) to avoid GPU starvation.
- **Common Filipino names + realistic birthdates** candidate stage (~67k).
- **Three rule tiers** - fast (~11 rules), medium (~41), full (~161) - so common
  mutations run even when a large rule set is skipped for budget.
- **Container support** - `Containerfile`, `podman-compose.yaml`,
  `podman-run.sh` (Kali image, GPU passthrough, Intel OpenCL preinstalled).
- **CI** - GitHub Actions job running `ruff` and `pytest`.
- **Docs** - `docs/ARCHITECTURE.md`, `docs/CRACKING-IMPROVEMENTS.md`,
  `PORTFOLIO.md`, `CONTRIBUTING.md`, `SECURITY.md`.

### Changed - behaviour vs upstream (transparent list)
- **Large rule sets are opt-in.** `rockyou-30000` (~30k rules) is no longer
  bundled into the default rules stage: with an 8.5M wordlist that is ~2.5×10¹⁴
  candidates and can never fit a sane budget, so it silently made the whole rules
  stage a no-op. Set `HANDSHAKE_FULL_RULES=1` to opt back in.
- **Redundant birthdate masks replaced.** Two "PH birthdate" masks were identical
  in cost to the generic 8-digit mask; they were removed and replaced with a
  realistic birthdate wordlist (~60k real dates in three layouts), which is far
  cheaper and actually runs.
- **Single combined rule file** is written and passed via one `-r`. Passing
  multiple `-r` files made hashcat's true runtime diverge from the estimated
  keyspace by ~16×, defeating the per-stage budget gate.

### Fixed
- **PH mobile-prefix mask keyspace** was declared `10^8` for a mask with only 7
  wildcards (`10^7`), making each prefix look 10× more expensive and causing them
  to be skipped. Corrected to `10^7`; the prefixes now run.
- Removed dead code and an unused import; replaced a `shell=True` shell call with
  ANSI escape codes (clear-screen).
- Memoised ISP candidate generation (`lru_cache`) to avoid recomputing the same
  derivations across stages.
- Bounded concurrent `aircrack-ng` processes with a semaphore; removed a redundant
  process-termination call.
- Test suite: added `pythonpath = ["."]` so `pytest` imports `src` without manual
  setup; real-capture tests now **skip** when the (sensitive, uncommitted) fixture
  is absent.

### Repository hygiene
- `.gitignore` hardened: captures (`handshakes/`), recovered passwords
  (`cracked_results/`), hashes/potfiles (`hc22000_cache/`), logs, backups, real
  capture fixtures, large/downloaded wordlists and binaries are excluded.
- Clean single-commit history (no large binary/wordlist blobs).
