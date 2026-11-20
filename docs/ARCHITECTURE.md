# n3rve Architecture

## Overview

n3rve is a modular WPA/WPA2 passphrase recovery tool. It captures 802.11 handshakes and PMKIDs from `.cap`/`.pcap`/`.pcapng` files, converts them to hashcat's hc22000 format, and cracks them using a speed-gated, multi-stage attack plan.

## Data Flow

```
Capture Files (.cap/.pcap/.pcapng)
        │
        ▼
┌─────────────────┐
│  handshake.py   │  Frame parsing, EAPOL pairing by replay
│  validator.py   │  counter, PMKID extraction, ESSID recovery
└─────────────────┘
        │
        ▼
┌─────────────────┐
│  hashcat/       │  Convert to hc22000 format
│  convert.py     │  (scapy parser + hcxpcapngtool merge)
└─────────────────┘
        │
        ▼
┌─────────────────┐
│  keygen.py      │  ISP default-key generation (PH + intl)
│  crack.py       │  Speed-gated multi-stage attack plan
└─────────────────┘
        │
        ▼
┌─────────────────┐
│  hashcat (GPU)  │  Primary cracker (OpenCL/CUDA)
│  aircrack-ng    │  CPU fallback
└─────────────────┘
        │
        ▼
┌─────────────────┐
│  report.py      │  Engagement Markdown report
│  cracked_results/  Recovered passwords
└─────────────────┘
```

## Key Design Decisions

### 1. Single Shared Pass Over All Networks

hashcat checks each candidate against all loaded hashes simultaneously. WPA PMK derivation is `PBKDF2(passphrase, ESSID)`, so each SSID is a separate salt. Running one pass over all captures costs the same as cracking one - this is the core performance optimization.

### 2. Breadth-First, Then Depth-First

The attack plan runs cheap, high-probability stages first (computed ISP keys, pattern keys, dictionary). If networks remain unsolved, the `--deep` flag attacks each individually, where expensive stages (dictionary + rules) become affordable against a single salt.

### 3. Speed-Gated Stages

Each stage's runtime is estimated from measured hashcat throughput. Stages that cannot finish within the per-stage budget (`HANDSHAKE_MAX_STAGE_MIN`, default 120 min) are skipped automatically. A fast GPU sweeps the full plan; an integrated GPU quietly skips what would take days.

### 4. Replay-Counter-Accurate Pairing

EAPOL frames from different handshake attempts are never spliced. Messages are matched by key replay counter with a configurable timing window (`HANDSHAKE_EAPOL_TIMEOUT`, default 2s). This prevents producing well-formed but uncrackable hashes.

## Modules

| Module | Responsibility |
|--------|---------------|
| `main.py` | CLI entry point, orchestration |
| `src/config.py` | Paths, URLs, constants |
| `src/console.py` | Rich terminal output, logging |
| `src/bootstrap.py` | First-run pip install |
| `src/setup.py` | Auto-install aircrack-ng, hashcat, hcxtools |
| `src/handshake.py` | Frame parsing, pairing, PMKID, ESSID |
| `src/validator.py` | Per-network validation report |
| `src/keygen.py` | ISP default-key generation |
| `src/cracker.py` | Aircrack-ng CPU backend |
| `src/hashcat/crack.py` | hashcat GPU backend, attack plan |
| `src/hashcat/convert.py` | Capture → hc22000 conversion |
| `src/hashcat/setup.py` | hashcat install, GPU detection |
| `src/report.py` | Engagement Markdown report |
| `src/utils.py` | Downloads, locking, wordlist utils |
| `src/backend.py` | CrackerBackend protocol |
| `src/gpu.py` | Discrete GPU detection |

## Extending n3rve

- **New ISP keygen**: Add a function to `src/keygen.py` returning candidate passwords, then wire it into `global_default_candidates()` or `ph_isp_candidates()`.
- **New attack stage**: Add a stage dict to `_build_attack_plan()` in `src/hashcat/crack.py`.
- **New backend**: Implement `CrackerBackend` protocol in `src/backend.py` and wire it into `main.py`.
