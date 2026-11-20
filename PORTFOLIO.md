# n3rve - Project Portfolio Summary

## One-Liner

**n3rve** is an automated WPA/WPA2 passphrase recovery tool that cracks captured Wi-Fi handshakes and PMKIDs using GPU-accelerated hashcat, with Philippine ISP default-key intelligence and client-ready engagement reporting.

## Elevator Pitch

n3rve takes `.cap`/`.pcap`/`.pcapng` capture files, extracts crackable WPA hashes (4-way handshakes and PMKIDs), and runs a speed-gated multi-stage attack plan - from computed ISP factory keys to an 8.5M-word dictionary - all in a single GPU pass. Built for authorized wireless security assessments, it includes a Podman container with GPU passthrough, replay-counter-accurate handshake pairing, and Markdown engagement reports for clients.

## Tech Stack

- **Python 3.10+** - core tool logic
- **hashcat** - GPU-accelerated WPA cracking (OpenCL/CUDA)
- **aircrack-ng** - CPU fallback backend
- **scapy** - 802.11 frame parsing
- **rich / prompt_toolkit** - terminal UI
- **Podman / Docker** - containerized deployment with GPU passthrough
- **pytest / ruff** - 200+ tests, CI pipeline

## Key Features Implemented

| Feature | Impact |
|---------|--------|
| GPU hashcat backend with speed-gated staging | Stages auto-skip when estimated runtime exceeds budget; fast GPU sweeps full plan, iGPU skips hopeless stages |
| Single shared pass over all networks | Cracking N networks costs the same as cracking 1 - critical for large estates |
| Replay-counter-accurate EAPOL pairing | Prevents spliced, uncrackable hashes; only pairs messages from the same handshake attempt |
| PMKID clientless attacks | Cracks networks with no connected client |
| PH ISP default-key generation | Computed factory keys for PLDT, Converge, Globe, Smart, DITO, Sky + international RouterKeygen ports |
| Engagement Markdown reports | Client-ready findings with risk ratings, effort expended, and remediation |
| Duplicate skip | Skips networks already cracked in prior runs (matched by SSID, not filename) |
| Podman container | Rootless GPU passthrough for Intel Iris Xe / NVIDIA / AMD |
| PH-specific masks | PH mobile (0917-0921), birthdates (MMDDYYYY), landline formats - added to every ISP family |
| Expanded hashcat rules | 60+ rules: PH mobile prefixes, years 2020-2025, leet speak, Filipino terms |
| Wordlist priority sorting | PH-first ordering: ISP names, mobile prefixes, years, Filipino terms tried first |

## Results (Controlled lab test - own equipment)

Run against handshake captures from my **own lab devices / networks I own**
(no third-party networks were accessed):

- Successfully recovered several weak/default WPA2 configurations
- GPU: Intel Iris Xe integrated (~39-46 kH/s on WPA)
- Dictionary stage: 8.5M words, ~31 minutes
- Previously cracked networks skipped automatically via duplicate detection

> No real passwords, SSIDs, or BSSIDs are published here.

## What I Learned / Engineering Highlights

- **Performance optimization**: Batching all networks into one hashcat pass reduced wall time from ~10 hours to ~1 hour on a 13-capture estate
- **Correctness**: Replay-counter matching prevents producing well-formed but uncrackable hashes - a subtle bug that wastes hours of GPU time
- **Graceful degradation**: Speed-gated staging means an integrated GPU completes useful work instead of grinding on hopeless brute-force masks
- **Container security**: Rootless Podman with device passthrough and SELinux labels for atomic hosts (Aurora/uBlue)
- **Defensible reporting**: "Effort expended" section makes negative results meaningful - shows exactly what was searched, not just "no hit"
- **PH-specific cracking**: Added PH mobile number masks (0917-0921), birthdate formats (MMDDYYYY), 60+ hashcat rules with Filipino terms and leet speak, and wordlist priority sorting that tries PH ISP names and mobile prefixes first

## Ethics & Authorized Use

This project is for **authorized security testing and education only**. All
testing described here was performed against **networks I own or had explicit
permission to assess**. No third-party networks were accessed, and no real
passwords, SSIDs, or BSSIDs are included in this repository. Do not use it on
networks you do not own or have written authorization to test.

## Links

- **Repo:** https://github.com/AlasdairDev/project-n3rve
- **Live demo:** Run `python3 main.py --list` against captures in `handshakes/`
- **Report sample:** `python3 main.py -r report.md`

---

### Suggested Resume Bullet

> **n3rve** - Built a GPU-accelerated WPA/WPA2 passphrase recovery tool (Python, hashcat, aircrack-ng) with Philippine ISP default-key intelligence, replay-counter-accurate handshake pairing, speed-gated attack staging, and client-ready engagement reporting. Containerized with Podman GPU passthrough. 200+ unit tests, CI pipeline. Validated in a controlled lab on my own equipment (authorized testing only).

### Suggested LinkedIn Description

> Built **n3rve**, an automated wireless security assessment tool for WPA/WPA2 passphrase recovery from captured 802.11 handshakes and PMKIDs.
>
> Key engineering challenges solved:
> - **Performance**: Single shared hashcat pass cracks all networks in a capture simultaneously (N networks = cost of 1)
> - **Correctness**: Replay-counter-accurate EAPOL pairing prevents spliced, uncrackable hashes
> - **Graceful degradation**: Speed-gated stages auto-skip on integrated GPUs instead of grinding on hopeless masks
> - **Defensible reporting**: Engagement reports document exactly what was searched, making negative results meaningful
>
> Stack: Python 3.10, hashcat (GPU/OpenCL), aircrack-ng (CPU), scapy, Podman, pytest, ruff
> Validated in a controlled lab on my own devices (authorized testing only).
> PH-specific enhancements: mobile number masks (0917-0921), birthdate formats, 60+ hashcat rules with Filipino terms and leet speak, wordlist priority sorting.
