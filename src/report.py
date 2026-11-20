"""Engagement report generation.

The terminal output scrolls away and is not something a client can be handed.
This writes the same findings as a self-contained Markdown file: what was in
scope, what each network runs, what was recovered, and what was searched without
success - the last being the part that makes a negative result meaningful rather
than just "we didn't get in".
"""

import os
import platform
from datetime import datetime

from src.console import log_debug, log_error


def _severity(net, password: str | None) -> str:
    """Client-facing risk for one network."""
    if password:
        return "HIGH"
    if not net.is_psk:
        return "INFO"
    return "LOW"


def _finding(net, password: str | None) -> str:
    if password:
        return "Passphrase recovered from a captured handshake."
    if not net.is_psk:
        return f"{net.security}: not passphrase-based, out of scope for this attack."
    return "Passphrase not recovered within the configured effort."


def build_report(
    networks: list,
    results: dict,
    *,
    wordlist: str,
    duration: str,
    stages_run: list | None = None,
    stages_skipped: list | None = None,
    gpu: str | None = None,
) -> str:
    """Render the engagement report as Markdown."""
    stages_run = stages_run or []
    stages_skipped = stages_skipped or []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    recovered = [n for n in networks if results.get(n.display_name)]

    out: list[str] = []
    out.append("# Wireless Assessment - WPA/WPA2 Passphrase Recovery\n")
    out.append(f"**Date:** {now}  ")
    out.append(f"**Platform:** {platform.system()} {platform.release()}  ")
    if gpu:
        out.append(f"**Compute:** {gpu}  ")
    out.append(f"**Wordlist:** `{os.path.basename(wordlist)}`  ")
    out.append(f"**Duration:** {duration}\n")

    out.append("## Summary\n")
    out.append(f"{len(recovered)} of {len(networks)} in-scope network(s) had their passphrase recovered.\n")
    out.append("| Network | BSSID | Security | Result | Risk |")
    out.append("|---|---|---|---|---|")
    for net in networks:
        pw = results.get(net.display_name)
        result = f"`{pw}`" if pw else "not recovered"
        out.append(f"| {net.display_name} | `{net.bssid}` | {net.security or 'unknown'} | {result} | {_severity(net, pw)} |")
    out.append("")

    out.append("## Findings\n")
    for net in networks:
        pw = results.get(net.display_name)
        out.append(f"### {net.display_name}  ({_severity(net, pw)})\n")
        out.append(f"- **BSSID:** `{net.bssid}`")
        out.append(f"- **Security:** {net.security or 'unknown'}")
        out.append(f"- **Handshake material:** {len(net.hashes)} crackable hash(es)"
                   f"{', PMKID present' if net.has_pmkid else ''}")
        out.append(f"- **Clients observed:** {len(net.clients)}")
        out.append(f"- **Finding:** {_finding(net, pw)}")
        if pw:
            out.append(f"- **Recovered passphrase:** `{pw}`")
        out.append("")

    if stages_run or stages_skipped:
        out.append("## Effort expended\n")
        out.append(
            "A negative result is only meaningful alongside what was searched. "
            "The following candidate sets were exhausted without a match:\n"
        )
        for label in stages_run:
            out.append(f"- {label}")
        if stages_skipped:
            out.append("\nNot searched (exceeded the configured time budget):\n")
            for label, reason in stages_skipped:
                out.append(f"- {label} - {reason}")
        out.append("")

    out.append("## Recommendations\n")
    if recovered:
        out.append(
            "- **Change the passphrase on every network listed as recovered.** Each was "
            "guessed from a captured handshake without any interaction with the network."
        )
        out.append(
            "- Replace factory-default and pattern-based passphrases (ISP defaults, names "
            "with appended digits, dates, phone numbers) with a random passphrase of at "
            "least 16 characters."
        )
    out.append(
        "- Where supported, enable **WPA3-SAE**: it is not vulnerable to the offline "
        "dictionary attack used here, because the handshake does not expose a crackable value."
    )
    out.append(
        "- Enable **802.11w (Protected Management Frames)** to make deauthentication-driven "
        "handshake capture substantially harder."
    )
    out.append(
        "- Disable **WPS** where present; its PIN is a separate and weaker path to the same key."
    )
    out.append("")

    out.append("## Scope and limitations\n")
    out.append(
        "- Testing was performed offline against previously captured 802.11 handshakes. "
        "No traffic was injected and no network was accessed as part of this analysis."
    )
    out.append(
        "- A network not recovered here is **not proven secure**: it means the passphrase "
        "was outside the candidate sets searched within the time allotted."
    )
    out.append(
        "- Networks using WPA-Enterprise (802.1X) or WPA3-SAE are reported for completeness "
        "but are not susceptible to this technique."
    )
    out.append("")
    return "\n".join(out)


def write_report(path: str, content: str) -> bool:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        log_debug(f"write_report: wrote {len(content)} bytes to {path}")
        return True
    except OSError as e:
        log_error(f"Failed to write report to {path}", e)
        return False
