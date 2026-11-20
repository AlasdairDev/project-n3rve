"""Capture validation and the per-network report shown before cracking.

Reporting is per *network*, not per file: one capture routinely holds several
APs, and a file-level "VALID" hides which of them actually produced a crackable
hash. Every row here corresponds to one hc22000 hash line that will be handed to
the cracker.
"""

import os
from dataclasses import dataclass, field
from typing import Any

from rich import box
from rich.table import Table

from src.console import console
from src.handshake import (  # noqa: F401  (re-exported for callers and tests)
    CaptureAnalysis,
    Network,
    analyze_packets,
    classify_eapol as _classify_eapol,
    extract_pmkid,
    read_relevant_packets,
)

CHECK = "OK"
CROSS = "--"


@dataclass
class ValidationResult:
    is_valid: bool = False
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    has_pmkid: bool = False
    error: str | None = None
    relevant_packets: list[Any] = field(default_factory=list)
    analysis: CaptureAnalysis | None = None

    @property
    def networks(self) -> list[Network]:
        return self.analysis.all_networks if self.analysis else []

    @property
    def valid_networks(self) -> list[Network]:
        return self.analysis.valid_networks if self.analysis else []


def validate_handshake(filepath: str) -> ValidationResult:
    """Analyse one capture and summarise what is crackable in it."""
    result = ValidationResult()
    try:
        packets = read_relevant_packets(filepath)
    except Exception as e:
        result.error = f"cannot read pcap: {e}"
        return result

    result.relevant_packets = packets
    analysis = result.analysis = analyze_packets(packets, filepath)
    if analysis.error:
        result.error = analysis.error
        return result

    for net in analysis.all_networks:
        result.has_m1 |= net.has_m1
        result.has_m2 |= net.has_m2
        result.has_m3 |= net.has_m3
        result.has_m4 |= net.has_m4
        result.has_pmkid |= net.has_pmkid
    result.is_valid = bool(analysis.valid_networks)
    return result


def extract_essid_bssid(packets: list[Any]) -> tuple[str, str]:
    """Recover (essid, bssid_hex) for the first network in a packet list.

    Kept for the single-network callers (the aircrack-ng fallback path, which can
    only work on one network at a time). bssid_hex is lower-case with no
    separators; empty strings when absent.
    """
    analysis = analyze_packets(packets)
    nets = analysis.valid_networks or analysis.all_networks
    for net in nets:
        if net.essid:
            return net.essid, net.bssid.replace(":", "")
    if nets:
        return "", nets[0].bssid.replace(":", "")
    return "", ""


def _status_style(ok: bool) -> str:
    return "[green]VALID[/green]" if ok else "[red]INVALID[/red]"


def validate_all_handshakes(file_list: list[str]) -> tuple[dict[str, ValidationResult], list[tuple[str, str]]]:
    """Validate every capture and print the per-network report.

    Returns (valid files -> result, [(file, reason)] for the rest).
    """
    if not file_list:
        return {}, []
    console.rule("[bold cyan]Captures[/bold cyan]", style="cyan", align="left")
    console.print("[dim]A PMKID, or an M2 paired by replay counter with M1/M3, is crackable.[/dim]\n")

    results = [(f, validate_handshake(f)) for f in file_list]

    table = Table(
        show_header=True, header_style="bold", box=box.SIMPLE_HEAD,
        pad_edge=False, show_edge=False, border_style="dim",
    )
    table.add_column("File")
    table.add_column("Network")
    table.add_column("BSSID")
    table.add_column("Security")
    for col in ("M1", "M2", "M3", "M4", "PMKID"):
        table.add_column(col, justify="center")
    table.add_column("Hashes", justify="right")
    table.add_column("Status")

    valid: dict[str, ValidationResult] = {}
    invalid: list[tuple[str, str]] = []
    network_count = 0

    for f, v in results:
        basename = os.path.basename(f)
        if v.error:
            table.add_row(basename, "-", "-", "-", *([CROSS] * 5), "0", "[red]ERROR[/red]")
            invalid.append((f, v.error))
            continue

        nets = v.networks
        if not nets:
            table.add_row(basename, "-", "-", "-", *([CROSS] * 5), "0", "[red]INVALID[/red]")
            invalid.append((f, "no 802.11 networks found in the capture"))
            continue

        for i, net in enumerate(sorted(nets, key=lambda n: (not n.is_valid, n.display_name))):
            network_count += 1
            name = net.display_name
            if net.essid_source == "filename":
                name += " [dim](name from file)[/dim]"
            security = net.security or "?"
            if not net.is_psk:
                security = f"[yellow]{security}[/yellow]"   # no passphrase exists
            elif net.security in ("Open", "WEP"):
                security = f"[red]{security}[/red]"
            table.add_row(
                basename if i == 0 else "",
                name,
                net.bssid,
                security,
                *[
                    f"[green]{CHECK}[/green]" if flag else f"[dim]{CROSS}[/dim]"
                    for flag in (net.has_m1, net.has_m2, net.has_m3, net.has_m4)
                ],
                f"[green]{CHECK}[/green]" if net.has_pmkid else f"[dim]{CROSS}[/dim]",
                f"[bold]{len(net.hashes)}[/bold]" if net.hashes else "[dim]0[/dim]",
                _status_style(net.is_valid),
            )

        if v.is_valid:
            valid[f] = v
            for net in nets:
                if not net.is_valid:
                    console.print(f"  [dim]{os.path.basename(f)}: skipping {net.display_name} - {net.reason()}[/dim]")
        else:
            invalid.append((f, nets[0].reason() if len(nets) == 1 else "no network in this capture is crackable"))

    console.print("")
    console.print(table)
    crackable = sum(len(v.valid_networks) for _, v in results if not v.error)
    console.print(
        f"\n  {len(valid)}/{len(results)} capture(s) usable - "
        f"{crackable}/{network_count} network(s) crackable"
    )
    return valid, invalid
