"""Write hc22000 hash files from a capture.

The extraction itself lives in :mod:`src.handshake`, which already merges this
project's scapy parser with ``hcxpcapngtool`` when that is installed. Doing the
merge there rather than here means the validation report, the hash file and the
attack plan all describe the same set of networks - a hash that shows up in the
table is one that actually gets cracked.
"""

import os

from src.console import log_error, log_debug
from src.handshake import (
    CaptureAnalysis,
    analyze_capture,
    analyze_packets,
    format_mac as _format_mac,  # noqa: F401  (re-exported: used by tests and callers)
)


def convert_capture(cap_path: str, output_path: str, packets: list | None = None) -> CaptureAnalysis | None:
    """Convert a capture to hc22000. Returns the analysis, or None when nothing
    crackable came out of it."""
    if packets is None:
        analysis = analyze_capture(cap_path)
    else:
        analysis = analyze_packets(packets, cap_path)

    if analysis.error:
        log_error(f"Failed to read {cap_path}", Exception(analysis.error))
        return None

    for net in analysis.all_networks:
        log_debug(
            f"convert_capture: {net.bssid} essid={net.essid!r} (via {net.essid_source or 'n/a'}) "
            f"M1={net.has_m1} M2={net.has_m2} M3={net.has_m3} M4={net.has_m4} "
            f"PMKID={net.has_pmkid} hashes={[h.source for h in net.hashes]}"
        )

    lines = analysis.hc22000_lines()
    if not lines:
        log_debug("convert_capture: nothing crackable extracted (no PMKID, no usable handshake)")
        return None

    log_debug(f"convert_capture: writing {len(lines)} hc22000 line(s) to {output_path}")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return analysis


def convert_cap_to_hc22000(cap_path: str, output_path: str, packets: list | None = None) -> bool:
    """Boolean wrapper around :func:`convert_capture`."""
    return convert_capture(cap_path, output_path, packets) is not None
