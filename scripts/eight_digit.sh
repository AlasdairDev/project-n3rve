#!/usr/bin/env bash
# Targeted 8-digit brute-force (mode 22000, mask ?d?d?d?d?d?d?d?d) on captures
# you own / are authorized to assess. Generic: takes capture paths as arguments.
#
#   ./scripts/eight_digit.sh handshakes/capture1.pcap handshakes/capture2.pcap
#
# Writes a per-capture result line to logs/masks/summary.txt.
set -u
cd /work || exit 1

CAPS="$*"
if [ -z "${CAPS:-}" ]; then
    echo "usage: $0 <capture.pcap> [<capture.pcap> ...]" >&2
    exit 1
fi

mkdir -p /work/logs/masks
SUM=/work/logs/masks/summary.txt
: > "$SUM"
echo "8-digit mask sweep - $(date)" >> "$SUM"

for c in $CAPS; do
    b=$(basename "$c")
    hc="/tmp/hc8_${b}.22000"
    python3 - "$c" "$hc" <<'PY' >/dev/null 2>&1
import sys
from src.hashcat.convert import convert_capture
convert_capture(sys.argv[1], sys.argv[2])
PY
    if [ ! -s "$hc" ]; then
        echo "$b : no hashes" >> "$SUM"
        continue
    fi
    before=$(grep -c . /work/hc22000_cache/hashcat.potfile 2>/dev/null || echo 0)
    hashcat -m 22000 -a 3 -O -w 2 \
        --session "m8_$(echo "$b" | md5sum | cut -c1-8)" \
        --potfile-path /work/hc22000_cache/hashcat.potfile \
        --status --status-timer 60 --quiet \
        "$hc" '?d?d?d?d?d?d?d?d' > "/work/logs/masks/${b}.log" 2>&1
    after=$(grep -c . /work/hc22000_cache/hashcat.potfile 2>/dev/null || echo 0)
    if [ "$after" -gt "$before" ]; then
        echo "$b : CRACKED (8-digit)" >> "$SUM"
        tail -n +"$((before+1))" /work/hc22000_cache/hashcat.potfile | sed 's/^/    /' >> "$SUM"
    else
        echo "$b : not 8-digit" >> "$SUM"
    fi
done
echo "DONE - $(date)" >> "$SUM"
