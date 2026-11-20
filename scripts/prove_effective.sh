#!/usr/bin/env bash
# Per-handshake effectiveness sweep (deduplicated by SSID).
# Each unique network gets its own run (1 PBKDF2 salt -> full GPU speed), with a
# bounded per-stage budget. New cracks are detected by diffing cracked_results/.
set -u
cd /work || exit 1
mkdir -p /work/logs/prove
SUM=/work/logs/prove/summary.txt
: > "$SUM"
echo "n3rve per-handshake sweep - $(date)  budget=${BUDGET:-8}m/stage" >> "$SUM"
echo "==================================================" >> "$SUM"

strip() { sed 's/\x1b\[[0-9;]*m//g'; }

declare -A seen
n=0
for f in handshakes/*.pcap handshakes/*.pcapng handshakes/*.cap; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    # Deduplicate captures that share an SSID (same key -> same network).
    key=$(printf '%s' "$b" | sed -E 's/^HS_[0-9A-Fa-f]{12}_//; s/\.(pcapng|pcap|cap)$//')
    [ -n "${seen[$key]:-}" ] && continue
    seen[$key]=1
    n=$((n+1))

    before=$(ls /work/cracked_results 2>/dev/null | sort)
    rm -rf /tmp/prove_one; mkdir -p /tmp/prove_one
    cp "$f" /tmp/prove_one/
    rm -f /work/hc22000_cache/.run.lock
    python3 main.py -H /tmp/prove_one --default-wordlist -b "${BUDGET:-8}" \
        > "/work/logs/prove/${b}.log" 2>&1
    after=$(ls /work/cracked_results 2>/dev/null | sort)
    new=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") 2>/dev/null)

    echo "=== $b ===" >> "$SUM"
    if [ -n "$new" ]; then
        echo "    CRACKED -> $new" >> "$SUM"
        while IFS= read -r nf; do
            [ -z "$nf" ] && continue
            grep -h "Password Found" "/work/cracked_results/$nf" 2>/dev/null | sed 's/^/      /' >> "$SUM"
        done <<< "$new"
    elif strip < "/work/logs/prove/${b}.log" | grep -qi "already cracked"; then
        echo "    already cracked (previous run)" >> "$SUM"
    elif strip < "/work/logs/prove/${b}.log" | grep -qi "not found"; then
        echo "    not found" >> "$SUM"
    else
        echo "    (no result - see log)" >> "$SUM"
    fi
    echo "" >> "$SUM"
done
echo "ALL DONE ($n unique networks) - $(date)" >> "$SUM"
