# Cracking Improvement Notes

Notes captured after an end-to-end attempt on a real 22-capture Philippine
dataset on an **Intel Iris Xe iGPU (~38-43 kH/s at 1 salt; ~16 kH/s with 11
salts)**. 5 of 16 unique networks cracked (all weak/default passwords); 11 hard
networks resisted. This is the "how to go further" backlog, ordered by impact.

---

## 1. Where the real limits are

| Limit | Effect | Fix |
|---|---|---|
| **GPU throughput** | ~40 kH/s → a 9-digit mask is ~6.5 h/network | Discrete GPU / rented cloud GPU (10-50×) |
| **Wordlist breadth** | 8.5M + rockyou (14.3M) miss custom passwords | SecLists 10M, weakpass, breach compilations, PH-specific lists |
| **Mask coverage** | 9-digit, 11-digit mobile, 8-hex skipped on budget | Run per network with a large budget, or on a faster GPU |
| **Batching penalty** | 11 salts drop speed 38→16 kH/s (~2.3×) | Prefer per-network (1 salt) on weak GPUs |
| **Wrong/guessed ESSID** | If the SSID salt is wrong, the hash can NEVER crack | Only crack when the true ESSID is recovered |

> **Critical:** a network whose ESSID was guessed from the filename (e.g. the
> `HS` capture) cannot crack if that guess is wrong - ESSID is the PBKDF2 salt.
> The tool should flag `essid_source == "filename"` as "possibly uncrackable".

---

## 2. What this run already exhausted (per network)

- Computed ISP default keys (+ suffix variants)
- ISP/SSID pattern keys (~8k)
- Common PH names + realistic birthdates (~67k)
- SSID name variants (incl. letter/digit split + year expansion, e.g. `name08` → `name2008`)
- SSID words + 2/3/4 digits
- PH default wordlist (35k) + fast/medium/full PH rules
- dictionary: bundled 8.5M **and** rockyou 14.3M
- 8-digit mask (a few device-type candidates ruled out; others pending)

## 3. What was SKIPPED (budget) - must be tried to be thorough

| Stage | Est. time / network (iGPU) |
|---|---|
| 4-digit, 6-digit-date hybrids | ~2.5 h, ~10 d |
| dictionary + full rules (1.37B) | ~9 h |
| mask: 9 digits | ~6.5 h |
| mask: 11-digit PH mobile (`09…`) | ~7.3 h |
| mask: 8 hex (upper) | ~28 h |
| mask: 10 digits / landline | days |

---

## 4. Highest-impact improvements (actionable TODO)

### P0 - hardware / throughput
- [ ] **Run on a discrete GPU or rented cloud GPU.** This is the single biggest
      factor; it makes the 9/11-digit masks and full rules affordable.
- [ ] **Auto per-network when salts are high or GPU is slow.** On an iGPU,
      1 salt ≈ 38 kH/s vs 16 kH/s at 11 salts. Detect `salts > ~4` (or measured
      drop) and process networks one at a time (or in small groups).
- [ ] Benchmark `-w 2/3/4` once and cache the fastest workload profile.

### P1 - candidate coverage (biggest crack-rate gains)
- [ ] **Add SecLists / weakpass wordlists** (10M list, top-1M, weakpass 8.4GB).
      `wordlists/` drop-in already exists; ship or fetch a default big list.
- [ ] **Device-default hotspot list** for common phone/ISP hotspot vendors -
      many ship predictable default hotspot keys.
- [ ] **All PH mobile operator prefixes** (`09xx`, ~50 values) as cheap 10^7
      masks - and apply them to *generic* networks too (hotspots), not only to
      recognised ISP SSIDs.
- [ ] **9-digit and 10-digit masks** with an explicit large budget.
- [ ] **8-hex lower-case** mask (in addition to upper).

### P2 - smarter attacks
- [ ] **PRINCE / combinator**: combine SSID words with a second small list
      (word+word, e.g. two words from the SSID).
- [ ] **Main-dictionary hybrids**: `dictionary + ?d?d?d?d` per network (bounded).
- [ ] **OneRuleToRuleThemAll** rules (better than best66 for real leaks).
- [ ] **Rule tiers by cost** (already: fast/medium/full) - expose a `--rules N`
      knob and estimate per-network.

### P3 - engine / workflow
- [ ] **Dedupe the merged master wordlist** (wifi + rockyou + ph) so overlapping
      candidates aren't re-derived in every stage.
- [ ] **Resume support**: skip stages already exhausted for a network across runs.
- [ ] **Per-network stage report** in the engagement report (which masks/rules
      ran vs skipped), so a "not found" is fully defensible.
- [ ] **Flag guessed ESSIDs** (`essid_source == "filename"`) and mark those
      networks as "cannot crack without the true SSID".
- [ ] Consider **hashlookup against public WPA-sec / PMKID databases** for
      already-known handshakes (privacy/size caveats).

---

## 5. Per-network hypotheses (this dataset)

| Network | Likely key type | Next best stage |
|---|---|---|
| ExampleNet-A | phone number / random | PH mobile masks (all prefixes) |
| ExampleNet-B | hotspot random | 8-hex + full rules |
| ExampleNet-C | hotspot random | 8-hex + full rules |
| ExampleNet-D | name+year / 8-digit | 8-digit, 4-digit hybrid |
| ExampleNet-E | MAC-derived / human | 8-hex, MAC-tail variants |
| ExampleNet-F | word+suffix | bigger rules / word+word |
| ExampleNet-G | word+digits | bigger rules |
| ExampleNet-H | personal name | bigger name lists |
| ExampleNet-I | personal/custom | bigger wordlists |
| ExampleNet-J | phrase | word+word combinator / bigger lists |
| ExampleNet-K (hidden) | unknown | **recover true ESSID first** |

---

## 6. Quick "go harder" commands

```bash
# per network, allow the heavy masks/rules (~hours each)
python3 main.py --focus handshakes/HS_xxxx.pcap -b 600

# add more wordlists
cp /path/to/seclists10M.txt wordlists/
python3 main.py --default-wordlist -b 600
```

---

## 7. TL;DR

The tool is sound; the 11 uncracked networks are limited by **GPU speed, wordlist
breadth, and the large-mask time budget** - not by bugs. The top three moves are:
**faster GPU**, **bigger wordlists (SecLists/weakpass)**, and **per-network runs
with the 9/11-digit mobile masks**. Also flag guessed ESSIDs, because a wrong
salt can never crack.
