# Wordlists drop-in

Put any `.txt` wordlist here and it is picked up automatically as an extra
dictionary stage (after the bundled list). One password per line.

Good candidates:

- `rockyou.txt` - the classic 14.3M leaked-password list. On Kali:
  `sudo apt install wordlists` then copy
  `/usr/share/wordlists/rockyou.txt`.
- SecLists extracts (e.g. `Top10000.txt`, `10-million-password-list-top-1000000.txt`).
- Any client/engagement-specific list.

Large files are git-ignored; this folder just makes them easy to use without
editing code. The tool deduplicates and filters to WPA-valid lengths (8-63).
