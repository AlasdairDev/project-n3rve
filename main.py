#!/usr/bin/env python3
"""n3rve - Automated WPA/WPA2 passphrase recovery from captured handshakes and PMKIDs."""

# ruff: noqa: E402
import atexit
import os
import sys
import signal
import time

# Phase 1: Auto-install Python dependencies
_REQUIREMENTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")

from src.bootstrap import pip_install_requirements as _pip_install_requirements

try:
    import rich  # noqa: F401
    import prompt_toolkit  # noqa: F401
    import scapy  # noqa: F401
except ImportError:
    print("Required Python libraries not found. Installing...")
    if _pip_install_requirements(_REQUIREMENTS):
        print("Libraries installed successfully. Please restart the program.")
        sys.exit(0)
    else:
        print("Failed to install required libraries.")
        print(f"Try manually: pip install --user -r {_REQUIREMENTS}")
        print(f"Or with override: pip install --break-system-packages -r {_REQUIREMENTS}")
        sys.exit(1)

# Phase 2: Project imports

from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.history import InMemoryHistory

from src.console import console, colored_log, log_error, log_debug
from src.config import HANDSHAKES_DIR, WORDLIST_NAME, RESULTS_DIR, HCOV_DIR
from src.utils import (
    acquire_run_lock,
    release_run_lock,
    choose_wordlist,
    scan_default_directory,
    get_manual_handshake_paths,
    sanitize_ssid,
    strip_capture_extension,
)
from src.validator import validate_all_handshakes, extract_essid_bssid
from src.keygen import global_default_candidates, heuristic_candidates
from src.cracker import get_already_cracked_essids, get_known_passwords, AircrackBackend
from src.hashcat import HashcatBackend
from src.hashcat.crack import _fmt_duration, reset_effort, last_effort
from src.setup import auto_setup
from src.backend import CrackerBackend


SEPARATOR = "-" * 60


def parse_args(argv=None):
    """Command-line interface.

    Flags rather than prompts and environment variables: on an engagement the
    tool is run repeatedly with different scopes, and having to answer a wordlist
    question each time (or remember which env var tunes the budget) makes it
    awkward to script and easy to get wrong.
    """
    import argparse

    from src.config import __version__

    parser = argparse.ArgumentParser(
        prog="n3rve",
        description="Recover WPA/WPA2 passphrases from captured handshakes (authorized testing only).",
        epilog="With no flags it uses handshakes/, the bundled wordlist, and a 120-minute per-stage budget.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-H", "--handshakes", metavar="DIR", help="directory of .cap/.pcap/.pcapng captures")
    parser.add_argument("-w", "--wordlist", metavar="FILE", help="wordlist to use (skips the prompt)")
    parser.add_argument("-b", "--budget", type=int, metavar="MIN", help="per-stage time budget in minutes")
    parser.add_argument(
        "-d", "--deep", action="store_true",
        help="after the shared pass, attack each unsolved network alone (the expensive stages then fit)",
    )
    parser.add_argument(
        "-f", "--focus", metavar="FILE",
        help="crack a single capture with a live focus dashboard (one network, full spotlight)",
    )
    parser.add_argument("-r", "--report", metavar="FILE", help="write a Markdown engagement report")
    parser.add_argument(
        "--list", action="store_true", dest="list_only",
        help="validate the captures and print the report table, then exit without cracking",
    )
    parser.add_argument("--no-install", action="store_true", help="never invoke the package manager")
    parser.add_argument(
        "-W", "--default-wordlist", action="store_true",
        help="use the bundled default wordlist without the interactive prompt",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="suppress the startup banner (useful for scripting)",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="print what a run in progress is doing (safe to use from another terminal) and exit",
    )
    return parser.parse_args(argv)


def select_captures(found_files: list[str]) -> list[str]:
    """Let the operator narrow a folder of captures down to one before cracking.

    The default sweep attacks everything in handshakes/ in a single shared pass,
    which is usually what you want. But sometimes you only care about one AP, and
    typing its full path into --focus is fiddly - so when the run is interactive
    and there is more than one capture, offer a numbered pick. Enter/'a' keeps the
    whole batch; a number isolates that one file. Non-interactive runs (pipes,
    cron, CI) skip the prompt and process everything, unchanged.
    """
    if len(found_files) <= 1 or not sys.stdin.isatty():
        return found_files

    console.print("\nCaptures found:")
    for i, path in enumerate(found_files, 1):
        console.print(f"  [cyan]{i:>2}[/cyan]  {os.path.basename(path)}")
    console.print("  [cyan] a[/cyan]  all of them")

    while True:
        choice = input(f"Crack which? (1-{len(found_files)}, or 'a' for all) [a]: ").strip().lower()
        if choice in ("", "a", "all"):
            return found_files
        if choice.isdigit() and 1 <= int(choice) <= len(found_files):
            picked = found_files[int(choice) - 1]
            colored_log("info", f"Focusing on {os.path.basename(picked)}.")
            return [picked]
        console.print(f"[yellow]Enter a number 1-{len(found_files)}, or 'a'.[/yellow]")


def print_run_status() -> int:
    """Report on a run in progress, for a terminal that is not showing it."""
    from src.hashcat.crack import read_progress
    from src.utils import _pid_alive

    info = read_progress()
    if not info:
        console.print("No run has been recorded yet.")
        return 1

    pid = int(info.get("pid", "0") or 0)
    alive = _pid_alive(pid)
    state = info.get("state", "unknown")
    if state == "finished" and not alive:
        console.print("[green]Finished.[/green]")
    elif alive:
        console.print(f"[cyan]Running[/cyan] (pid {pid})")
    else:
        console.print(f"[yellow]Stopped[/yellow] before finishing (pid {pid} is gone)")
    console.print(f"  Stage      {info.get('stage', '?')}  {info.get('label', '')}")
    console.print(f"  Recovered  {info.get('recovered', '?')}")
    if info.get("run_elapsed"):
        console.print(f"  Run time   {info['run_elapsed']} (at the start of this stage)")
    if info.get("stage_started"):
        console.print(f"  Stage from {info['stage_started']}")
    console.print(f"  Updated    {info.get('updated', '?')}")
    return 0


def build_aircrack_candidates(valid_files_map):
    """Precompute likely default keys (PLDT derivations, PH/international pattern
    guesses, brand+MAC combos) for every network in every capture, so the CPU
    fallback path tries them first.

    Keyed by (capture path, ESSID): a capture holding two ISPs' routers needs two
    different candidate sets, and each aircrack-ng pass targets one AP.
    """
    candidates = {}
    for f, v in valid_files_map.items():
        nets = v.valid_networks
        if not nets:
            essid, bssid = extract_essid_bssid(v.relevant_packets)
            candidates[f] = global_default_candidates(essid, bssid) + heuristic_candidates(essid)
            continue
        for net in nets:
            bssid = net.bssid.replace(":", "")
            candidates[(f, net.display_name)] = global_default_candidates(net.essid, bssid) + heuristic_candidates(
                net.essid
            )
    return candidates


def build_networks_map(valid_files_map):
    """capture path -> [(network name, BSSID)] for the per-AP aircrack-ng passes."""
    return {
        f: [(net.display_name, net.bssid) for net in v.valid_networks]
        for f, v in valid_files_map.items()
        if v.valid_networks
    }


def print_summary(results: list, skipped_count: int = 0, previously: dict | None = None):
    """Print a final table of every processed network and its outcome.

    ``results`` is a list of (network name, password or None) - one entry per
    *network*, so a capture holding several APs contributes one row each.
    """
    if not results:
        if skipped_count:
            console.print(f"Nothing to do - all {skipped_count} network(s) were already cracked or duplicates.")
        else:
            console.print("No handshakes were processed.")
        return

    previously = previously or {}
    cracked = [(essid, pw) for essid, pw in results if pw]
    failed = [essid for essid, pw in results if not pw]
    # Networks solved by an earlier run get skipped this time, but they still
    # count toward the standing total, otherwise the estate looks worse than it is.
    earlier = [(name, pw) for name, pw in sorted(previously.items()) if name not in dict(cracked)]

    from rich import box
    from rich.table import Table

    table = Table(
        show_header=True, header_style="bold", box=box.SIMPLE_HEAD,
        pad_edge=False, show_edge=False, border_style="dim",
    )
    table.add_column("Network")
    table.add_column("Result")

    # Recovered ones first, since that's what the reader came for.
    for essid, pw in cracked:
        table.add_row(f"[bold green]+[/bold green] {essid}", f"[bold green]{pw}[/bold green]")
    for essid, pw in earlier:
        table.add_row(f"[green]+[/green] [dim]{essid}[/dim]", f"[green]{pw}[/green] [dim](earlier run)[/dim]")
    for essid in failed:
        table.add_row(f"[dim]-[/dim] [dim]{essid}[/dim]", "[dim]not found[/dim]")

    console.print()
    console.rule("[bold cyan]Summary[/bold cyan]", style="cyan", align="left")
    total_known = len(cracked) + len(earlier)
    total_nets = len(results) + len(earlier)
    headline = f"  [bold]{total_known}[/bold] of [bold]{total_nets}[/bold] network(s) recovered"
    if earlier:
        headline += f"   [dim]({len(cracked)} new this run, {len(earlier)} from earlier)[/dim]"
    console.print(headline)
    console.print("")
    console.print(table)

    if cracked:
        console.print(f"\n  Passwords saved to '{RESULTS_DIR}/'.")
    else:
        console.print(
            "\n  [dim]Nothing recovered. Stages too costly across several SSIDs fit against one -[/dim]"
            "\n  [dim]re-run with --deep to attack each network individually.[/dim]"
        )
    console.print("")


def main(argv=None):
    args = parse_args(argv)
    if args.status:
        sys.exit(print_run_status())
    # Flags feed the same switches the env vars already expose, so there's one
    # code path and scripted runs behave exactly like interactive ones.
    if args.budget:
        os.environ["HANDSHAKE_MAX_STAGE_MIN"] = str(args.budget)
    if args.deep:
        os.environ["HANDSHAKE_DEEP"] = "1"
    if args.no_install:
        os.environ["HANDSHAKE_NO_AUTOINSTALL"] = "1"

    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    except AttributeError:
        pass

    try:
        # ANSI escape to clear screen; falls back to shell clear on Windows where
        # ANSI may not be enabled (handled by console.py's _enable_vt already).
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    except Exception:
        pass

    lock_path = os.path.join(HCOV_DIR, ".run.lock")
    holder = acquire_run_lock(lock_path)
    if holder:
        colored_log("error", f"Another run is already in progress (pid {holder}).")
        colored_log(
            "info",
            "Two runs share one GPU and one potfile, and each kills the other's "
            "hashcat mid-stage. Wait for it, or stop it first:",
        )
        colored_log("info", f"  kill {holder}")
        sys.exit(1)
    atexit.register(release_run_lock, lock_path)

    run_started = time.time()
    try:
        setup = auto_setup(quiet=args.quiet)
        if not setup.get("aircrack_available") and not setup.get("hashcat_available"):
            sys.exit(1)

        use_hashcat = setup.get("hashcat_available", False)
        gpu_name = setup.get("gpu_name")

        if use_hashcat and gpu_name:
            gpu_type = "Discrete" if setup.get("gpu_is_discrete") else "Integrated"
            colored_log("info", f"GPU detected: {gpu_name} ({gpu_type}) - using hashcat (GPU).")
        elif use_hashcat:
            colored_log("info", "Using hashcat (GPU/OpenCL).")
        else:
            colored_log("info", "Using aircrack-ng (CPU).")

        log_debug(
            f"main: hashcat={'yes' if use_hashcat else 'no'}, "
            f"gpu_name={gpu_name}, "
            f"aircrack-ng={'yes' if setup.get('aircrack_available') else 'no'}"
        )

        session = PromptSession(history=InMemoryHistory())

        # Wordlist selection
        default_wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), WORDLIST_NAME)
        if args.default_wordlist:
            wordlist_path = default_wordlist
            colored_log("info", f"Using default wordlist: {os.path.basename(default_wordlist)}")
        else:
            wordlist_path = args.wordlist or choose_wordlist(session, default_wordlist)
        if not os.path.isfile(wordlist_path):
            # Every backend needs a dictionary stage. Without one, the run would
            # fail once per capture with a cryptic error instead of saying why.
            colored_log("error", f"Wordlist not found: {wordlist_path}")
            colored_log(
                "info",
                f"Put a wordlist at '{WORDLIST_NAME}' in the project root, or pick a custom one (option 2).",
            )
            sys.exit(1)

        # Start each run's effort record clean so a report reflects only this run.
        reset_effort()

        # Focus mode: one capture, one live dashboard
        if args.focus:
            focus_path = args.focus
            if not os.path.isfile(focus_path):
                colored_log("error", f"Capture not found: {focus_path}")
                sys.exit(1)
            if not use_hashcat:
                colored_log("error", "Focus mode needs the hashcat GPU backend, which isn't available.")
                sys.exit(1)
            valid_files_map, _ = validate_all_handshakes([focus_path])
            if not valid_files_map or not valid_files_map[focus_path].valid_networks:
                colored_log("error", "No crackable handshake in that capture (no PMKID, no pairable 4-way).")
                sys.exit(1)
            from src.hashcat.crack import run_focus_capture

            v = valid_files_map[focus_path]
            nets = [n.display_name for n in v.valid_networks]
            if len(nets) > 1:
                colored_log(
                    "info",
                    f"This capture holds {len(nets)} networks ({', '.join(nets)}); "
                    f"focus mode attacks them together in one pass.",
                )
            result = run_focus_capture(
                focus_path, wordlist_path, setup.get("gpu_is_discrete", False), v.relevant_packets
            )
            result = result or {}
            if args.report:
                from src.report import build_report, write_report

                effort = last_effort()
                content = build_report(
                    v.valid_networks, {n: pw for n, pw in result.items()},
                    wordlist=wordlist_path, duration=_fmt_duration(time.time() - run_started), gpu=gpu_name,
                    stages_run=effort["searched"], stages_skipped=effort["skipped"],
                )
                if write_report(args.report, content):
                    colored_log("success", f"Engagement report written to {args.report}")
            print_summary([(n, result.get(n)) for n in nets], previously=get_known_passwords())
            sys.exit(0)

        handshakes_dir = args.handshakes or HANDSHAKES_DIR
        found_files = scan_default_directory(handshakes_dir)
        handshake_queue = []

        if not found_files:
            console.print(f"No .cap/.pcap/.pcapng files found in '{handshakes_dir}'.")
            switch_to_manual = input("Switch to manual file entry? (y/N): ").strip().lower()
            if switch_to_manual == "y":
                handshake_queue = get_manual_handshake_paths(session)
            else:
                console.print("Exiting.")
                sys.exit(0)
        else:
            colored_log("info", f"Found {len(found_files)} .cap/.pcap file(s) in '{handshakes_dir}'.")
            handshake_queue.extend(found_files)

        if not handshake_queue:
            colored_log("warning", "No handshake files to process. Exiting.")
            sys.exit(0)

        valid_files_map, _ = validate_all_handshakes(handshake_queue)

        if not valid_files_map:
            colored_log("warning", "No valid handshake files to process. Exiting.")
            sys.exit(0)

        if args.list_only:
            colored_log("info", "--list given: validation only, nothing cracked.")
            sys.exit(0)

        already_cracked = get_already_cracked_essids()

        # Hide captures already fully recovered in a previous run before offering the
        # pick: a network whose ESSID sits in cracked_results/ is done, so showing it
        # in the menu (or cracking it again) only wastes time. A capture survives if it
        # still holds at least one uncracked network - matching the per-network dedup
        # below, which keys on the SSID inside the capture, not the file name.
        def _fully_cracked(path: str) -> bool:
            names = [sanitize_ssid(n.display_name) for n in valid_files_map[path].valid_networks]
            return bool(names) and all(n in already_cracked for n in names)

        selectable = [p for p in valid_files_map if not _fully_cracked(p)]
        hidden = len(valid_files_map) - len(selectable)
        if hidden:
            colored_log("info", f"Hiding {hidden} capture(s) already cracked in a previous run.")
        if not selectable:
            colored_log("success", "Every capture here is already cracked - nothing left to do.")
            sys.exit(0)

        chosen = select_captures(selectable)
        valid_files_map = {p: valid_files_map[p] for p in chosen}

        handshake_queue = list(valid_files_map.keys())
        console.print(f"Processing {len(handshake_queue)} valid handshake(s)...")

        handshake_queue.sort(key=lambda p: os.path.getsize(p), reverse=True)

        # Dedupe on the network the capture contains, not its file name: two dumps
        # of the same AP are duplicates no matter what they're called, and a
        # capture is only fully done once every network in it is cracked.
        seen: set[str] = set()
        deduped = []
        skipped_count = 0

        for p in handshake_queue:
            names = [sanitize_ssid(n.display_name) for n in valid_files_map[p].valid_networks]
            if not names:
                names = [sanitize_ssid(strip_capture_extension(p))]
            pending = [n for n in names if n not in already_cracked and n not in seen]
            if not pending:
                skipped_count += len(names)
                continue
            seen.update(pending)
            deduped.append(p)

        if skipped_count:
            console.print(
                f"Skipped {skipped_count} previously cracked or duplicate "
                f"network(s). Processing {len(deduped)} capture(s)."
            )

        backend: CrackerBackend
        if use_hashcat:
            packets_map = {f: v.relevant_packets for f, v in valid_files_map.items()}
            backend = HashcatBackend(setup.get("gpu_is_discrete", False), packets_map)
        else:
            # Precompute likely default keys (PLDT derivations, PH pattern guesses)
            # from the captured packets so the CPU fallback tries them first.
            aircrack_candidates = build_aircrack_candidates(valid_files_map)
            backend = AircrackBackend(aircrack_candidates, build_networks_map(valid_files_map))

        results: list[tuple[str, str | None]] = []
        all_networks = [n.display_name for p in deduped for n in valid_files_map[p].valid_networks]

        if use_hashcat and deduped:
            # One shared pass over every network. hashcat tests each candidate
            # against all loaded hashes at the same speed, so running per-capture
            # would repeat the expensive generic stages once per file for no extra
            # coverage. That's hours of duplicated work on a real estate.
            console.print()
            console.rule("[bold cyan]Cracking[/bold cyan]", style="cyan", align="left")
            log_debug(f"main: batch crack over {deduped}")
            cracked = backend.crack_all(deduped, wordlist_path)
            log_debug(f"main: batch returned {cracked!r}")

            if cracked is None:
                colored_log("warning", "Hashcat could not run - falling back to aircrack-ng.")
                aircrack_candidates = build_aircrack_candidates(valid_files_map)
                fallback = AircrackBackend(aircrack_candidates, build_networks_map(valid_files_map))
                cracked = {}
                for handshake_path in deduped:
                    got = fallback.crack(handshake_path, wordlist_path, strip_capture_extension(handshake_path))
                    cracked.update(got or {})

            cracked = cracked or {}

            # Second pass: whatever's still unsolved gets attacked on its own,
            # where the expensive stages become affordable (cost scales with the
            # number of distinct SSIDs, each one a separate PBKDF2 salt).
            unsolved = [n for n in all_networks if n not in cracked]
            if unsolved and use_hashcat:
                if os.environ.get("HANDSHAKE_DEEP"):
                    from src.hashcat.crack import crack_networks_individually

                    colored_log("info", f"Deep pass over {len(unsolved)} unsolved network(s).")
                    cracked.update(
                        crack_networks_individually(
                            backend.last_batch_lines, unsolved, wordlist_path, setup.get("gpu_is_discrete", False)
                        )
                    )
                else:
                    colored_log(
                        "info",
                        f"{len(unsolved)} network(s) unsolved. Stages too costly across "
                        f"{len(all_networks)} SSIDs fit against one - re-run with "
                        f"--deep to attack each on its own.",
                    )

            for name in all_networks:
                results.append((name, cracked.get(name)))
            for name, pw in cracked.items():
                if name not in all_networks:
                    results.append((name, pw))
        else:
            for idx, handshake_path in enumerate(deduped, 1):
                base_essid = strip_capture_extension(handshake_path)
                networks = [n.display_name for n in valid_files_map[handshake_path].valid_networks]

                console.print()
                console.rule(f"[bold cyan]Capture {idx}/{len(deduped)}[/bold cyan]  {base_essid}", style="cyan", align="left")
                if networks:
                    console.print(f"Networks: {', '.join(networks)}")

                log_debug(f"main: routing to {backend.__class__.__name__} for {base_essid} ({networks})")
                cracked = backend.crack(handshake_path, wordlist_path, base_essid)
                log_debug(f"main: backend returned {cracked!r}")

                cracked = cracked or {}
                for name in networks or [base_essid]:
                    results.append((name, cracked.get(name)))
                for name, pw in cracked.items():
                    if name not in (networks or [base_essid]):
                        results.append((name, pw))

                if cracked:
                    console.print("  [green]Done.[/green]")
                else:
                    console.print("  [red]Failed.[/red]")

        if args.report:
            from src.report import build_report, write_report

            all_nets = [n for f in deduped for n in valid_files_map[f].valid_networks]
            seen_names: set = set()
            unique_nets = [n for n in all_nets if not (n.display_name in seen_names or seen_names.add(n.display_name))]
            effort = last_effort()
            content = build_report(
                unique_nets,
                {name: pw for name, pw in results if pw},
                wordlist=wordlist_path,
                duration=_fmt_duration(time.time() - run_started),
                gpu=gpu_name,
                stages_run=effort["searched"],
                stages_skipped=effort["skipped"],
            )
            if write_report(args.report, content):
                colored_log("success", f"Engagement report written to {args.report}")

        print_summary(results, skipped_count, get_known_passwords())

    except KeyboardInterrupt:
        colored_log("warning", "Interrupted by user (Ctrl+C). Stopping.")
        if "results" in locals() and results:
            print_summary(results, locals().get("skipped_count", 0))
        sys.exit(1)
    except Exception as e:
        log_error("A critical unhandled error occurred in main execution.", e)
        colored_log(
            "error",
            "A critical error occurred. Check 'debug_log.txt' for details. Exiting.",
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
