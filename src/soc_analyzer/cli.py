#!/usr/bin/env python3
"""SOC Log Analyzer — CLI entry point.

Usage examples
--------------
  # Analyze a single file, print to terminal
  soc-analyzer auth.log

  # Multiple files, output JSON
  soc-analyzer auth.log syslog -f json -o report.json

  # Filter to CRITICAL only, verbose (shows raw lines)
  soc-analyzer auth.log --severity CRITICAL --verbose

  # Export markdown report
  soc-analyzer access.log -f markdown -o report.md

  # Read from stdin
  cat auth.log | soc-analyzer -
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .parser import LogParser, summarize
from .formatters import format_pretty, format_json, format_csv, format_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soc-analyzer",
        description="SOC Log Analyzer — detect threats in auth, web, and Windows logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Log file(s) to analyse. Use '-' to read from stdin.",
    )
    p.add_argument(
        "-f", "--format",
        choices=["pretty", "json", "csv", "markdown"],
        default="pretty",
        help="Output format (default: pretty)",
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    p.add_argument(
        "-s", "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Show only events at this severity level and above",
    )
    p.add_argument(
        "-c", "--category",
        metavar="CAT",
        default=None,
        help="Filter by category (brute_force, lfi, sqli, xss, recon, auth, privilege, ...)",
    )
    p.add_argument(
        "--ip",
        metavar="IP",
        default=None,
        help="Filter events from a specific source IP address",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Include raw log lines in pretty output",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour codes in pretty output",
    )
    p.add_argument(
        "--brute-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Number of hits from the same IP to flag as brute force (default: 5)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"soc-analyzer {__version__}",
    )
    return p


SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def main() -> int:
    args = build_parser().parse_args()
    parser = LogParser(brute_threshold=args.brute_threshold)

    # ── Collect lines from all inputs ────────────────────────────────────────
    all_lines: list[str] = []
    for farg in args.files:
        if farg == "-":
            all_lines.extend(sys.stdin.readlines())
        else:
            p = Path(farg)
            if not p.exists():
                print(f"[ERROR] File not found: {farg}", file=sys.stderr)
                return 1
            all_lines.extend(p.read_text(errors="replace").splitlines(keepends=True))

    # ── Parse ────────────────────────────────────────────────────────────────
    events = parser.parse_lines(all_lines)

    # ── Filter ───────────────────────────────────────────────────────────────
    if args.severity:
        min_rank = SEV_RANK[args.severity]
        events = [e for e in events if SEV_RANK[e.severity] >= min_rank]

    if args.category:
        events = [e for e in events if e.category == args.category.lower()]

    if args.ip:
        events = [e for e in events if e.source_ip == args.ip]

    # ── Format ───────────────────────────────────────────────────────────────
    use_colour = not args.no_color and sys.stdout.isatty()

    if args.format == "pretty":
        output = format_pretty(events, colour=use_colour, verbose=args.verbose)
    elif args.format == "json":
        output = format_json(events)
    elif args.format == "csv":
        output = format_csv(events)
    elif args.format == "markdown":
        output = format_markdown(events)
    else:
        output = format_pretty(events, colour=use_colour, verbose=args.verbose)

    # ── Write ────────────────────────────────────────────────────────────────
    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # ── Exit code: 1 if any CRITICAL or HIGH events found ───────────────────
    has_threat = any(SEV_RANK[e.severity] >= SEV_RANK["HIGH"] for e in events)
    return 1 if has_threat else 0


if __name__ == "__main__":
    sys.exit(main())
