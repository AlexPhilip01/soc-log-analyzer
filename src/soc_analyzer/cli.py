"""
CLI entry point for soc-analyzer.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .alerting import WebhookAlerter
from .formatters import format_events
from .geoip import GeoResult, enrich_events
from .parser import SecurityEvent, Severity, parse_file, parse_stdin
from .rules import run_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soc-analyzer",
        description="SOC Log Analyzer — detect threats in SSH, Apache/Nginx, and Windows Event logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("files", metavar="FILE", nargs="*",
                   help="Log file(s) to analyze. Use '-' to read from stdin.")

    out = p.add_argument_group("output")
    out.add_argument("-f", "--format", choices=["pretty", "json", "csv", "markdown"],
                     default="pretty", help="Output format (default: pretty)")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Write output to FILE instead of stdout")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Include the raw log line under each event")
    out.add_argument("--no-color", action="store_true",
                     help="Disable ANSI colour codes")

    filt = p.add_argument_group("filters")
    filt.add_argument("-s", "--severity",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                      default=None, metavar="LEVEL",
                      help="Show only events at this level and above")
    filt.add_argument("-c", "--category", metavar="CAT", default=None,
                      help="Filter by category (brute_force, sqli, lfi, xss, recon, auth, privilege…)")
    filt.add_argument("--ip", metavar="IP", default=None,
                      help="Show only events from this source IP")

    det = p.add_argument_group("detection")
    det.add_argument("--brute-threshold", type=int, default=5, metavar="N",
                     help="Hits-per-IP before brute-force escalation (default: 5)")

    watch = p.add_argument_group("live tail")
    watch.add_argument("--watch", action="store_true",
                       help="Tail FILE(s) in real time; print events as new lines arrive")
    watch.add_argument("--poll-interval", type=float, default=0.5, metavar="SECS",
                       help="File poll interval in seconds for --watch (default: 0.5)")

    geo = p.add_argument_group("geo enrichment")
    geo.add_argument("--geo", action="store_true",
                     help="Resolve attacker IPs to country/city via ip-api.com (free, no key)")

    alert = p.add_argument_group("webhook / slack alerting")
    alert.add_argument("--alert-webhook", metavar="URL", default=None,
                       help="POST HIGH/CRITICAL events to this URL (Slack webhooks auto-detected)")
    alert.add_argument("--alert-severity",
                       choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                       default="HIGH", metavar="LEVEL",
                       help="Minimum severity to send to webhook (default: HIGH)")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _apply_filters(events, min_severity, category, ip):
    filtered = events
    if min_severity:
        min_sev = Severity(min_severity)
        filtered = [ev for ev in filtered if ev.severity >= min_sev]
    if category:
        cat = category.lower()
        filtered = [ev for ev in filtered if ev.category.lower() == cat]
    if ip:
        filtered = [ev for ev in filtered if ev.source_ip == ip]
    return filtered


def _run_watch(args):
    from .watcher import watch
    alerter = None
    if args.alert_webhook:
        alerter = WebhookAlerter(url=args.alert_webhook,
                                 min_severity=Severity(args.alert_severity))
    min_sev = Severity(args.severity) if args.severity else None
    use_color = not args.no_color
    watch(paths=args.files, poll_interval=args.poll_interval,
          brute_threshold=args.brute_threshold, min_severity=min_sev,
          use_color=use_color, alert_callback=alerter)
    return 0


def _run_batch(args):
    all_records = []
    for f in args.files:
        if f == "-":
            all_records.extend(parse_stdin(sys.stdin))
        else:
            path = Path(f)
            if not path.exists():
                print(f"[ERROR] File not found: {f}", file=sys.stderr)
                return 2
            try:
                all_records.extend(parse_file(path))
            except Exception as exc:
                print(f"[ERROR] Could not parse {f}: {exc}", file=sys.stderr)
                return 2

    events = run_rules(all_records, brute_threshold=args.brute_threshold)
    events = _apply_filters(events, args.severity, args.category, args.ip)

    geo_map: dict[str, GeoResult] = {}
    if args.geo:
        print("[geo] Resolving IPs…", file=sys.stderr)
        geo_map = enrich_events(events, use_geo=True)
        for ev in events:
            if ev.source_ip and ev.source_ip in geo_map:
                g = geo_map[ev.source_ip]
                ev.extra["geo"] = g.short()
                if not g.is_private and g.country_code != "??":
                    ev.description += f"  [{g.short()}]"

    use_color = not args.no_color and sys.stdout.isatty()
    output = format_events(events, fmt=args.format, use_color=use_color,
                           verbose=args.verbose, geo_map=geo_map)

    if args.output:
        try:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Report written to: {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"[ERROR] Cannot write to {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(output)

    if args.alert_webhook:
        alerter = WebhookAlerter(url=args.alert_webhook,
                                 min_severity=Severity(args.alert_severity))
        sent, failed = alerter.send_batch(events)
        print(f"[alert] Sent {sent} alert(s), {failed} failed.", file=sys.stderr)

    dangerous = [ev for ev in events if ev.severity in (Severity.HIGH, Severity.CRITICAL)]
    return 1 if dangerous else 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.files:
        parser.print_help()
        return 0
    if args.watch:
        return _run_watch(args)
    return _run_batch(args)


if __name__ == "__main__":
    sys.exit(main())
