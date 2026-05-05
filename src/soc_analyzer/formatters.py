"""Output formatters: pretty terminal, JSON, CSV."""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime
from typing import TextIO

from .parser import SecurityEvent, summarize

# ── ANSI colours ─────────────────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_GREY   = "\033[90m"
_WHITE  = "\033[97m"

SEV_COLOUR = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _YELLOW + _BOLD,
    "MEDIUM":   _CYAN,
    "LOW":      _GREEN,
    "INFO":     _GREY,
}

def _c(text: str, colour: str, use_colour: bool) -> str:
    return f"{colour}{text}{_RESET}" if use_colour else text


# ── Pretty / terminal ─────────────────────────────────────────────────────────
def format_pretty(events: list[SecurityEvent], colour: bool = True, verbose: bool = False) -> str:
    lines: list[str] = []
    summary = summarize(events)

    # Header
    lines.append("")
    lines.append(_c("╔══════════════════════════════════════════════════╗", _BOLD, colour))
    lines.append(_c("║         SOC LOG ANALYZER  —  THREAT REPORT       ║", _BOLD, colour))
    lines.append(_c("╚══════════════════════════════════════════════════╝", _BOLD, colour))
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Events    : {summary['total']}")
    lines.append("")

    # Severity breakdown
    lines.append(_c("  SEVERITY BREAKDOWN", _BOLD, colour))
    lines.append("  " + "─" * 44)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = summary["by_severity"].get(sev, 0)
        bar   = "█" * min(count, 30)
        lines.append(f"  {_c(sev.ljust(10), SEV_COLOUR.get(sev,''), colour)} {str(count).rjust(4)}  {_c(bar, SEV_COLOUR.get(sev,''), colour)}")
    lines.append("")

    # Category breakdown
    lines.append(_c("  CATEGORY BREAKDOWN", _BOLD, colour))
    lines.append("  " + "─" * 44)
    for cat, cnt in sorted(summary["by_category"].items(), key=lambda x: -x[1]):
        lines.append(f"  {cat.ljust(20)} {cnt}")
    lines.append("")

    # Top IPs
    if summary["top_ips"]:
        lines.append(_c("  TOP OFFENDING IPs", _BOLD, colour))
        lines.append("  " + "─" * 44)
        for ip, cnt in summary["top_ips"]:
            flag = _c(" ⚠ BRUTE FORCE", _RED, colour) if cnt >= 5 else ""
            lines.append(f"  {ip.ljust(18)} {str(cnt).rjust(4)} hits{flag}")
        lines.append("")

    # Event list
    lines.append(_c("  DETECTED EVENTS", _BOLD, colour))
    lines.append("  " + "─" * 44)
    for ev in events:
        sev_str = _c(ev.severity.ljust(9), SEV_COLOUR.get(ev.severity, ""), colour)
        ts  = f"[{ev.timestamp}] " if ev.timestamp else ""
        ip  = f"  src={_c(ev.source_ip, _CYAN, colour)}" if ev.source_ip else ""
        bf  = _c("  [BRUTE FORCE]", _RED, colour) if ev.brute_force else ""
        lines.append(f"  {sev_str} {ts}{ev.description}{ip}{bf}")
        if verbose:
            lines.append(f"  {'':9}  line {ev.line_no}: {_c(ev.raw.strip()[:120], _GREY, colour)}")
    lines.append("")

    return "\n".join(lines)


# ── JSON ──────────────────────────────────────────────────────────────────────
def format_json(events: list[SecurityEvent], pretty: bool = True) -> str:
    summary = summarize(events)
    output = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            **summary,
            "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in summary["top_ips"]],
        },
        "events": [ev.as_dict() for ev in events],
    }
    return json.dumps(output, indent=2 if pretty else None)


# ── CSV ───────────────────────────────────────────────────────────────────────
def format_csv(events: list[SecurityEvent]) -> str:
    buf = io.StringIO()
    fields = ["line_no", "timestamp", "severity", "category", "description",
              "source_ip", "brute_force", "rule", "raw"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for ev in events:
        writer.writerow(ev.as_dict())
    return buf.getvalue()


# ── Markdown ──────────────────────────────────────────────────────────────────
def format_markdown(events: list[SecurityEvent]) -> str:
    summary = summarize(events)
    lines: list[str] = []

    lines.append("# SOC Log Analyzer — Threat Report")
    lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Total events:** {summary['total']}")
    lines.append("")

    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {summary['by_severity'].get(sev, 0)} |")
    lines.append("")

    lines.append("## Top Offending IPs")
    lines.append("")
    lines.append("| IP Address | Hit Count |")
    lines.append("|------------|----------:|")
    for ip, cnt in summary["top_ips"]:
        lines.append(f"| `{ip}` | {cnt} |")
    lines.append("")

    lines.append("## Events")
    lines.append("")
    lines.append("| # | Time | Severity | Category | Description | Source IP |")
    lines.append("|---|------|----------|----------|-------------|-----------|")
    for i, ev in enumerate(events, 1):
        ts  = ev.timestamp or "—"
        ip  = f"`{ev.source_ip}`" if ev.source_ip else "—"
        bf  = " ⚠" if ev.brute_force else ""
        lines.append(f"| {i} | {ts} | **{ev.severity}** | {ev.category} | {ev.description}{bf} | {ip} |")
    lines.append("")

    return "\n".join(lines)
