"""
Output formatters: pretty (ANSI colour), JSON, CSV, Markdown.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime

from .parser import SecurityEvent, Severity

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ──────────────────────────────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_SEV_COLOR = {
    Severity.CRITICAL: "\033[91m",   # bright red
    Severity.HIGH:     "\033[31m",   # red
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.LOW:      "\033[36m",   # cyan
    Severity.INFO:     "\033[37m",   # white
}

_SEV_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH    ",
    Severity.MEDIUM:   "🟡 MEDIUM  ",
    Severity.LOW:      "🔵 LOW     ",
    Severity.INFO:     "⚪ INFO    ",
}

_BAR_CHAR = "█"


def _color(sev: Severity, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_SEV_COLOR[sev]}{text}{_RESET}"


def _bold(text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_BOLD}{text}{_RESET}"


# ──────────────────────────────────────────────────────────────────────────────
# Pretty formatter
# ──────────────────────────────────────────────────────────────────────────────

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def format_pretty(events: list[SecurityEvent], use_color: bool = True, verbose: bool = False, geo_map: dict | None = None) -> str:
    lines: list[str] = []
    w = 60

    # Header
    lines.append(_bold("╔" + "═" * (w - 2) + "╗", use_color))
    title = "SOC LOG ANALYZER  —  THREAT REPORT"
    pad = (w - 4 - len(title)) // 2
    lines.append(_bold(f"║{' ' * pad} {title} {' ' * (w - 4 - len(title) - pad)}║", use_color))
    lines.append(_bold("╚" + "═" * (w - 2) + "╝", use_color))
    lines.append(f"  Generated : {datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append(f"  Events    : {len(events)}")

    if not events:
        lines.append("\n  ✅  No threats detected.")
        return "\n".join(lines)

    # Severity breakdown
    sev_counts = Counter(ev.severity for ev in events)
    lines.append("")
    lines.append(_bold("  SEVERITY BREAKDOWN", use_color))
    lines.append("  " + "─" * (w - 4))
    max_count = max(sev_counts.values(), default=1)
    for sev in _SEV_ORDER:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        bar_len = max(1, int(count / max_count * 30))
        bar = _BAR_CHAR * bar_len
        badge = sev.value.ljust(8)
        line = f"  {_color(sev, badge, use_color)}  {count:>4}  {_color(sev, bar, use_color)}"
        lines.append(line)

    # Top source IPs
    ip_counts = Counter(ev.source_ip for ev in events if ev.source_ip)
    if ip_counts:
        lines.append("")
        lines.append(_bold("  TOP SOURCE IPs", use_color))
        lines.append("  " + "─" * (w - 4))
        _gm = geo_map or {}
        for row in _geo_ip_table(ip_counts, _gm, max_rows=5):
            lines.append(row)

    # Events
    lines.append("")
    lines.append(_bold("  EVENTS", use_color))
    lines.append("  " + "─" * (w - 4))

    for ev in sorted(events, key=lambda e: _SEV_ORDER.index(e.severity)):
        ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "??:??:??:??"
        badge = _SEV_BADGE.get(ev.severity, ev.severity.value)
        badge_colored = _color(ev.severity, badge, use_color)

        lines.append("")
        lines.append(f"  {badge_colored}  [{ts_str}]")
        lines.append(f"  Rule     : {ev.rule_id}")
        lines.append(f"  Category : {ev.category}")
        lines.append(f"  Source   : {ev.source_ip or 'N/A'}")
        lines.append(f"  File     : {ev.source_file or 'N/A'}")
        desc = ev.description
        # Word-wrap description at 55 chars
        if len(desc) > 55:
            chunks = [desc[i:i+55] for i in range(0, len(desc), 55)]
            lines.append(f"  Detail   : {chunks[0]}")
            for chunk in chunks[1:]:
                lines.append(f"             {chunk}")
        else:
            lines.append(f"  Detail   : {desc}")
        if verbose:
            raw = ev.raw_line[:120] + ("…" if len(ev.raw_line) > 120 else "")
            lines.append(f"  Raw      : {raw}")

    lines.append("")
    lines.append("  " + "═" * (w - 4))
    crit = sev_counts.get(Severity.CRITICAL, 0)
    high = sev_counts.get(Severity.HIGH, 0)
    summary = f"  {crit} CRITICAL  {high} HIGH  —  review immediately" if (crit + high) else "  No HIGH/CRITICAL events."
    lines.append(_bold(summary, use_color))
    lines.append("")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# JSON formatter
# ──────────────────────────────────────────────────────────────────────────────

def format_json(events: list[SecurityEvent]) -> str:
    sev_counts = Counter(ev.severity.value for ev in events)
    ip_counts  = Counter(ev.source_ip for ev in events if ev.source_ip)
    top_ips    = [{"ip": ip, "count": c} for ip, c in ip_counts.most_common(10)]

    def ev_to_dict(ev: SecurityEvent) -> dict:
        return {
            "rule_id":     ev.rule_id,
            "severity":    ev.severity.value,
            "category":    ev.category,
            "description": ev.description,
            "source_ip":   ev.source_ip,
            "timestamp":   ev.timestamp.isoformat() if ev.timestamp else None,
            "source_file": ev.source_file,
            "raw_line":    ev.raw_line,
            "extra":       ev.extra,
        }

    payload = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total":       len(events),
            "by_severity": sev_counts,
            "top_ips":     top_ips,
        },
        "events": [ev_to_dict(ev) for ev in events],
    }
    return json.dumps(payload, indent=2, default=str)


# ──────────────────────────────────────────────────────────────────────────────
# CSV formatter
# ──────────────────────────────────────────────────────────────────────────────

_CSV_FIELDS = [
    "timestamp", "severity", "rule_id", "category",
    "source_ip", "description", "source_file",
]


def format_csv(events: list[SecurityEvent]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for ev in events:
        writer.writerow({
            "timestamp":   ev.timestamp.isoformat() if ev.timestamp else "",
            "severity":    ev.severity.value,
            "rule_id":     ev.rule_id,
            "category":    ev.category,
            "source_ip":   ev.source_ip or "",
            "description": ev.description,
            "source_file": ev.source_file,
        })
    return buf.getvalue()


# ──────────────────────────────────────────────────────────────────────────────
# Markdown formatter
# ──────────────────────────────────────────────────────────────────────────────

def format_markdown(events: list[SecurityEvent], geo_map: dict | None = None) -> str:
    sev_counts = Counter(ev.severity for ev in events)
    ip_counts  = Counter(ev.source_ip for ev in events if ev.source_ip)

    lines: list[str] = []
    lines.append("# SOC Log Analyzer — Threat Report")
    lines.append(f"\n**Generated:** {datetime.now():%Y-%m-%d %H:%M:%S}  ")
    lines.append(f"**Total Events:** {len(events)}\n")

    lines.append("## Severity Breakdown\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in _SEV_ORDER:
        count = sev_counts.get(sev, 0)
        if count:
            lines.append(f"| {sev.value} | {count} |")

    if ip_counts:
        _gm = geo_map or {}
        lines.append("\n## Top Source IPs\n")
        if _gm:
            lines.append("| IP Address | Country | Events |")
            lines.append("|------------|---------|--------|")
            for ip, count in ip_counts.most_common(10):
                geo = _gm.get(ip)
                geo_str = geo.short() if geo else ""
                lines.append(f"| `{ip}` | {geo_str} | {count} |")
        else:
            lines.append("| IP Address | Events |")
            lines.append("|------------|--------|")
            for ip, count in ip_counts.most_common(10):
                lines.append(f"| `{ip}` | {count} |")

    lines.append("\n## Events\n")
    lines.append("| Timestamp | Severity | Rule | Category | Source IP | Description |")
    lines.append("|-----------|----------|------|----------|-----------|-------------|")

    for ev in sorted(events, key=lambda e: _SEV_ORDER.index(e.severity)):
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—"
        desc = ev.description.replace("|", "\\|")
        lines.append(
            f"| {ts} | **{ev.severity.value}** | `{ev.rule_id}` "
            f"| {ev.category} | {ev.source_ip or '—'} | {desc} |"
        )

    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────────────────────────────────────

def format_events(
    events: list[SecurityEvent],
    fmt: str = "pretty",
    use_color: bool = True,
    verbose: bool = False,
    geo_map: dict | None = None,
) -> str:
    geo_map = geo_map or {}
    if fmt == "json":
        return format_json(events)
    if fmt == "csv":
        return format_csv(events)
    if fmt == "markdown":
        return format_markdown(events, geo_map=geo_map)
    return format_pretty(events, use_color=use_color, verbose=verbose, geo_map=geo_map)


# ──────────────────────────────────────────────────────────────────────────────
# GeoIP-aware Top IPs table (replaces simple counter in pretty/markdown)
# ──────────────────────────────────────────────────────────────────────────────

def _geo_ip_table(ip_counts: Counter, geo_map: dict, max_rows: int = 10) -> list[str]:
    """Return formatted rows with optional geo annotation."""
    rows = []
    for ip, count in ip_counts.most_common(max_rows):
        geo = geo_map.get(ip)
        geo_str = f"  ({geo.short()})" if geo and not geo.is_private else ""
        rows.append(f"  {ip:<20}  {count:>4} event(s){geo_str}")
    return rows


