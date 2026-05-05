"""Parse log lines and return structured SecurityEvent objects."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from .rules import RULES, BRUTE_FORCE_THRESHOLD, Rule


# ── Timestamp patterns ───────────────────────────────────────────────────────
_TS_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),   # ISO-8601
    re.compile(r"(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})"),          # syslog
    re.compile(r"\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})"),        # Apache CLF
]

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _extract_timestamp(line: str) -> Optional[str]:
    for pat in _TS_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1)
    return None


# ── Event dataclass ──────────────────────────────────────────────────────────
@dataclass
class SecurityEvent:
    line_no: int
    raw: str
    rule_name: str
    severity: str
    category: str
    description: str
    source_ip: Optional[str]
    timestamp: Optional[str]
    brute_force: bool = False

    @property
    def sev_rank(self) -> int:
        return SEV_ORDER.get(self.severity, 0)

    def as_dict(self) -> dict:
        return {
            "line_no": self.line_no,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "source_ip": self.source_ip,
            "brute_force": self.brute_force,
            "rule": self.rule_name,
            "raw": self.raw.strip(),
        }


# ── Parser ───────────────────────────────────────────────────────────────────
class LogParser:
    """Scan log lines against the rule set and return SecurityEvent objects."""

    def __init__(self, brute_threshold: int = BRUTE_FORCE_THRESHOLD):
        self.brute_threshold = brute_threshold

    def parse_lines(self, lines: list[str]) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        ip_counts: dict[str, int] = defaultdict(int)

        for lineno, line in enumerate(lines, start=1):
            line = line.rstrip()
            if not line:
                continue
            event = self._match(lineno, line)
            if event:
                events.append(event)
                if event.source_ip:
                    ip_counts[event.source_ip] += 1

        # Brute-force escalation pass
        brute_ips = {ip for ip, cnt in ip_counts.items() if cnt >= self.brute_threshold}
        for ev in events:
            if ev.source_ip in brute_ips and ev.sev_rank >= SEV_ORDER["MEDIUM"]:
                ev.brute_force = True
                ev.severity = "CRITICAL"

        return events

    def parse_file(self, path: Path) -> list[SecurityEvent]:
        lines = path.read_text(errors="replace").splitlines()
        return self.parse_lines(lines)

    def _match(self, lineno: int, line: str) -> Optional[SecurityEvent]:
        for rule in RULES:
            m = rule.pattern.search(line)
            if m:
                ip = None
                if rule.ip_group is not None:
                    try:
                        ip = m.group(rule.ip_group)
                    except IndexError:
                        pass
                return SecurityEvent(
                    line_no=lineno,
                    raw=line,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    source_ip=ip,
                    timestamp=_extract_timestamp(line),
                )
        return None


# ── Summary helpers ──────────────────────────────────────────────────────────
def summarize(events: list[SecurityEvent]) -> dict:
    sev_counts: dict[str, int] = defaultdict(int)
    cat_counts: dict[str, int] = defaultdict(int)
    ip_counts:  dict[str, int] = defaultdict(int)

    for ev in events:
        sev_counts[ev.severity] += 1
        cat_counts[ev.category] += 1
        if ev.source_ip:
            ip_counts[ev.source_ip] += 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total": len(events),
        "by_severity": dict(sev_counts),
        "by_category": dict(cat_counts),
        "top_ips": top_ips,
        "brute_force_count": sum(1 for e in events if e.brute_force),
    }
