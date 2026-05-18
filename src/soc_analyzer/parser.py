"""
Log parser — parses SSH auth, Apache/Nginx access, and Windows Event CSV logs.
Returns a list of SecurityEvent dataclasses for downstream rule evaluation.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    def __ge__(self, other: "Severity") -> bool:
        order = list(Severity)
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "Severity") -> bool:
        order = list(Severity)
        return order.index(self) > order.index(other)


@dataclass
class SecurityEvent:
    rule_id:    str
    severity:   Severity
    category:   str
    description: str
    source_ip:  str | None
    timestamp:  datetime | None
    raw_line:   str
    source_file: str = ""
    extra:      dict = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Log-type detection
# ──────────────────────────────────────────────────────────────────────────────

_SSH_RE      = re.compile(r"^\w{3}\s+\d+ \d{2}:\d{2}:\d{2}")
_APACHE_RE   = re.compile(r'^\S+ \S+ \S+ \[')
_WIN_HEADER  = re.compile(r"EventID|Event.ID", re.IGNORECASE)


def detect_log_type(lines: list[str]) -> str:
    sample = "\n".join(lines[:20])
    if _WIN_HEADER.search(sample):
        return "windows"
    if _APACHE_RE.search(sample):
        return "apache"
    return "ssh"


# ──────────────────────────────────────────────────────────────────────────────
# SSH parser
# ──────────────────────────────────────────────────────────────────────────────

_SSH_TS_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _parse_ssh_ts(line: str) -> datetime | None:
    m = _SSH_TS_RE.match(line)
    if not m:
        return None
    try:
        year = datetime.now().year
        return datetime.strptime(
            f"{m['month']} {m['day']} {m['time']} {year}",
            "%b %d %H:%M:%S %Y",
        )
    except ValueError:
        return None


def parse_ssh(lines: list[str], source_file: str = "") -> list[dict]:
    """Return raw dicts; rules.py will convert them to SecurityEvent."""
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        ts = _parse_ssh_ts(line)
        ips = _IP_RE.findall(line)
        records.append({
            "line": line,
            "timestamp": ts,
            "source_ip": ips[0] if ips else None,
            "source_file": source_file,
            "log_type": "ssh",
        })
    return records


# ──────────────────────────────────────────────────────────────────────────────
# Apache / Nginx combined log parser
# ──────────────────────────────────────────────────────────────────────────────

_APACHE_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) \S+'
    r'(?:\s+"(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
_APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache(lines: list[str], source_file: str = "") -> list[dict]:
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _APACHE_LINE_RE.match(line)
        if not m:
            records.append({
                "line": line, "timestamp": None, "source_ip": None,
                "source_file": source_file, "log_type": "apache",
                "method": None, "path": None, "status": None, "ua": None,
            })
            continue
        try:
            ts = datetime.strptime(m["ts"], _APACHE_TS_FMT).replace(tzinfo=None)
        except ValueError:
            ts = None
        records.append({
            "line": line,
            "timestamp": ts,
            "source_ip": m["ip"],
            "source_file": source_file,
            "log_type": "apache",
            "method": m["method"],
            "path": m["path"],
            "status": int(m["status"]),
            "ua": m.groupdict().get("ua") or "",
        })
    return records


# ──────────────────────────────────────────────────────────────────────────────
# Windows Event Log (CSV) parser
# ──────────────────────────────────────────────────────────────────────────────

_WIN_TS_FMTS = [
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
]


def _parse_win_ts(raw: str) -> datetime | None:
    raw = raw.strip()
    for fmt in _WIN_TS_FMTS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _normalise_win_header(h: str) -> str:
    return h.strip().lower().replace(" ", "_").replace("-", "_")


def parse_windows(lines: list[str], source_file: str = "") -> list[dict]:
    text = "\n".join(lines)
    reader = csv.DictReader(io.StringIO(text))
    records = []
    for row in reader:
        norm = {_normalise_win_header(k): v for k, v in row.items()}
        raw_line = ",".join(row.values())

        # Event ID — try common column names
        event_id = None
        for key in ("eventid", "event_id", "id"):
            if key in norm:
                try:
                    event_id = int(norm[key])
                except (ValueError, TypeError):
                    pass
                break

        # Timestamp
        ts = None
        for key in ("timecreated", "timestamp", "time", "date_time", "datetime"):
            if key in norm and norm[key]:
                ts = _parse_win_ts(norm[key])
                if ts:
                    break

        # Message / description
        message = norm.get("message", norm.get("description", raw_line))

        # Source IP
        ips = _IP_RE.findall(message)

        records.append({
            "line": raw_line,
            "timestamp": ts,
            "source_ip": ips[0] if ips else None,
            "source_file": source_file,
            "log_type": "windows",
            "event_id": event_id,
            "message": message,
            "norm": norm,
        })
    return records


# ──────────────────────────────────────────────────────────────────────────────
# Unified entry point
# ──────────────────────────────────────────────────────────────────────────────

def parse_file(path: str | Path) -> list[dict]:
    """Auto-detect log type and return list of raw record dicts."""
    p = Path(path)
    with open(p, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    log_type = detect_log_type(lines)
    if log_type == "windows":
        return parse_windows(lines, source_file=str(p))
    if log_type == "apache":
        return parse_apache(lines, source_file=str(p))
    return parse_ssh(lines, source_file=str(p))


def parse_stdin(stream) -> list[dict]:
    lines = stream.readlines()
    log_type = detect_log_type(lines)
    if log_type == "windows":
        return parse_windows(lines, source_file="<stdin>")
    if log_type == "apache":
        return parse_apache(lines, source_file="<stdin>")
    return parse_ssh(lines, source_file="<stdin>")
