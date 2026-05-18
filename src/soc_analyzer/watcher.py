"""
Live tail mode — watch one or more log files for new lines and run
detection rules on each new line as it arrives.

Uses pure-stdlib polling (stat + seek) so it works on Linux, macOS,
and Windows without inotify bindings.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Callable

from .formatters import format_pretty
from .parser import SecurityEvent, Severity, detect_log_type, parse_apache, parse_ssh, parse_windows
from .rules import run_rules

# ANSI helpers
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_RED   = "\033[91m"
_CYAN  = "\033[36m"
_DIM   = "\033[2m"

_SEV_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[36m",
    Severity.INFO:     "\033[37m",
}


def _color(sev: Severity, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_SEV_COLOR[sev]}{text}{_RESET}"


def _print_event(ev: SecurityEvent, use_color: bool) -> None:
    ts = ev.timestamp.strftime("%H:%M:%S") if ev.timestamp else "??:??:??"
    sev = ev.severity.value.ljust(8)
    ip  = (ev.source_ip or "—").ljust(16)
    line = f"[{ts}] {_color(ev.severity, sev, use_color)}  {ip}  {ev.rule_id:<28}  {ev.description[:70]}"
    print(line, flush=True)


def _detect_type_from_file(path: Path) -> str:
    """Peek at the first 20 lines to detect log type."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = [fh.readline() for _ in range(20)]
        return detect_log_type(lines)
    except OSError:
        return "ssh"


def _parse_line(line: str, log_type: str, source_file: str) -> list[dict]:
    """Parse a single line into a record dict list."""
    if log_type == "apache":
        return parse_apache([line], source_file=source_file)
    if log_type == "windows":
        return parse_windows([line], source_file=source_file)
    return parse_ssh([line], source_file=source_file)


class FileTailer:
    """Tail a single file, yielding new lines as they appear."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = open(path, encoding="utf-8", errors="replace")
        self._fh.seek(0, 2)          # start at end
        self._inode = os.stat(path).st_ino
        self._size  = os.stat(path).st_size

    def close(self) -> None:
        self._fh.close()

    def read_new_lines(self) -> list[str]:
        """Return any new lines written since last call."""
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return []

        # File rotated (new inode or shrank)
        if stat.st_ino != self._inode or stat.st_size < self._size:
            self._fh.close()
            self._fh = open(self.path, encoding="utf-8", errors="replace")
            self._inode = stat.st_ino

        self._size = stat.st_size
        new_lines = self._fh.readlines()
        return [l.rstrip("\n") for l in new_lines if l.strip()]


def watch(
    paths: list[str | Path],
    poll_interval: float = 0.5,
    brute_threshold: int = 5,
    min_severity: Severity | None = None,
    use_color: bool = True,
    alert_callback: Callable[[SecurityEvent], None] | None = None,
) -> None:
    """
    Watch *paths* for new log lines and print events as they arrive.
    Blocks until KeyboardInterrupt (Ctrl-C).
    """
    tailers: dict[Path, FileTailer] = {}
    log_types: dict[Path, str] = {}

    for raw in paths:
        p = Path(raw)
        if not p.exists():
            print(f"[watch] File not found, waiting: {p}", file=sys.stderr)
            continue
        tailers[p] = FileTailer(p)
        log_types[p] = _detect_type_from_file(p)

    if use_color:
        print(f"\n{_BOLD}{'─'*80}{_RESET}")
        print(f"{_BOLD}  🔍  SOC Log Analyzer — LIVE WATCH MODE{_RESET}")
        files_str = ", ".join(str(p) for p in tailers)
        print(f"{_DIM}  Watching: {files_str}{_RESET}")
        print(f"{_DIM}  Poll interval: {poll_interval}s  |  Ctrl-C to stop{_RESET}")
        print(f"{_BOLD}{'─'*80}{_RESET}\n")
        print(f"  {'TIME':<8}  {'SEVERITY':<8}  {'SOURCE IP':<16}  {'RULE':<28}  DESCRIPTION")
        print(f"  {'─'*8}  {'─'*8}  {'─'*16}  {'─'*28}  {'─'*40}")
    else:
        print("SOC Log Analyzer — LIVE WATCH MODE")
        print(f"Watching: {', '.join(str(p) for p in tailers)}")

    try:
        while True:
            # Check for new files that didn't exist at start
            for raw in paths:
                p = Path(raw)
                if p not in tailers and p.exists():
                    tailers[p] = FileTailer(p)
                    log_types[p] = _detect_type_from_file(p)
                    print(f"[watch] Now watching: {p}", file=sys.stderr)

            for p, tailer in list(tailers.items()):
                new_lines = tailer.read_new_lines()
                for line in new_lines:
                    recs = _parse_line(line, log_types[p], str(p))
                    events = run_rules(recs, brute_threshold=brute_threshold)
                    for ev in events:
                        if min_severity and ev.severity < min_severity:
                            continue
                        print("  ", end="")
                        _print_event(ev, use_color)
                        if alert_callback:
                            alert_callback(ev)

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n{'─'*80}")
        print("  Watch stopped.")
    finally:
        for t in tailers.values():
            t.close()
