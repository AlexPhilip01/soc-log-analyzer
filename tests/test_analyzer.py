"""Tests for soc-log-analyzer."""

import pytest
from src.soc_analyzer.parser import LogParser, summarize
from src.soc_analyzer.formatters import format_json, format_csv, format_markdown, format_pretty


# ── Fixtures ──────────────────────────────────────────────────────────────────
SSH_BRUTE = [
    "May 04 03:12:01 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    "May 04 03:12:02 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    "May 04 03:12:03 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    "May 04 03:12:04 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    "May 04 03:12:05 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    "May 04 03:12:06 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
]

WEB_ATTACKS = [
    '1.2.3.4 - - [04/May/2026:08:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0',
    '1.2.3.4 - - [04/May/2026:08:00:01 +0000] "GET /page?id=1 UNION SELECT * FROM users HTTP/1.1" 400 0',
    '5.5.5.5 - - [04/May/2026:08:00:02 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 0',
]

WIN_EVENTS = [
    "2026-05-04 02:30:15,EventID=4625,Account=Administrator,IP=192.168.1.1",
    "2026-05-04 02:30:16,EventID=4625,Account=Administrator,IP=192.168.1.1",
    "2026-05-04 02:30:17,EventID=4625,Account=Administrator,IP=192.168.1.1",
    "2026-05-04 02:30:18,EventID=4625,Account=Administrator,IP=192.168.1.1",
    "2026-05-04 02:30:19,EventID=4625,Account=Administrator,IP=192.168.1.1",
    "2026-05-04 02:30:20,EventID=4625,Account=Administrator,IP=192.168.1.1",
    "2026-05-04 03:00:00,EventID=4688,Account=SYSTEM,CommandLine=net user hacker /add",
    "2026-05-04 03:00:01,EventID=4688,Account=SYSTEM,CommandLine=net localgroup administrators hacker /add",
]

BENIGN = [
    "May 04 04:00:00 server sshd[2]: Accepted publickey for deploy from 10.0.0.1 port 443 ssh2",
    '10.0.0.5 - - [04/May/2026:08:05:00 +0000] "GET /dashboard HTTP/1.1" 200 8921',
]


@pytest.fixture
def parser():
    return LogParser(brute_threshold=5)


# ── SSH tests ─────────────────────────────────────────────────────────────────
class TestSSH:
    def test_detects_failed_login(self, parser):
        events = parser.parse_lines(["May 04 03:00:00 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"])
        assert len(events) == 1
        assert events[0].severity in ("HIGH", "CRITICAL")

    def test_brute_force_escalation(self, parser):
        events = parser.parse_lines(SSH_BRUTE)
        # All hits from the same IP should be escalated
        critical = [e for e in events if e.severity == "CRITICAL"]
        assert len(critical) > 0

    def test_brute_force_flag(self, parser):
        events = parser.parse_lines(SSH_BRUTE)
        assert any(e.brute_force for e in events)

    def test_extracts_source_ip(self, parser):
        events = parser.parse_lines(["May 04 03:00:00 sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2"])
        assert events[0].source_ip == "9.9.9.9"

    def test_accepted_login_low_severity(self, parser):
        events = parser.parse_lines(["May 04 03:00:00 sshd[1]: Accepted password for admin from 10.0.0.1 port 22 ssh2"])
        assert events[0].severity == "LOW"


# ── Web attack tests ───────────────────────────────────────────────────────────
class TestWebAttacks:
    def test_lfi_passwd_critical(self, parser):
        events = parser.parse_lines(['1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0'])
        assert events[0].severity == "CRITICAL"
        assert events[0].category == "lfi"

    def test_sqli_critical(self, parser):
        events = parser.parse_lines(['1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /?id=1 UNION SELECT 1,2,3 HTTP/1.1" 400 0'])
        assert events[0].severity == "CRITICAL"
        assert events[0].category == "sqli"

    def test_xss_critical(self, parser):
        events = parser.parse_lines(['1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 0'])
        assert events[0].severity == "CRITICAL"
        assert events[0].category == "xss"

    def test_multiple_web_attacks(self, parser):
        events = parser.parse_lines(WEB_ATTACKS)
        assert len(events) >= 3


# ── Windows tests ─────────────────────────────────────────────────────────────
class TestWindowsEvents:
    def test_failed_logon_4625(self, parser):
        events = parser.parse_lines(["2026-05-04 02:30:15,EventID=4625,Account=Administrator,IP=192.168.1.1"])
        assert len(events) == 1
        assert "4625" in events[0].description

    def test_net_user_add_critical(self, parser):
        events = parser.parse_lines(["2026-05-04 03:00:00,EventID=4688,CommandLine=net user hacker /add"])
        critical = [e for e in events if e.severity == "CRITICAL"]
        assert len(critical) >= 1

    def test_brute_force_on_windows(self, parser):
        events = parser.parse_lines(WIN_EVENTS)
        brute = [e for e in events if e.brute_force]
        assert len(brute) > 0


# ── Summary tests ──────────────────────────────────────────────────────────────
class TestSummary:
    def test_summary_counts(self, parser):
        events = parser.parse_lines(SSH_BRUTE + WEB_ATTACKS)
        s = summarize(events)
        assert s["total"] == len(events)
        assert "CRITICAL" in s["by_severity"] or "HIGH" in s["by_severity"]

    def test_top_ips(self, parser):
        events = parser.parse_lines(SSH_BRUTE)
        s = summarize(events)
        assert s["top_ips"][0][0] == "10.0.0.1"

    def test_benign_logs_no_critical(self, parser):
        events = parser.parse_lines(BENIGN)
        critical = [e for e in events if e.severity == "CRITICAL"]
        assert len(critical) == 0


# ── Formatter tests ────────────────────────────────────────────────────────────
class TestFormatters:
    @pytest.fixture
    def sample_events(self, parser):
        return parser.parse_lines(SSH_BRUTE + WEB_ATTACKS)

    def test_json_valid(self, sample_events):
        import json
        out = format_json(sample_events)
        data = json.loads(out)
        assert "events" in data
        assert "summary" in data

    def test_csv_has_header(self, sample_events):
        out = format_csv(sample_events)
        assert out.startswith("line_no,timestamp,severity")

    def test_markdown_has_table(self, sample_events):
        out = format_markdown(sample_events)
        assert "| Severity |" in out
        assert "CRITICAL" in out or "HIGH" in out

    def test_pretty_no_crash(self, sample_events):
        out = format_pretty(sample_events, colour=False)
        assert "SOC LOG ANALYZER" in out

    def test_empty_events(self):
        out = format_pretty([], colour=False)
        assert "0" in out
