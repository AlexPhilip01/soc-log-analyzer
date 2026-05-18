"""
Webhook alerting for HIGH and CRITICAL events.

Supports:
  - Slack incoming webhooks (auto-detected by URL pattern)
  - Generic JSON webhooks (any other URL)

Pure stdlib — urllib only, zero new dependencies.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime

from .parser import SecurityEvent, Severity

# Severities that trigger alerts
ALERT_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

# Slack colour attachments
_SEV_COLOR_HEX = {
    Severity.CRITICAL: "#FF0000",
    Severity.HIGH:     "#FF6600",
    Severity.MEDIUM:   "#FFCC00",
    Severity.LOW:      "#0099FF",
    Severity.INFO:     "#AAAAAA",
}

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


def _is_slack_url(url: str) -> bool:
    return "hooks.slack.com" in url


def _slack_payload(ev: SecurityEvent) -> dict:
    ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "unknown time"
    emoji  = _SEV_EMOJI.get(ev.severity, "")
    color  = _SEV_COLOR_HEX.get(ev.severity, "#AAAAAA")

    return {
        "text": f"{emoji} *SOC Alert — {ev.severity.value}*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Rule",        "value": ev.rule_id,              "short": True},
                    {"title": "Category",    "value": ev.category,             "short": True},
                    {"title": "Source IP",   "value": ev.source_ip or "—",     "short": True},
                    {"title": "Timestamp",   "value": ts_str,                  "short": True},
                    {"title": "Source File", "value": ev.source_file or "—",   "short": False},
                    {"title": "Detail",      "value": ev.description,          "short": False},
                ],
                "footer": "soc-log-analyzer",
                "ts": int(ev.timestamp.timestamp()) if ev.timestamp else int(datetime.now().timestamp()),
            }
        ],
    }


def _generic_payload(ev: SecurityEvent) -> dict:
    return {
        "alert": {
            "tool":        "soc-log-analyzer",
            "generated_at": datetime.now().isoformat(),
            "rule_id":     ev.rule_id,
            "severity":    ev.severity.value,
            "category":    ev.category,
            "description": ev.description,
            "source_ip":   ev.source_ip,
            "timestamp":   ev.timestamp.isoformat() if ev.timestamp else None,
            "source_file": ev.source_file,
            "raw_line":    ev.raw_line,
        }
    }


def _post(url: str, payload: dict, timeout: int = 5) -> bool:
    """POST JSON payload to *url*. Returns True on success."""
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "soc-log-analyzer/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except urllib.error.HTTPError as exc:
        print(f"[alert] HTTP {exc.code} from webhook: {exc.reason}", file=sys.stderr)
        return False
    except (urllib.error.URLError, OSError) as exc:
        print(f"[alert] Could not reach webhook: {exc}", file=sys.stderr)
        return False


class WebhookAlerter:
    """
    Callable that posts HIGH/CRITICAL SecurityEvents to a webhook URL.

    Usage::

        alerter = WebhookAlerter(url="https://hooks.slack.com/...")
        alerter(event)          # called per-event in watch mode
        alerter.send_batch(events)  # called for batch mode
    """

    def __init__(
        self,
        url: str,
        min_severity: Severity = Severity.HIGH,
        quiet: bool = False,
    ) -> None:
        self.url          = url
        self.min_severity = min_severity
        self.quiet        = quiet
        self._is_slack    = _is_slack_url(url)
        self._sent        = 0
        self._failed      = 0

    def _should_alert(self, ev: SecurityEvent) -> bool:
        return ev.severity >= self.min_severity

    def _build_payload(self, ev: SecurityEvent) -> dict:
        return _slack_payload(ev) if self._is_slack else _generic_payload(ev)

    def __call__(self, ev: SecurityEvent) -> None:
        """Send a single event (used as callback in watch mode)."""
        if not self._should_alert(ev):
            return
        ok = _post(self.url, self._build_payload(ev))
        if ok:
            self._sent += 1
            if not self.quiet:
                print(f"[alert] ✅  Sent {ev.severity.value} alert for {ev.rule_id}", file=sys.stderr)
        else:
            self._failed += 1

    def send_batch(self, events: list[SecurityEvent]) -> tuple[int, int]:
        """
        Send alerts for all qualifying events in *events*.
        Returns (sent_count, failed_count).
        """
        for ev in events:
            self(ev)
        return self._sent, self._failed

    @property
    def stats(self) -> tuple[int, int]:
        return self._sent, self._failed
