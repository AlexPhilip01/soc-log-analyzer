"""
GeoIP resolution for source IPs.

Primary:  ip-api.com batch JSON endpoint (free, no API key, 45 req/min)
Fallback: returns "Unknown" — no hard dependency, tool still works offline.

Results are cached in-process to avoid hammering the API on repeated IPs.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from ipaddress import ip_address
from typing import NamedTuple

_BATCH_URL = "http://ip-api.com/batch"
_TIMEOUT   = 4          # seconds per request
_CACHE: dict[str, "GeoResult"] = {}


class GeoResult(NamedTuple):
    country:      str       # "United States"
    country_code: str       # "US"
    city:         str       # "San Jose"
    org:          str       # "AS13335 Cloudflare"
    is_private:   bool      # True for RFC-1918 / loopback

    def short(self) -> str:
        """Return a compact one-liner like 'US · San Jose · AS13335 Cloudflare'."""
        if self.is_private:
            return "Private / Internal"
        parts = [self.country_code, self.city, self.org]
        return " · ".join(p for p in parts if p and p != "Unknown")


_PRIVATE_RESULT = GeoResult(
    country="Private",
    country_code="--",
    city="Internal",
    org="",
    is_private=True,
)

_UNKNOWN_RESULT = GeoResult(
    country="Unknown",
    country_code="??",
    city="",
    org="",
    is_private=False,
)


def _is_private(ip: str) -> bool:
    try:
        return ip_address(ip).is_private or ip_address(ip).is_loopback
    except ValueError:
        return False


def lookup_many(ips: list[str]) -> dict[str, GeoResult]:
    """
    Resolve a list of IPs to GeoResult objects.
    Returns a dict keyed by IP.  Never raises.
    """
    results: dict[str, GeoResult] = {}
    to_fetch: list[str] = []

    for ip in ips:
        if not ip:
            continue
        if ip in _CACHE:
            results[ip] = _CACHE[ip]
        elif _is_private(ip):
            _CACHE[ip] = _PRIVATE_RESULT
            results[ip] = _PRIVATE_RESULT
        else:
            to_fetch.append(ip)

    if not to_fetch:
        return results

    # ip-api.com batch endpoint accepts up to 100 IPs per request
    for chunk_start in range(0, len(to_fetch), 100):
        chunk = to_fetch[chunk_start:chunk_start + 100]
        payload = json.dumps([
            {"query": ip, "fields": "status,country,countryCode,city,org,query"}
            for ip in chunk
        ]).encode()

        try:
            req = urllib.request.Request(
                _BATCH_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, OSError, json.JSONDecodeError, Exception):
            # Offline or rate-limited — fill with Unknown and continue
            for ip in chunk:
                _CACHE[ip] = _UNKNOWN_RESULT
                results[ip] = _UNKNOWN_RESULT
            continue

        for item in data:
            ip = item.get("query", "")
            if item.get("status") == "success":
                geo = GeoResult(
                    country=item.get("country", "Unknown"),
                    country_code=item.get("countryCode", "??"),
                    city=item.get("city", ""),
                    org=item.get("org", ""),
                    is_private=False,
                )
            else:
                geo = _UNKNOWN_RESULT
            _CACHE[ip] = geo
            results[ip] = geo

    return results


def lookup(ip: str) -> GeoResult:
    """Resolve a single IP. Returns _UNKNOWN_RESULT on failure."""
    return lookup_many([ip]).get(ip, _UNKNOWN_RESULT)


def enrich_events(events: list, use_geo: bool) -> dict[str, GeoResult]:
    """
    Given a list of SecurityEvents, fetch GeoIP for all unique source IPs.
    Returns a mapping {ip: GeoResult}.  No-ops when use_geo=False.
    """
    if not use_geo:
        return {}
    unique_ips = list({ev.source_ip for ev in events if ev.source_ip})
    return lookup_many(unique_ips)
