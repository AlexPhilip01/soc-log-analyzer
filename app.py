"""
SOC Log Analyzer — Flask Web Application
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# Add the src directory to path so we can import soc_analyzer
sys.path.insert(0, str(Path(__file__).parent / "src"))

from soc_analyzer.parser import Severity, parse_file
from soc_analyzer.rules import run_rules
from soc_analyzer.geoip import enrich_events

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB max upload

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEV_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#3b82f6",
    "INFO":     "#6b7280",
}
CATEGORY_ICONS = {
    "brute_force":    "🔨",
    "lfi":            "📂",
    "sqli":           "💉",
    "xss":            "⚡",
    "rce":            "💀",
    "recon":          "🔍",
    "auth":           "🔑",
    "privilege":      "👑",
    "persistence":    "🕷️",
    "evasion":        "👻",
    "execution":      "⚙️",
    "credential_dump":"🧠",
    "rfi":            "🌐",
}


def event_to_dict(ev) -> dict:
    return {
        "rule_id":     ev.rule_id,
        "severity":    ev.severity.value,
        "category":    ev.category,
        "description": ev.description,
        "source_ip":   ev.source_ip or "—",
        "timestamp":   ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—",
        "source_file": ev.source_file,
        "raw_line":    ev.raw_line[:200],
        "color":       SEV_COLORS.get(ev.severity.value, "#6b7280"),
        "icon":        CATEGORY_ICONS.get(ev.category, "🔒"),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"File type '{ext}' not supported. Use .log, .txt, .csv"}), 400

    brute_threshold = int(request.form.get("brute_threshold", 5))
    min_severity    = request.form.get("severity", "")
    category_filter = request.form.get("category", "")
    use_geo         = request.form.get("geo", "false") == "true"

    # Save to temp file and analyze
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        records = parse_file(tmp_path)
        events  = run_rules(records, brute_threshold=brute_threshold)

        # Filters
        if min_severity:
            min_sev = Severity(min_severity)
            events = [e for e in events if e.severity >= min_sev]
        if category_filter:
            events = [e for e in events if e.category == category_filter]

        # GeoIP
        geo_map = {}
        if use_geo:
            geo_map = enrich_events(events, use_geo=True)

        # Build response
        sev_counts = Counter(e.severity.value for e in events)
        cat_counts = Counter(e.category for e in events)
        ip_counts  = Counter(e.source_ip for e in events if e.source_ip and e.source_ip != "—")

        top_ips = []
        for ip, count in ip_counts.most_common(10):
            geo = geo_map.get(ip)
            top_ips.append({
                "ip":    ip,
                "count": count,
                "geo":   geo.short() if geo else "",
            })

        events_data = [event_to_dict(e) for e in events]

        # Timeline — group by hour
        timeline: dict[str, dict] = {}
        for ev in events:
            if ev.timestamp:
                hour = ev.timestamp.strftime("%H:00")
                if hour not in timeline:
                    timeline[hour] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                timeline[hour][ev.severity.value] = timeline[hour].get(ev.severity.value, 0) + 1

        return jsonify({
            "total":       len(events),
            "filename":    file.filename,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sev_counts":  {s: sev_counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "cat_counts":  dict(cat_counts.most_common(10)),
            "top_ips":     top_ips,
            "events":      events_data,
            "timeline":    timeline,
            "sev_colors":  SEV_COLORS,
            "geo_enabled": use_geo,
        })

    finally:
        os.unlink(tmp_path)


@app.route("/sample/<log_type>")
def sample(log_type):
    """Analyze a built-in sample log file."""
    samples = {
        "ssh":     "data/sample_logs/auth.log",
        "apache":  "data/sample_logs/apache_access.log",
        "windows": "data/sample_logs/windows_events.csv",
    }
    if log_type not in samples:
        return jsonify({"error": "Unknown sample"}), 404

    path = Path(__file__).parent / samples[log_type]
    if not path.exists():
        return jsonify({"error": "Sample file not found"}), 404

    records = parse_file(path)
    events  = run_rules(records, brute_threshold=5)

    sev_counts = Counter(e.severity.value for e in events)
    cat_counts = Counter(e.category for e in events)
    ip_counts  = Counter(e.source_ip for e in events if e.source_ip and e.source_ip != "—")

    top_ips = [{"ip": ip, "count": c, "geo": ""} for ip, c in ip_counts.most_common(10)]

    timeline: dict[str, dict] = {}
    for ev in events:
        if ev.timestamp:
            hour = ev.timestamp.strftime("%H:00")
            if hour not in timeline:
                timeline[hour] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            timeline[hour][ev.severity.value] = timeline[hour].get(ev.severity.value, 0) + 1

    return jsonify({
        "total":       len(events),
        "filename":    samples[log_type],
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sev_counts":  {s: sev_counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "cat_counts":  dict(cat_counts.most_common(10)),
        "top_ips":     top_ips,
        "events":      [event_to_dict(e) for e in events],
        "timeline":    timeline,
        "sev_colors":  SEV_COLORS,
        "geo_enabled": False,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
