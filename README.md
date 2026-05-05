# SOC Log Analyzer

> **Security Operations Center threat detection tool** — parse SSH, Apache/Nginx, and Windows Event logs to surface brute-force attacks, LFI, SQL injection, XSS, privilege escalation, and more.

[![CI](https://github.com/AlexPhilip01/soc-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexPhilip01/soc-log-analyzer/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

| Capability | Details |
|---|---|
| **Log formats** | SSH auth (`/var/log/auth.log`), Apache/Nginx access logs, Windows Event Log (CSV) |
| **25+ detection rules** | Brute force, LFI, path traversal, XSS, SQLi, privilege escalation, recon, persistence |
| **Brute-force detection** | Auto-escalates IPs with ≥ N hits to `CRITICAL` |
| **Output formats** | Pretty terminal (ANSI colour), JSON, CSV, Markdown |
| **Filtering** | By severity, category, or source IP |
| **Zero dependencies** | Pure Python stdlib — nothing to install beyond Python 3.10+ |
| **CI-ready** | Non-zero exit code when HIGH/CRITICAL events found — works in pipelines |

---

## Quick Start

```bash
# Clone
git clone https://github.com/AlexPhilip01/soc-log-analyzer.git
cd soc-log-analyzer

# Install (editable — no venv required for stdlib-only tool)
pip install -e .

# Analyze a file
soc-analyzer /var/log/auth.log

# Try the built-in samples
soc-analyzer data/sample_logs/auth.log
soc-analyzer data/sample_logs/apache_access.log
soc-analyzer data/sample_logs/windows_events.log
```

---

## Usage

```
soc-analyzer [FILE ...] [OPTIONS]
```

| Option | Description |
|---|---|
| `FILE` | One or more log files. Use `-` to read from stdin. |
| `-f, --format` | Output format: `pretty` (default), `json`, `csv`, `markdown` |
| `-o, --output FILE` | Write output to a file instead of stdout |
| `-s, --severity LEVEL` | Show only events at this level and above (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `-c, --category CAT` | Filter by category (`brute_force`, `lfi`, `sqli`, `xss`, `recon`, `auth`, `privilege`, …) |
| `--ip IP` | Show events from a specific source IP |
| `-v, --verbose` | Include the raw log line under each event |
| `--no-color` | Disable ANSI colour codes |
| `--brute-threshold N` | Hits-per-IP before brute-force flag fires (default: 5) |
| `--version` | Show version and exit |

### Examples

```bash
# Terminal report, show only CRITICAL and above
soc-analyzer auth.log -s CRITICAL

# Export JSON report
soc-analyzer auth.log apache_access.log -f json -o report.json

# Export Markdown for a GitHub issue / ticket
soc-analyzer auth.log -f markdown -o report.md

# Pipe from stdin
tail -f /var/log/auth.log | soc-analyzer -

# Filter to a specific attacker IP
soc-analyzer auth.log --ip 45.67.89.101

# Filter by attack category
soc-analyzer access.log -c sqli --verbose

# Use in a CI/CD pipeline (exits 1 on HIGH+ events)
soc-analyzer auth.log --no-color && echo "Clean" || echo "Threats detected"
```

---

## Detection Rules

### SSH
| Rule | Severity | Trigger |
|---|---|---|
| `ssh_failed_login` | HIGH → CRITICAL* | Failed password attempts |
| `ssh_invalid_user` | HIGH | Login with non-existent username |
| `ssh_root_login` | HIGH | Any auth attempt as root |
| `ssh_accepted_password` | LOW | Password-based login success |
| `ssh_accepted_pubkey` | INFO | Pubkey login success |
| `sudo_to_root` | HIGH | Sudo privilege escalation |

### Web (Apache / Nginx)
| Rule | Severity | Trigger |
|---|---|---|
| `web_lfi_passwd` | CRITICAL | `GET /etc/passwd` in URL |
| `web_lfi_shadow` | CRITICAL | `GET /etc/shadow` in URL |
| `web_path_traversal` | CRITICAL | `../../..` in URL |
| `web_sqli` | CRITICAL | `UNION SELECT`, `DROP TABLE`, etc. |
| `web_xss` | CRITICAL | `<script>` in URL |
| `web_wp_brute` | HIGH → CRITICAL* | `POST /wp-login.php` 4xx |
| `web_scanner` | HIGH | Known tools in User-Agent (nikto, sqlmap, …) |

### Windows Event Log
| Rule | Severity | Trigger |
|---|---|---|
| `win_failed_logon` | HIGH → CRITICAL* | Event ID 4625 |
| `win_success_logon` | LOW | Event ID 4624 |
| `win_net_user_add` | CRITICAL | `net user <x> /add` |
| `win_add_to_admins` | CRITICAL | `net localgroup administrators /add` |
| `win_process_create` | MEDIUM | Event ID 4688 |
| `win_registry_change` | HIGH | Event ID 4657 |

*\* Automatically escalated to CRITICAL when the same IP exceeds the brute-force threshold (default: 5 hits).*

---

## Output Formats

### Pretty (terminal)
```
╔══════════════════════════════════════════════════╗
║         SOC LOG ANALYZER  —  THREAT REPORT       ║
╚══════════════════════════════════════════════════╝
  Generated : 2026-05-04 06:00:00
  Events    : 16

  SEVERITY BREAKDOWN
  ────────────────────────────────────────────────
  CRITICAL    6  ██████
  HIGH        7  ███████
  LOW         2  ██
  INFO        1  █
  ...
```

### JSON
```json
{
  "generated_at": "2026-05-04T06:00:00",
  "summary": {
    "total": 16,
    "by_severity": { "CRITICAL": 6, "HIGH": 7 },
    "top_ips": [{"ip": "192.168.1.45", "count": 7}]
  },
  "events": [...]
}
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=soc_analyzer --cov-report=term-missing

# Lint
ruff check src/ tests/
```

### Project Structure

```
soc-log-analyzer/
├── src/
│   └── soc_analyzer/
│       ├── __init__.py       # Version
│       ├── cli.py            # CLI entry point (argparse)
│       ├── parser.py         # Log parser + SecurityEvent dataclass
│       ├── rules.py          # 25+ detection rules
│       └── formatters.py     # pretty / JSON / CSV / Markdown output
├── data/
│   └── sample_logs/
│       ├── auth.log          # Sample SSH auth log
│       ├── apache_access.log # Sample Apache access log
│       └── windows_events.log
├── tests/
│   └── test_analyzer.py      # pytest test suite
├── .github/
│   └── workflows/
│       └── ci.yml            # GitHub Actions CI
├── pyproject.toml
└── README.md
```

---

## Contributing

1. Fork the repo and create a feature branch: `git checkout -b feat/my-feature`
2. Add detection rules in `src/soc_analyzer/rules.py`
3. Add tests in `tests/test_analyzer.py`
4. Run `pytest` and `ruff check` before opening a PR

---

## License

MIT © AlexPhilip01
