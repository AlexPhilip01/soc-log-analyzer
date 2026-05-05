"""Detection rules for SOC log analysis."""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str          # e.g. brute_force, lfi, sqli, recon
    description: str
    ip_group: Optional[int] = None  # regex group index that captures the source IP


RULES: list[Rule] = [
    # ── SSH ──────────────────────────────────────────────────────────────────
    Rule(
        name="ssh_failed_login",
        pattern=re.compile(r"failed password for (?:invalid user )?(\S+) from ([\d.]+)", re.I),
        severity="HIGH",
        category="brute_force",
        description="SSH failed password attempt",
        ip_group=2,
    ),
    Rule(
        name="ssh_invalid_user",
        pattern=re.compile(r"invalid user \S+ from ([\d.]+)", re.I),
        severity="HIGH",
        category="recon",
        description="SSH login with invalid username",
        ip_group=1,
    ),
    Rule(
        name="ssh_accepted_password",
        pattern=re.compile(r"accepted password for (\S+) from ([\d.]+)", re.I),
        severity="LOW",
        category="auth",
        description="SSH login accepted (password)",
        ip_group=2,
    ),
    Rule(
        name="ssh_accepted_pubkey",
        pattern=re.compile(r"accepted publickey for (\S+) from ([\d.]+)", re.I),
        severity="INFO",
        category="auth",
        description="SSH login accepted (pubkey)",
        ip_group=2,
    ),
    Rule(
        name="ssh_root_login",
        pattern=re.compile(r"(accepted|failed) \S+ for root from ([\d.]+)", re.I),
        severity="HIGH",
        category="privilege",
        description="SSH login attempt as root",
        ip_group=2,
    ),
    # ── Sudo / Privilege ─────────────────────────────────────────────────────
    Rule(
        name="sudo_to_root",
        pattern=re.compile(r"sudo.*user=root.*command=(.*)", re.I),
        severity="HIGH",
        category="privilege",
        description="Sudo privilege escalation to root",
    ),
    Rule(
        name="su_failure",
        pattern=re.compile(r"su: authentication failure.*user=(.*)", re.I),
        severity="HIGH",
        category="privilege",
        description="su authentication failure",
    ),
    # ── Web / Apache / Nginx ─────────────────────────────────────────────────
    Rule(
        name="web_wp_brute",
        pattern=re.compile(r'([\d.]+).*"POST.*/wp-login\.php.*" (4\d\d)', re.I),
        severity="HIGH",
        category="brute_force",
        description="WordPress login brute-force attempt",
        ip_group=1,
    ),
    Rule(
        name="web_wp_probe",
        pattern=re.compile(r'([\d.]+).*"GET.*/wp-(login|admin)\.php', re.I),
        severity="MEDIUM",
        category="recon",
        description="WordPress admin page probe",
        ip_group=1,
    ),
    Rule(
        name="web_lfi_passwd",
        pattern=re.compile(r'([\d.]+).*"GET.*etc/passwd', re.I),
        severity="CRITICAL",
        category="lfi",
        description="LFI attempt: /etc/passwd",
        ip_group=1,
    ),
    Rule(
        name="web_lfi_shadow",
        pattern=re.compile(r'([\d.]+).*"GET.*etc/shadow', re.I),
        severity="CRITICAL",
        category="lfi",
        description="LFI attempt: /etc/shadow",
        ip_group=1,
    ),
    Rule(
        name="web_path_traversal",
        pattern=re.compile(r'([\d.]+).*"GET.*\.\./\.\./\.\.',  re.I),
        severity="CRITICAL",
        category="lfi",
        description="Path traversal attempt",
        ip_group=1,
    ),
    Rule(
        name="web_xss",
        pattern=re.compile(r'([\d.]+).*"GET.*<script', re.I),
        severity="CRITICAL",
        category="xss",
        description="Reflected XSS attempt",
        ip_group=1,
    ),
    Rule(
        name="web_sqli",
        pattern=re.compile(r'([\d.]+).*(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|INSERT\s+INTO|SELECT\s+\*)', re.I),
        severity="CRITICAL",
        category="sqli",
        description="SQL injection attempt",
        ip_group=1,
    ),
    Rule(
        name="web_scanner",
        pattern=re.compile(r'([\d.]+).*(nikto|sqlmap|nmap|masscan|zgrab|nuclei)', re.I),
        severity="HIGH",
        category="recon",
        description="Known scanner/tool detected in User-Agent",
        ip_group=1,
    ),
    Rule(
        name="web_delete",
        pattern=re.compile(r'([\d.]+).*"DELETE\s', re.I),
        severity="MEDIUM",
        category="auth",
        description="HTTP DELETE request",
        ip_group=1,
    ),
    Rule(
        name="web_4xx_flood",
        pattern=re.compile(r'([\d.]+).*" [45]\d\d ', re.I),
        severity="LOW",
        category="recon",
        description="HTTP 4xx/5xx error response",
        ip_group=1,
    ),
    # ── Windows Event Log ────────────────────────────────────────────────────
    Rule(
        name="win_failed_logon",
        pattern=re.compile(r"EventID=4625.*IP=([\d.]+)", re.I),
        severity="HIGH",
        category="brute_force",
        description="Windows failed logon (Event 4625)",
        ip_group=1,
    ),
    Rule(
        name="win_success_logon",
        pattern=re.compile(r"EventID=4624.*IP=([\d.]+)", re.I),
        severity="LOW",
        category="auth",
        description="Windows successful logon (Event 4624)",
        ip_group=1,
    ),
    Rule(
        name="win_process_create",
        pattern=re.compile(r"EventID=4688.*CommandLine=(.*)", re.I),
        severity="MEDIUM",
        category="execution",
        description="Windows process creation (Event 4688)",
    ),
    Rule(
        name="win_registry_change",
        pattern=re.compile(r"EventID=4657", re.I),
        severity="HIGH",
        category="persistence",
        description="Windows registry key modification (Event 4657)",
    ),
    Rule(
        name="win_net_user_add",
        pattern=re.compile(r"net user.*?(\S+).*?/add", re.I),
        severity="CRITICAL",
        category="persistence",
        description="Account creation via 'net user /add'",
    ),
    Rule(
        name="win_add_to_admins",
        pattern=re.compile(r"net localgroup administrators.*?/add", re.I),
        severity="CRITICAL",
        category="privilege",
        description="User added to local Administrators group",
    ),
    # ── Generic / Misc ───────────────────────────────────────────────────────
    Rule(
        name="port_scan",
        pattern=re.compile(r"([\d.]+).*SYN.*\bDROP\b", re.I),
        severity="MEDIUM",
        category="recon",
        description="Possible port scan (SYN/DROP)",
        ip_group=1,
    ),
    Rule(
        name="cron_job",
        pattern=re.compile(r"CRON.*CMD\s+\((.*)\)", re.I),
        severity="INFO",
        category="execution",
        description="Cron job executed",
    ),
]

BRUTE_FORCE_THRESHOLD = 5   # hits from the same IP before auto-upgrading to CRITICAL
