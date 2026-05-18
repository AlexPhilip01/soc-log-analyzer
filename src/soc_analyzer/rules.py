"""
Detection rules engine.

Each rule function receives a raw record dict from parser.py and returns
a SecurityEvent (or None).  The engine then applies brute-force escalation.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Callable

from .parser import SecurityEvent, Severity

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ev(rule_id, severity, category, description, rec, **extra) -> SecurityEvent:
    return SecurityEvent(
        rule_id=rule_id,
        severity=severity,
        category=category,
        description=description,
        source_ip=rec.get("source_ip"),
        timestamp=rec.get("timestamp"),
        raw_line=rec.get("line", ""),
        source_file=rec.get("source_file", ""),
        extra=extra,
    )


# ──────────────────────────────────────────────────────────────────────────────
# SSH rules
# ──────────────────────────────────────────────────────────────────────────────

_SSH_FAILED    = re.compile(r"Failed (password|publickey) for (\S+)", re.I)
_SSH_INVALID   = re.compile(r"Invalid user (\S+)", re.I)
_SSH_ROOT      = re.compile(r"(Failed|Accepted) \S+ for root", re.I)
_SSH_ACC_PW    = re.compile(r"Accepted password for (\S+)", re.I)
_SSH_ACC_PK    = re.compile(r"Accepted publickey for (\S+)", re.I)
_SSH_SUDO      = re.compile(r"sudo.*COMMAND.*su\b|sudo.*-i\b", re.I)
_SSH_CONN_CLOSED = re.compile(r"Connection closed by authenticating user", re.I)
_SSH_DISC      = re.compile(r"Disconnected from authenticating user (\S+)", re.I)
_SSH_BRUTE_PAT = re.compile(r"message repeated (\d+) times", re.I)
_SSH_PERM_DENIED = re.compile(r"Permission denied", re.I)


def rule_ssh_failed_login(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "ssh":
        return None
    line = rec["line"]
    m = _SSH_FAILED.search(line)
    if not m:
        return None
    user = m.group(2)
    return _ev("ssh_failed_login", Severity.HIGH, "brute_force",
               f"SSH failed login for user '{user}'", rec, user=user)


def rule_ssh_invalid_user(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "ssh":
        return None
    m = _SSH_INVALID.search(rec["line"])
    if not m:
        return None
    user = m.group(1)
    return _ev("ssh_invalid_user", Severity.HIGH, "auth",
               f"SSH login attempt for non-existent user '{user}'", rec, user=user)


def rule_ssh_root_login(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "ssh":
        return None
    if _SSH_ROOT.search(rec["line"]):
        return _ev("ssh_root_login", Severity.HIGH, "privilege",
                   "SSH authentication attempt as root", rec)
    return None


def rule_ssh_accepted_password(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "ssh":
        return None
    m = _SSH_ACC_PW.search(rec["line"])
    if not m:
        return None
    user = m.group(1)
    return _ev("ssh_accepted_password", Severity.LOW, "auth",
               f"Successful SSH password login for '{user}'", rec, user=user)


def rule_ssh_accepted_pubkey(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "ssh":
        return None
    m = _SSH_ACC_PK.search(rec["line"])
    if not m:
        return None
    user = m.group(1)
    return _ev("ssh_accepted_pubkey", Severity.INFO, "auth",
               f"Successful SSH pubkey login for '{user}'", rec, user=user)


def rule_sudo_to_root(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "ssh":
        return None
    if _SSH_SUDO.search(rec["line"]):
        return _ev("sudo_to_root", Severity.HIGH, "privilege",
                   "Sudo privilege escalation to root", rec)
    return None


def rule_ssh_repeated_failures(rec: dict) -> SecurityEvent | None:
    """Catch 'message repeated N times' patterns in syslog."""
    if rec["log_type"] != "ssh":
        return None
    m = _SSH_BRUTE_PAT.search(rec["line"])
    if m and "Failed" in rec["line"]:
        count = int(m.group(1))
        return _ev("ssh_repeated_failures", Severity.CRITICAL, "brute_force",
                   f"SSH failures repeated {count} times in syslog", rec, count=count)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Web (Apache / Nginx) rules
# ──────────────────────────────────────────────────────────────────────────────

_LFI_PASSWD  = re.compile(r"(etc/passwd|etc%2Fpasswd)", re.I)
_LFI_SHADOW  = re.compile(r"(etc/shadow|etc%2Fshadow)", re.I)
_PATH_TRAV   = re.compile(r"(\.\./|\.\.%2F){2,}", re.I)
_SQLI        = re.compile(
    r"(union(\s|%20|\+)+select|drop(\s|%20|\+)+table|'(\s)?or(\s)?'|"
    r"1=1|exec(\s|\()|(xp_|sp_)\w|insert\s+into|delete\s+from|"
    r"benchmark\(|sleep\(|load_file\()",
    re.I,
)
_XSS         = re.compile(r"(<script|javascript:|on\w+=|<img[^>]+onerror)", re.I)
_SCANNERS    = re.compile(
    r"(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|"
    r"burpsuite|acunetix|nessus|openvas|w3af|skipfish|arachni)",
    re.I,
)
_WP_LOGIN    = re.compile(r"/wp-login\.php", re.I)
_PHPMYADMIN  = re.compile(r"/(phpmyadmin|pma)/", re.I)
_SHELL_UPLOAD = re.compile(r"\.(php|phtml|php5|phar)\?", re.I)
_SHELL_CMD   = re.compile(r"(cmd=|exec=|system=|shell=|passthru=)", re.I)
_ADMIN_SCAN  = re.compile(r"/(admin|administrator|wp-admin|manager|console)", re.I)
_RFI         = re.compile(r"(https?://|ftp://)[^\s]+\.php", re.I)
_JAVA_LOG4J  = re.compile(r"\$\{jndi:", re.I)


def rule_web_lfi_passwd(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _LFI_PASSWD.search(rec["path"]):
        return _ev("web_lfi_passwd", Severity.CRITICAL, "lfi",
                   f"LFI attempt: /etc/passwd in request {rec['path']}", rec)
    return None


def rule_web_lfi_shadow(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _LFI_SHADOW.search(rec["path"]):
        return _ev("web_lfi_shadow", Severity.CRITICAL, "lfi",
                   f"LFI attempt: /etc/shadow in request {rec['path']}", rec)
    return None


def rule_web_path_traversal(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _PATH_TRAV.search(rec["path"]):
        return _ev("web_path_traversal", Severity.CRITICAL, "lfi",
                   f"Path traversal detected in {rec['path']}", rec)
    return None


def rule_web_sqli(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _SQLI.search(rec["path"]):
        return _ev("web_sqli", Severity.CRITICAL, "sqli",
                   f"SQL injection attempt in {rec['path']}", rec)
    return None


def rule_web_xss(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _XSS.search(rec["path"]):
        return _ev("web_xss", Severity.CRITICAL, "xss",
                   f"XSS attempt detected in {rec['path']}", rec)
    return None


def rule_web_scanner(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache":
        return None
    ua = rec.get("ua") or ""
    if _SCANNERS.search(ua):
        return _ev("web_scanner", Severity.HIGH, "recon",
                   f"Known scanner User-Agent detected: {ua[:80]}", rec, ua=ua)
    return None


def rule_web_wp_brute(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _WP_LOGIN.search(rec["path"]) and rec.get("method") == "POST":
        status = rec.get("status", 0)
        sev = Severity.HIGH if status < 400 else Severity.HIGH
        return _ev("web_wp_brute", sev, "brute_force",
                   f"WordPress login attempt (HTTP {status})", rec)
    return None


def rule_web_phpmyadmin(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _PHPMYADMIN.search(rec["path"]):
        return _ev("web_phpmyadmin", Severity.HIGH, "recon",
                   f"phpMyAdmin access attempt: {rec['path']}", rec)
    return None


def rule_web_shell_upload(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _SHELL_UPLOAD.search(rec["path"]):
        return _ev("web_shell_upload", Severity.CRITICAL, "rce",
                   f"Possible webshell upload/exec: {rec['path']}", rec)
    return None


def rule_web_shell_cmd(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _SHELL_CMD.search(rec["path"]):
        return _ev("web_shell_cmd", Severity.CRITICAL, "rce",
                   f"Remote command execution attempt: {rec['path']}", rec)
    return None


def rule_web_admin_scan(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _ADMIN_SCAN.search(rec["path"]) and rec.get("status") in (401, 403, 404):
        return _ev("web_admin_scan", Severity.MEDIUM, "recon",
                   f"Admin panel probe (HTTP {rec.get('status')}): {rec['path']}", rec)
    return None


def rule_web_rfi(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache" or not rec.get("path"):
        return None
    if _RFI.search(rec["path"]):
        return _ev("web_rfi", Severity.CRITICAL, "rfi",
                   f"Remote file inclusion attempt: {rec['path']}", rec)
    return None


def rule_web_log4j(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "apache":
        return None
    line = rec.get("line", "")
    if _JAVA_LOG4J.search(line):
        return _ev("web_log4j", Severity.CRITICAL, "rce",
                   "Log4Shell (CVE-2021-44228) exploitation attempt", rec)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Windows Event Log rules
# ──────────────────────────────────────────────────────────────────────────────

_NET_USER_ADD  = re.compile(r"net\s+user\s+\S+\s+/add", re.I)
_NET_ADMIN_ADD = re.compile(r"net\s+localgroup\s+administrators.*?/add", re.I)
_MIMIKATZ      = re.compile(r"(mimikatz|sekurlsa|lsadump|privilege::debug)", re.I)
_POWERSHELL_ENC = re.compile(r"powershell.*-enc\w*\s+[A-Za-z0-9+/=]{30,}", re.I)
_TASK_SCHED    = re.compile(r"schtasks.*/(create|change)", re.I)
_REG_RUN       = re.compile(r"(HKCU|HKLM).*\\(Run|RunOnce)", re.I)
_WMI_EXEC      = re.compile(r"wmic.*process\s+call\s+create", re.I)


def rule_win_failed_logon(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    if rec.get("event_id") == 4625:
        return _ev("win_failed_logon", Severity.HIGH, "brute_force",
                   "Windows failed logon (Event 4625)", rec)
    return None


def rule_win_success_logon(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    if rec.get("event_id") == 4624:
        return _ev("win_success_logon", Severity.LOW, "auth",
                   "Windows successful logon (Event 4624)", rec)
    return None


def rule_win_net_user_add(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    msg = rec.get("message", "")
    if _NET_USER_ADD.search(msg):
        return _ev("win_net_user_add", Severity.CRITICAL, "persistence",
                   "New local user account created via 'net user /add'", rec)
    return None


def rule_win_add_to_admins(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    msg = rec.get("message", "")
    if _NET_ADMIN_ADD.search(msg):
        return _ev("win_add_to_admins", Severity.CRITICAL, "privilege",
                   "User added to Administrators group", rec)
    return None


def rule_win_process_create(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    if rec.get("event_id") == 4688:
        msg = rec.get("message", "")
        # Escalate if suspicious process
        if _MIMIKATZ.search(msg):
            return _ev("win_mimikatz", Severity.CRITICAL, "credential_dump",
                       "Mimikatz-like credential dumping detected", rec)
        if _POWERSHELL_ENC.search(msg):
            return _ev("win_ps_encoded", Severity.HIGH, "execution",
                       "Encoded PowerShell command detected", rec)
        if _WMI_EXEC.search(msg):
            return _ev("win_wmi_exec", Severity.HIGH, "execution",
                       "WMI remote process execution detected", rec)
        return _ev("win_process_create", Severity.MEDIUM, "execution",
                   "Process creation logged (Event 4688)", rec)
    return None


def rule_win_registry_change(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    if rec.get("event_id") == 4657:
        msg = rec.get("message", "")
        sev = Severity.CRITICAL if _REG_RUN.search(msg) else Severity.HIGH
        desc = ("Registry Run-key modified (possible persistence)" if _REG_RUN.search(msg)
                else "Registry value changed (Event 4657)")
        return _ev("win_registry_change", sev, "persistence", desc, rec)
    return None


def rule_win_task_scheduler(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    msg = rec.get("message", "")
    if _TASK_SCHED.search(msg):
        return _ev("win_task_sched", Severity.HIGH, "persistence",
                   "Scheduled task created/modified — possible persistence", rec)
    return None


def rule_win_account_lockout(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    if rec.get("event_id") == 4740:
        return _ev("win_account_lockout", Severity.HIGH, "brute_force",
                   "Windows account locked out (Event 4740)", rec)
    return None


def rule_win_security_log_cleared(rec: dict) -> SecurityEvent | None:
    if rec["log_type"] != "windows":
        return None
    if rec.get("event_id") in (1102, 517):
        return _ev("win_log_cleared", Severity.CRITICAL, "evasion",
                   "Windows Security Event Log cleared — possible cover-up", rec)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Rule registry
# ──────────────────────────────────────────────────────────────────────────────

ALL_RULES: list[Callable[[dict], SecurityEvent | None]] = [
    # SSH
    rule_ssh_failed_login,
    rule_ssh_invalid_user,
    rule_ssh_root_login,
    rule_ssh_accepted_password,
    rule_ssh_accepted_pubkey,
    rule_sudo_to_root,
    rule_ssh_repeated_failures,
    # Web
    rule_web_lfi_passwd,
    rule_web_lfi_shadow,
    rule_web_path_traversal,
    rule_web_sqli,
    rule_web_xss,
    rule_web_scanner,
    rule_web_wp_brute,
    rule_web_phpmyadmin,
    rule_web_shell_upload,
    rule_web_shell_cmd,
    rule_web_admin_scan,
    rule_web_rfi,
    rule_web_log4j,
    # Windows
    rule_win_failed_logon,
    rule_win_success_logon,
    rule_win_net_user_add,
    rule_win_add_to_admins,
    rule_win_process_create,
    rule_win_registry_change,
    rule_win_task_scheduler,
    rule_win_account_lockout,
    rule_win_security_log_cleared,
]


# ──────────────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────────────

def run_rules(
    records: list[dict],
    brute_threshold: int = 5,
) -> list[SecurityEvent]:
    """Apply all rules and escalate brute-force IPs above threshold."""
    events: list[SecurityEvent] = []
    ip_counts: defaultdict[str, int] = defaultdict(int)

    for rec in records:
        for rule in ALL_RULES:
            ev = rule(rec)
            if ev is None:
                continue
            if ev.source_ip:
                ip_counts[ev.source_ip] += 1
            events.append(ev)

    # Brute-force escalation
    for ev in events:
        if (
            ev.source_ip
            and ip_counts[ev.source_ip] >= brute_threshold
            and ev.severity in (Severity.HIGH, Severity.MEDIUM)
            and ev.category in ("brute_force", "auth")
        ):
            ev.severity = Severity.CRITICAL
            ev.description += f" [ESCALATED: {ip_counts[ev.source_ip]} hits from {ev.source_ip}]"

    return events
