"""
Mini SIEM — Linux Log Parser
=============================
Deconstructs unstructured Linux log strings into structured dictionaries.

Supported Log Formats:
1. Standard Linux Syslog (RFC 3164) & Systemd (RFC 5424)
2. OpenSSH authentication logs (Failed, Accepted, Invalid User, Root Logins)
3. PAM / Sudo privilege execution and auth failure logs
4. Firewall / UFW / iptables connection and port scan logs
5. Apache and Nginx Combined Access & Error logs
"""

import re
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Adjust path to import central configuration
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config

logger = logging.getLogger("MiniSIEM.Parser")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   COMPILED REGULAR EXPRESSIONS (Optimized for high-throughput)
# ═══════════════════════════════════════════════════════════════

# Syslog header: "Oct 24 14:02:11 hostname service[1234]: message" or "Oct 24 14:02:11 hostname service: message"
RE_SYSLOG_HEADER = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>[\w\.\-]+)\s+'
    r'(?P<service>[\w\.\-\(\)\/]+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

# ISO 8601 Syslog header: "2026-10-24T14:02:11.123456+00:00 hostname service[1234]: message"
RE_ISO_SYSLOG_HEADER = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?P<hostname>[\w\.\-]+)\s+'
    r'(?P<service>[\w\.\-\(\)\/]+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

# SSH Events
RE_SSH_FAILED_PWD = re.compile(
    r'Failed password for (?:invalid user )?(?P<username>[^\s]+) from (?P<ip>[\d\.\:a-fA-F]+) port (?P<port>\d+)'
)
RE_SSH_ACCEPTED_PWD = re.compile(
    r'Accepted (?:password|publickey) for (?P<username>[^\s]+) from (?P<ip>[\d\.\:a-fA-F]+) port (?P<port>\d+)'
)
RE_SSH_INVALID_USER = re.compile(
    r'Invalid user (?P<username>[^\s]+) from (?P<ip>[\d\.\:a-fA-F]+) port (?P<port>\d+)'
)

# Sudo & PAM Events
RE_PAM_AUTH_FAIL = re.compile(
    r'pam_unix\((?P<pam_service>[\w\-]+):auth\): authentication failure;.*?(?:ruser=(?P<ruser>[^\s]*)).*?(?:user=(?P<target_user>[^\s]*))'
)
RE_SUDO_COMMAND = re.compile(
    r'^\s*(?P<username>[^\s]+)\s*:\s*TTY=(?P<tty>[^\s]*)\s*;\s*PWD=(?P<pwd>[^\s]*)\s*;\s*USER=(?P<target_user>[^\s]+)\s*;\s*COMMAND=(?P<command>.*)$'
)

# UFW / Firewall / Port Scan Indicators
RE_UFW_BLOCK = re.compile(
    r'.*?(?:\[UFW BLOCK\]|Inbound connection blocked:).*?SRC=(?P<src_ip>[\d\.\:a-fA-F]+).*?DST=(?P<dst_ip>[\d\.\:a-fA-F]+)?.*?PROTO=(?P<proto>\w+).*?SPT=(?P<spt>\d+).*?DPT=(?P<dpt>\d+)'
)

# Apache / Nginx Combined Log Format
RE_WEB_COMBINED = re.compile(
    r'^(?P<client_ip>[\d\.\:a-fA-F]+)\s+-\s+(?P<ident>[^\s]+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>[^\s]+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


# ═══════════════════════════════════════════════════════════════
#   HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def _parse_syslog_timestamp(month: str, day: str, time_str: str) -> str:
    """
    Converts Syslog RFC 3164 timestamp ('Oct 24 14:02:11') to ISO format: 'YYYY-MM-DD HH:MM:SS'.
    Assumes current year, adjusting for year boundary rollovers.
    """
    try:
        now = datetime.now()
        dt_str = f"{now.year} {month} {day.strip()} {time_str}"
        dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
        
        # Handle December -> January boundary if parsing historical year-end logs
        if dt > now and (dt - now).days > 60:
            dt = dt.replace(year=now.year - 1)
            
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_web_timestamp(ts_str: str) -> str:
    """Converts Apache timestamp ('28/Feb/2026:15:32:01 +0000') to ISO format."""
    try:
        clean_ts = ts_str.split()[0] # Remove timezone offset
        dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ═══════════════════════════════════════════════════════════════
#   CORE LOG PARSER ENGINE
# ═══════════════════════════════════════════════════════════════

class LogParser:
    """Main parsing orchestrator that extracts key cybersecurity attributes from log lines."""

    @staticmethod
    def parse_line(raw_line: str, source_name: str = "unknown") -> Dict[str, Any]:
        """
        Parses a raw log line into a normalized dictionary.
        Guaranteed to return a structured dictionary; never raises exceptions.
        """
        raw_clean = raw_line.strip()
        
        # Default structured event skeleton
        event: Dict[str, Any] = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source_name,
            "hostname": "localhost",
            "service": "system",
            "pid": None,
            "username": None,
            "source_ip": None,
            "destination_ip": None,
            "port": None,
            "event_type": "generic_log",
            "message": raw_clean,
            "raw_log": raw_clean
        }

        if not raw_clean:
            return event

        # ── 1. CHECK WEB LOGS (Apache / Nginx) ──────────────────────
        web_match = RE_WEB_COMBINED.match(raw_clean)
        if web_match:
            data = web_match.groupdict()
            status_code = int(data["status"])
            event["timestamp"] = _parse_web_timestamp(data["timestamp"])
            event["source_ip"] = data["client_ip"]
            event["service"] = "webserver"
            event["message"] = f'{data["method"]} {data["url"]} HTTP {status_code}'
            event["port"] = 80 if status_code != 443 else 443
            
            # Classify Web Events
            if status_code == 404:
                event["event_type"] = "http_404"
            else:
                event["event_type"] = "http_request"
                
            return event

        # ── 2. CHECK STANDARD SYSLOG HEADER ────────────────────────
        msg_body = raw_clean
        header_match = RE_SYSLOG_HEADER.match(raw_clean)
        
        if header_match:
            data = header_match.groupdict()
            event["timestamp"] = _parse_syslog_timestamp(data["month"], data["day"], data["time"])
            event["hostname"] = data["hostname"]
            event["service"] = data["service"]
            event["pid"] = int(data["pid"]) if data.get("pid") else None
            msg_body = data["message"]
            event["message"] = msg_body
        else:
            iso_match = RE_ISO_SYSLOG_HEADER.match(raw_clean)
            if iso_match:
                data = iso_match.groupdict()
                try:
                    # Clean ISO format to YYYY-MM-DD HH:MM:SS
                    ts = data["timestamp"].replace("T", " ")[:19]
                    event["timestamp"] = ts
                except Exception:
                    pass
                event["hostname"] = data["hostname"]
                event["service"] = data["service"]
                event["pid"] = int(data["pid"]) if data.get("pid") else None
                msg_body = data["message"]
                event["message"] = msg_body

        # ── 3. PARSE SSH MESSAGES ──────────────────────────────────
        if "sshd" in event["service"].lower():
            # Failed SSH Login
            match = RE_SSH_FAILED_PWD.search(msg_body)
            if match:
                user = match.group("username")
                event["username"] = user
                event["source_ip"] = match.group("ip")
                event["port"] = int(match.group("port"))
                
                if user == "root":
                    event["event_type"] = "ssh_root_login"
                else:
                    event["event_type"] = "ssh_failed_login"
                return event

            # Accepted SSH Login
            match = RE_SSH_ACCEPTED_PWD.search(msg_body)
            if match:
                user = match.group("username")
                event["username"] = user
                event["source_ip"] = match.group("ip")
                event["port"] = int(match.group("port"))
                
                if user == "root":
                    event["event_type"] = "ssh_root_login"
                else:
                    event["event_type"] = "ssh_successful_login"
                return event

            # Invalid SSH User
            match = RE_SSH_INVALID_USER.search(msg_body)
            if match:
                event["username"] = match.group("username")
                event["source_ip"] = match.group("ip")
                event["port"] = int(match.group("port"))
                event["event_type"] = "ssh_invalid_user"
                return event

        # ── 4. PARSE SUDO & PAM PRIVILEGE ACTIVITY ─────────────────
        if "sudo" in event["service"].lower() or "pam" in msg_body.lower():
            # Sudo command execution
            match = RE_SUDO_COMMAND.search(msg_body)
            if match:
                calling_user = match.group("username")
                target_user = match.group("target_user")
                command = match.group("command")
                event["username"] = calling_user
                event["message"] = f"sudo execution by {calling_user} as {target_user}: {command}"
                
                if target_user == "root":
                    event["event_type"] = "sudo_to_root"
                else:
                    event["event_type"] = "sudo_execution"
                return event

            # PAM Auth failure
            match = RE_PAM_AUTH_FAIL.search(msg_body)
            if match:
                ruser = match.group("ruser") or match.group("target_user")
                event["username"] = ruser if ruser else "unknown"
                event["event_type"] = "sudo_failure" if "sudo" in event["service"].lower() else "pam_auth_failure"
                return event

        # ── 5. PARSE FIREWALL / PORT SCAN LOGS ─────────────────────
        if "ufw" in event["service"].lower() or "blocked" in msg_body.lower():
            match = RE_UFW_BLOCK.search(msg_body)
            if match:
                event["source_ip"] = match.group("src_ip")
                event["destination_ip"] = match.group("dst_ip")
                event["port"] = int(match.group("dpt")) if match.group("dpt") else None
                event["event_type"] = "connection_attempt"
                event["service"] = "firewall"
                return event

        # ── 6. GENERIC FALLBACK ────────────────────────────────────
        # Extract IP via regex if an IP is present anywhere in unclassified logs
        if not event["source_ip"]:
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg_body)
            if ip_match:
                event["source_ip"] = ip_match.group(0)

        return event


# ═══════════════════════════════════════════════════════════════
#   STANDALONE PARSER SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Parser Module Self-Test...")
    
    test_cases = [
        # 1. SSH Failed Password
        (
            "Feb 28 14:22:01 srv01 sshd[12345]: Failed password for invalid user admin from 198.51.100.22 port 54321 ssh2",
            "auth.log",
            {"event_type": "ssh_failed_login", "username": "admin", "source_ip": "198.51.100.22", "port": 54321, "service": "sshd"}
        ),
        # 2. SSH Accepted (Normal Login)
        (
            "Feb 28 14:25:00 srv01 sshd[12350]: Accepted password for alice from 10.0.0.5 port 42100 ssh2",
            "auth.log",
            {"event_type": "ssh_successful_login", "username": "alice", "source_ip": "10.0.0.5", "port": 42100}
        ),
        # 3. Direct Root Login
        (
            "Feb 28 14:26:10 srv01 sshd[12355]: Accepted password for root from 203.0.113.88 port 51234 ssh2",
            "auth.log",
            {"event_type": "ssh_root_login", "username": "root", "source_ip": "203.0.113.88"}
        ),
        # 4. Invalid User Probe
        (
            "Feb 28 14:27:00 srv01 sshd[12360]: Invalid user oracle from 198.51.100.50 port 33211 ssh2",
            "auth.log",
            {"event_type": "ssh_invalid_user", "username": "oracle", "source_ip": "198.51.100.50"}
        ),
        # 5. Sudo to Root Execution
        (
            "Feb 28 14:28:15 srv01 sudo:    bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            "auth.log",
            {"event_type": "sudo_to_root", "username": "bob", "service": "sudo"}
        ),
        # 6. Sudo Failure
        (
            "Feb 28 14:29:00 srv01 sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser=attacker rhost= user=root",
            "auth.log",
            {"event_type": "sudo_failure", "username": "attacker"}
        ),
        # 7. Web 404 Directory Scan
        (
            '192.168.1.50 - - [28/Feb/2026:14:30:00 +0000] "GET /admin/config.php HTTP/1.1" 404 312 "-" "Nikto"',
            "access.log",
            {"event_type": "http_404", "source_ip": "192.168.1.50", "service": "webserver"}
        ),
        # 8. Firewall / Port Scan Block
        (
            "Feb 28 14:31:00 srv01 ufw[555]: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=192.168.1.10 PROTO=TCP SPT=45123 DPT=8080",
            "syslog",
            {"event_type": "connection_attempt", "source_ip": "198.51.100.99", "port": 8080, "service": "firewall"}
        )
    ]

    for idx, (raw_str, src, expected) in enumerate(test_cases, start=1):
        parsed = LogParser.parse_line(raw_str, src)
        print(f"[*] Testing Case #{idx}: {expected.get('event_type')}")
        
        for key, exp_val in expected.items():
            actual_val = parsed.get(key)
            assert actual_val == exp_val, (
                f"Mismatch in Case #{idx} for key '{key}': expected '{exp_val}', got '{actual_val}'\nParsed: {parsed}"
            )
        print(f"    [✓] Matched: {parsed['event_type']} | User: {parsed.get('username')} | IP: {parsed.get('source_ip')} | Port: {parsed.get('port')}")

    print("\n[✓] STEP 5 SELF-TEST PASSED. Linux Log Parser correctly extracts all security attributes.")