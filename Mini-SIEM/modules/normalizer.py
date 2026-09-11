"""
Mini SIEM — Event Normalizer & Ingestion Layer
==============================================
Validates, sanitizes, and standardizes parsed event dictionaries.
Assigns baseline severities and writes normalized records to SQLite.

Guarantees consistent data models for:
- Detection Engine (Rule evaluations)
- Correlation Engine (Multi-stage incident tracking)
- Flet SOC UI (Filtering, searching, table rendering)
"""

import re
import sys
import logging
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn

logger = logging.getLogger("MiniSIEM.Normalizer")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   EXPLOIT SIGNATURE INSPECTION PATTERNS
# ═══════════════════════════════════════════════════════════════

# Common web attack payload patterns
RE_SQLI_PATTERN = re.compile(
    r'(?:union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|--\s*$|\/\*.*\*\/)',
    re.IGNORECASE
)
RE_XSS_PATTERN = re.compile(
    r'(?:<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)',
    re.IGNORECASE
)
RE_PATH_TRAVERSAL = re.compile(
    r'(?:\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|\/proc\/self)',
    re.IGNORECASE
)


# ═══════════════════════════════════════════════════════════════
#   NORMALIZATION & SANITIZATION HELPERS
# ═══════════════════════════════════════════════════════════════

def sanitize_ip(ip_str: Optional[str]) -> Optional[str]:
    """Validates and standardizes IPv4 and IPv6 address strings. Returns None if invalid."""
    if not ip_str:
        return None
    cleaned = str(ip_str).strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None


def sanitize_port(port_val: Any) -> Optional[int]:
    """Validates and casts network ports to integer range 1-65535."""
    if port_val is None:
        return None
    try:
        p = int(port_val)
        return p if 1 <= p <= 65535 else None
    except (ValueError, TypeError):
        return None


def sanitize_string(val: Optional[str], max_len: int = 1000) -> Optional[str]:
    """Strips control characters, normalizes whitespace, and truncates excess length."""
    if val is None:
        return None
    cleaned = str(val).strip()
    # Remove null bytes and non-printable control characters
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', cleaned)
    return cleaned[:max_len] if len(cleaned) > max_len else cleaned


def assign_baseline_severity(event_type: str, message: str) -> str:
    """
    Computes standard baseline severity based on event type and message payload.
    Downstream detection rules can elevate this based on frequency or correlation.
    """
    et = (event_type or "").lower()
    msg = message or ""

    # Check for direct high-risk signatures
    if et in ("ssh_root_login", "sudo_to_root"):
        return config.SEVERITY_HIGH

    # Check for web injection payloads
    if RE_SQLI_PATTERN.search(msg) or RE_XSS_PATTERN.search(msg) or RE_PATH_TRAVERSAL.search(msg):
        return config.SEVERITY_HIGH

    # Medium severity indicators
    if et in ("ssh_failed_login", "ssh_invalid_user", "sudo_failure", "pam_auth_failure"):
        return config.SEVERITY_MEDIUM

    # Low / Informational indicators
    if et in ("ssh_successful_login", "sudo_execution", "http_404", "http_request", "connection_attempt"):
        return config.SEVERITY_LOW

    return config.SEVERITY_LOW


# ═══════════════════════════════════════════════════════════════
#   EVENT NORMALIZER ENGINE
# ═══════════════════════════════════════════════════════════════

class EventNormalizer:
    """Standardizes parsed log records and persists them to SQLite."""

    @staticmethod
    def normalize(parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes raw dictionary from LogParser and outputs a standardized,
        sanitized data structure adhering to the SIEM event model.
        """
        # Ensure standard timestamp format
        ts = parsed.get("timestamp")
        if not ts:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            try:
                # Re-validate format consistency
                dt = datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")
                ts = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        raw_log = sanitize_string(parsed.get("raw_log", ""), max_len=4096) or ""
        message = sanitize_string(parsed.get("message", ""), max_len=2048) or raw_log[:500]
        event_type = sanitize_string(parsed.get("event_type", "generic_log"), max_len=64)

        # Baseline severity assignment
        severity = parsed.get("severity")
        if severity not in config.SEVERITY_LEVELS:
            severity = assign_baseline_severity(event_type, message)

        normalized: Dict[str, Any] = {
            "timestamp": ts,
            "source": sanitize_string(parsed.get("source", "unknown"), max_len=128),
            "hostname": sanitize_string(parsed.get("hostname", "localhost"), max_len=128),
            "service": sanitize_string(parsed.get("service", "system"), max_len=64),
            "username": sanitize_string(parsed.get("username"), max_len=64),
            "source_ip": sanitize_ip(parsed.get("source_ip")),
            "destination_ip": sanitize_ip(parsed.get("destination_ip")),
            "port": sanitize_port(parsed.get("port")),
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "raw_log": raw_log
        }

        return normalized

    @staticmethod
    def save_to_db(event: Dict[str, Any]) -> Optional[int]:
        """
        Inserts a normalized event into the SQLite 'events' table.
        Returns the new integer event ID, or None if write failed.
        """
        sql = """
        INSERT INTO events (
            timestamp, source, hostname, service, username,
            source_ip, destination_ip, port, event_type,
            severity, message, raw_log
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            event["timestamp"],
            event["source"],
            event["hostname"],
            event["service"],
            event["username"],
            event["source_ip"],
            event["destination_ip"],
            event["port"],
            event["event_type"],
            event["severity"],
            event["message"],
            event["raw_log"]
        )

        try:
            with db_conn() as conn:
                cursor = conn.execute(sql, params)
                event_id = cursor.lastrowid
                return event_id
        except Exception as e:
            logger.error(f"Failed to persist normalized event to database: {e}", exc_info=True)
            return None

    @classmethod
    def process_and_save(cls, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convenience pipeline method:
        Normalizes the parsed data, inserts into SQLite, and returns
        the normalized event dictionary with its database 'id' attached.
        """
        normalized = cls.normalize(parsed)
        event_id = cls.save_to_db(normalized)
        normalized["id"] = event_id
        return normalized


# ═══════════════════════════════════════════════════════════════
#   STANDALONE NORMALIZER SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Normalizer Module Self-Test...")
    
    # 1. Initialize clean DB schema
    from modules.database import initialize_db
    assert initialize_db() is True, "Database initialization failed"

    # 2. Test Cases covering data sanitization, exploit detection, and persistence
    test_parsed_samples = [
        # Case A: SSH Failed Login (should be sanitized and assigned MEDIUM)
        {
            "timestamp": "2026-02-28 15:00:00",
            "source": "auth.log",
            "hostname": "srv-prod",
            "service": "sshd",
            "username": "admin",
            "source_ip": "198.51.100.44",
            "port": "22",
            "event_type": "ssh_failed_login",
            "message": "Failed password for admin from 198.51.100.44 port 22",
            "raw_log": "Feb 28 15:00:00 srv-prod sshd[101]: Failed password for admin from 198.51.100.44 port 22"
        },
        # Case B: SQL Injection in Web Log (should elevate to HIGH severity)
        {
            "timestamp": "2026-02-28 15:01:00",
            "source": "access.log",
            "hostname": "web-srv",
            "service": "webserver",
            "username": None,
            "source_ip": "203.0.113.5",
            "port": 80,
            "event_type": "http_request",
            "message": "GET /search.php?id=1' UNION SELECT username,password FROM users-- HTTP 200",
            "raw_log": '203.0.113.5 - - [28/Feb/2026:15:01:00] "GET /search.php?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" 200'
        },
        # Case C: Dirty / Malformed Data (invalid IP, dirty string, bad port)
        {
            "timestamp": "invalid-timestamp",
            "source": "syslog",
            "hostname": "srv-test\x00\x08",
            "service": "kernel",
            "username": "bob",
            "source_ip": "999.999.999.999",  # Invalid IP -> must become None
            "port": 999999,                   # Out of range -> must become None
            "event_type": "generic_log",
            "message": "Out of memory kill process",
            "raw_log": "Out of memory kill process"
        }
    ]

    saved_records = []
    for idx, sample in enumerate(test_parsed_samples, start=1):
        processed = EventNormalizer.process_and_save(sample)
        print(f"[*] Processing Case #{idx}: {processed['event_type']} -> ID: {processed.get('id')}")
        assert processed.get("id") is not None, f"Failed to save event #{idx} to database"
        saved_records.append(processed)

    # 3. Assertions on normalized records
    # Assert Case A
    assert saved_records[0]["severity"] == "MEDIUM"
    assert saved_records[0]["port"] == 22
    assert saved_records[0]["source_ip"] == "198.51.100.44"
    print("    [✓] Case A validated: Correct baseline severity (MEDIUM) & cast port (22).")

    # Assert Case B (SQLi elevation)
    assert saved_records[1]["severity"] == "HIGH", f"Expected HIGH for SQLi payload, got {saved_records[1]['severity']}"
    print("    [✓] Case B validated: Web exploit payload successfully elevated severity to HIGH.")

    # Assert Case C (Sanitization)
    assert saved_records[2]["source_ip"] is None, "Invalid IP should be sanitized to None"
    assert saved_records[2]["port"] is None, "Invalid port should be sanitized to None"
    assert "\x00" not in saved_records[2]["hostname"], "Control characters must be removed"
    print("    [✓] Case C validated: Bad IP/port sanitized and control characters stripped.")

    # 4. Verify SQLite retrieval
    with db_conn() as conn:
        row_count = conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()["cnt"]
        assert row_count >= 3, f"Expected at least 3 events in DB, found {row_count}"
        print(f"[✓] Database query confirmed: {row_count} events stored in 'events' table.")

    print("\n[✓] STEP 6 SELF-TEST PASSED. Event Normalizer & Ingestion functional.")