"""
Mini SIEM — Detection Rule Engine
==================================
Evaluates incoming normalized events against active detection rules.
Maintains in-memory sliding time windows for high-throughput rate calculations
and queries SQLite to update rule trigger statistics.

Outputs structured alert payloads when conditions are satisfied.
"""

import re
import sys
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn

logger = logging.getLogger("MiniSIEM.DetectionEngine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   EXPLOIT PATTERNS FOR URL / MESSAGE INSPECTION
# ═══════════════════════════════════════════════════════════════

RE_SUSPICIOUS_PAYLOADS = [
    (re.compile(r'(?:union\s+select|select\s+.*\s+from|drop\s+table|or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|--\s*$|\/\*.*\*\/)', re.IGNORECASE), "SQL Injection Attempt"),
    (re.compile(r'(?:<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)', re.IGNORECASE), "Cross-Site Scripting (XSS) Attempt"),
    (re.compile(r'(?:\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|\/proc\/self|\.env)', re.IGNORECASE), "Path Traversal / Sensitive File Access"),
]


# ═══════════════════════════════════════════════════════════════
#   DETECTION RULE OBJECT
# ═══════════════════════════════════════════════════════════════

class Rule:
    """In-memory representation of a detection rule loaded from SQLite."""
    def __init__(self, data: Dict[str, Any]):
        self.id: str = data["id"]
        self.name: str = data["name"]
        self.description: str = data.get("description", "")
        self.event_type: str = data["event_type"]
        self.condition: str = data["condition"]
        self.threshold: int = int(data["threshold"])
        self.time_window: int = int(data["time_window"])
        self.severity: str = data["severity"]
        self.enabled: bool = bool(data["enabled"])
        self.trigger_count: int = int(data.get("trigger_count", 0))

    def matches_event_type(self, event_type: str) -> bool:
        """Checks if rule applies to this event type ('any' applies to all)."""
        if self.event_type == "any":
            return True
        return self.event_type.lower() == (event_type or "").lower()


# ═══════════════════════════════════════════════════════════════
#   DETECTION ENGINE CORE
# ═══════════════════════════════════════════════════════════════

class DetectionEngine:
    """
    Stateful detection engine that analyzes incoming normalized events
    against configured rules using rolling time-sliding windows.
    """
    def __init__(self):
        self.rules: Dict[str, Rule] = {}
        
        # Sliding windows: rule_id -> key (e.g. IP or username) -> deque of (timestamp, event_dict)
        self._windows: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        
        # Specific tracking for failed logins (to support success_after_failures condition)
        # key: source_ip -> deque of (timestamp, event_dict)
        self._failed_logins: Dict[str, deque] = defaultdict(deque)

        # Load rules from SQLite
        self.reload_rules()

    def reload_rules(self) -> int:
        """Refreshes active rules from the SQLite database."""
        try:
            with db_conn() as conn:
                rows = conn.execute("SELECT * FROM rules WHERE enabled = 1").fetchall()
                self.rules = {row["id"]: Rule(dict(row)) for row in rows}
            logger.info(f"Loaded {len(self.rules)} active detection rules from database.")
            return len(self.rules)
        except Exception as e:
            logger.error(f"Failed to load detection rules from database: {e}", exc_info=True)
            return 0

    def _parse_ts(self, ts_str: Optional[str]) -> float:
        """Converts standard timestamp string to Unix epoch seconds."""
        if not ts_str:
            return time.time()
        try:
            dt = datetime.strptime(str(ts_str)[:19], "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except Exception:
            return time.time()

    def _clean_window(self, queue: deque, current_ts: float, window_seconds: int):
        """Evicts expired records from a sliding window deque."""
        cutoff = current_ts - window_seconds
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _record_trigger_in_db(self, rule_id: str):
        """Increments trigger_count for a rule in SQLite."""
        try:
            with db_conn() as conn:
                conn.execute(
                    "UPDATE rules SET trigger_count = trigger_count + 1 WHERE id = ?",
                    (rule_id,)
                )
            if rule_id in self.rules:
                self.rules[rule_id].trigger_count += 1
        except Exception as e:
            logger.debug(f"Failed to increment trigger_count for rule {rule_id}: {e}")

    # ───────────────────────────────────────────────────────────
    #   CONDITION EVALUATION METHODS
    # ───────────────────────────────────────────────────────────

    def _eval_single_event(self, rule: Rule, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handles immediate 1-to-1 event alerts."""
        if not rule.matches_event_type(event.get("event_type", "")):
            return None

        return {
            "rule_id": rule.id,
            "title": rule.name,
            "severity": rule.severity,
            "source_ip": event.get("source_ip"),
            "username": event.get("username"),
            "description": f"{rule.description} | Service: {event.get('service')} | Message: {event.get('message')}",
            "occurrences": 1,
            "first_seen": event.get("timestamp"),
            "last_seen": event.get("timestamp"),
            "related_events": [event]
        }

    def _eval_count_by_source_ip(self, rule: Rule, event: Dict[str, Any], event_ts: float) -> Optional[Dict[str, Any]]:
        """Tracks event count per source IP within sliding window."""
        if not rule.matches_event_type(event.get("event_type", "")):
            return None

        ip = event.get("source_ip")
        if not ip:
            return None

        q = self._windows[rule.id][ip]
        self._clean_window(q, event_ts, rule.time_window)
        q.append((event_ts, event))

        if len(q) >= rule.threshold:
            first_event = q[0][1]
            occurrences = len(q)
            related = [e for _, e in q]
            # Clear window after trigger to avoid continuous duplicate alerting on the same burst
            q.clear()

            return {
                "rule_id": rule.id,
                "title": rule.name,
                "severity": rule.severity,
                "source_ip": ip,
                "username": event.get("username"),
                "description": f"{rule.description} ({occurrences} events from {ip} in {rule.time_window}s)",
                "occurrences": occurrences,
                "first_seen": first_event.get("timestamp"),
                "last_seen": event.get("timestamp"),
                "related_events": related
            }
        return None

    def _eval_count_by_username(self, rule: Rule, event: Dict[str, Any], event_ts: float) -> Optional[Dict[str, Any]]:
        """Tracks event count per username within sliding window."""
        if not rule.matches_event_type(event.get("event_type", "")):
            return None

        user = event.get("username")
        if not user:
            return None

        q = self._windows[rule.id][user]
        self._clean_window(q, event_ts, rule.time_window)
        q.append((event_ts, event))

        if len(q) >= rule.threshold:
            first_event = q[0][1]
            occurrences = len(q)
            related = [e for _, e in q]
            q.clear()

            return {
                "rule_id": rule.id,
                "title": rule.name,
                "severity": rule.severity,
                "source_ip": event.get("source_ip"),
                "username": user,
                "description": f"{rule.description} ({occurrences} events for user '{user}' in {rule.time_window}s)",
                "occurrences": occurrences,
                "first_seen": first_event.get("timestamp"),
                "last_seen": event.get("timestamp"),
                "related_events": related
            }
        return None

    def _eval_distinct_ports(self, rule: Rule, event: Dict[str, Any], event_ts: float) -> Optional[Dict[str, Any]]:
        """Tracks distinct destination ports targeted by an IP (port scan detector)."""
        if not rule.matches_event_type(event.get("event_type", "")):
            return None

        ip = event.get("source_ip")
        port = event.get("port")
        if not ip or not port:
            return None

        q = self._windows[rule.id][ip]
        self._clean_window(q, event_ts, rule.time_window)
        q.append((event_ts, event))

        # Check unique ports across all active events in the window
        unique_ports = {e.get("port") for _, e in q if e.get("port")}
        if len(unique_ports) >= rule.threshold:
            first_event = q[0][1]
            occurrences = len(q)
            related = [e for _, e in q]
            q.clear()

            return {
                "rule_id": rule.id,
                "title": rule.name,
                "severity": rule.severity,
                "source_ip": ip,
                "username": event.get("username"),
                "description": f"{rule.description} ({len(unique_ports)} distinct ports targeted from {ip} in {rule.time_window}s: {sorted(list(unique_ports))[:8]}...)",
                "occurrences": occurrences,
                "first_seen": first_event.get("timestamp"),
                "last_seen": event.get("timestamp"),
                "related_events": related
            }
        return None

    def _eval_success_after_failures(self, rule: Rule, event: Dict[str, Any], event_ts: float) -> Optional[Dict[str, Any]]:
        """Detects successful login following multiple auth failures from the same IP."""
        ip = event.get("source_ip")
        if not ip:
            return None

        # If it's a failed login, track it in the failed logins buffer
        if event.get("event_type") in ("ssh_failed_login", "ssh_invalid_user"):
            q = self._failed_logins[ip]
            self._clean_window(q, event_ts, rule.time_window)
            q.append((event_ts, event))
            return None

        # If it's a successful login, check how many failures were recently recorded
        if event.get("event_type") == "ssh_successful_login":
            q = self._failed_logins[ip]
            self._clean_window(q, event_ts, rule.time_window)
            if len(q) >= rule.threshold:
                fail_count = len(q)
                first_event = q[0][1]
                related = [e for _, e in q] + [event]
                q.clear()  # reset after detection

                return {
                    "rule_id": rule.id,
                    "title": rule.name,
                    "severity": rule.severity,
                    "source_ip": ip,
                    "username": event.get("username"),
                    "description": f"{rule.description} (User '{event.get('username')}' logged in successfully from {ip} after {fail_count} recent failures)",
                    "occurrences": fail_count + 1,
                    "first_seen": first_event.get("timestamp"),
                    "last_seen": event.get("timestamp"),
                    "related_events": related
                }
        return None

    def _eval_url_pattern(self, rule: Rule, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Inspects URL / message body for attack patterns (SQLi, XSS, traversal)."""
        msg = event.get("message", "") or event.get("raw_log", "")
        for pattern, attack_name in RE_SUSPICIOUS_PAYLOADS:
            if pattern.search(msg):
                return {
                    "rule_id": rule.id,
                    "title": rule.name,
                    "severity": rule.severity,
                    "source_ip": event.get("source_ip"),
                    "username": event.get("username"),
                    "description": f"{rule.description} | Detected {attack_name} pattern in payload: {msg[:120]}",
                    "occurrences": 1,
                    "first_seen": event.get("timestamp"),
                    "last_seen": event.get("timestamp"),
                    "related_events": [event]
                }
        return None

    # ───────────────────────────────────────────────────────────
    #   MAIN EVALUATION DISPATCHER
    # ───────────────────────────────────────────────────────────

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a normalized event against all enabled detection rules.
        Returns a list of generated alert dictionaries (empty if no rules matched).
        """
        alerts: List[Dict[str, Any]] = []
        event_ts = self._parse_ts(event.get("timestamp"))

        # Maintain background failure queue for AUTH-003 even if rules aren't directly checking it
        if event.get("event_type") in ("ssh_failed_login", "ssh_invalid_user") and event.get("source_ip"):
            q = self._failed_logins[event["source_ip"]]
            self._clean_window(q, event_ts, config.DETECTION_DEFAULT_WINDOW * 5)
            q.append((event_ts, event))

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            alert: Optional[Dict[str, Any]] = None

            if rule.condition == "single_event":
                alert = self._eval_single_event(rule, event)
            elif rule.condition == "count_by_source_ip":
                alert = self._eval_count_by_source_ip(rule, event, event_ts)
            elif rule.condition == "count_by_username":
                alert = self._eval_count_by_username(rule, event, event_ts)
            elif rule.condition == "distinct_ports_by_source_ip":
                alert = self._eval_distinct_ports(rule, event, event_ts)
            elif rule.condition == "success_after_failures":
                alert = self._eval_success_after_failures(rule, event, event_ts)
            elif rule.condition == "url_pattern_match":
                alert = self._eval_url_pattern(rule, event)

            if alert:
                alert["timestamp"] = event.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert["status"] = config.ALERT_STATUS_NEW
                self._record_trigger_in_db(rule.id)
                alerts.append(alert)
                logger.warning(f"🚨 RULE TRIGGERED: [{rule.id}] {rule.name} (Severity: {rule.severity}) from {alert.get('source_ip')}")

        return alerts


# ═══════════════════════════════════════════════════════════════
#   STANDALONE DETECTION ENGINE SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Detection Engine Module Self-Test...")
    
    # 1. Prepare clean DB & seed rules
    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    engine = DetectionEngine()
    print(f"[✓] Detection Engine initialized with {len(engine.rules)} active rules.")

    generated_alerts = []

    # ── Test Scenario 1: SSH Brute Force (AUTH-001 threshold = 5) ──
    print("\n[*] Scenario 1: Sending 5 failed SSH logins from 198.51.100.100...")
    for i in range(5):
        evt = {
            "timestamp": f"2026-02-28 16:00:0{i}",
            "source": "auth.log",
            "hostname": "srv1",
            "service": "sshd",
            "username": "root",
            "source_ip": "198.51.100.100",
            "port": 22,
            "event_type": "ssh_failed_login",
            "severity": "MEDIUM",
            "message": "Failed password for root",
            "raw_log": "Failed password for root"
        }
        al = engine.evaluate_event(evt)
        if al:
            generated_alerts.extend(al)

    assert len(generated_alerts) >= 1, "Failed to trigger AUTH-001 for 5 SSH failures"
    print(f"    [✓] Triggered: {generated_alerts[-1]['title']} (Severity: {generated_alerts[-1]['severity']})")

    # ── Test Scenario 2: Direct Root Login (AUTH-005 single_event) ──
    print("\n[*] Scenario 2: Sending direct Root login event...")
    root_evt = {
        "timestamp": "2026-02-28 16:01:00",
        "source": "auth.log",
        "hostname": "srv1",
        "service": "sshd",
        "username": "root",
        "source_ip": "203.0.113.50",
        "port": 22,
        "event_type": "ssh_root_login",
        "severity": "HIGH",
        "message": "Accepted password for root",
        "raw_log": "Accepted password for root"
    }
    al2 = engine.evaluate_event(root_evt)
    assert len(al2) >= 1, "Failed to trigger AUTH-005 for root login"
    print(f"    [✓] Triggered: {al2[0]['title']} (Severity: {al2[0]['severity']})")
    generated_alerts.extend(al2)

    # ── Test Scenario 3: Success After Multiple Failures (AUTH-003) ──
    print("\n[*] Scenario 3: Sending 3 failures followed by 1 success from 192.168.1.75...")
    for i in range(3):
        engine.evaluate_event({
            "timestamp": f"2026-02-28 16:02:0{i}",
            "source": "auth.log",
            "hostname": "srv1",
            "service": "sshd",
            "username": "alice",
            "source_ip": "192.168.1.75",
            "port": 22,
            "event_type": "ssh_failed_login",
            "severity": "MEDIUM",
            "message": "Failed password for alice",
            "raw_log": "Failed password for alice"
        })

    # Now successful login from same IP
    success_evt = {
        "timestamp": "2026-02-28 16:02:10",
        "source": "auth.log",
        "hostname": "srv1",
        "service": "sshd",
        "username": "alice",
        "source_ip": "192.168.1.75",
        "port": 22,
        "event_type": "ssh_successful_login",
        "severity": "LOW",
        "message": "Accepted password for alice",
        "raw_log": "Accepted password for alice"
    }
    al3 = engine.evaluate_event(success_evt)
    auth003_alerts = [a for a in al3 if a["rule_id"] == "AUTH-003"]
    assert len(auth003_alerts) == 1, "Failed to trigger AUTH-003 for success after multiple failures"
    print(f"    [✓] Triggered: {auth003_alerts[0]['title']} (Severity: {auth003_alerts[0]['severity']})")
    generated_alerts.extend(al3)

    # ── Test Scenario 4: Suspicious URL Pattern / SQLi (WEB-002) ──
    print("\n[*] Scenario 4: Sending HTTP request with SQL injection payload...")
    sqli_evt = {
        "timestamp": "2026-02-28 16:03:00",
        "source": "access.log",
        "hostname": "srv1",
        "service": "webserver",
        "username": None,
        "source_ip": "10.0.0.99",
        "port": 80,
        "event_type": "http_request",
        "severity": "HIGH",
        "message": "GET /products.php?id=1 UNION SELECT 1,2,username,password FROM users HTTP 200",
        "raw_log": "GET /products.php?id=1 UNION SELECT 1,2,username,password FROM users HTTP 200"
    }
    al4 = engine.evaluate_event(sqli_evt)
    assert len(al4) >= 1, "Failed to trigger WEB-002 for SQL injection"
    print(f"    [✓] Triggered: {al4[0]['title']} (Severity: {al4[0]['severity']})")
    generated_alerts.extend(al4)

    # ── Verify trigger count persistence in DB ──
    with db_conn() as conn:
        triggered_rules = conn.execute("SELECT id, name, trigger_count FROM rules WHERE trigger_count > 0").fetchall()
        print(f"\n[✓] Database trigger_count verification ({len(triggered_rules)} rules incremented):")
        for r in triggered_rules:
            print(f"    └─ [{r['id']}] {r['name']} -> triggered {r['trigger_count']} time(s)")

    print(f"\n[✓] STEP 7 SELF-TEST PASSED. Detection Rule Engine fully functional ({len(generated_alerts)} total alerts created).")