"""
Mini SIEM — Incident Correlation Engine
========================================
Connects discrete security alerts into unified, multi-stage security incidents.
Tracks attack chains across time windows based on Source IP, Username, and Tactics.

Persists correlated incidents to the 'correlations' table in SQLite and notifies
subscribers for immediate dashboard visualization.
"""

import sys
import json
import time
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

# Adjust path to import central configuration, database, and alert manager
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn
from modules.alert_manager import AlertManager

logger = logging.getLogger("MiniSIEM.CorrelationEngine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   CORRELATION ENGINE CLASS
# ═══════════════════════════════════════════════════════════════

class CorrelationEngine:
    """
    Stateful correlation engine that observes incoming alerts and detects
    multi-stage attack chains within a configurable rolling time window.
    """
    def __init__(self, time_window_seconds: int = config.CORRELATION_WINDOW):
        self.time_window = time_window_seconds
        
        # In-memory alert buffers for correlation
        # source_ip -> deque of (timestamp_epoch, alert_dict)
        self._ip_alerts: Dict[str, deque] = defaultdict(deque)
        
        # username -> deque of (timestamp_epoch, alert_dict)
        self._user_alerts: Dict[str, deque] = defaultdict(deque)
        
        # Set of active correlation signatures to prevent duplicate incidents in same window
        # (signature_hash, last_triggered_epoch)
        self._active_correlations: Dict[str, float] = {}

        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.Lock()

    # ───────────────────────────────────────────────────────────
    #   SUBSCRIBER PATTERN
    # ───────────────────────────────────────────────────────────

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]):
        """Registers a listener to receive new correlated incidents in real-time."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]):
        """Unregisters an incident listener."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _notify_subscribers(self, incident: Dict[str, Any]):
        """Dispatches correlated incident payload to subscribers."""
        with self._lock:
            subs = list(self._subscribers)

        for callback in subs:
            try:
                callback(incident)
            except Exception as e:
                logger.error(f"Error in correlation subscriber callback: {e}", exc_info=True)

    # ───────────────────────────────────────────────────────────
    #   BUFFER MANAGEMENT
    # ───────────────────────────────────────────────────────────

    def _clean_queue(self, queue: deque, current_ts: float):
        """Evicts alerts older than the correlation time window."""
        cutoff = current_ts - self.time_window
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _parse_ts(self, ts_str: Optional[str]) -> float:
        """Parses timestamp string to epoch seconds."""
        if not ts_str:
            return time.time()
        try:
            dt = datetime.strptime(str(ts_str)[:19], "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except Exception:
            return time.time()

    # ───────────────────────────────────────────────────────────
    #   CORRELATION RULES & CHAIN DETECTORS
    # ───────────────────────────────────────────────────────────

    def _check_account_compromise(self, ip: str, alerts: List[Dict[str, Any]], current_ts: float) -> Optional[Dict[str, Any]]:
        """
        Detects: Failed Logins / Brute Force -> Successful Login -> [Optional] Sudo Escalation.
        """
        has_failed = False
        has_success = False
        has_sudo = False
        involved_users = set()

        for a in alerts:
            rid = a.get("rule_id", "")
            title = a.get("title", "").lower()
            u = a.get("username")
            if u:
                involved_users.add(u)

            if rid in ("AUTH-001", "AUTH-002", "AUTH-004") or "failed" in title or "brute" in title:
                has_failed = True
            elif rid == "AUTH-003" or "success" in title:
                has_success = True
            elif rid in ("AUTH-006", "AUTH-007") or "sudo" in title or "escalation" in title:
                has_sudo = True

        # Trigger if we have both failed attempts followed by success
        if has_failed and has_success:
            user_str = ", ".join(involved_users) if involved_users else "target user"
            desc = (
                f"Multi-stage Account Compromise detected from IP {ip}. "
                f"Attack chain: Authentication failures -> Successful login ({user_str})"
            )
            if has_sudo:
                desc += " -> Unauthorized Sudo / Privilege Escalation activity."

            sig = f"compromise:{ip}:{sorted(list(involved_users))}"
            if self._is_duplicate_correlation(sig, current_ts):
                return None

            return {
                "source_ip": ip,
                "username": list(involved_users)[0] if involved_users else None,
                "title": "CRITICAL: Possible Account Compromise & Takeover",
                "severity": config.SEVERITY_CRITICAL,
                "description": desc,
                "signature": sig,
                "related_alerts": alerts
            }
        return None

    def _check_web_to_host_pivot(self, ip: str, alerts: List[Dict[str, Any]], current_ts: float) -> Optional[Dict[str, Any]]:
        """
        Detects: Web Exploits (SQLi/XSS/404 Scan) -> SSH/System Authentication from same IP.
        """
        has_web = False
        has_auth = False

        for a in alerts:
            rid = a.get("rule_id", "")
            title = a.get("title", "").lower()

            if rid in ("WEB-001", "WEB-002") or "web" in title or "http" in title or "sql" in title:
                has_web = True
            elif rid.startswith("AUTH-") or "ssh" in title or "login" in title:
                has_auth = True

        if has_web and has_auth:
            sig = f"web_pivot:{ip}"
            if self._is_duplicate_correlation(sig, current_ts):
                return None

            return {
                "source_ip": ip,
                "username": alerts[-1].get("username"),
                "title": "CRITICAL: Web Attack Pivoting to Host Access",
                "severity": config.SEVERITY_CRITICAL,
                "description": f"IP {ip} performed web exploitation attempts and subsequently targeted host authentication services.",
                "signature": sig,
                "related_alerts": alerts
            }
        return None

    def _check_recon_to_escalation(self, ip: str, alerts: List[Dict[str, Any]], current_ts: float) -> Optional[Dict[str, Any]]:
        """
        Detects: Port Scanning / Network Probe -> Direct Root Login or Sudo activity.
        """
        has_recon = False
        has_root_or_sudo = False

        for a in alerts:
            rid = a.get("rule_id", "")
            title = a.get("title", "").lower()

            if rid in ("NET-001", "NET-002") or "port scan" in title or "suspicious ip" in title:
                has_recon = True
            elif rid in ("AUTH-005", "AUTH-007") or "root login" in title or "privilege escalation" in title:
                has_root_or_sudo = True

        if has_recon and has_root_or_sudo:
            sig = f"recon_escalation:{ip}"
            if self._is_duplicate_correlation(sig, current_ts):
                return None

            return {
                "source_ip": ip,
                "username": alerts[-1].get("username"),
                "title": "CRITICAL: Reconnaissance Preceding Root Compromise",
                "severity": config.SEVERITY_CRITICAL,
                "description": f"Host {ip} performed horizontal network reconnaissance followed immediately by direct root/privilege escalation actions.",
                "signature": sig,
                "related_alerts": alerts
            }
        return None

    def _is_duplicate_correlation(self, signature: str, current_ts: float) -> bool:
        """Suppresses identical correlation triggers generated in the same time window."""
        last_time = self._active_correlations.get(signature)
        if last_time and (current_ts - last_time) < self.time_window:
            return True
        self._active_correlations[signature] = current_ts
        return False

    # ───────────────────────────────────────────────────────────
    #   INCIDENT PERSISTENCE
    # ───────────────────────────────────────────────────────────

    def save_correlation(self, incident: Dict[str, Any]) -> int:
        """
        Stores correlated incident record in SQLite 'correlations' table.
        Serializes related_alerts into a JSON list.
        """
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        related_json = json.dumps([
            {
                "id": a.get("id"),
                "title": a.get("title"),
                "rule_id": a.get("rule_id"),
                "severity": a.get("severity"),
                "timestamp": a.get("timestamp")
            }
            for a in incident.get("related_alerts", [])
        ])

        sql = """
        INSERT INTO correlations (
            created_at, source_ip, username, title,
            severity, description, status, related_alerts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            created_at,
            incident.get("source_ip"),
            incident.get("username"),
            incident.get("title"),
            incident.get("severity", config.SEVERITY_CRITICAL),
            incident.get("description"),
            config.ALERT_STATUS_NEW,
            related_json
        )

        try:
            with db_conn() as conn:
                cursor = conn.execute(sql, params)
                incident_id = cursor.lastrowid
                incident["id"] = incident_id
                incident["created_at"] = created_at
                incident["status"] = config.ALERT_STATUS_NEW
                logger.critical(
                    f"🔥 CORRELATED INCIDENT GENERATED: [Incident #{incident_id}] "
                    f"{incident['title']} | Target IP: {incident.get('source_ip')}"
                )
                return incident_id
        except Exception as e:
            logger.error(f"Failed to save correlated incident to database: {e}", exc_info=True)
            return -1

    # ───────────────────────────────────────────────────────────
    #   MAIN PROCESSOR HOOK
    # ───────────────────────────────────────────────────────────

    def process_incoming_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Main entry point called when a new alert is created or updated.
        Buffers the alert and runs all correlation chain evaluations.
        """
        correlated_incidents: List[Dict[str, Any]] = []
        event_ts = self._parse_ts(alert.get("timestamp"))

        source_ip = alert.get("source_ip")
        username = alert.get("username")

        with self._lock:
            # Buffer by Source IP
            if source_ip:
                q_ip = self._ip_alerts[source_ip]
                self._clean_queue(q_ip, event_ts)
                q_ip.append((event_ts, alert))
                recent_ip_alerts = [a for _, a in q_ip]

                # Run chain checks
                c1 = self._check_account_compromise(source_ip, recent_ip_alerts, event_ts)
                if c1:
                    correlated_incidents.append(c1)

                c2 = self._check_web_to_host_pivot(source_ip, recent_ip_alerts, event_ts)
                if c2:
                    correlated_incidents.append(c2)

                c3 = self._check_recon_to_escalation(source_ip, recent_ip_alerts, event_ts)
                if c3:
                    correlated_incidents.append(c3)

            # Buffer by Username
            if username:
                q_user = self._user_alerts[username]
                self._clean_queue(q_user, event_ts)
                q_user.append((event_ts, alert))

        # Persist and dispatch detected correlations
        for inc in correlated_incidents:
            inc_id = self.save_correlation(inc)
            if inc_id > 0:
                self._notify_subscribers(inc)

        return correlated_incidents

    # ───────────────────────────────────────────────────────────
    #   INCIDENT QUERY & STATUS API
    # ───────────────────────────────────────────────────────────

    def get_correlations(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Queries recent correlated incidents with deserialized related_alerts."""
        sql = "SELECT * FROM correlations ORDER BY id DESC LIMIT ? OFFSET ?"
        try:
            with db_conn() as conn:
                rows = conn.execute(sql, (limit, offset)).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["related_alerts"] = json.loads(d.get("related_alerts") or "[]")
                    except Exception:
                        d["related_alerts"] = []
                    results.append(d)
                return results
        except Exception as e:
            logger.error(f"Failed to query correlations: {e}", exc_info=True)
            return []

    def get_correlation_by_id(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """Fetches a single correlated incident by ID with full details."""
        try:
            with db_conn() as conn:
                row = conn.execute("SELECT * FROM correlations WHERE id = ?", (incident_id,)).fetchone()
                if not row:
                    return None
                d = dict(row)
                try:
                    d["related_alerts"] = json.loads(d.get("related_alerts") or "[]")
                except Exception:
                    d["related_alerts"] = []
                return d
        except Exception as e:
            logger.error(f"Failed to fetch correlation #{incident_id}: {e}")
            return None

    def update_correlation_status(self, incident_id: int, new_status: str) -> bool:
        """Transitions an incident's status (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
        if new_status not in config.ALERT_STATUSES:
            return False
        try:
            with db_conn() as conn:
                res = conn.execute(
                    "UPDATE correlations SET status = ? WHERE id = ?",
                    (new_status, incident_id)
                )
                return res.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to update status for correlation #{incident_id}: {e}")
            return False


# ═══════════════════════════════════════════════════════════════
#   STANDALONE CORRELATION ENGINE SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Correlation Engine Module Self-Test...")

    # 1. Initialize DB schema
    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    alert_mgr = AlertManager()
    corr_engine = CorrelationEngine(time_window_seconds=180)

    # Wire alert manager to correlation engine
    alert_mgr.subscribe(corr_engine.process_incoming_alert)

    # Track subscriber incident dispatches
    dispatched_incidents: List[Dict[str, Any]] = []
    corr_engine.subscribe(lambda inc: dispatched_incidents.append(inc))

    # ── Test 1: Account Compromise Scenario ──
    print("\n[*] Scenario 1: Simulating Account Compromise Chain from 198.51.100.99...")
    
    # Step A: Brute Force alert
    a1 = alert_mgr.process_alert({
        "rule_id": "AUTH-002",
        "title": "SSH Brute Force",
        "severity": "HIGH",
        "source_ip": "198.51.100.99",
        "username": "victim_user",
        "description": "10+ failed SSH attempts",
        "occurrences": 10
    })

    # Step B: Successful Login alert
    a2 = alert_mgr.process_alert({
        "rule_id": "AUTH-003",
        "title": "Successful Login After Multiple Failures",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.99",
        "username": "victim_user",
        "description": "User logged in after failures",
        "occurrences": 1
    })

    # Step C: Sudo to Root alert
    a3 = alert_mgr.process_alert({
        "rule_id": "AUTH-007",
        "title": "Privilege Escalation Indicator",
        "severity": "HIGH",
        "source_ip": "198.51.100.99",
        "username": "victim_user",
        "description": "User elevated to root via sudo",
        "occurrences": 1
    })

    assert len(dispatched_incidents) >= 1, "Failed to correlate Account Compromise attack chain!"
    inc1 = dispatched_incidents[0]
    print(f"    [✓] Generated Incident #{inc1['id']}: {inc1['title']}")
    print(f"        └─ Description: {inc1['description']}")
    print(f"        └─ Severity: {inc1['severity']}")

    # ── Test 2: Web Pivot to Host Scenario ──
    print("\n[*] Scenario 2: Simulating Web Attack Pivot to SSH from 203.0.113.77...")
    
    # Step A: SQL Injection alert
    alert_mgr.process_alert({
        "rule_id": "WEB-002",
        "title": "Suspicious URL Pattern",
        "severity": "HIGH",
        "source_ip": "203.0.113.77",
        "username": None,
        "description": "SQL Injection attempt detected",
        "occurrences": 1
    })

    # Step B: Root login alert from same IP
    alert_mgr.process_alert({
        "rule_id": "AUTH-005",
        "title": "Root Login",
        "severity": "HIGH",
        "source_ip": "203.0.113.77",
        "username": "root",
        "description": "Direct root login",
        "occurrences": 1
    })

    assert len(dispatched_incidents) >= 2, "Failed to correlate Web Pivot attack chain!"
    inc2 = dispatched_incidents[1]
    print(f"    [✓] Generated Incident #{inc2['id']}: {inc2['title']}")
    print(f"        └─ Description: {inc2['description']}")

    # ── Test 3: Verify Persistence & Query API ──
    print("\n[*] Test 3: Verifying correlation database records and retrieval...")
    all_corrs = corr_engine.get_correlations()
    assert len(all_corrs) >= 2, f"Expected >= 2 stored correlations, got {len(all_corrs)}"
    print(f"    [✓] Query returned {len(all_corrs)} correlated incidents from SQLite:")
    for c in all_corrs:
        print(f"        └─ Incident #{c['id']}: {c['title']} | Status: {c['status']} | Related Alerts: {len(c['related_alerts'])}")

    # Test status update
    assert corr_engine.update_correlation_status(inc1["id"], "INVESTIGATING") is True
    updated = corr_engine.get_correlation_by_id(inc1["id"])
    assert updated["status"] == "INVESTIGATING"
    print(f"    [✓] Incident #{inc1['id']} status updated to INVESTIGATING.")

    print("\n[✓] STEP 9 SELF-TEST PASSED. Correlation Engine fully operational.")