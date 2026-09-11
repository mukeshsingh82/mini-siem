"""
Mini SIEM — Alert Manager
==========================
Manages the complete alert lifecycle: ingestion, deduplication, persistence,
state transitions, metric calculations, and real-time subscriber dispatch.

Thread-safe and integrated with SQLite WAL mode.
"""

import sys
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn

logger = logging.getLogger("MiniSIEM.AlertManager")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   ALERT MANAGER CLASS
# ═══════════════════════════════════════════════════════════════

class AlertManager:
    """
    Central coordinator for security alerts.
    Persists alerts, aggregates rapid bursts, tracks statuses,
    and publishes alerts to real-time subscribers (GUI / Correlation Engine).
    """
    def __init__(self, dedup_window_seconds: int = 120):
        self.dedup_window_seconds = dedup_window_seconds
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.Lock()

    # ───────────────────────────────────────────────────────────
    #   SUBSCRIBER MANAGEMENT
    # ───────────────────────────────────────────────────────────

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]):
        """Registers a callback function to receive alerts in real time."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)
                logger.debug(f"Registered new alert subscriber. Total: {len(self._subscribers)}")

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]):
        """Unregisters a callback function."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _notify_subscribers(self, alert: Dict[str, Any]):
        """Broadcasts a newly created or updated alert to all subscribers."""
        with self._lock:
            subs = list(self._subscribers)

        for callback in subs:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert subscriber callback: {e}", exc_info=True)

    # ───────────────────────────────────────────────────────────
    #   ALERT INGESTION & DEDUPLICATION
    # ───────────────────────────────────────────────────────────

    def process_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Receives an alert payload from the Detection Engine.
        Checks for an existing active alert matching the rule and target (IP or username)
        within the deduplication window. If found, aggregates it; otherwise creates a new alert.
        """
        rule_id = alert_data.get("rule_id")
        source_ip = alert_data.get("source_ip")
        username = alert_data.get("username")
        severity = alert_data.get("severity", config.SEVERITY_LOW)
        title = alert_data.get("title", "Security Alert")
        description = alert_data.get("description", "")
        occurrences = int(alert_data.get("occurrences", 1))
        now_str = alert_data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        first_seen = alert_data.get("first_seen") or now_str
        last_seen = alert_data.get("last_seen") or now_str

        # Check for matching active alert to deduplicate
        existing_alert = self._find_active_duplicate(rule_id, source_ip, username)

        if existing_alert:
            # Aggregate into existing alert
            alert_id = existing_alert["id"]
            new_occurrences = existing_alert["occurrences"] + occurrences
            self._update_existing_alert(alert_id, new_occurrences, last_seen, description)
            
            # Build merged return dict
            merged = dict(existing_alert)
            merged["occurrences"] = new_occurrences
            merged["last_seen"] = last_seen
            merged["timestamp"] = last_seen
            merged["is_duplicate"] = True
            
            self._notify_subscribers(merged)
            return merged
        else:
            # Insert new alert
            alert_id = self._insert_new_alert(
                timestamp=now_str,
                rule_id=rule_id,
                severity=severity,
                source_ip=source_ip,
                username=username,
                title=title,
                description=description,
                occurrences=occurrences,
                first_seen=first_seen,
                last_seen=last_seen,
                status=config.ALERT_STATUS_NEW
            )

            created_alert = {
                "id": alert_id,
                "timestamp": now_str,
                "rule_id": rule_id,
                "severity": severity,
                "source_ip": source_ip,
                "username": username,
                "title": title,
                "description": description,
                "occurrences": occurrences,
                "status": config.ALERT_STATUS_NEW,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "is_duplicate": False,
                "related_events": alert_data.get("related_events", [])
            }

            self._notify_subscribers(created_alert)
            return created_alert

    def _find_active_duplicate(self, rule_id: Optional[str], source_ip: Optional[str], username: Optional[str]) -> Optional[Dict[str, Any]]:
        """Finds an open alert (NEW or INVESTIGATING) matching rule_id and IP/user within the dedup window."""
        if not rule_id:
            return None

        # Calculate timestamp cutoff for dedup
        cutoff_dt = datetime.now() - timedelta(seconds=self.dedup_window_seconds)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

        query = """
        SELECT * FROM alerts
        WHERE rule_id = ?
          AND status IN ('NEW', 'INVESTIGATING')
          AND last_seen >= ?
        """
        params: List[Any] = [rule_id, cutoff_str]

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        elif username:
            query += " AND username = ?"
            params.append(username)
        else:
            return None

        query += " ORDER BY id DESC LIMIT 1"

        try:
            with db_conn() as conn:
                row = conn.execute(query, params).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.debug(f"Error querying active duplicate alert: {e}")
            return None

    def _update_existing_alert(self, alert_id: int, occurrences: int, last_seen: str, description: str):
        """Updates occurrences and last_seen on an aggregated alert."""
        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    UPDATE alerts
                    SET occurrences = ?, last_seen = ?, timestamp = ?, description = ?
                    WHERE id = ?
                    """,
                    (occurrences, last_seen, last_seen, description, alert_id)
                )
        except Exception as e:
            logger.error(f"Failed to update existing alert #{alert_id}: {e}", exc_info=True)

    def _insert_new_alert(self, **kwargs) -> int:
        """Inserts a new row into the alerts SQLite table."""
        sql = """
        INSERT INTO alerts (
            timestamp, rule_id, severity, source_ip, username,
            title, description, occurrences, status, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            kwargs["timestamp"],
            kwargs["rule_id"],
            kwargs["severity"],
            kwargs["source_ip"],
            kwargs["username"],
            kwargs["title"],
            kwargs["description"],
            kwargs["occurrences"],
            kwargs["status"],
            kwargs["first_seen"],
            kwargs["last_seen"]
        )

        with db_conn() as conn:
            cursor = conn.execute(sql, params)
            return cursor.lastrowid

    # ───────────────────────────────────────────────────────────
    #   STATUS MANAGEMENT
    # ───────────────────────────────────────────────────────────

    def update_status(self, alert_id: int, new_status: str) -> bool:
        """
        Transitions an alert's status (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE).
        Returns True if updated successfully.
        """
        if new_status not in config.ALERT_STATUSES:
            logger.error(f"Invalid alert status: {new_status}")
            return False

        try:
            with db_conn() as conn:
                res = conn.execute(
                    "UPDATE alerts SET status = ? WHERE id = ?",
                    (new_status, alert_id)
                )
                if res.rowcount > 0:
                    logger.info(f"Alert #{alert_id} status updated to {new_status}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to update status for alert #{alert_id}: {e}", exc_info=True)
            return False

    # ───────────────────────────────────────────────────────────
    #   QUERY & RETRIEVAL API
    # ───────────────────────────────────────────────────────────

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert by ID."""
        try:
            with db_conn() as conn:
                row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to fetch alert #{alert_id}: {e}")
            return None

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        search_query: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Flexible filter query returning matching alerts ordered by most recent.
        """
        conditions = []
        params: List[Any] = []

        if severity and severity != "ALL":
            conditions.append("severity = ?")
            params.append(severity)

        if status and status != "ALL":
            conditions.append("status = ?")
            params.append(status)

        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)

        if source_ip:
            conditions.append("source_ip LIKE ?")
            params.append(f"%{source_ip}%")

        if search_query:
            conditions.append("(title LIKE ? OR description LIKE ? OR username LIKE ? OR source_ip LIKE ?)")
            q = f"%{search_query}%"
            params.extend([q, q, q, q])

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date)

        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM alerts {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        try:
            with db_conn() as conn:
                rows = conn.execute(sql, params).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to query alerts: {e}", exc_info=True)
            return []

    # ───────────────────────────────────────────────────────────
    #   SOC KPI & METRIC CALCULATIONS
    # ───────────────────────────────────────────────────────────

    def get_soc_metrics(self) -> Dict[str, Any]:
        """
        Calculates live SOC dashboard numbers directly from SQLite:
        - Total counts by severity
        - Total counts by status
        - Today's events and alerts
        - Top source IPs by alert count
        - Top alerting rules
        - 7-day severity trend
        """
        metrics: Dict[str, Any] = {
            "total_events": 0,
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "new_alerts": 0,
            "investigating_alerts": 0,
            "resolved_alerts": 0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "status_distribution": {"NEW": 0, "INVESTIGATING": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0},
            "top_source_ips": {},
            "top_rules": {},
            "active_sources_count": 0,
            "events_per_minute": 0.0
        }

        try:
            with db_conn() as conn:
                # 1. Total events
                evt_row = conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
                metrics["total_events"] = evt_row["cnt"] if evt_row else 0

                # 2. Total alerts & severity breakdown
                sev_rows = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
                ).fetchall()
                for r in sev_rows:
                    sev = r["severity"]
                    cnt = r["cnt"]
                    if sev in metrics["severity_distribution"]:
                        metrics["severity_distribution"][sev] = cnt
                    metrics["total_alerts"] += cnt

                metrics["critical_alerts"] = metrics["severity_distribution"]["CRITICAL"]
                metrics["high_alerts"] = metrics["severity_distribution"]["HIGH"]
                metrics["medium_alerts"] = metrics["severity_distribution"]["MEDIUM"]
                metrics["low_alerts"] = metrics["severity_distribution"]["LOW"]

                # 3. Status breakdown
                st_rows = conn.execute(
                    "SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status"
                ).fetchall()
                for r in st_rows:
                    st = r["status"]
                    if st in metrics["status_distribution"]:
                        metrics["status_distribution"][st] = r["cnt"]

                metrics["new_alerts"] = metrics["status_distribution"]["NEW"]
                metrics["investigating_alerts"] = metrics["status_distribution"]["INVESTIGATING"]
                metrics["resolved_alerts"] = metrics["status_distribution"]["RESOLVED"]

                # 4. Top Source IPs (by event + alert counts)
                ip_rows = conn.execute(
                    """
                    SELECT source_ip, COUNT(*) as cnt 
                    FROM events 
                    WHERE source_ip IS NOT NULL AND source_ip != ''
                    GROUP BY source_ip 
                    ORDER BY cnt DESC 
                    LIMIT 5
                    """
                ).fetchall()
                metrics["top_source_ips"] = {r["source_ip"]: r["cnt"] for r in ip_rows}

                # 5. Top Alerting Rules
                rule_rows = conn.execute(
                    """
                    SELECT r.name, COUNT(a.id) as cnt
                    FROM alerts a
                    LEFT JOIN rules r ON a.rule_id = r.id
                    GROUP BY a.rule_id
                    ORDER BY cnt DESC
                    LIMIT 5
                    """
                ).fetchall()
                metrics["top_rules"] = {r["name"] or "Custom Rule": r["cnt"] for r in rule_rows}

                # 6. Active Log Sources
                src_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM log_sources WHERE status = 'ACTIVE'"
                ).fetchone()
                metrics["active_sources_count"] = src_row["cnt"] if src_row else 0

                # 7. Events per minute (over last 5 minutes)
                five_min_ago = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
                epm_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ?",
                    (five_min_ago,)
                ).fetchone()
                if epm_row:
                    metrics["events_per_minute"] = round(epm_row["cnt"] / 5.0, 1)

        except Exception as e:
            logger.error(f"Error computing SOC metrics: {e}", exc_info=True)

        return metrics

    def get_events_over_time(self, hours: int = 24) -> List[int]:
        """
        Returns bucketed event counts over the specified timeframe (12 buckets)
        for line chart rendering.
        """
        buckets = [0] * 12
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            
            with db_conn() as conn:
                rows = conn.execute(
                    "SELECT timestamp FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
                    (start_str,)
                ).fetchall()

            if not rows:
                return buckets

            total_seconds = hours * 3600
            start_epoch = start_time.timestamp()

            for r in rows:
                try:
                    dt = datetime.strptime(r["timestamp"][:19], "%Y-%m-%d %H:%M:%S")
                    epoch = dt.timestamp()
                    offset = epoch - start_epoch
                    bucket_idx = int((offset / total_seconds) * 12)
                    if 0 <= bucket_idx < 12:
                        buckets[bucket_idx] += 1
                    elif bucket_idx >= 12:
                        buckets[11] += 1
                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Error calculating events over time: {e}")

        return buckets


# ═══════════════════════════════════════════════════════════════
#   STANDALONE ALERT MANAGER SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Alert Manager Module Self-Test...")
    
    # 1. Initialize clean DB schema & seed rules
    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    manager = AlertManager(dedup_window_seconds=60)

    # Track subscriber notifications
    received_notifications: List[Dict[str, Any]] = []

    def test_listener(alert: Dict[str, Any]):
        received_notifications.append(alert)

    manager.subscribe(test_listener)

    # ── Test 1: Insert New Alert ──
    print("\n[*] Test 1: Ingesting initial Critical Alert...")
    alert1 = manager.process_alert({
        "rule_id": "AUTH-003",
        "title": "Successful Login After Multiple Failures",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.22",
        "username": "admin",
        "description": "User logged in after multiple failures",
        "occurrences": 1
    })

    assert alert1["id"] is not None
    assert alert1["status"] == "NEW"
    assert len(received_notifications) == 1
    print(f"    [✓] Alert #{alert1['id']} created. Subscriber notified.")

    # ── Test 2: Deduplication / Aggregation ──
    print("\n[*] Test 2: Ingesting duplicate alert from same IP within dedup window...")
    alert2 = manager.process_alert({
        "rule_id": "AUTH-003",
        "title": "Successful Login After Multiple Failures",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.22",
        "username": "admin",
        "description": "User logged in after multiple failures (repeat)",
        "occurrences": 1
    })

    assert alert2["id"] == alert1["id"], "Failed to deduplicate: created new alert ID instead of merging!"
    assert alert2["occurrences"] == 2
    assert alert2["is_duplicate"] is True
    print(f"    [✓] Deduplication verified: Alert #{alert1['id']} occurrences incremented to {alert2['occurrences']}.")

    # ── Test 3: Status Transition ──
    print("\n[*] Test 3: Testing status transitions (NEW -> INVESTIGATING -> RESOLVED)...")
    assert manager.update_status(alert1["id"], "INVESTIGATING") is True
    fetched = manager.get_alert_by_id(alert1["id"])
    assert fetched["status"] == "INVESTIGATING"

    assert manager.update_status(alert1["id"], "RESOLVED") is True
    fetched = manager.get_alert_by_id(alert1["id"])
    assert fetched["status"] == "RESOLVED"
    print(f"    [✓] Status transition verified: Alert #{alert1['id']} is now RESOLVED.")

    # ── Test 4: Ingest Additional Alerts for Filtering & Metrics ──
    print("\n[*] Test 4: Ingesting High and Medium alerts for filtering tests...")
    manager.process_alert({
        "rule_id": "AUTH-001",
        "title": "Multiple Failed SSH Logins",
        "severity": "MEDIUM",
        "source_ip": "10.0.0.99",
        "username": "root",
        "description": "5 failed logins",
        "occurrences": 1
    })

    manager.process_alert({
        "rule_id": "AUTH-005",
        "title": "Root Login",
        "severity": "HIGH",
        "source_ip": "203.0.113.8",
        "username": "root",
        "description": "Direct root login",
        "occurrences": 1
    })

    # Test query filters
    med_alerts = manager.get_alerts(severity="MEDIUM")
    assert len(med_alerts) >= 1
    print(f"    [✓] Filter by severity=MEDIUM returned {len(med_alerts)} record(s).")

    search_alerts = manager.get_alerts(search_query="203.0.113.8")
    assert len(search_alerts) >= 1
    print(f"    [✓] Search query for IP returned {len(search_alerts)} record(s).")

    # ── Test 5: SOC Metrics Calculation ──
    print("\n[*] Test 5: Computing SOC live metrics...")
    metrics = manager.get_soc_metrics()
    print(f"    └─ Total Alerts: {metrics['total_alerts']}")
    print(f"    └─ Critical:     {metrics['critical_alerts']}")
    print(f"    └─ High:         {metrics['high_alerts']}")
    print(f"    └─ Medium:       {metrics['medium_alerts']}")
    print(f"    └─ Severity Map: {metrics['severity_distribution']}")
    print(f"    └─ Status Map:   {metrics['status_distribution']}")

    assert metrics["total_alerts"] >= 3
    assert metrics["critical_alerts"] >= 1
    assert metrics["high_alerts"] >= 1
    print("    [✓] Live SOC metrics verified.")

    print("\n[✓] STEP 8 SELF-TEST PASSED. Alert Manager module fully functional.")