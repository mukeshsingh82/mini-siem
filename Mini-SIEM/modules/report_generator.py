"""
Mini SIEM — Professional Security Report Generator
===================================================
Compiles audit and compliance reports from real SQLite data.
Generates self-contained HTML (with embedded CSS and responsive layout),
structured JSON, and CSV exports into the reports/ directory.
"""

import os
import sys
import csv
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn

logger = logging.getLogger("MiniSIEM.ReportGenerator")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   REPORT GENERATOR CORE ENGINE
# ═══════════════════════════════════════════════════════════════

class ReportGenerator:
    """Aggregates SIEM database telemetry and generates security reports."""

    def __init__(self, time_range_days: int = 7):
        self.time_range_days = time_range_days
        self.cutoff_str = (datetime.now() - timedelta(days=time_range_days)).strftime("%Y-%m-%d %H:%M:%S")

    def gather_report_data(self) -> Dict[str, Any]:
        """Queries all SIEM database tables and computes metrics for the report."""
        data: Dict[str, Any] = {
            "meta": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "time_range_days": self.time_range_days,
                "platform": config.APP_NAME,
                "version": config.APP_VERSION,
                "scope": "Linux Host & Network Telemetry",
            },
            "kpi": {},
            "service_stats": {},
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "status_counts": {"NEW": 0, "INVESTIGATING": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0},
            "top_ips": [],
            "top_rules": [],
            "critical_alerts": [],
            "correlated_incidents": [],
            "log_sources": [],
            "assessment": [],
        }

        try:
            with db_conn() as conn:
                # 1. Log Volume & Events Count
                evt_cnt = conn.execute("SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ?", (self.cutoff_str,)).fetchone()["cnt"]
                data["kpi"]["total_events"] = evt_cnt

                # 2. Service Distribution
                svc_rows = conn.execute(
                    "SELECT service, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY service ORDER BY cnt DESC LIMIT 8",
                    (self.cutoff_str,)
                ).fetchall()
                data["service_stats"] = {r["service"] or "system": r["cnt"] for r in svc_rows}

                # 3. Alert Counts by Severity
                sev_rows = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM alerts WHERE timestamp >= ? GROUP BY severity",
                    (self.cutoff_str,)
                ).fetchall()
                total_alerts = 0
                for r in sev_rows:
                    sev = r["severity"]
                    if sev in data["severity_counts"]:
                        data["severity_counts"][sev] = r["cnt"]
                    total_alerts += r["cnt"]
                data["kpi"]["total_alerts"] = total_alerts

                # 4. Alert Status Counts
                st_rows = conn.execute(
                    "SELECT status, COUNT(*) as cnt FROM alerts WHERE timestamp >= ? GROUP BY status",
                    (self.cutoff_str,)
                ).fetchall()
                for r in st_rows:
                    st = r["status"]
                    if st in data["status_counts"]:
                        data["status_counts"][st] = r["cnt"]

                # 5. Top Source IPs
                ip_rows = conn.execute(
                    """
                    SELECT source_ip, COUNT(*) as event_count
                    FROM events
                    WHERE timestamp >= ? AND source_ip IS NOT NULL AND source_ip != ''
                    GROUP BY source_ip
                    ORDER BY event_count DESC
                    LIMIT 8
                    """,
                    (self.cutoff_str,)
                ).fetchall()

                for r in ip_rows:
                    ip = r["source_ip"]
                    al_cnt = conn.execute(
                        "SELECT COUNT(*) as cnt FROM alerts WHERE source_ip = ? AND timestamp >= ?",
                        (ip, self.cutoff_str)
                    ).fetchone()["cnt"]
                    data["top_ips"].append({
                        "ip": ip,
                        "events": r["event_count"],
                        "alerts": al_cnt,
                        "threat_level": "HIGH" if al_cnt > 3 else "MEDIUM" if al_cnt > 0 else "LOW"
                    })

                # 6. Top Triggered Rules
                rule_rows = conn.execute(
                    """
                    SELECT r.id, r.name, r.severity, COUNT(a.id) as triggers
                    FROM alerts a
                    JOIN rules r ON a.rule_id = r.id
                    WHERE a.timestamp >= ?
                    GROUP BY a.rule_id
                    ORDER BY triggers DESC
                    LIMIT 8
                    """,
                    (self.cutoff_str,)
                ).fetchall()
                data["top_rules"] = [dict(r) for r in rule_rows]

                # 7. Critical & High Alerts Table
                crit_rows = conn.execute(
                    """
                    SELECT id, timestamp, severity, title, source_ip, username, occurrences, status, description
                    FROM alerts
                    WHERE timestamp >= ? AND severity IN ('CRITICAL', 'HIGH')
                    ORDER BY id DESC
                    LIMIT 15
                    """,
                    (self.cutoff_str,)
                ).fetchall()
                data["critical_alerts"] = [dict(r) for r in crit_rows]

                # 8. Correlated Incidents
                corr_rows = conn.execute(
                    "SELECT * FROM correlations WHERE created_at >= ? ORDER BY id DESC LIMIT 10",
                    (self.cutoff_str,)
                ).fetchall()
                for r in corr_rows:
                    d = dict(r)
                    try:
                        d["related_alerts"] = json.loads(d.get("related_alerts") or "[]")
                    except Exception:
                        d["related_alerts"] = []
                    data["correlated_incidents"].append(d)

                # 9. Active Sources Status
                src_rows = conn.execute("SELECT name, source_type, path, status, event_count FROM log_sources").fetchall()
                data["log_sources"] = [dict(r) for r in src_rows]

            # 10. Automated Risk Score Calculation (0 to 100)
            crit_count = data["severity_counts"]["CRITICAL"]
            high_count = data["severity_counts"]["HIGH"]
            med_count = data["severity_counts"]["MEDIUM"]
            corr_count = len(data["correlated_incidents"])

            raw_score = (crit_count * 25) + (corr_count * 20) + (high_count * 10) + (med_count * 2)
            risk_score = min(100, max(5, raw_score if data["kpi"]["total_events"] > 0 else 0))
            data["kpi"]["risk_score"] = risk_score
            data["kpi"]["risk_rating"] = (
                "CRITICAL THREAT" if risk_score >= 75 else
                "HIGH RISK" if risk_score >= 50 else
                "ELEVATED RISK" if risk_score >= 25 else
                "LOW / NORMAL"
            )

            # 11. Automated Security Assessment Guidance
            data["assessment"] = self._build_recommendations(data)

        except Exception as e:
            logger.error(f"Error gathering report data: {e}", exc_info=True)

        return data

    def _build_recommendations(self, data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generates dynamic, rule-based recommendations according to observed attacks."""
        recs = []
        crit_alerts = [a["title"].lower() for a in data["critical_alerts"]]
        service_names = [s.lower() for s in data["service_stats"].keys()]

        if any("ssh" in t or "brute" in t for t in crit_alerts):
            recs.append({
                "category": "SSH Hardening",
                "severity": "HIGH",
                "finding": "Multiple SSH brute-force or credential stuffing attempts detected.",
                "action": "Disable password authentication in /etc/ssh/sshd_config (PasswordAuthentication no), enforce public-key authentication, and deploy Fail2ban/iptables rate-limiting."
            })

        if any("root" in t for t in crit_alerts):
            recs.append({
                "category": "Privileged Access",
                "severity": "CRITICAL",
                "finding": "Direct root authentication attempts observed.",
                "action": "Set PermitRootLogin no in sshd_config. Enforce administrative access strictly via unprivileged user accounts using audited sudo commands."
            })

        if any("sql" in t or "404" in t or "web" in t for t in crit_alerts) or "webserver" in service_names:
            recs.append({
                "category": "Web Application Security",
                "severity": "HIGH",
                "finding": "Web scanning or injection patterns detected targeting HTTP services.",
                "action": "Ensure web applications utilize parameterized database queries, implement a Web Application Firewall (ModSecurity/Coraza), and review HTTP 404 scanning logs."
            })

        if len(data["correlated_incidents"]) > 0:
            recs.append({
                "category": "Incident Response",
                "severity": "CRITICAL",
                "finding": f"{len(data['correlated_incidents'])} multi-stage correlated attack chains identified.",
                "action": "Isolate the involved host IP addresses immediately, inspect active user sessions, rotate affected account credentials, and check audit logs for unauthorized persistence."
            })

        if not recs:
            recs.append({
                "category": "General Linux Baseline",
                "severity": "LOW",
                "finding": "No high-severity anomalous attack chains recorded during this audit period.",
                "action": "Maintain scheduled OS security patches (unattended-upgrades), review firewall port policies, and preserve centralized log retention."
            })

        return recs

    # ───────────────────────────────────────────────────────────
    #   HTML REPORT GENERATOR
    # ───────────────────────────────────────────────────────────

    def generate_html_report(self) -> Path:
        """Renders an executive-grade, standalone HTML security report with embedded CSS."""
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        data = self.gather_report_data()

        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = config.REPORTS_DIR / filename

        risk_score = data["kpi"]["risk_score"]
        if risk_score >= 75:
            risk_color = "#EF4444"
        elif risk_score >= 50:
            risk_color = "#F59E0B"
        elif risk_score >= 25:
            risk_color = "#EAB308"
        else:
            risk_color = "#10B981"

        # Pre-build HTML table fragments to avoid nested quotes inside f-strings
        if not data['correlated_incidents']:
            corr_html = '<p style="color: var(--text-muted); font-size: 12px;">No complex multi-stage attack chains recorded during this timeframe.</p>'
        else:
            corr_rows = []
            for c in data['correlated_incidents']:
                sev = c.get('severity', 'LOW')
                st = c.get('status', 'NEW')
                ip = c.get('source_ip') or '-'
                user = c.get('username') or '-'
                alerts_count = len(c.get('related_alerts', []))
                corr_rows.append(
                    f"<tr>"
                    f"<td>{c.get('created_at')}</td>"
                    f'<td><span class="badge badge-{sev}">{sev}</span></td>'
                    f"<td><strong>{c.get('title')}</strong></td>"
                    f'<td style="color: var(--low); font-family: monospace;">{ip}</td>'
                    f"<td>{user}</td>"
                    f"<td>{alerts_count} alerts</td>"
                    f'<td><span class="badge badge-{st}">{st}</span></td>'
                    f"</tr>"
                )
            corr_html = (
                "<table><thead><tr>"
                "<th>Created At</th><th>Severity</th><th>Incident Title</th><th>Source IP</th>"
                "<th>Target User</th><th>Linked Alerts</th><th>Status</th>"
                "</tr></thead><tbody>" + "".join(corr_rows) + "</tbody></table>"
            )

        if not data['top_ips']:
            top_ips_html = '<p style="color: var(--text-muted); font-size: 12px;">No remote IP telemetry recorded.</p>'
        else:
            ip_rows = []
            for ip in data['top_ips']:
                ip_rows.append(
                    f"<tr>"
                    f'<td style="color: var(--low); font-weight: bold; font-family: monospace;">{ip["ip"]}</td>'
                    f'<td>{ip["events"]:,}</td>'
                    f'<td>{ip["alerts"]}</td>'
                    f'<td><span class="badge badge-{ip["threat_level"]}">{ip["threat_level"]}</span></td>'
                    f"</tr>"
                )
            top_ips_html = (
                "<table><thead><tr>"
                "<th>Source IP</th><th>Total Log Events</th><th>Generated Alerts</th><th>Assessed Threat Level</th>"
                "</tr></thead><tbody>" + "".join(ip_rows) + "</tbody></table>"
            )

        if not data['critical_alerts']:
            crit_alerts_html = '<p style="color: var(--text-muted); font-size: 12px;">No critical alerts recorded during this timeframe.</p>'
        else:
            crit_rows = []
            for a in data['critical_alerts']:
                sev = a.get('severity', 'LOW')
                st = a.get('status', 'NEW')
                ip = a.get('source_ip') or '-'
                user = a.get('username') or '-'
                crit_rows.append(
                    f"<tr>"
                    f"<td>{a.get('timestamp')}</td>"
                    f'<td><span class="badge badge-{sev}">{sev}</span></td>'
                    f"<td><strong>{a.get('title')}</strong></td>"
                    f'<td style="color: var(--low); font-family: monospace;">{ip}</td>'
                    f"<td>{user}</td>"
                    f"<td>{a.get('occurrences')}</td>"
                    f'<td><span class="badge badge-{st}">{st}</span></td>'
                    f'<td style="color: var(--text-muted);">{a.get("description")}</td>'
                    f"</tr>"
                )
            crit_alerts_html = (
                "<table><thead><tr>"
                "<th>Timestamp</th><th>Severity</th><th>Alert Title</th><th>Source IP</th>"
                "<th>User</th><th>Occurrences</th><th>Status</th><th>Description</th>"
                "</tr></thead><tbody>" + "".join(crit_rows) + "</tbody></table>"
            )

        rec_cards = []
        for rec in data['assessment']:
            rec_cards.append(
                f'<div class="rec-card {rec["severity"]}">'
                f'<div class="rec-title"><span>{rec["category"]}</span>'
                f'<span class="badge badge-{rec["severity"]}">{rec["severity"]} Priority</span></div>'
                f'<div class="rec-finding"><strong>Observation:</strong> {rec["finding"]}</div>'
                f'<div class="rec-action"><strong>Remediation:</strong> {rec["action"]}</div>'
                f'</div>'
            )
        recs_html = "".join(rec_cards)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mini SIEM — Security Audit & Incident Report</title>
    <style>
        :root {{
            --bg: #0B1121;
            --surface: #161E2E;
            --surface-alt: #1F2937;
            --border: #2D3748;
            --text-main: #F9FAFB;
            --text-muted: #9CA3AF;
            --critical: #EF4444;
            --high: #F59E0B;
            --medium: #EAB308;
            --low: #3B82F6;
            --green: #10B981;
            --purple: #8B5CF6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: #0B1121; color: var(--text-main); padding: 40px 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 26px; color: var(--text-main); }}
        .header h1 span {{ color: var(--low); }}
        .header .meta {{ text-align: right; font-size: 12px; color: var(--text-muted); }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .kpi-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
        .kpi-card .title {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: bold; margin-bottom: 6px; }}
        .kpi-card .val {{ font-size: 26px; font-weight: bold; }}
        .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 25px; margin-bottom: 25px; }}
        .section h2 {{ font-size: 16px; margin-bottom: 15px; color: var(--text-main); border-left: 4px solid var(--low); padding-left: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }}
        th {{ background: #0F172A; color: var(--text-muted); text-align: left; padding: 10px; border-bottom: 1px solid var(--border); font-weight: 600; }}
        td {{ padding: 10px; border-bottom: 1px solid var(--border); color: var(--text-main); }}
        tr:hover td {{ background: var(--surface-alt); }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; color: #fff; text-transform: uppercase; }}
        .badge-CRITICAL {{ background: var(--critical); }}
        .badge-HIGH {{ background: var(--high); }}
        .badge-MEDIUM {{ background: var(--medium); color: #000; }}
        .badge-LOW {{ background: var(--low); }}
        .badge-NEW {{ background: var(--critical); }}
        .badge-INVESTIGATING {{ background: var(--high); }}
        .badge-RESOLVED {{ background: var(--green); }}
        .badge-ACTIVE {{ background: var(--green); }}
        .badge-WARNING {{ background: var(--high); }}
        .badge-OFFLINE {{ background: var(--critical); }}
        .rec-card {{ background: var(--surface-alt); border-left: 4px solid var(--low); padding: 15px; border-radius: 4px; margin-bottom: 12px; }}
        .rec-card.HIGH {{ border-left-color: var(--high); }}
        .rec-card.CRITICAL {{ border-left-color: var(--critical); }}
        .rec-title {{ font-weight: bold; font-size: 13px; margin-bottom: 4px; display: flex; justify-content: space-between; }}
        .rec-finding {{ font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }}
        .rec-action {{ font-size: 12px; color: #A7F3D0; font-family: monospace; background: #0F172A; padding: 8px; border-radius: 4px; }}
        .footer {{ text-align: center; color: var(--text-muted); font-size: 11px; margin-top: 40px; border-top: 1px solid var(--border); padding-top: 20px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>🛡️ Mini <span>SIEM</span> — Security Assessment Report</h1>
            <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Host Telemetry, Intrusion Analysis & SOC Compliance Audit</p>
        </div>
        <div class="meta">
            <p><strong>Generated:</strong> {data['meta']['generated_at']}</p>
            <p><strong>Audit Scope:</strong> Last {data['meta']['time_range_days']} Days</p>
            <p><strong>System:</strong> {data['meta']['platform']} v{data['meta']['version']}</p>
        </div>
    </div>

    <!-- 1. KPI EXECUTIVE SUMMARY -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="title">Calculated Risk Score</div>
            <div class="val" style="color: {risk_color};">{data['kpi']['risk_score']} / 100</div>
            <p style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">{data['kpi']['risk_rating']}</p>
        </div>
        <div class="kpi-card">
            <div class="title">Total Logs Ingested</div>
            <div class="val" style="color: var(--low);">{data['kpi']['total_events']:,}</div>
            <p style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Normalized Events</p>
        </div>
        <div class="kpi-card">
            <div class="title">Critical & High Alerts</div>
            <div class="val" style="color: var(--critical);">{data['severity_counts']['CRITICAL'] + data['severity_counts']['HIGH']}</div>
            <p style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">{data['severity_counts']['CRITICAL']} Critical / {data['severity_counts']['HIGH']} High</p>
        </div>
        <div class="kpi-card">
            <div class="title">Correlated Incidents</div>
            <div class="val" style="color: var(--purple);">{len(data['correlated_incidents'])}</div>
            <p style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Multi-Stage Attack Chains</p>
        </div>
    </div>

    <!-- 2. CORRELATED ATTACK CHAINS -->
    <div class="section">
        <h2>🔥 Multi-Stage Correlated Security Incidents</h2>
        {corr_html}
    </div>

    <!-- 3. TOP THREAT ACTORS -->
    <div class="section">
        <h2>🌐 Top Offending Source IP Addresses</h2>
        {top_ips_html}
    </div>

    <!-- 4. CRITICAL ALERTS CATALOG -->
    <div class="section">
        <h2>🚨 Critical & High Security Alerts Forensics</h2>
        {crit_alerts_html}
    </div>

    <!-- 5. SECURITY ASSESSMENT & RECOMMENDATIONS -->
    <div class="section">
        <h2>🛡️ SOC Hardening & Remediation Guidance</h2>
        {recs_html}
    </div>

    <div class="footer">
        Generated by <strong>{config.APP_NAME}</strong> — {config.APP_SUBTITLE} | Confidential Cybersecurity Audit
    </div>
</div>
</body>
</html>
"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML Security Report generated: {filepath}")
        return filepath

    # ───────────────────────────────────────────────────────────
    #   JSON & CSV GENERATORS
    # ───────────────────────────────────────────────────────────

    def generate_json_report(self) -> Path:
        """Exports raw audit findings to formatted JSON."""
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        data = self.gather_report_data()

        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = config.REPORTS_DIR / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"JSON Security Report generated: {filepath}")
        return filepath

    def generate_csv_report(self) -> Path:
        """Exports critical alerts and telemetry to CSV."""
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        data = self.gather_report_data()

        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = config.REPORTS_DIR / filename

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["=== MINI SIEM SECURITY AUDIT REPORT ==="])
            writer.writerow(["Generated At", data["meta"]["generated_at"]])
            writer.writerow(["Risk Score", f"{data['kpi']['risk_score']} / 100", data["kpi"]["risk_rating"]])
            writer.writerow([])
            writer.writerow(["=== CRITICAL & HIGH ALERTS ==="])
            writer.writerow(["ID", "Timestamp", "Severity", "Title", "Source IP", "Username", "Occurrences", "Status", "Description"])
            for a in data["critical_alerts"]:
                writer.writerow([
                    a.get("id"),
                    a.get("timestamp"),
                    a.get("severity"),
                    a.get("title"),
                    a.get("source_ip"),
                    a.get("username"),
                    a.get("occurrences"),
                    a.get("status"),
                    a.get("description")
                ])

        logger.info(f"CSV Security Report generated: {filepath}")
        return filepath


# ═══════════════════════════════════════════════════════════════
#   STANDALONE REPORT GENERATOR TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Report Generator Module Self-Test...")

    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    gen = ReportGenerator(time_range_days=7)
    
    html_path = gen.generate_html_report()
    assert html_path.exists(), "HTML report generation failed"
    print(f"[✓] HTML Report written successfully: {html_path.name}")

    json_path = gen.generate_json_report()
    assert json_path.exists(), "JSON report generation failed"
    print(f"[✓] JSON Report written successfully: {json_path.name}")

    csv_path = gen.generate_csv_report()
    assert csv_path.exists(), "CSV report generation failed"
    print(f"[✓] CSV Report written successfully: {csv_path.name}")

    print("\n[✓] STEP 15 REPORT GENERATOR BACKEND TEST PASSED.")