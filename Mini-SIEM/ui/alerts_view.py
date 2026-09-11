"""
Mini SIEM — Alerts & Incident Investigation View
=================================================
SOC Alert Triage dashboard enabling analysts to inspect detections,
correlate contributing events, and transition alert lifecycle states.
"""

import sys
import flet as ft
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Adjust path to import central configuration, database, and alert manager
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn
from modules.alert_manager import AlertManager
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL, COLOR_PURPLE,
    create_card, create_severity_badge, create_section_header, get_severity_color, get_status_color
)


# ═══════════════════════════════════════════════════════════════
#   ALERTS VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class AlertsView(ft.Container):
    """Main Alert Triage & Incident Investigation View."""
    def __init__(self, page: ft.Page, alert_manager: AlertManager):
        super().__init__()
        self.page_ref = page
        self.alert_manager = alert_manager
        self.expand = True
        self.padding = 20

        # Pagination & Query State
        self.current_page = 1
        self.page_size = 30
        self.total_records = 0
        self.total_pages = 1
        self.active_inspected_alert: Optional[Dict[str, Any]] = None

        # Filter Controls
        self.input_search = ft.TextField(
            hint_text="Search alert title, description, rule ID, IP, or user...",
            prefix_icon=ft.Icons.SEARCH,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=12,
            height=38,
            expand=True,
            on_submit=lambda e: self._apply_filters(),
        )
        self.dd_severity = ft.Dropdown(
            label="Severity",
            value="ALL",
            options=[ft.dropdown.Option("ALL")] + [ft.dropdown.Option(s) for s in config.SEVERITY_LEVELS],
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=130,
        )
        self.dd_status = ft.Dropdown(
            label="Status",
            value="ALL",
            options=[ft.dropdown.Option("ALL")] + [ft.dropdown.Option(st) for st in config.ALERT_STATUSES],
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=150,
        )
        self.input_ip = ft.TextField(
            label="Source IP",
            hint_text="Filter IP...",
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=130,
            on_submit=lambda e: self._apply_filters(),
        )

        # Pagination UI
        self.lbl_record_count = ft.Text("Loading alerts...", size=12, color=TEXT_MUTED)
        self.lbl_page_info = ft.Text("Page 1 of 1", size=12, color=TEXT_WHITE, weight="bold")
        self.btn_prev_page = ft.IconButton(
            ft.Icons.CHEVRON_LEFT,
            icon_color=TEXT_WHITE,
            disabled=True,
            on_click=self._prev_page,
        )
        self.btn_next_page = ft.IconButton(
            ft.Icons.CHEVRON_RIGHT,
            icon_color=TEXT_WHITE,
            disabled=True,
            on_click=self._next_page,
        )

        # Alerts Table List View
        self.table_rows_list = ft.ListView(expand=True, spacing=4)

        # Modal Controls
        self.details_modal = self._build_details_modal()

        self.content = self._build_layout()

    # ───────────────────────────────────────────────────────────
    #   LAYOUT CONSTRUCTION
    # ───────────────────────────────────────────────────────────

    def _build_layout(self) -> ft.Column:
        return ft.Column(
            [
                self._build_header(),
                self._build_filter_bar(),
                self._build_table_card(),
                self._build_pagination_bar(),
            ],
            expand=True,
            spacing=12,
        )

    def _build_header(self) -> ft.Row:
        return ft.Row(
            [
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("Alerts & Incident Investigation", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Triage security alerts, analyze forensic timelines, and manage incident states", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
                ft.Row(
                    [
                        ft.ElevatedButton(
                            "Refresh Alerts",
                            icon=ft.Icons.REFRESH,
                            bgcolor=SURFACE_ALT,
                            color=TEXT_WHITE,
                            on_click=lambda e: self.load_alerts(),
                        ),
                    ],
                    spacing=10,
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

    def _build_filter_bar(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    ft.Row([self.input_search], spacing=10),
                    ft.Row(
                        [
                            self.dd_severity,
                            self.dd_status,
                            self.input_ip,
                            ft.Container(expand=True),
                            ft.OutlinedButton(
                                "Clear Filters",
                                icon=ft.Icons.CLEAR_ALL,
                                style=ft.ButtonStyle(color=TEXT_MUTED),
                                on_click=lambda e: self._clear_filters(),
                            ),
                            ft.ElevatedButton(
                                "Apply Filters",
                                icon=ft.Icons.FILTER_ALT,
                                bgcolor=COLOR_LOW,
                                color="#FFFFFF",
                                on_click=lambda e: self._apply_filters(),
                            ),
                        ],
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                ],
                spacing=10,
            ),
            padding=12,
        )

    def _build_table_card(self) -> ft.Container:
        header_row = ft.Container(
            content=ft.Row(
                [
                    ft.Text("Timestamp", color=TEXT_MUTED, size=11, weight="bold", width=140),
                    ft.Text("Severity", color=TEXT_MUTED, size=11, weight="bold", width=80),
                    ft.Text("Rule / Title", color=TEXT_MUTED, size=11, weight="bold", width=220),
                    ft.Text("Source IP", color=TEXT_MUTED, size=11, weight="bold", width=120),
                    ft.Text("User", color=TEXT_MUTED, size=11, weight="bold", width=95),
                    ft.Text("Hits", color=TEXT_MUTED, size=11, weight="bold", width=55, text_align="center"),
                    ft.Text("Status", color=TEXT_MUTED, size=11, weight="bold", width=110),
                    ft.Text("Description", color=TEXT_MUTED, size=11, weight="bold", expand=True),
                    ft.Text("Triage", color=TEXT_MUTED, size=11, weight="bold", width=65, text_align="center"),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor="#0F172A",
            padding=ft.Padding(left=10, right=10, top=8, bottom=8),
            border_radius=4,
        )

        return create_card(
            ft.Column(
                [
                    header_row,
                    ft.Divider(color=BORDER_COLOR, height=1),
                    self.table_rows_list,
                ],
                spacing=6,
                expand=True,
            ),
            expand=True,
            padding=10,
        )

    def _build_pagination_bar(self) -> ft.Row:
        return ft.Row(
            [
                self.lbl_record_count,
                ft.Row(
                    [
                        self.btn_prev_page,
                        self.lbl_page_info,
                        self.btn_next_page,
                    ],
                    spacing=5,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

    # ───────────────────────────────────────────────────────────
    #   STATUS BADGE COMPONENT
    # ───────────────────────────────────────────────────────────

    def _create_status_badge(self, status: str) -> ft.Container:
        st = (status or "NEW").upper()
        color = get_status_color(st)
        return ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.CIRCLE, size=7, color=color),
                    ft.Text(st, size=10, weight="bold", color=color),
                ],
                spacing=5,
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE_COLOR,
            border=app_border(1, color),
            padding=ft.Padding(left=6, right=6, top=2, bottom=2),
            border_radius=4,
            width=105,
        )

    # ───────────────────────────────────────────────────────────
    #   ALERT ROW RENDERING
    # ───────────────────────────────────────────────────────────

    def _render_alert_row(self, alert: Dict[str, Any]) -> ft.Container:
        sev = alert.get("severity", "LOW")
        title = alert.get("title", "Security Alert")
        src_ip = alert.get("source_ip") or "-"
        user = alert.get("username") or "-"
        occurrences = alert.get("occurrences", 1)
        status = alert.get("status", "NEW")
        desc = alert.get("description", "")

        return ft.Container(
            content=ft.Row(
                [
                    ft.Text(str(alert.get("timestamp", ""))[:19], color=TEXT_MUTED, size=11, width=140),
                    create_severity_badge(sev, width=80),
                    ft.Text(title, weight="bold", width=220, size=12, color=TEXT_WHITE, no_wrap=True),
                    ft.Text(src_ip, color=COLOR_LOW if src_ip != "-" else TEXT_MUTED, size=11, width=120, no_wrap=True),
                    ft.Text(user, color=COLOR_GREEN if user != "-" else TEXT_MUTED, size=11, width=95, no_wrap=True),
                    ft.Container(
                        content=ft.Text(str(occurrences), size=11, weight="bold", color=TEXT_WHITE, text_align="center"),
                        bgcolor=SURFACE_COLOR,
                        border=app_border(1, BORDER_COLOR),
                        border_radius=4,
                        width=45,
                        padding=2,
                        alignment=ft.Alignment(0.5, 0.5),
                    ),
                    self._create_status_badge(status),
                    ft.Text(desc, color=TEXT_MUTED, size=11, expand=True, no_wrap=True),
                    ft.ElevatedButton(
                        "Investigate",
                        icon=ft.Icons.SECURITY,
                        bgcolor=SURFACE_COLOR,
                        color=COLOR_LOW,
                        style=ft.ButtonStyle(padding=ft.Padding(6, 4, 6, 4), text_style=ft.TextStyle(size=10)),
                        height=28,
                        on_click=lambda e, al=alert: self._open_inspect_modal(al),
                    ),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE_ALT,
            padding=ft.Padding(left=10, right=10, top=5, bottom=5),
            border_radius=4,
            on_click=lambda e, al=alert: self._open_inspect_modal(al),
            ink=True,
        )

    # ───────────────────────────────────────────────────────────
    #   ALERT INVESTIGATION MODAL
    # ───────────────────────────────────────────────────────────

    def _build_details_modal(self) -> ft.AlertDialog:
        self.modal_content_column = ft.Column([], tight=True, spacing=12, scroll=ft.ScrollMode.AUTO)
        return ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.SHIELD_OUTLINED, color=COLOR_CRITICAL, size=22),
                ft.Text("Security Alert Triage & Forensics", size=16, weight="bold", color=TEXT_WHITE)
            ], spacing=8),
            content=ft.Container(
                content=self.modal_content_column,
                width=720,
                height=520,
                padding=5,
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self._close_inspect_modal()),
            ],
            bgcolor=SURFACE_COLOR,
        )

    def _query_related_events(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Queries normalized events that match this alert's target and time window."""
        source_ip = alert.get("source_ip")
        username = alert.get("username")
        first_seen = alert.get("first_seen")
        last_seen = alert.get("last_seen")

        if not source_ip and not username:
            return []

        sql = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if source_ip:
            sql += " AND source_ip = ?"
            params.append(source_ip)
        elif username:
            sql += " AND username = ?"
            params.append(username)

        if first_seen and last_seen:
            # Broaden time range by 5 minutes before and after
            sql += " AND timestamp >= datetime(?, '-5 minutes') AND timestamp <= datetime(?, '+5 minutes')"
            params.extend([first_seen, last_seen])

        sql += " ORDER BY id DESC LIMIT 15"

        try:
            with db_conn() as conn:
                rows = conn.execute(sql, params).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            print(f"[!] Error querying related events: {e}")
            return []

    def _open_inspect_modal(self, alert: Dict[str, Any]):
        self.active_inspected_alert = alert

        def meta_item(label: str, val: Any, color: str = TEXT_WHITE) -> ft.Container:
            return ft.Container(
                content=ft.Column(
                    [
                        ft.Text(label, size=10, color=TEXT_MUTED, weight="bold"),
                        ft.Text(str(val) if val is not None and str(val) != "" else "N/A", size=12, color=color, selectable=True),
                    ],
                    spacing=2,
                ),
                expand=1,
            )

        # 1. Forensic Metadata Rows
        meta_rows = [
            ft.Row([
                meta_item("Alert ID", f"#{alert.get('id')}"),
                meta_item("Detection Rule ID", alert.get("rule_id", "N/A")),
                meta_item("Severity", alert.get("severity"), get_severity_color(alert.get("severity"))),
                meta_item("Current Status", alert.get("status"), get_status_color(alert.get("status"))),
            ]),
            ft.Row([
                meta_item("Target Title", alert.get("title")),
                meta_item("Source IP", alert.get("source_ip"), COLOR_LOW),
                meta_item("Target Username", alert.get("username"), COLOR_GREEN),
                meta_item("Total Hits", f"{alert.get('occurrences', 1)} occurrence(s)"),
            ]),
            ft.Row([
                meta_item("First Detected", alert.get("first_seen")),
                meta_item("Last Detected", alert.get("last_seen")),
                meta_item("Log Timestamp", alert.get("timestamp")),
            ]),
        ]

        # 2. Analyst Action Buttons
        action_bar = ft.Container(
            content=ft.Row(
                [
                    ft.Text("ANALYST TRIAGE ACTIONS:", size=11, weight="bold", color=TEXT_MUTED),
                    ft.Container(expand=True),
                    ft.ElevatedButton(
                        "Investigating",
                        icon=ft.Icons.SEARCH,
                        bgcolor=COLOR_HIGH,
                        color="#FFFFFF",
                        style=ft.ButtonStyle(padding=ft.Padding(10, 6, 10, 6)),
                        on_click=lambda e: self._set_alert_status(alert["id"], config.ALERT_STATUS_INVESTIGATING),
                    ),
                    ft.ElevatedButton(
                        "Resolve",
                        icon=ft.Icons.CHECK_CIRCLE,
                        bgcolor=COLOR_GREEN,
                        color="#FFFFFF",
                        style=ft.ButtonStyle(padding=ft.Padding(10, 6, 10, 6)),
                        on_click=lambda e: self._set_alert_status(alert["id"], config.ALERT_STATUS_RESOLVED),
                    ),
                    ft.ElevatedButton(
                        "False Positive",
                        icon=ft.Icons.BLOCK,
                        bgcolor=SURFACE_ALT,
                        color=TEXT_MUTED,
                        style=ft.ButtonStyle(padding=ft.Padding(10, 6, 10, 6)),
                        on_click=lambda e: self._set_alert_status(alert["id"], config.ALERT_STATUS_FALSE_POS),
                    ),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor="#0F172A",
            padding=8,
            border_radius=6,
            border=app_border(1, BORDER_COLOR),
        )

        # 3. Description Box
        desc_box = ft.Container(
            content=ft.Column(
                [
                    ft.Text("DETECTION DESCRIPTION & EVIDENCE", size=10, color=TEXT_MUTED, weight="bold"),
                    ft.Text(alert.get("description", "No description provided."), size=12, color=TEXT_WHITE, selectable=True),
                ],
                spacing=4,
            ),
            bgcolor=SURFACE_ALT,
            padding=10,
            border_radius=6,
            border=app_border(1, BORDER_COLOR),
        )

        # 4. Contributing System Events
        related_events = self._query_related_events(alert)
        if not related_events:
            events_subview = ft.Text("No directly linked raw events found in active time window.", size=11, color=TEXT_MUTED)
        else:
            event_items = []
            for ev in related_events:
                event_items.append(
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Text(str(ev.get("timestamp"))[:19], size=10, color=TEXT_MUTED, width=125),
                                ft.Text(str(ev.get("service")), size=10, color=TEXT_WHITE, width=70),
                                ft.Text(str(ev.get("event_type")), size=10, color=COLOR_LOW, width=115),
                                ft.Text(str(ev.get("message")), size=10, color=TEXT_WHITE, expand=True, no_wrap=True),
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        bgcolor="#0F172A",
                        padding=ft.Padding(left=8, right=8, top=4, bottom=4),
                        border_radius=4,
                    )
                )
            events_subview = ft.Column(event_items, spacing=4)

        contributing_box = ft.Container(
            content=ft.Column(
                [
                    ft.Text(f"CONTRIBUTING SYSTEM EVENTS ({len(related_events)} records)", size=10, color=TEXT_MUTED, weight="bold"),
                    events_subview,
                ],
                spacing=6,
            ),
            bgcolor=SURFACE_ALT,
            padding=10,
            border_radius=6,
            border=app_border(1, BORDER_COLOR),
        )

        self.modal_content_column.controls = [
            action_bar,
            ft.Column(meta_rows, spacing=8),
            desc_box,
            contributing_box,
        ]

        self.page_ref.dialog = self.details_modal
        self.details_modal.open = True
        self.page_ref.update()

    def _close_inspect_modal(self):
        self.details_modal.open = False
        self.page_ref.update()

    def _set_alert_status(self, alert_id: int, new_status: str):
        """Updates status in SQLite and refreshes view."""
        success = self.alert_manager.update_status(alert_id, new_status)
        if success:
            self._show_snack(f"Alert #{alert_id} status updated to {new_status}")
            self._close_inspect_modal()
            self.load_alerts()
        else:
            self._show_snack(f"Failed to update status for Alert #{alert_id}", is_error=True)

    # ───────────────────────────────────────────────────────────
    #   DATABASE QUERY EXECUTION
    # ───────────────────────────────────────────────────────────

    def load_alerts(self):
        """Queries alerts table with current filters and pagination."""
        search_val = self.input_search.value or ""
        sev_val = self.dd_severity.value
        status_val = self.dd_status.value
        ip_val = self.input_ip.value or ""

        offset = (self.current_page - 1) * self.page_size
        alerts = self.alert_manager.get_alerts(
            severity=sev_val if sev_val != "ALL" else None,
            status=status_val if status_val != "ALL" else None,
            source_ip=ip_val.strip() if ip_val.strip() else None,
            search_query=search_val.strip() if search_val.strip() else None,
            limit=self.page_size,
            offset=offset,
        )

        # Count total for pagination
        metrics = self.alert_manager.get_soc_metrics()
        self.total_records = metrics["total_alerts"]
        self.total_pages = max(1, (self.total_records + self.page_size - 1) // self.page_size)

        if not alerts:
            self.table_rows_list.controls = [
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Icon(ft.Icons.NOTIFICATIONS_OFF, size=36, color=TEXT_MUTED),
                            ft.Text("No security alerts match the selected criteria.", color=TEXT_MUTED, size=13),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=6,
                    ),
                    padding=40,
                    alignment=ft.Alignment(0.5, 0.5),
                )
            ]
        else:
            self.table_rows_list.controls = [self._render_alert_row(a) for a in alerts]

        start_num = (self.current_page - 1) * self.page_size + 1 if self.total_records > 0 else 0
        end_num = min(self.current_page * self.page_size, self.total_records)
        self.lbl_record_count.value = f"Showing {start_num:,}–{end_num:,} of {self.total_records:,} alerts"
        self.lbl_page_info.value = f"Page {self.current_page} of {self.total_pages}"
        
        self.btn_prev_page.disabled = (self.current_page <= 1)
        self.btn_next_page.disabled = (self.current_page >= self.total_pages)

        self.update()

    # ───────────────────────────────────────────────────────────
    #   FILTER & PAGINATION HANDLERS
    # ───────────────────────────────────────────────────────────

    def _apply_filters(self):
        self.current_page = 1
        self.load_alerts()

    def _clear_filters(self):
        self.input_search.value = ""
        self.dd_severity.value = "ALL"
        self.dd_status.value = "ALL"
        self.input_ip.value = ""
        self.current_page = 1
        self.load_alerts()

    def _prev_page(self, e):
        if self.current_page > 1:
            self.current_page -= 1
            self.load_alerts()

    def _next_page(self, e):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.load_alerts()

    def _show_snack(self, message: str, is_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor=COLOR_CRITICAL if is_error else COLOR_GREEN,
            duration=3000,
        )
        self.page_ref.overlay.append(snack)
        snack.open = True
        self.page_ref.update()


# ═══════════════════════════════════════════════════════════════
#   STANDALONE ALERTS VIEW SELF-TEST
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Entry point for standalone Alerts View test."""
    page.title = f"{config.APP_NAME} — Alerts Investigation Test"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0

    from modules.database import initialize_db, seed_rules
    from modules.normalizer import EventNormalizer
    initialize_db()
    seed_rules()

    alert_mgr = AlertManager()

    # Seed sample alert & underlying event
    EventNormalizer.process_and_save({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": "auth.log",
        "hostname": "srv-prod",
        "service": "sshd",
        "username": "root",
        "source_ip": "198.51.100.99",
        "port": 22,
        "event_type": "ssh_failed_login",
        "message": "Failed password for root from 198.51.100.99 port 22",
        "raw_log": "Feb 28 17:30:00 srv-prod sshd[222]: Failed password for root from 198.51.100.99 port 22 ssh2"
    })

    alert_mgr.process_alert({
        "rule_id": "AUTH-002",
        "title": "SSH Brute Force",
        "severity": "HIGH",
        "source_ip": "198.51.100.99",
        "username": "root",
        "description": "10+ failed SSH login attempts detected from 198.51.100.99",
        "occurrences": 10
    })

    from ui.sidebar import Sidebar
    sidebar = Sidebar(on_nav_change=lambda route: print(f"Navigated to: {route}"))
    alerts_view = AlertsView(page=page, alert_manager=alert_mgr)

    page.add(
        ft.Row([sidebar, alerts_view], expand=True, spacing=0)
    )


if __name__ == "__main__":
    print("[*] Launching Flet Alerts View Standalone Window...")
    ft.app(target=main)