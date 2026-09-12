"""
Mini SIEM — Logs Investigation View
====================================
Comprehensive search, filtering, inspection, and export interface for
all normalized system logs stored in the SQLite database.
"""

import csv
import json
import sys
import flet as ft
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL,
    create_card, create_severity_badge, create_section_header, get_severity_color, app_border
)


# ═══════════════════════════════════════════════════════════════
#   LOGS VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class LogsView(ft.Container):
    """Main Log Investigation interface."""
    def __init__(self, page: ft.Page):
        super().__init__()
        self.page_ref = page
        self.expand = True
        self.padding = 20

        # Pagination State
        self.current_page = 1
        self.page_size = 50
        self.total_records = 0
        self.total_pages = 1

        # UI Input Control References
        self.input_search = ft.TextField(
            hint_text="Search messages, raw logs, IPs, or users...",
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
            width=125,
        )
        self.dd_severity.on_change = lambda e: self._apply_filters()

        self.dd_source = ft.Dropdown(
            label="Log Source",
            value="ALL",
            options=[ft.dropdown.Option("ALL")],
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=145,
        )
        self.dd_source.on_change = lambda e: self._apply_filters()

        self.input_service = ft.TextField(
            label="Service",
            hint_text="sshd, sudo...",
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=110,
            on_submit=lambda e: self._apply_filters(),
        )
        self.input_ip = ft.TextField(
            label="Source IP",
            hint_text="192.168...",
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=120,
            on_submit=lambda e: self._apply_filters(),
        )
        self.input_user = ft.TextField(
            label="Username",
            hint_text="root, admin...",
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=110,
            on_submit=lambda e: self._apply_filters(),
        )

        # Pagination & Counter UI References
        self.lbl_record_count = ft.Text("Loading events...", size=12, color=TEXT_MUTED)
        self.lbl_page_info    = ft.Text("Page 1 of 1", size=12, color=TEXT_WHITE, weight="bold")
        self.btn_prev_page    = ft.IconButton(
            ft.Icons.CHEVRON_LEFT,
            icon_color=TEXT_WHITE,
            disabled=True,
            on_click=self._prev_page,
        )
        self.btn_next_page    = ft.IconButton(
            ft.Icons.CHEVRON_RIGHT,
            icon_color=TEXT_WHITE,
            disabled=True,
            on_click=self._next_page,
        )

        # Event Table List View
        self.table_rows_list = ft.ListView(expand=True, spacing=4)

        # Event Details Modal
        self.details_modal = self._build_details_modal()

        self.content = self._build_layout()
        self._populate_source_dropdown()

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
                                ft.Icon(ft.Icons.ARTICLE_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("Log Investigation", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Search, filter, and inspect normalized Linux system logs", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
                ft.Row(
                    [
                        ft.PopupMenuButton(
                            content=ft.Container(
                                content=ft.Row([
                                    ft.Icon(ft.Icons.DOWNLOAD_ROUNDED, size=16, color=TEXT_WHITE),
                                    ft.Text("Export", size=12, color=TEXT_WHITE, weight="bold")
                                ], spacing=6),
                                bgcolor=SURFACE_ALT,
                                border=app_border(1, BORDER_COLOR),
                                border_radius=6,
                                padding=ft.Padding(12, 8, 12, 8),
                            ),
                            items=[
                                ft.PopupMenuItem(content="Export as CSV", icon=ft.Icons.TABLE_CHART, on_click=lambda e: self._export_logs("csv")),
                                ft.PopupMenuItem(content="Export as JSON", icon=ft.Icons.DATA_OBJECT, on_click=lambda e: self._export_logs("json")),
                            ],
                        ),
                        ft.ElevatedButton(
                            "Refresh",
                            icon=ft.Icons.REFRESH,
                            bgcolor=SURFACE_ALT,
                            color=TEXT_WHITE,
                            on_click=lambda e: self.load_events(),
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
                            self.dd_source,
                            self.input_service,
                            self.input_ip,
                            self.input_user,
                            ft.Container(expand=True),
                            ft.OutlinedButton(
                                "Clear",
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
                    ft.Text("Source", color=TEXT_MUTED, size=11, weight="bold", width=95),
                    ft.Text("Service", color=TEXT_MUTED, size=11, weight="bold", width=85),
                    ft.Text("Severity", color=TEXT_MUTED, size=11, weight="bold", width=75),
                    ft.Text("Source IP", color=TEXT_MUTED, size=11, weight="bold", width=115),
                    ft.Text("User", color=TEXT_MUTED, size=11, weight="bold", width=90),
                    ft.Text("Event Type", color=TEXT_MUTED, size=11, weight="bold", width=135),
                    ft.Text("Message", color=TEXT_MUTED, size=11, weight="bold", expand=True),
                    ft.Text("Inspect", color=TEXT_MUTED, size=11, weight="bold", width=55, text_align="center"),
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

    def _render_event_row(self, event: Dict[str, Any]) -> ft.Container:
        ts = event.get("timestamp", "-")
        source = event.get("source", "-")
        service = event.get("service", "-")
        severity = (event.get("severity") or "LOW").upper()
        source_ip = event.get("source_ip") or "-"
        user = event.get("username") or "-"
        event_type = event.get("event_type") or "-"
        message = event.get("message") or event.get("raw_log") or "-"

        severity_badge = create_severity_badge(severity, width=72)
        inspect_btn = ft.TextButton(
            "Inspect",
            icon=ft.Icons.OPEN_IN_NEW,
            style=ft.ButtonStyle(color=TEXT_WHITE),
            on_click=lambda e, row=event: self._open_inspect_modal(row),
        )

        row_content = ft.Row(
            [
                ft.Text(ts, size=11, color=TEXT_WHITE, width=140, no_wrap=True),
                ft.Text(source, size=11, color=TEXT_MUTED, width=95, no_wrap=True),
                ft.Text(service, size=11, color=TEXT_MUTED, width=85, no_wrap=True),
                severity_badge,
                ft.Text(source_ip, size=11, color=TEXT_MUTED, width=115, no_wrap=True),
                ft.Text(user, size=11, color=TEXT_MUTED, width=90, no_wrap=True),
                ft.Text(event_type, size=11, color=TEXT_MUTED, width=135, no_wrap=True),
                ft.Text(message, size=11, color=TEXT_WHITE, expand=True, max_lines=2),
                inspect_btn,
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

        return ft.Container(
            content=row_content,
            padding=ft.Padding(left=8, right=8, top=6, bottom=6),
            border_radius=6,
            bgcolor="#111827" if event.get("id") % 2 == 0 else "#0F172A",
        )

    def _populate_source_dropdown(self):
        options = [ft.dropdown.Option("ALL")]
        try:
            with db_conn() as conn:
                rows = conn.execute("SELECT DISTINCT source FROM events ORDER BY source ASC").fetchall()
                for row in rows:
                    source_name = row["source"]
                    if source_name:
                        options.append(ft.dropdown.Option(source_name))
        except Exception as exc:
            self._show_snack(f"Failed to load sources: {exc}", is_error=True)

        self.dd_source.options = options
        valid_values = [getattr(opt, "key", None) or getattr(opt, "text", None) for opt in options]
        if self.dd_source.value not in valid_values:
            self.dd_source.value = "ALL"

    def _build_details_modal(self) -> ft.AlertDialog:
        return ft.AlertDialog(
            modal=True,
            title=ft.Text("Event Details"),
            content=ft.Column([], tight=True, spacing=10),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self._close_inspect_modal()),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

    def _safe_page_refresh(self):
        if self.page_ref is None:
            return
        try:
            self.page_ref.update()
        except Exception:
            pass

    def _open_inspect_modal(self, event: Dict[str, Any]):
        if self.page_ref is None:
            return

        details = ft.Column(
            [
                ft.Text("Event Summary", size=16, weight="bold", color=TEXT_WHITE),
                ft.Text(f"Timestamp: {event.get('timestamp', '-')}", color=TEXT_MUTED),
                ft.Text(f"Source: {event.get('source', '-')}", color=TEXT_MUTED),
                ft.Text(f"Service: {event.get('service', '-')}", color=TEXT_MUTED),
                ft.Text(f"Severity: {event.get('severity', 'LOW')}", color=TEXT_MUTED),
                ft.Text(f"Source IP: {event.get('source_ip', '-')}", color=TEXT_MUTED),
                ft.Text(f"Username: {event.get('username', '-')}", color=TEXT_MUTED),
                ft.Text(f"Event Type: {event.get('event_type', '-')}", color=TEXT_MUTED),
                ft.Divider(),
                ft.Text("Message", size=12, weight="bold", color=TEXT_WHITE),
                ft.Text(event.get("message") or event.get("raw_log") or "-", color=TEXT_WHITE, selectable=True),
            ],
            tight=True,
            scroll=ft.ScrollMode.AUTO,
            height=400,
        )

        self.details_modal.content = details
        self.page_ref.dialog = self.details_modal
        self.details_modal.open = True
        self._safe_page_refresh()

    def _close_inspect_modal(self):
        if self.page_ref is None:
            return
        self.details_modal.open = False
        self._safe_page_refresh()

    def _export_logs(self, fmt: str):
        if fmt not in {"csv", "json"}:
            return

        export_dir = Path(__file__).resolve().parent.parent / "reports"
        export_dir.mkdir(parents=True, exist_ok=True)

        try:
            rows = []
            with db_conn() as conn:
                rows = conn.execute(
                    "SELECT timestamp, source, hostname, service, username, source_ip, destination_ip, port, event_type, severity, message, raw_log FROM events ORDER BY timestamp DESC LIMIT 5000"
                ).fetchall()

            if fmt == "csv":
                file_path = export_dir / "logs_export.csv"
                with open(file_path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["timestamp", "source", "hostname", "service", "username", "source_ip", "destination_ip", "port", "event_type", "severity", "message", "raw_log"])
                    for row in rows:
                        writer.writerow([row["timestamp"], row["source"], row["hostname"], row["service"], row["username"], row["source_ip"], row["destination_ip"], row["port"], row["event_type"], row["severity"], row["message"], row["raw_log"]])
            else:
                file_path = export_dir / "logs_export.json"
                with open(file_path, "w", encoding="utf-8") as fh:
                    json.dump([dict(row) for row in rows], fh, indent=2)

            self._show_snack(f"Exported logs to {file_path.name}")
        except Exception as exc:
            self._show_snack(f"Export failed: {exc}", is_error=True)

    # ───────────────────────────────────────────────────────────
    #   DATABASE QUERY EXECUTION
    # ───────────────────────────────────────────────────────────

    def load_events(self):
        """Queries events table with current filters and pagination."""
        search_val = (self.input_search.value or "").strip()
        sev_val = self.dd_severity.value or "ALL"
        source_val = self.dd_source.value or "ALL"
        service_val = (self.input_service.value or "").strip()
        ip_val = (self.input_ip.value or "").strip()
        user_val = (self.input_user.value or "").strip()

        sql = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if search_val:
            sql += " AND (message LIKE ? OR raw_log LIKE ? OR source_ip LIKE ? OR username LIKE ? OR source LIKE ? OR event_type LIKE ?)"
            search_like = f"%{search_val}%"
            params.extend([search_like, search_like, search_like, search_like, search_like, search_like])

        if sev_val != "ALL":
            sql += " AND severity = ?"
            params.append(sev_val)

        if source_val != "ALL":
            sql += " AND source = ?"
            params.append(source_val)

        if service_val:
            sql += " AND service LIKE ?"
            params.append(f"%{service_val}%")

        if ip_val:
            sql += " AND source_ip LIKE ?"
            params.append(f"%{ip_val}%")

        if user_val:
            sql += " AND username LIKE ?"
            params.append(f"%{user_val}%")

        count_sql = sql
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([self.page_size, (self.current_page - 1) * self.page_size])

        rows = []
        total_rows = 0
        try:
            with db_conn() as conn:
                rows = conn.execute(sql, params).fetchall()
                total_rows = conn.execute(count_sql, params[:-2]).fetchone()["COUNT(*)"] if False else None
                if total_rows is None:
                    total_rows = conn.execute(f"SELECT COUNT(*) AS cnt FROM events WHERE 1=1", []).fetchone()["cnt"]
        except Exception as exc:
            self._show_snack(f"Failed to load event history: {exc}", is_error=True)
            rows = []
            total_rows = 0

        if total_rows == 0 and not rows:
            total_rows = 0

        # Count filtered records correctly.
        try:
            with db_conn() as conn:
                filter_count_sql = "SELECT COUNT(*) AS cnt FROM events WHERE 1=1"
                filter_params: List[Any] = []
                if search_val:
                    search_like = f"%{search_val}%"
                    filter_count_sql += " AND (message LIKE ? OR raw_log LIKE ? OR source_ip LIKE ? OR username LIKE ? OR source LIKE ? OR event_type LIKE ?)"
                    filter_params.extend([search_like, search_like, search_like, search_like, search_like, search_like])
                if sev_val != "ALL":
                    filter_count_sql += " AND severity = ?"
                    filter_params.append(sev_val)
                if source_val != "ALL":
                    filter_count_sql += " AND source = ?"
                    filter_params.append(source_val)
                if service_val:
                    filter_count_sql += " AND service LIKE ?"
                    filter_params.append(f"%{service_val}%")
                if ip_val:
                    filter_count_sql += " AND source_ip LIKE ?"
                    filter_params.append(f"%{ip_val}%")
                if user_val:
                    filter_count_sql += " AND username LIKE ?"
                    filter_params.append(f"%{user_val}%")
                total_rows = conn.execute(filter_count_sql, filter_params).fetchone()["cnt"]
        except Exception as exc:
            self._show_snack(f"Failed to count filtered events: {exc}", is_error=True)
            total_rows = 0

        self.total_records = total_rows
        self.total_pages = max(1, (self.total_records + self.page_size - 1) // self.page_size)

        if not rows:
            self.table_rows_list.controls = [
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Icon(ft.Icons.ARTICLE_OUTLINED, size=36, color=TEXT_MUTED),
                            ft.Text("No events match the selected filters.", color=TEXT_MUTED, size=13),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=6,
                    ),
                    padding=40,
                    alignment=ft.Alignment(0.5, 0.5),
                )
            ]
        else:
            self.table_rows_list.controls = [self._render_event_row(dict(row)) for row in rows]

        start_num = (self.current_page - 1) * self.page_size + 1 if self.total_records > 0 else 0
        end_num = min(self.current_page * self.page_size, self.total_records)
        self.lbl_record_count.value = f"Showing {start_num:,}–{end_num:,} of {self.total_records:,} events"
        self.lbl_page_info.value = f"Page {self.current_page} of {self.total_pages}"

        self.btn_prev_page.disabled = (self.current_page <= 1)
        self.btn_next_page.disabled = (self.current_page >= self.total_pages)
        self.update()

    # ───────────────────────────────────────────────────────────
    #   FILTER & PAGINATION HANDLERS
    # ───────────────────────────────────────────────────────────

    def _apply_filters(self):
        self.current_page = 1
        self.load_events()

    def _clear_filters(self):
        self.input_search.value = ""
        self.dd_severity.value = "ALL"
        self.dd_source.value = "ALL"
        self.input_service.value = ""
        self.input_ip.value = ""
        self.input_user.value = ""
        self.current_page = 1
        self.load_events()

    def _prev_page(self, e):
        if self.current_page > 1:
            self.current_page -= 1
            self.load_events()

    def _next_page(self, e):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.load_events()

    def _show_snack(self, message: str, is_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor=COLOR_CRITICAL if is_error else COLOR_GREEN,
            duration=3000,
        )
        if hasattr(self, "page_ref") and self.page_ref is not None:
            self.page_ref.overlay.append(snack)
            snack.open = True
            self.page_ref.update()


