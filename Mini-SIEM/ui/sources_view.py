"""
Mini SIEM — Log Sources Management View
========================================
Manages monitored Linux log sources, diagnoses filesystem read permissions,
tracks ingestion volumes, and allows analysts to add custom log files.
"""

import os
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
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL, COLOR_PURPLE,
    create_card, create_section_header, get_status_color, app_border
)


# ═══════════════════════════════════════════════════════════════
#   LOG SOURCES VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class SourcesView(ft.Container):
    """Log Sources & System Telemetry Management View."""
    def __init__(self, page: ft.Page):
        super().__init__()
        self.page_ref = page
        self.expand = True
        self.padding = 20

        self.sources_data: List[Dict[str, Any]] = []

        # Top KPI Card References
        self.ref_total_sources   = ft.Ref[ft.Text]()
        self.ref_active_sources  = ft.Ref[ft.Text]()
        self.ref_warning_sources = ft.Ref[ft.Text]()
        self.ref_offline_sources = ft.Ref[ft.Text]()

        # Search & Filter Controls
        self.input_search = ft.TextField(
            hint_text="Search source name, path, or type...",
            prefix_icon=ft.Icons.SEARCH,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=12,
            height=38,
            expand=True,
            on_submit=lambda e: self.load_sources(),
        )
        self.dd_status_filter = ft.Dropdown(
            label="Status",
            value="ALL",
            options=[
                ft.dropdown.Option("ALL"),
                ft.dropdown.Option("ACTIVE"),
                ft.dropdown.Option("WARNING"),
                ft.dropdown.Option("OFFLINE")
            ],
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=140,
        )

        # Sources List View
        self.sources_table_list = ft.ListView(expand=True, spacing=6)

        # Modals
        self.add_source_modal = self._build_add_source_modal()

        self.content = self._build_layout()

    # ───────────────────────────────────────────────────────────
    #   LAYOUT CONSTRUCTION
    # ───────────────────────────────────────────────────────────

    def _build_layout(self) -> ft.Column:
        return ft.Column(
            [
                self._build_header(),
                self._build_kpi_cards(),
                self._build_filter_bar(),
                self._build_table_card(),
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
                                ft.Icon(ft.Icons.DNS_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("Log Sources & Endpoints", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Manage Linux log feeds, probe read permissions, and track ingestion volume", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
                ft.Row(
                    [
                        ft.ElevatedButton(
                            "Add Custom Log File",
                            icon=ft.Icons.ADD_LINK_ROUNDED,
                            bgcolor=COLOR_LOW,
                            color="#FFFFFF",
                            on_click=lambda e: self._open_add_source_modal(),
                        ),
                        ft.ElevatedButton(
                            "Probe & Refresh",
                            icon=ft.Icons.REFRESH,
                            bgcolor=SURFACE_ALT,
                            color=TEXT_WHITE,
                            on_click=lambda e: self.probe_and_load_sources(),
                        ),
                    ],
                    spacing=10,
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

    # ───────────────────────────────────────────────────────────
    #   KPI METRIC CARDS
    # ───────────────────────────────────────────────────────────

    def _create_kpi_card(self, title: str, ref_obj: ft.Ref[ft.Text], icon: str, color: str) -> ft.Container:
        return ft.Container(
            content=ft.Row(
                [
                    ft.Container(
                        content=ft.Row([ft.Icon(icon, color="#FFFFFF", size=20)], alignment=ft.MainAxisAlignment.CENTER),
                        bgcolor=color,
                        width=42,
                        height=42,
                        border_radius=8,
                    ),
                    ft.Column(
                        [
                            ft.Text(title, color=TEXT_MUTED, size=11, weight="bold"),
                            ft.Text("0", size=18, weight="bold", ref=ref_obj, color=TEXT_WHITE),
                        ],
                        spacing=2,
                    ),
                ],
                spacing=10,
            ),
            bgcolor=SURFACE_COLOR,
            border=app_border(1, BORDER_COLOR),
            padding=12,
            border_radius=8,
            expand=True,
        )

    def _build_kpi_cards(self) -> ft.Row:
        return ft.Row(
            [
                self._create_kpi_card("Total Sources", self.ref_total_sources, ft.Icons.FOLDER_SPECIAL_OUTLINED, COLOR_LOW),
                self._create_kpi_card("Active Feeds", self.ref_active_sources, ft.Icons.CHECK_CIRCLE_OUTLINE, COLOR_GREEN),
                self._create_kpi_card("Permission Warnings", self.ref_warning_sources, ft.Icons.LOCK_OUTLINE, COLOR_HIGH),
                self._create_kpi_card("Offline / Missing", self.ref_offline_sources, ft.Icons.HIGHLIGHT_OFF, COLOR_CRITICAL),
            ],
            spacing=15,
        )

    def _build_filter_bar(self) -> ft.Container:
        return create_card(
            ft.Row(
                [
                    self.input_search,
                    self.dd_status_filter,
                    ft.OutlinedButton(
                        "Clear",
                        icon=ft.Icons.CLEAR_ALL,
                        style=ft.ButtonStyle(color=TEXT_MUTED),
                        on_click=lambda e: self._clear_filters(),
                    ),
                ],
                spacing=10,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=10,
        )

    def _build_table_card(self) -> ft.Container:
        header_row = ft.Container(
            content=ft.Row(
                [
                    ft.Text("Source Name", color=TEXT_MUTED, size=11, weight="bold", width=140),
                    ft.Text("Status", color=TEXT_MUTED, size=11, weight="bold", width=110),
                    ft.Text("Type", color=TEXT_MUTED, size=11, weight="bold", width=120),
                    ft.Text("Filesystem Path", color=TEXT_MUTED, size=11, weight="bold", expand=True),
                    ft.Text("Events Logged", color=TEXT_MUTED, size=11, weight="bold", width=110, text_align="center"),
                    ft.Text("Last Activity", color=TEXT_MUTED, size=11, weight="bold", width=140),
                    ft.Text("Actions", color=TEXT_MUTED, size=11, weight="bold", width=70, text_align="center"),
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
                    self.sources_table_list,
                ],
                spacing=6,
                expand=True,
            ),
            expand=True,
            padding=10,
        )

    # ───────────────────────────────────────────────────────────
    #   STATUS BADGE COMPONENT
    # ───────────────────────────────────────────────────────────

    def _create_source_status_badge(self, status: str) -> ft.Container:
        st = (status or "OFFLINE").upper()
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
            width=100,
        )

    # ───────────────────────────────────────────────────────────
    #   SOURCE ROW RENDERING
    # ───────────────────────────────────────────────────────────

    def _render_source_row(self, src: Dict[str, Any]) -> ft.Container:
        sid = src.get("id")
        name = src.get("name", "")
        st_type = src.get("source_type", "custom_log")
        path_str = src.get("path", "")
        status = src.get("status", "OFFLINE")
        count = src.get("event_count", 0)
        last_evt = src.get("last_event") or "No events yet"

        # Check if custom source (can be deleted)
        is_default = any(d["name"] == name for d in config.DEFAULT_LOG_SOURCES)

        return ft.Container(
            content=ft.Row(
                [
                    ft.Text(name, weight="bold", color=TEXT_WHITE, size=12, width=140, no_wrap=True),
                    self._create_source_status_badge(status),
                    ft.Container(
                        content=ft.Text(st_type, size=11, color=COLOR_LOW, no_wrap=True),
                        bgcolor=SURFACE_COLOR,
                        padding=ft.Padding(6, 2, 6, 2),
                        border_radius=4,
                        border=app_border(1, BORDER_COLOR),
                        width=120,
                    ),
                    ft.Text(path_str, size=11, color=TEXT_MUTED, font_family="monospace", expand=True, no_wrap=True),
                    ft.Container(
                        content=ft.Text(f"{count:,}", size=11, weight="bold", color=TEXT_WHITE, text_align="center"),
                        bgcolor=SURFACE_COLOR,
                        border=app_border(1, BORDER_COLOR),
                        border_radius=4,
                        width=85,
                        padding=2,
                        alignment=ft.Alignment(0.5, 0.5),
                    ),
                    ft.Text(str(last_evt)[:19], size=11, color=TEXT_MUTED, width=140),
                    ft.Row(
                        [
                            ft.IconButton(
                                ft.Icons.REFRESH,
                                icon_size=15,
                                icon_color=COLOR_LOW,
                                tooltip="Re-probe Path Permissions",
                                on_click=lambda e, p=path_str, s_id=sid: self._probe_single_source(s_id, p),
                            ),
                            ft.IconButton(
                                ft.Icons.DELETE_OUTLINE,
                                icon_size=15,
                                icon_color=COLOR_CRITICAL if not is_default else TEXT_MUTED,
                                disabled=is_default,
                                tooltip="Remove Custom Source" if not is_default else "Default Linux Source (Protected)",
                                on_click=lambda e, s_id=sid, s_name=name: self._delete_custom_source(s_id, s_name),
                            ),
                        ],
                        spacing=0,
                        width=70,
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE_ALT,
            padding=ft.Padding(left=10, right=10, top=6, bottom=6),
            border_radius=4,
        )

    # ───────────────────────────────────────────────────────────
    #   ADD CUSTOM SOURCE MODAL
    # ───────────────────────────────────────────────────────────

    def _build_add_source_modal(self) -> ft.AlertDialog:
        self.form_src_name = ft.TextField(
            label="Source Name (e.g. custom_app_auth)",
            text_size=12,
            height=45,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
        )
        self.form_src_path = ft.TextField(
            label="Full Absolute Linux Path (e.g. /var/log/my_service.log)",
            text_size=12,
            height=45,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
        )
        self.form_src_type = ft.Dropdown(
            label="Log Format Parser",
            options=[
                ft.dropdown.Option("custom_log"),
                ft.dropdown.Option("linux_auth"),
                ft.dropdown.Option("linux_syslog"),
                ft.dropdown.Option("apache_access"),
                ft.dropdown.Option("apache_error"),
                ft.dropdown.Option("nginx_access"),
                ft.dropdown.Option("nginx_error"),
            ],
            value="custom_log",
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
        )

        modal_body = ft.Container(
            content=ft.Column(
                [
                    ft.Text("Register a custom Linux log file for real-time tailing and detection.", size=11, color=TEXT_MUTED),
                    self.form_src_name,
                    self.form_src_path,
                    self.form_src_type,
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text("ℹ️ LINUX PERMISSIONS NOTE:", size=10, weight="bold", color=COLOR_HIGH),
                                ft.Text(
                                    "Ensure your user account has read permissions for the target file. "
                                    "If restricted, grant permissions or add your user to the 'adm' group.",
                                    size=10,
                                    color=TEXT_MUTED,
                                ),
                            ],
                            spacing=3,
                        ),
                        bgcolor="#0F172A",
                        padding=8,
                        border_radius=6,
                        border=app_border(1, BORDER_COLOR),
                    ),
                ],
                spacing=10,
            ),
            width=520,
            height=300,
            padding=5,
        )

        return ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.ADD_LINK, color=COLOR_LOW, size=20),
                ft.Text("Add Custom Log Source", size=16, weight="bold", color=TEXT_WHITE),
            ], spacing=8),
            content=modal_body,
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self._close_modal(self.add_source_modal)),
                ft.ElevatedButton("Verify & Add", bgcolor=COLOR_LOW, color="#FFFFFF", on_click=lambda e: self._save_custom_source()),
            ],
            bgcolor=SURFACE_COLOR,
        )

    def _safe_page_refresh(self):
        if self.page_ref is None:
            return
        try:
            self.page_ref.update()
        except Exception:
            pass

    def _open_add_source_modal(self):
        self.form_src_name.value = ""
        self.form_src_path.value = ""
        self.form_src_type.value = "custom_log"
        self.page_ref.dialog = self.add_source_modal
        self.add_source_modal.open = True
        self._safe_page_refresh()

    def _save_custom_source(self):
        name = self.form_src_name.value.strip()
        path_str = self.form_src_path.value.strip()
        src_type = self.form_src_type.value

        if not name or not path_str:
            self._show_snack("Source Name and File Path cannot be empty.", is_error=True)
            return

        p = Path(path_str)
        # Probe initial status
        if not p.exists():
            status = "OFFLINE"
        elif not os.access(p, os.R_OK):
            status = "WARNING"
        else:
            status = "ACTIVE"

        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO log_sources (name, source_type, path, status, event_count)
                    VALUES (?, ?, ?, ?, 0)
                    """,
                    (name, src_type, str(p.resolve()), status)
                )

            self._close_modal(self.add_source_modal)
            self._show_snack(f"Source '{name}' added with status: {status}")
            self.probe_and_load_sources()

        except Exception as e:
            self._show_snack(f"Database error (Duplicate name or path?): {e}", is_error=True)

    def _delete_custom_source(self, source_id: int, source_name: str):
        try:
            with db_conn() as conn:
                conn.execute("DELETE FROM log_sources WHERE id = ?", (source_id,))
            self._show_snack(f"Removed log source '{source_name}'.")
            self.probe_and_load_sources()
        except Exception as e:
            self._show_snack(f"Failed to remove source: {e}", is_error=True)

    # ───────────────────────────────────────────────────────────
    #   DIAGNOSTIC PROBING ENGINE
    # ───────────────────────────────────────────────────────────

    def _probe_path(self, path_str: str) -> str:
        """Determines if a log file path exists and is readable."""
        p = Path(path_str)
        if not p.exists():
            return "OFFLINE"
        if not os.access(p, os.R_OK):
            return "WARNING"
        return "ACTIVE"

    def _probe_single_source(self, source_id: int, path_str: str):
        status = self._probe_path(path_str)
        try:
            with db_conn() as conn:
                conn.execute("UPDATE log_sources SET status = ? WHERE id = ?", (status, source_id))
            
            if status == "WARNING":
                self._show_snack(f"Permission denied on {path_str}. Run with read privileges.", is_error=True)
            elif status == "OFFLINE":
                self._show_snack(f"File not found at {path_str}.", is_error=True)
            else:
                self._show_snack(f"Path {path_str} is ACTIVE and readable.")
            self.load_sources()
        except Exception as e:
            self._show_snack(f"Error updating source probe: {e}", is_error=True)

    def probe_and_load_sources(self):
        """Probes all configured log paths and syncs status with SQLite."""
        try:
            with db_conn() as conn:
                rows = conn.execute("SELECT * FROM log_sources").fetchall()
                for r in rows:
                    curr_status = self._probe_path(r["path"])
                    if curr_status != r["status"]:
                        conn.execute("UPDATE log_sources SET status = ? WHERE id = ?", (curr_status, r["id"]))
        except Exception as e:
            print(f"[!] Error probing log sources: {e}")

        self.load_sources()

    def load_sources(self):
        """Pulls all log sources from SQLite and updates UI."""
        try:
            with db_conn() as conn:
                rows = conn.execute("SELECT * FROM log_sources ORDER BY id ASC").fetchall()
                self.sources_data = [dict(r) for r in rows]

            # 1. Update KPI Numbers
            total = len(self.sources_data)
            active = sum(1 for s in self.sources_data if s.get("status") == "ACTIVE")
            warning = sum(1 for s in self.sources_data if s.get("status") == "WARNING")
            offline = sum(1 for s in self.sources_data if s.get("status") == "OFFLINE")

            if self.ref_total_sources.current:
                self.ref_total_sources.current.value = str(total)
            if self.ref_active_sources.current:
                self.ref_active_sources.current.value = str(active)
            if self.ref_warning_sources.current:
                self.ref_warning_sources.current.value = str(warning)
            if self.ref_offline_sources.current:
                self.ref_offline_sources.current.value = str(offline)

            # 2. In-Memory Filter
            search = (self.input_search.value or "").lower().strip()
            status_filter = self.dd_status_filter.value

            filtered = self.sources_data
            if search:
                filtered = [
                    s for s in filtered
                    if search in s.get("name", "").lower()
                    or search in s.get("path", "").lower()
                    or search in s.get("source_type", "").lower()
                ]

            if status_filter and status_filter != "ALL":
                filtered = [s for s in filtered if s.get("status") == status_filter]

            # 3. Render Rows
            if not filtered:
                self.sources_table_list.controls = [
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Icon(ft.Icons.FOLDER_OFF_OUTLINED, size=36, color=TEXT_MUTED),
                                ft.Text("No log sources match the specified filter.", color=TEXT_MUTED, size=13),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=6,
                        ),
                        padding=40,
                        alignment=ft.Alignment(0.5, 0.5),
                    )
                ]
            else:
                self.sources_table_list.controls = [self._render_source_row(s) for s in filtered]

            self._safe_page_refresh()

        except Exception as e:
            print(f"[!] Error loading log sources: {e}")

    # ───────────────────────────────────────────────────────────
    #   HELPERS
    # ───────────────────────────────────────────────────────────

    def _clear_filters(self):
        self.input_search.value = ""
        self.dd_status_filter.value = "ALL"
        self.load_sources()

    def _close_modal(self, modal: ft.AlertDialog):
        modal.open = False
        self._safe_page_refresh()

    def _show_snack(self, message: str, is_error: bool = False):
        if self.page_ref is None:
            return
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor=COLOR_CRITICAL if is_error else COLOR_GREEN,
            duration=3500,
        )
        self.page_ref.overlay.append(snack)
        snack.open = True
        self._safe_page_refresh()


# ═══════════════════════════════════════════════════════════════
#   STANDALONE LOG SOURCES VIEW SELF-TEST
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Entry point for standalone Log Sources View test."""
    page.title = f"{config.APP_NAME} — Log Sources Test"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0

    from modules.database import initialize_db, seed_default_log_sources
    initialize_db()
    seed_default_log_sources()

    from ui.sidebar import Sidebar
    sidebar = Sidebar(on_nav_change=lambda route: print(f"Navigated to: {route}"))
    sources_view = SourcesView(page=page)

    page.add(
        ft.Row([sidebar, sources_view], expand=True, spacing=0)
    )


if __name__ == "__main__":
    print("[*] Launching Flet Log Sources View Standalone Window...")
    ft.app(target=main)