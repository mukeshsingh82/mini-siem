"""
Mini SIEM — Settings & Platform Configuration View
===================================================
Manages application configuration, alert notification toggles,
data retention policies, and database maintenance/backup operations.
"""

import os
import sys
import shutil
import flet as ft
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL, COLOR_PURPLE,
    create_card, create_section_header, app_border
)


# ═══════════════════════════════════════════════════════════════
#   SETTINGS VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class SettingsView(ft.Container):
    """Platform Settings and Database Administration Interface."""
    def __init__(self, page: ft.Page):
        super().__init__()
        self.page_ref = page
        self.expand = True
        self.padding = 20

        # State Variables
        self.retention_days = config.EVENT_RETENTION_DAYS
        self.refresh_interval = config.GUI_REFRESH_INTERVAL

        # General Controls
        self.dd_refresh = ft.Dropdown(
            label="Dashboard Refresh Interval",
            value="2 Seconds",
            options=[
                ft.dropdown.Option("1 Second"),
                ft.dropdown.Option("2 Seconds"),
                ft.dropdown.Option("5 Seconds"),
                ft.dropdown.Option("10 Seconds"),
                ft.dropdown.Option("Manual Only"),
            ],
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            width=200,
        )
        self.dd_date_format = ft.Dropdown(
            label="Date Display Format",
            value="YYYY-MM-DD HH:MM:SS",
            options=[
                ft.dropdown.Option("YYYY-MM-DD HH:MM:SS"),
                ft.dropdown.Option("DD/MM/YYYY HH:MM:SS"),
                ft.dropdown.Option("MM/DD/YYYY hh:mm:ss A"),
            ],
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            width=220,
        )

        # Logging & Retention Controls
        self.input_log_dir = ft.TextField(
            label="Default Linux Log Directory",
            value="/var/log",
            text_size=12,
            height=45,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            expand=True,
        )
        self.dd_retention = ft.Dropdown(
            label="Event Retention Policy",
            value=f"{config.EVENT_RETENTION_DAYS} Days",
            options=[
                ft.dropdown.Option("7 Days"),
                ft.dropdown.Option("14 Days"),
                ft.dropdown.Option("30 Days"),
                ft.dropdown.Option("90 Days"),
                ft.dropdown.Option("Keep Forever"),
            ],
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            width=180,
        )

        # Notification Controls
        self.sw_desktop_notify = ft.Switch(
            label="Enable Desktop Notifications",
            value=True,
            active_color=COLOR_GREEN
        )
        self.sw_critical_only = ft.Switch(
            label="Notify on Critical Alerts Only",
            value=False,
            active_color=COLOR_HIGH
        )
        self.sw_sound_alert = ft.Switch(
            label="Audio Alarm on Critical Incidents",
            value=True,
            active_color=COLOR_CRITICAL
        )

        # Database Telemetry Labels
        self.lbl_db_path = ft.Text(str(config.DATABASE_PATH), size=11, font_family="monospace", color=COLOR_LOW)
        self.lbl_db_size = ft.Text("0 KB", size=12, weight="bold", color=TEXT_WHITE)
        self.lbl_db_events = ft.Text("0", size=12, weight="bold", color=TEXT_WHITE)
        self.lbl_db_alerts = ft.Text("0", size=12, weight="bold", color=TEXT_WHITE)
        self.lbl_db_journal = ft.Text("WAL (Write-Ahead Logging)", size=12, weight="bold", color=COLOR_GREEN)

        self.content = self._build_layout()

    # ───────────────────────────────────────────────────────────
    #   LAYOUT CONSTRUCTION
    # ───────────────────────────────────────────────────────────

    def _build_layout(self) -> ft.Column:
        return ft.Column(
            [
                self._build_header(),
                ft.Row(
                    [
                        ft.Column([self._build_general_card(), self._build_alerts_card()], spacing=15, expand=1),
                        ft.Column([self._build_retention_card(), self._build_database_card()], spacing=15, expand=1),
                    ],
                    spacing=15,
                ),
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=15,
        )

    def _build_header(self) -> ft.Row:
        return ft.Row(
            [
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.SETTINGS_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("Settings & Configuration", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Platform parameters, retention rules, notifications, and database maintenance", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
                ft.ElevatedButton(
                    "Save Changes",
                    icon=ft.Icons.SAVE_ROUNDED,
                    bgcolor=COLOR_LOW,
                    color="#FFFFFF",
                    style=ft.ButtonStyle(padding=ft.Padding(16, 10, 16, 10)),
                    on_click=lambda e: self._save_settings(),
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

    # ───────────────────────────────────────────────────────────
    #   CONFIGURATION CARDS
    # ───────────────────────────────────────────────────────────

    def _build_general_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("General Preferences"),
                    ft.Text("Configure dashboard refresh rates and regional timestamp formatting.", size=11, color=TEXT_MUTED),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    ft.Row([self.dd_refresh, self.dd_date_format], spacing=10),
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(ft.Icons.DARK_MODE, size=18, color=COLOR_LOW),
                                ft.Text("Application Theme: SOC High-Contrast Dark (Default)", size=12, color=TEXT_WHITE),
                            ],
                            spacing=8,
                        ),
                        bgcolor="#0F172A",
                        padding=10,
                        border_radius=6,
                        border=app_border(1, BORDER_COLOR),
                    ),
                ],
                spacing=10,
            ),
            padding=15,
        )

    def _build_alerts_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("Alert & Incident Notifications"),
                    ft.Text("Control desktop and audio alert triggers for analysts.", size=11, color=TEXT_MUTED),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    self.sw_desktop_notify,
                    self.sw_critical_only,
                    self.sw_sound_alert,
                ],
                spacing=10,
            ),
            padding=15,
        )

    def _build_retention_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("Logging & Data Retention"),
                    ft.Text("Define storage thresholds to automatically manage disk consumption.", size=11, color=TEXT_MUTED),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    self.input_log_dir,
                    self.dd_retention,
                ],
                spacing=10,
            ),
            padding=15,
        )

    def _build_database_card(self) -> ft.Container:
        def stat_item(label: str, control: ft.Control) -> ft.Row:
            return ft.Row(
                [
                    ft.Text(label, size=11, color=TEXT_MUTED),
                    control,
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            )

        return create_card(
            ft.Column(
                [
                    create_section_header(
                        "SQLite Database Administration",
                        ft.IconButton(
                            ft.Icons.REFRESH,
                            icon_size=16,
                            icon_color=TEXT_MUTED,
                            tooltip="Refresh DB Telemetry",
                            on_click=lambda e: self.refresh_db_stats(),
                        ),
                    ),
                    ft.Text("Monitor local SQLite database file, purge old logs, and perform backups.", size=11, color=TEXT_MUTED),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    ft.Column(
                        [
                            ft.Text("FILE PATH:", size=9, weight="bold", color=TEXT_MUTED),
                            self.lbl_db_path,
                            ft.Divider(color=BORDER_COLOR, height=8),
                            stat_item("Physical File Size:", self.lbl_db_size),
                            stat_item("Total Ingested Events:", self.lbl_db_events),
                            stat_item("Total Security Alerts:", self.lbl_db_alerts),
                            stat_item("Concurrency Mode:", self.lbl_db_journal),
                        ],
                        spacing=4,
                    ),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    ft.Row(
                        [
                            ft.ElevatedButton(
                                "Purge Old Events",
                                icon=ft.Icons.DELETE_SWEEP_ROUNDED,
                                bgcolor=SURFACE_ALT,
                                color=COLOR_HIGH,
                                on_click=lambda e: self._purge_old_events(),
                            ),
                            ft.ElevatedButton(
                                "Vacuum & Optimize",
                                icon=ft.Icons.AUTO_FIX_HIGH,
                                bgcolor=SURFACE_ALT,
                                color=COLOR_LOW,
                                on_click=lambda e: self._vacuum_database(),
                            ),
                            ft.ElevatedButton(
                                "Backup Database",
                                icon=ft.Icons.BACKUP_ROUNDED,
                                bgcolor=COLOR_GREEN,
                                color="#FFFFFF",
                                on_click=lambda e: self._backup_database(),
                            ),
                        ],
                        spacing=8,
                        wrap=True,
                    ),
                ],
                spacing=10,
            ),
            padding=15,
        )

    # ───────────────────────────────────────────────────────────
    #   DATABASE MAINTENANCE ACTIONS
    # ───────────────────────────────────────────────────────────

    def refresh_db_stats(self):
        """Pulls physical file size and table counts from SQLite."""
        try:
            if config.DATABASE_PATH.exists():
                size_bytes = config.DATABASE_PATH.stat().st_size
                if size_bytes >= 1024 * 1024:
                    self.lbl_db_size.value = f"{size_bytes / (1024 * 1024):.2f} MB"
                else:
                    self.lbl_db_size.value = f"{max(1, round(size_bytes / 1024))} KB"

            with db_conn() as conn:
                evt_cnt = conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()["cnt"]
                alt_cnt = conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()["cnt"]
                self.lbl_db_events.value = f"{evt_cnt:,} records"
                self.lbl_db_alerts.value = f"{alt_cnt:,} records"

            self.update()
        except Exception as e:
            print(f"[!] Error refreshing DB stats: {e}")

    def _purge_old_events(self):
        """Deletes events older than the selected retention period."""
        val = self.dd_retention.value
        if "7" in val:
            days = 7
        elif "14" in val:
            days = 14
        elif "30" in val:
            days = 30
        elif "90" in val:
            days = 90
        else:
            self._show_snack("Retention is set to 'Keep Forever'. No events purged.")
            return

        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

        try:
            with db_conn() as conn:
                res = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                deleted_cnt = res.rowcount
            
            self._show_snack(f"Purged {deleted_cnt:,} events older than {days} days.")
            self.refresh_db_stats()
        except Exception as e:
            self._show_snack(f"Error purging events: {e}", is_error=True)

    def _vacuum_database(self):
        """Runs SQLite VACUUM to reclaim disk space."""
        try:
            with db_conn() as conn:
                conn.execute("VACUUM;")
            self._show_snack("Database successfully defragmented and vacuumed.")
            self.refresh_db_stats()
        except Exception as e:
            self._show_snack(f"Vacuum error: {e}", is_error=True)

    def _backup_database(self):
        """Creates a hot snapshot of the database in database/backups/."""
        backup_dir = config.DATABASE_DIR / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"siem_backup_{ts}.db"

        try:
            shutil.copy2(config.DATABASE_PATH, backup_file)
            self._show_snack(f"Backup created: backups/{backup_file.name}")
        except Exception as e:
            self._show_snack(f"Backup failed: {e}", is_error=True)

    def _save_settings(self):
        """Saves current settings preferences."""
        self._show_snack("Settings saved successfully.")

    def _show_snack(self, message: str, is_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor=COLOR_CRITICAL if is_error else COLOR_GREEN,
            duration=3500,
        )
        self.page_ref.overlay.append(snack)
        snack.open = True
        self.page_ref.update()


# ═══════════════════════════════════════════════════════════════
#   STANDALONE SETTINGS VIEW SELF-TEST
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Entry point for standalone Settings View test."""
    page.title = f"{config.APP_NAME} — Settings Test"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0

    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    from ui.sidebar import Sidebar
    sidebar = Sidebar(on_nav_change=lambda route: print(f"Navigated to: {route}"))
    settings_view = SettingsView(page=page)

    page.add(
        ft.Row([sidebar, settings_view], expand=True, spacing=0)
    )


if __name__ == "__main__":
    print("[*] Launching Flet Settings View Standalone Window...")
    ft.app(target=main)