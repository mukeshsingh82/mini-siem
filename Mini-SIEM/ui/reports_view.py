"""
Mini SIEM — Security Reports Management View
=============================================
SOC Reporting dashboard allowing analysts to configure, compile,
preview, and download executive security audit reports.
"""

import os
import sys
import subprocess
import flet as ft
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Adjust path to import central configuration and backend
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.report_generator import ReportGenerator
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL, COLOR_PURPLE,
    create_card, create_section_header
)


# ═══════════════════════════════════════════════════════════════
#   REPORTS VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class ReportsView(ft.Container):
    """Reports Management and Generation View."""
    def __init__(self, page: ft.Page):
        super().__init__()
        self.page_ref = page
        self.expand = True
        self.padding = 20

        # Generator Controls
        self.dd_time_range = ft.Dropdown(
            label="Audit Time Range",
            value="7 Days",
            options=[
                ft.dropdown.Option("24 Hours"),
                ft.dropdown.Option("7 Days"),
                ft.dropdown.Option("30 Days"),
                ft.dropdown.Option("All Time"),
            ],
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            width=160,
        )

        self.dd_format = ft.Dropdown(
            label="Report Format",
            value="HTML (Executive)",
            options=[
                ft.dropdown.Option("HTML (Executive)"),
                ft.dropdown.Option("JSON (Structured Data)"),
                ft.dropdown.Option("CSV (Alerts & Metrics)"),
            ],
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            width=200,
        )

        # Archive Table List View
        self.archive_table_list = ft.ListView(expand=True, spacing=6)

        # File Preview Dialog
        self.preview_modal = self._build_preview_modal()

        self.content = self._build_layout()

    # ───────────────────────────────────────────────────────────
    #   LAYOUT CONSTRUCTION
    # ───────────────────────────────────────────────────────────

    def _build_layout() -> ft.Column:
        pass

    def _build_layout(self) -> ft.Column:
        return ft.Column(
            [
                self._build_header(),
                self._build_generator_card(),
                self._build_archive_card(),
            ],
            expand=True,
            spacing=15,
        )

    def _build_header(self) -> ft.Row:
        return ft.Row(
            [
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.BAR_CHART_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("Security Reports & Auditing", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Generate executive summaries, threat assessments, and compliance reports", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

    def _build_generator_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("Generate New Security Report"),
                    ft.Text(
                        "Compiles real-time log event telemetry, active detection rule triggers, and multi-stage "
                        "attack correlations into an executive-ready audit document.",
                        size=11,
                        color=TEXT_MUTED,
                    ),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    ft.Row(
                        [
                            self.dd_time_range,
                            self.dd_format,
                            ft.ElevatedButton(
                                "Generate Security Report",
                                icon=ft.Icons.AUTO_FIX_HIGH,
                                bgcolor=COLOR_LOW,
                                color="#FFFFFF",
                                style=ft.ButtonStyle(padding=ft.Padding(16, 12, 16, 12)),
                                on_click=lambda e: self._generate_report_action(),
                            ),
                        ],
                        spacing=12,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                ],
                spacing=12,
            ),
            padding=15,
        )

    def _build_archive_card(self) -> ft.Container:
        header_row = ft.Container(
            content=ft.Row(
                [
                    ft.Text("Report Document", color=TEXT_MUTED, size=11, weight="bold", expand=True),
                    ft.Text("Format", color=TEXT_MUTED, size=11, weight="bold", width=90),
                    ft.Text("File Size", color=TEXT_MUTED, size=11, weight="bold", width=90),
                    ft.Text("Generated Date", color=TEXT_MUTED, size=11, weight="bold", width=160),
                    ft.Text("Actions", color=TEXT_MUTED, size=11, weight="bold", width=100, text_align="center"),
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
                    create_section_header(
                        "Generated Reports Archive",
                        ft.IconButton(
                            ft.Icons.REFRESH,
                            icon_color=TEXT_MUTED,
                            tooltip="Refresh Archive",
                            on_click=lambda e: self.refresh_archive_list(),
                        ),
                    ),
                    header_row,
                    ft.Divider(color=BORDER_COLOR, height=1),
                    self.archive_table_list,
                ],
                spacing=6,
                expand=True,
            ),
            expand=True,
            padding=10,
        )

    # ───────────────────────────────────────────────────────────
    #   ARCHIVE ROW RENDERING
    # ───────────────────────────────────────────────────────────

    def _render_archive_row(self, file_path: Path) -> ft.Container:
        filename = file_path.name
        ext = file_path.suffix.lower()
        size_kb = max(1, round(file_path.stat().st_size / 1024))
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        # Color & icon per format
        if ext == ".html":
            icon = ft.Icons.HTML
            color = COLOR_LOW
            fmt_label = "HTML"
        elif ext == ".json":
            icon = ft.Icons.DATA_OBJECT
            color = COLOR_PURPLE
            fmt_label = "JSON"
        else:
            icon = ft.Icons.TABLE_CHART
            color = COLOR_GREEN
            fmt_label = "CSV"

        return ft.Container(
            content=ft.Row(
                [
                    ft.Row(
                        [
                            ft.Icon(icon, color=color, size=18),
                            ft.Text(filename, weight="bold", color=TEXT_WHITE, size=12, no_wrap=True),
                        ],
                        spacing=8,
                        expand=True,
                    ),
                    ft.Container(
                        content=ft.Text(fmt_label, size=10, weight="bold", color="#FFFFFF"),
                        bgcolor=color,
                        padding=ft.Padding(6, 2, 6, 2),
                        border_radius=4,
                        width=70,
                        alignment=ft.Alignment(0.5, 0.5),
                    ),
                    ft.Text(f"{size_kb} KB", size=11, color=TEXT_MUTED, width=90),
                    ft.Text(mtime, size=11, color=TEXT_MUTED, width=160),
                    ft.Row(
                        [
                            ft.IconButton(
                                ft.Icons.OPEN_IN_NEW,
                                icon_size=15,
                                icon_color=COLOR_LOW,
                                tooltip="Open / View Report",
                                on_click=lambda e, p=file_path: self._open_file(p),
                            ),
                            ft.IconButton(
                                ft.Icons.DELETE_OUTLINE,
                                icon_size=15,
                                icon_color=COLOR_CRITICAL,
                                tooltip="Delete Report",
                                on_click=lambda e, p=file_path: self._delete_file(p),
                            ),
                        ],
                        spacing=0,
                        width=90,
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
    #   REPORT ACTIONS
    # ───────────────────────────────────────────────────────────

    def _generate_report_action(self):
        time_choice = self.dd_time_range.value
        if "24 Hours" in time_choice:
            days = 1
        elif "7 Days" in time_choice:
            days = 7
        elif "30 Days" in time_choice:
            days = 30
        else:
            days = 365

        fmt_choice = self.dd_format.value
        gen = ReportGenerator(time_range_days=days)

        try:
            if "HTML" in fmt_choice:
                p = gen.generate_html_report()
            elif "JSON" in fmt_choice:
                p = gen.generate_json_report()
            else:
                p = gen.generate_csv_report()

            self._show_snack(f"Generated report: {p.name}")
            self.refresh_archive_list()
        except Exception as e:
            self._show_snack(f"Report generation error: {e}", is_error=True)

    def _open_file(self, path: Path):
        """Attempts to open report using standard Linux system default or preview modal."""
        if path.suffix.lower() == ".html":
            try:
                # Open with system web browser (e.g. xdg-open on Linux)
                if sys.platform.startswith("linux"):
                    subprocess.Popen(["xdg-open", str(path)])
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", str(path)])
                elif sys.platform == "win32":
                    os.startfile(str(path))
                self._show_snack(f"Opened {path.name} in browser.")
                return
            except Exception:
                pass

        # Fallback modal viewer for text/JSON/CSV
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(5000)  # load up to 5k chars for preview

            self.preview_text.value = content
            self.preview_title.value = f"Preview — {path.name}"
            self.page_ref.dialog = self.preview_modal
            self.preview_modal.open = True
            self.page_ref.update()
        except Exception as e:
            self._show_snack(f"Failed to read file: {e}", is_error=True)

    def _delete_file(self, path: Path):
        try:
            if path.exists():
                path.unlink()
                self._show_snack(f"Deleted {path.name}.")
                self.refresh_archive_list()
        except Exception as e:
            self._show_snack(f"Failed to delete file: {e}", is_error=True)

    def refresh_archive_list(self):
        """Scans reports/ directory and populates archive table."""
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        files = list(config.REPORTS_DIR.glob("security_report_*.*"))
        # Sort by most recently modified
        files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

        if not files:
            self.archive_table_list.controls = [
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Icon(ft.Icons.DESCRIPTION_OUTLINED, size=36, color=TEXT_MUTED),
                            ft.Text("No generated security reports in archive. Generate one above.", color=TEXT_MUTED, size=13),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=6,
                    ),
                    padding=40,
                    alignment=ft.Alignment(0.5, 0.5),
                )
            ]
        else:
            self.archive_table_list.controls = [self._render_archive_row(f) for f in files]

        self.update()

    # ───────────────────────────────────────────────────────────
    #   PREVIEW MODAL
    # ───────────────────────────────────────────────────────────

    def _build_preview_modal(self) -> ft.AlertDialog:
        self.preview_title = ft.Text("Report Preview", size=16, weight="bold", color=TEXT_WHITE)
        self.preview_text = ft.Text("", size=11, font_family="monospace", color="#A7F3D0", selectable=True)

        return ft.AlertDialog(
            modal=True,
            title=self.preview_title,
            content=ft.Container(
                content=ft.Column([self.preview_text], scroll=ft.ScrollMode.AUTO),
                width=650,
                height=450,
                bgcolor="#0F172A",
                padding=10,
                border_radius=6,
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self._close_modal(self.preview_modal)),
            ],
            bgcolor=SURFACE_COLOR,
        )

    # ───────────────────────────────────────────────────────────
    #   HELPERS
    # ───────────────────────────────────────────────────────────

    def _close_modal(self, modal: ft.AlertDialog):
        modal.open = False
        self.page_ref.update()

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
#   STANDALONE REPORTS VIEW SELF-TEST
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Entry point for standalone Reports View test."""
    page.title = f"{config.APP_NAME} — Reports Management Test"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0

    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    from ui.sidebar import Sidebar
    sidebar = Sidebar(on_nav_change=lambda route: print(f"Navigated to: {route}"))
    reports_view = ReportsView(page=page)

    page.add(
        ft.Row([sidebar, reports_view], expand=True, spacing=0)
    )


if __name__ == "__main__":
    print("[*] Launching Flet Reports View Standalone Window...")
    ft.app(target=main)