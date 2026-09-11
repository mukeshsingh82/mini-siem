"""
Mini SIEM — About & Security Architecture View
==============================================
Presents platform architecture, processing pipeline diagrams, technology stack,
threat detection matrix, and cybersecurity defensive guidelines.
"""

import sys
import flet as ft
from pathlib import Path

# Adjust path to import central configuration and theme
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL, COLOR_PURPLE,
    create_card, create_section_header, app_border
)


# ═══════════════════════════════════════════════════════════════
#   ABOUT VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class AboutView(ft.Container):
    """About & Platform Architecture View."""
    def __init__(self, page: ft.Page):
        super().__init__()
        self.page_ref = page
        self.expand = True
        self.padding = 20
        self.content = self._build_layout()

    def _build_layout(self) -> ft.Column:
        return ft.Column(
            [
                self._build_hero_banner(),
                self._build_architecture_card(),
                ft.Row(
                    [
                        ft.Column([self._build_capabilities_card(), self._build_disclaimer_card()], spacing=15, expand=1),
                        ft.Column([self._build_tech_stack_card(), self._build_developer_card()], spacing=15, expand=1),
                    ],
                    spacing=15,
                ),
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=15,
        )

    # ───────────────────────────────────────────────────────────
    #   HERO BANNER
    # ───────────────────────────────────────────────────────────

    def _build_hero_banner(self) -> ft.Container:
        return create_card(
            ft.Row(
                [
                    ft.Container(
                        content=ft.Icon(ft.Icons.SHIELD, size=42, color=COLOR_LOW),
                        bgcolor="#0F172A",
                        border=app_border(1, BORDER_COLOR),
                        border_radius=12,
                        padding=15,
                    ),
                    ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Text(config.APP_NAME, size=24, weight="bold", color=TEXT_WHITE),
                                    ft.Container(
                                        content=ft.Text(f"v{config.APP_VERSION}", size=11, weight="bold", color="#FFFFFF"),
                                        bgcolor=COLOR_LOW,
                                        padding=ft.Padding(8, 2, 8, 2),
                                        border_radius=4,
                                    ),
                                    ft.Container(
                                        content=ft.Text("Target: Linux OS", size=11, weight="bold", color=COLOR_GREEN),
                                        bgcolor="#064E3B",
                                        padding=ft.Padding(8, 2, 8, 2),
                                        border_radius=4,
                                    ),
                                ],
                                spacing=10,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Text(config.APP_SUBTITLE, size=13, color=COLOR_PURPLE, weight="bold"),
                            ft.Text(
                                "A fully functional, lightweight Security Information and Event Management (SIEM) "
                                "desktop application engineered for Linux host and service log monitoring.",
                                size=12,
                                color=TEXT_MUTED,
                            ),
                        ],
                        spacing=4,
                        expand=True,
                    ),
                ],
                spacing=20,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=20,
        )

    # ───────────────────────────────────────────────────────────
    #   SYSTEM ARCHITECTURE FLOW
    # ───────────────────────────────────────────────────────────

    def _build_architecture_card(self) -> ft.Container:
        steps = [
            ("1. Linux Log Feeds", "/var/log/auth.log\nsyslog, apache, nginx", ft.Icons.DNS),
            ("2. Log Collector", "Watchdog real-time tailer\nRotation & inode recovery", ft.Icons.FILE_DOWNLOAD),
            ("3. Log Parser", "Regex deconstruction\nRFC 3164 / ISO 8601", ft.Icons.TRANSFORM),
            ("4. Event Normalizer", "Standard data schema\nSanitization & severity", ft.Icons.CLEANING_SERVICES),
            ("5. SQLite Database", "WAL concurrent mode\nOptimized indexing", ft.Icons.STORAGE),
            ("6. Detection Engine", "Sliding time-windows\nThreshold calculations", ft.Icons.BOLT),
            ("7. Correlation Engine", "Multi-stage attack chains\nIncident stitching", ft.Icons.DEVICE_HUB),
            ("8. Alert Manager", "Burst deduplication\nTriage lifecycle states", ft.Icons.NOTIFICATIONS_ACTIVE),
            ("9. Flet SOC Dashboard", "Live Canvas telemetry\nForensic investigation", ft.Icons.DASHBOARD),
        ]

        step_boxes = []
        for idx, (title, sub, icon) in enumerate(steps):
            box = ft.Container(
                content=ft.Column(
                    [
                        ft.Row([ft.Icon(icon, size=16, color=COLOR_LOW), ft.Text(title, size=11, weight="bold", color=TEXT_WHITE)], spacing=6),
                        ft.Text(sub, size=9, color=TEXT_MUTED),
                    ],
                    spacing=3,
                ),
                bgcolor=SURFACE_ALT,
                border=app_border(1, BORDER_COLOR),
                border_radius=6,
                padding=10,
                expand=1,
            )
            step_boxes.append(box)

        # Split into two visual rows
        row1 = ft.Row(step_boxes[:5], spacing=8)
        row2 = ft.Row(step_boxes[5:], spacing=8)

        return create_card(
            ft.Column(
                [
                    create_section_header("End-to-End Processing Architecture"),
                    ft.Text("Autonomous event processing pipeline operating asynchronously in background threads:", size=11, color=TEXT_MUTED),
                    row1,
                    ft.Row([ft.Icon(ft.Icons.ARROW_DOWNWARD, color=COLOR_LOW, size=16)], alignment=ft.MainAxisAlignment.CENTER),
                    row2,
                ],
                spacing=10,
            ),
            padding=15,
        )

    # ───────────────────────────────────────────────────────────
    #   THREAT CAPABILITIES MATRIX
    # ───────────────────────────────────────────────────────────

    def _build_capabilities_card(self) -> ft.Container:
        capabilities = [
            ("SSH Brute Force", "Detects rapid authentication failures within rolling 60-120s sliding windows.", COLOR_HIGH),
            ("Account Compromise", "Correlates brute force failures followed immediately by successful login.", COLOR_CRITICAL),
            ("Privilege Escalation", "Detects unauthorized sudo to root and PAM security failures.", COLOR_HIGH),
            ("Direct Root Logins", "Immediate detection of direct root logins via SSH or console.", COLOR_HIGH),
            ("Web Application Probing", "Identifies SQL Injection, XSS, Path Traversal, and directory scans.", COLOR_HIGH),
            ("Port Scan Reconnaissance", "Detects horizontal port scans hitting multiple destination ports.", COLOR_LOW),
        ]

        rows = []
        for title, desc, color in capabilities:
            rows.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.SHIELD_OUTLINED, color=color, size=16),
                            ft.Column(
                                [
                                    ft.Text(title, size=12, weight="bold", color=TEXT_WHITE),
                                    ft.Text(desc, size=10, color=TEXT_MUTED),
                                ],
                                spacing=1,
                                expand=True,
                            ),
                        ],
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    bgcolor=SURFACE_ALT,
                    padding=8,
                    border_radius=6,
                )
            )

        return create_card(
            ft.Column(
                [
                    create_section_header("Threat Detection Matrix"),
                    ft.Column(rows, spacing=6),
                ],
                spacing=10,
            ),
            padding=15,
        )

    # ───────────────────────────────────────────────────────────
    #   TECHNOLOGY STACK
    # ───────────────────────────────────────────────────────────

    def _build_tech_stack_card(self) -> ft.Container:
        tech_items = [
            ("Core Runtime", "Python 3.10+ (Standard Library Centric)", ft.Icons.TERMINAL),
            ("User Interface", "Flet GUI (Flutter Engine Desktop Client)", ft.Icons.DESKTOP_MAC),
            ("Database Layer", "SQLite 3 with Write-Ahead Logging (WAL Mode)", ft.Icons.STORAGE),
            ("File Monitoring", "Watchdog FileSystemObserver (Hybrid Inode Poll)", ft.Icons.FIND_IN_PAGE),
            ("Parser Engine", "POSIX Regular Expressions (RFC 3164/5424/NCSA)", ft.Icons.CODE),
            ("Rule Engine", "In-Memory Sliding Deque Buffers with JSON Rules", ft.Icons.SETTINGS_SUGGEST),
        ]

        rows = []
        for name, detail, icon in tech_items:
            rows.append(
                ft.Row(
                    [
                        ft.Row([ft.Icon(icon, size=16, color=COLOR_LOW), ft.Text(name, size=11, weight="bold", color=TEXT_WHITE)], spacing=8),
                        ft.Text(detail, size=11, color=TEXT_MUTED),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                )
            )

        return create_card(
            ft.Column(
                [
                    create_section_header("Technology Stack & Specifications"),
                    ft.Column(rows, spacing=8),
                ],
                spacing=10,
            ),
            padding=15,
        )

    # ───────────────────────────────────────────────────────────
    #   DEFENSIVE DISCLAIMER
    # ───────────────────────────────────────────────────────────

    def _build_disclaimer_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    ft.Row([
                        ft.Icon(ft.Icons.GAVEL_ROUNDED, color=COLOR_HIGH, size=18),
                        ft.Text("Defensive Cybersecurity Principles", size=14, weight="bold", color=TEXT_WHITE)
                    ], spacing=8),
                    ft.Text(
                        "Mini SIEM is a defensive cybersecurity monitoring and telemetry platform. "
                        "All incoming log data is treated as untrusted input. The application never executes "
                        "shell commands sourced from log content, does not store user passwords, and does not "
                        "alter Linux operating system security controls.",
                        size=11,
                        color=TEXT_MUTED,
                    ),
                    ft.Container(
                        content=ft.Text(
                            "⚠️ For authorized monitoring and educational demonstration purposes only.",
                            size=10,
                            color=COLOR_HIGH,
                            weight="bold",
                        ),
                        bgcolor="#0F172A",
                        padding=8,
                        border_radius=4,
                    ),
                ],
                spacing=8,
            ),
            padding=15,
        )

    # ───────────────────────────────────────────────────────────
    #   DEVELOPER CREDITS
    # ───────────────────────────────────────────────────────────

    def _build_developer_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("Platform & Project Information"),
                    ft.Text("Developed as an open-source cybersecurity portfolio project.", size=11, color=TEXT_MUTED),
                    ft.Divider(color=BORDER_COLOR, height=1),
                    ft.Row([
                        ft.Text("License:", size=11, color=TEXT_MUTED),
                        ft.Text("MIT Open Source License", size=11, weight="bold", color=TEXT_WHITE),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Row([
                        ft.Text("Platform Architecture:", size=11, color=TEXT_MUTED),
                        ft.Text("Modular Micro-Engine Architecture", size=11, weight="bold", color=COLOR_LOW),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Row([
                        ft.Text("Repository:", size=11, color=TEXT_MUTED),
                        ft.Text("GitHub / Mini-SIEM", size=11, weight="bold", color=COLOR_PURPLE),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ],
                spacing=8,
            ),
            padding=15,
        )


# ═══════════════════════════════════════════════════════════════
#   STANDALONE ABOUT VIEW SELF-TEST
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Entry point for standalone About View test."""
    page.title = f"{config.APP_NAME} — About & Architecture Test"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0

    from ui.sidebar import Sidebar
    sidebar = Sidebar(on_nav_change=lambda route: print(f"Navigated to: {route}"))
    about_view = AboutView(page=page)

    page.add(
        ft.Row([sidebar, about_view], expand=True, spacing=0)
    )


if __name__ == "__main__":
    print("[*] Launching Flet About View Standalone Window...")
    ft.app(target=main)