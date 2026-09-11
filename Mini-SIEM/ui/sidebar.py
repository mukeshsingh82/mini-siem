"""
Mini SIEM — Sidebar & Navigation Shell
======================================
Fixed left navigation bar with routing callbacks, live badge alerts count,
and real-time SOC system component diagnostics.
"""

import flet as ft
from datetime import datetime
from typing import Callable, Optional
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_CRITICAL, COLOR_GREEN, app_border, right_border
)
import config


class Sidebar(ft.Container):
    """Left-hand persistent navigation menu with live system health indicators."""
    def __init__(self, on_nav_change: Callable[[str], None]):
        super().__init__()
        self.on_nav_change = on_nav_change
        self.current_route = "dashboard"
        
        self.width = 230
        self.bgcolor = SURFACE_COLOR
        self.border = right_border(1, BORDER_COLOR)
        self.padding = 15

        # Live Alert Counter Badge Ref
        self.alert_badge_ref = ft.Ref[ft.Text]()
        
        # System Health Indicator Status Refs
        self.collector_status_ref = ft.Ref[ft.Text]()
        self.db_status_ref = ft.Ref[ft.Text]()
        self.detection_status_ref = ft.Ref[ft.Text]()
        self.correlation_status_ref = ft.Ref[ft.Text]()

        self.content = self._build_content()

    def _nav_item(self, route: str, icon: str, label: str, badge_val: Optional[str] = None) -> ft.Container:
        """Constructs a clickable sidebar item."""
        is_selected = (self.current_route == route)
        
        row_controls = [
            ft.Icon(icon, size=18, color=TEXT_WHITE if is_selected else TEXT_MUTED),
            ft.Text(
                label,
                size=13,
                color=TEXT_WHITE if is_selected else TEXT_MUTED,
                weight="bold" if is_selected else "normal"
            ),
        ]

        if badge_val is not None:
            row_controls.append(ft.Container(expand=True))
            row_controls.append(
                ft.Container(
                    content=ft.Row(
                        [ft.Text(str(badge_val), size=10, color="#FFFFFF", weight="bold", ref=self.alert_badge_ref)],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    bgcolor=COLOR_CRITICAL,
                    padding=ft.Padding(left=6, right=6, top=1, bottom=1),
                    border_radius=9,
                )
            )

        return ft.Container(
            content=ft.Row(row_controls, spacing=10),
            bgcolor="#1E3A8A" if is_selected else None,
            padding=ft.Padding(left=12, right=12, top=9, bottom=9),
            border_radius=8,
            on_click=lambda e, r=route: self._handle_click(r),
            ink=True,
        )

    def _handle_click(self, route: str):
        self.current_route = route
        self.content = self._build_content()
        self.update()
        if self.on_nav_change:
            self.on_nav_change(route)

    def update_alert_count(self, count: int):
        """Updates the notification pill in the Alerts sidebar item."""
        if self.alert_badge_ref.current:
            self.alert_badge_ref.current.value = str(count)
            self.alert_badge_ref.current.update()

    def _build_content(self) -> ft.Column:
        return ft.Column(
            [
                # App Branding Header
                ft.Row(
                    [
                        ft.Icon(ft.Icons.SHIELD, color=COLOR_LOW, size=28),
                        ft.Row(
                            [
                                ft.Text("Mini ", size=18, weight="bold", color=TEXT_WHITE),
                                ft.Text("SIEM", size=18, weight="bold", color=COLOR_LOW),
                            ],
                            spacing=0,
                        ),
                    ],
                    spacing=8,
                ),
                ft.Text(config.APP_SUBTITLE, color=TEXT_MUTED, size=10),
                ft.Divider(color=BORDER_COLOR, height=20),

                # Navigation Links
                self._nav_item("dashboard", ft.Icons.DASHBOARD_ROUNDED, "Dashboard"),
                self._nav_item("logs", ft.Icons.ARTICLE_ROUNDED, "Logs"),
                self._nav_item("alerts", ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, "Alerts", badge_val="0"),
                self._nav_item("rules", ft.Icons.SECURITY_ROUNDED, "Detection Rules"),
                self._nav_item("sources", ft.Icons.DNS_ROUNDED, "Log Sources"),
                self._nav_item("reports", ft.Icons.BAR_CHART_ROUNDED, "Reports"),
                self._nav_item("settings", ft.Icons.SETTINGS_ROUNDED, "Settings"),
                self._nav_item("about", ft.Icons.INFO_OUTLINE_ROUNDED, "About"),

                ft.Container(expand=True),

                # System Diagnostics Panel
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("SYSTEM STATUS", weight="bold", size=10, color=TEXT_MUTED),
                            ft.Row([
                                ft.Icon(ft.Icons.CIRCLE, color=COLOR_GREEN, size=8),
                                ft.Text("Log Collector", size=11, color=TEXT_MUTED, expand=True),
                                ft.Text("Running", size=11, color=COLOR_GREEN, ref=self.collector_status_ref)
                            ]),
                            ft.Row([
                                ft.Icon(ft.Icons.CIRCLE, color=COLOR_GREEN, size=8),
                                ft.Text("Database", size=11, color=TEXT_MUTED, expand=True),
                                ft.Text("Connected", size=11, color=COLOR_GREEN, ref=self.db_status_ref)
                            ]),
                            ft.Row([
                                ft.Icon(ft.Icons.CIRCLE, color=COLOR_GREEN, size=8),
                                ft.Text("Rule Engine", size=11, color=TEXT_MUTED, expand=True),
                                ft.Text("Active", size=11, color=COLOR_GREEN, ref=self.detection_status_ref)
                            ]),
                            ft.Row([
                                ft.Icon(ft.Icons.CIRCLE, color=COLOR_GREEN, size=8),
                                ft.Text("Correlation", size=11, color=TEXT_MUTED, expand=True),
                                ft.Text("Active", size=11, color=COLOR_GREEN, ref=self.correlation_status_ref)
                            ]),
                            ft.Divider(color=BORDER_COLOR, height=12),
                            ft.Text(f"Target: Linux OS ({config.APP_VERSION})", size=9, color=TEXT_MUTED),
                        ],
                        spacing=5,
                    ),
                    bgcolor="#0F172A",
                    border=app_border(1, BORDER_COLOR),
                    padding=10,
                    border_radius=8,
                ),
            ],
            spacing=3,
        )