"""
Mini SIEM — SOC Dashboard View
===============================
High-density SOC Command Center view with live SQLite metrics,
interactive Canvas charts, real-time alert streaming, and quick actions.
"""

import math
import sys
import flet as ft
import flet.canvas as cv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

# Adjust path to import central configuration and backend
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.alert_manager import AlertManager
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_GREEN, COLOR_PURPLE,
    create_card, create_severity_badge, create_section_header, get_severity_color, app_border
)


class DashboardView(ft.Container):
    """Primary SOC Command Center view."""
    def __init__(self, alert_manager: AlertManager, on_navigate: Optional[Callable[[str], None]] = None):
        super().__init__()
        self.alert_manager = alert_manager
        self.on_navigate = on_navigate
        self.expand = True
        self.padding = 20

        # UI Element References for live metric updating
        self.ref_total_events   = ft.Ref[ft.Text]()
        self.ref_critical       = ft.Ref[ft.Text]()
        self.ref_high           = ft.Ref[ft.Text]()
        self.ref_sources        = ft.Ref[ft.Text]()
        self.ref_epm            = ft.Ref[ft.Text]()

        self.line_chart_holder  = ft.Ref[ft.Container]()
        self.donut_chart_holder = ft.Ref[ft.Container]()
        self.donut_legend_holder= ft.Ref[ft.Column]()
        self.top_ips_holder     = ft.Ref[ft.Column]()
        self.top_rules_holder   = ft.Ref[ft.Column]()
        self.system_time_ref    = ft.Ref[ft.Text]()

        # Real-time Incident Stream List
        self.stream_list = ft.ListView(expand=True, spacing=6, auto_scroll=True)

        # Selected Time Range for Events Over Time
        self.selected_hours = 24

        self.content = self._build_layout()

    def _build_layout(self) -> ft.Column:
        return ft.Column(
            [
                self._build_header(),
                ft.Container(height=4),
                self._build_kpi_cards(),
                ft.Row([self._build_line_chart_card(), self._build_donut_chart_card()], spacing=15),
                ft.Row(
                    [
                        self._build_incident_stream_card(),
                        ft.Column([self._build_top_ips_card(), self._build_top_rules_card()], spacing=15, expand=1),
                    ],
                    spacing=15,
                ),
                self._build_quick_actions_card(),
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
                                ft.Icon(ft.Icons.DASHBOARD_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("SOC Dashboard", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Live environment telemetry and threat detections", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
                ft.Row(
                    [
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.ACCESS_TIME_ROUNDED, size=14, color=COLOR_LOW),
                                    ft.Text("System Time: --:--:--", size=11, color=TEXT_MUTED, ref=self.system_time_ref),
                                ],
                                spacing=6,
                            ),
                            bgcolor=SURFACE_ALT,
                            padding=ft.Padding(10, 6, 10, 6),
                            border_radius=6,
                            border=app_border(1, BORDER_COLOR),
                        ),
                        ft.ElevatedButton(
                            "Refresh Data",
                            icon=ft.Icons.REFRESH,
                            bgcolor=SURFACE_ALT,
                            color=TEXT_WHITE,
                            on_click=lambda e: self.refresh_data(),
                        ),
                    ],
                    spacing=10,
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

    def _create_kpi_card(self, title: str, ref_obj: ft.Ref[ft.Text], icon: str, color: str) -> ft.Container:
        return ft.Container(
            content=ft.Row(
                [
                    ft.Container(
                        content=ft.Row([ft.Icon(icon, color="#FFFFFF", size=22)], alignment=ft.MainAxisAlignment.CENTER),
                        bgcolor=color,
                        width=46,
                        height=46,
                        border_radius=8,
                    ),
                    ft.Column(
                        [
                            ft.Text(title, color=TEXT_MUTED, size=11, weight="bold"),
                            ft.Text("0", size=20, weight="bold", ref=ref_obj, color=TEXT_WHITE),
                        ],
                        spacing=2,
                    ),
                ],
                spacing=12,
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
                self._create_kpi_card("Total Events", self.ref_total_events, ft.Icons.ARTICLE, COLOR_LOW),
                self._create_kpi_card("Critical Alerts", self.ref_critical, ft.Icons.DANGEROUS, COLOR_CRITICAL),
                self._create_kpi_card("High Alerts", self.ref_high, ft.Icons.WARNING_AMBER, COLOR_HIGH),
                self._create_kpi_card("Active Sources", self.ref_sources, ft.Icons.DNS, COLOR_GREEN),
                self._create_kpi_card("Events / Min", self.ref_epm, ft.Icons.SPEED, COLOR_PURPLE),
            ],
            spacing=15,
        )

    def _render_line_chart_canvas(self, data: List[int]) -> cv.Canvas:
        w, h = 600, 180
        if not data or max(data) == 0:
            shapes = [cv.Line(0, y, w, y, paint=ft.Paint(color=SURFACE_ALT, stroke_width=1)) for y in [45, 90, 135, 180]]
            return cv.Canvas(shapes, width=w, height=h)

        max_val = max(data) if max(data) > 0 else 1
        n = len(data)

        def x_at(i):
            return (i / (n - 1)) * w if n > 1 else w / 2

        def y_at(v):
            return h - (v / max_val) * (h - 25) - 10

        shapes = []
        for step in range(5):
            gy = h - (step / 4) * h
            shapes.append(cv.Line(0, gy, w, gy, paint=ft.Paint(color=SURFACE_ALT, stroke_width=1)))

        if n > 1:
            area_elements = [cv.Path.MoveTo(x_at(0), h)]
            for i in range(n):
                area_elements.append(cv.Path.LineTo(x_at(i), y_at(data[i])))
            area_elements.append(cv.Path.LineTo(x_at(n - 1), h))
            area_elements.append(cv.Path.Close())
            shapes.append(cv.Path(area_elements, paint=ft.Paint(style=ft.PaintingStyle.FILL, color="#1E3A5F")))

            line_elements = [cv.Path.MoveTo(x_at(0), y_at(data[0]))]
            for i in range(1, n):
                line_elements.append(cv.Path.LineTo(x_at(i), y_at(data[i])))
            shapes.append(cv.Path(
                line_elements,
                paint=ft.Paint(style=ft.PaintingStyle.STROKE, stroke_width=2.5, color=COLOR_LOW)
            ))

        for i in range(n):
            shapes.append(cv.Circle(x_at(i), y_at(data[i]), 3, paint=ft.Paint(style=ft.PaintingStyle.FILL, color=COLOR_LOW)))

        return cv.Canvas(shapes, width=w, height=h)

    def _on_time_range_change(self, e):
        val = e.control.value
        if "1 Hour" in val:
            self.selected_hours = 1
        elif "6 Hours" in val:
            self.selected_hours = 6
        elif "7 Days" in val:
            self.selected_hours = 168
        else:
            self.selected_hours = 24
        self.refresh_data()

    def _build_line_chart_card(self) -> ft.Container:
        dropdown = ft.Dropdown(
            value="Last 24 Hours",
            options=[
                ft.dropdown.Option("Last 1 Hour"),
                ft.dropdown.Option("Last 6 Hours"),
                ft.dropdown.Option("Last 24 Hours"),
                ft.dropdown.Option("Last 7 Days"),
            ],
            width=140,
            height=34,
            text_size=11,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
        )
        dropdown.on_change = self._on_time_range_change

        labels_row = ft.Row(
            [ft.Text(t, size=10, color=TEXT_MUTED) for t in ["-24h", "-20h", "-16h", "-12h", "-8h", "-4h", "Now"]],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

        return create_card(
            ft.Column(
                [
                    create_section_header("Events Over Time", dropdown),
                    ft.Container(content=self._render_line_chart_canvas([0]*12), ref=self.line_chart_holder),
                    labels_row,
                ],
                spacing=8,
            ),
            expand=2,
            height=280,
        )

    def _render_donut_chart_canvas(self, counts: Dict[str, int]) -> cv.Canvas:
        total = sum(counts.values())
        if total <= 0:
            total = 1

        cx, cy, r = 75, 75, 55
        stroke_w = 22
        shapes = []
        start_angle = -math.pi / 2
        gap = 0.04

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for sev in order:
            val = counts.get(sev, 0)
            if val <= 0:
                continue
            sweep = (val / total) * 2 * math.pi
            shapes.append(cv.Arc(
                cx - r, cy - r, cx + r, cy + r,
                start_angle + gap / 2, max(sweep - gap, 0.02),
                False,
                paint=ft.Paint(style=ft.PaintingStyle.STROKE, stroke_width=stroke_w, color=get_severity_color(sev))
            ))
            start_angle += sweep

        return cv.Canvas(shapes, width=150, height=150)

    def _build_donut_legend(self, counts: Dict[str, int]) -> ft.Column:
        total = sum(counts.values()) or 1
        order = [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]
        rows = []
        for key, label in order:
            val = counts.get(key, 0)
            pct = round((val / total) * 100) if total > 0 else 0
            rows.append(
                ft.Row(
                    [
                        ft.Row([
                            ft.Icon(ft.Icons.CIRCLE, color=get_severity_color(key), size=9),
                            ft.Text(label, size=11, color=TEXT_WHITE)
                        ], spacing=6),
                        ft.Text(f"{val} ({pct}%)", size=11, color=TEXT_MUTED),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                )
            )
        return ft.Column(rows, spacing=4)

    def _build_donut_chart_card(self) -> ft.Container:
        initial_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        return create_card(
            ft.Column(
                [
                    create_section_header("Alerts by Severity"),
                    ft.Row(
                        [
                            ft.Container(
                                content=self._render_donut_chart_canvas(initial_counts),
                                ref=self.donut_chart_holder,
                                width=150,
                                height=150,
                            ),
                            ft.Container(
                                content=self._build_donut_legend(initial_counts),
                                ref=self.donut_legend_holder,
                                expand=True,
                                padding=ft.Padding(left=10, right=0, top=0, bottom=0),
                            ),
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                ],
                spacing=10,
            ),
            expand=1,
            height=280,
        )

    def _build_incident_stream_card(self) -> ft.Container:
        header_row = ft.Row(
            [
                ft.Text("Time", color=TEXT_MUTED, size=11, width=65),
                ft.Text("Severity", color=TEXT_MUTED, size=11, width=75),
                ft.Text("Rule / Event", color=TEXT_MUTED, size=11, width=190),
                ft.Text("Source IP", color=TEXT_MUTED, size=11, width=110),
                ft.Text("Details", color=TEXT_MUTED, size=11, expand=True),
            ]
        )

        return create_card(
            ft.Column(
                [
                    create_section_header(
                        "Real-Time Incident Stream",
                        ft.TextButton(
                            "View All Alerts",
                            icon=ft.Icons.OPEN_IN_NEW,
                            style=ft.ButtonStyle(color=COLOR_LOW),
                            on_click=lambda e: self._nav_to("alerts"),
                        ),
                    ),
                    header_row,
                    ft.Divider(color=BORDER_COLOR, height=1),
                    self.stream_list,
                ],
                spacing=6,
            ),
            expand=2,
            height=320,
        )

    def _render_alert_stream_row(self, alert: Dict[str, Any]) -> ft.Container:
        ts = str(alert.get("timestamp", ""))[-8:]
        sev = alert.get("severity", "LOW")
        title = alert.get("title", "Security Alert")
        src_ip = alert.get("source_ip") or "Local / Host"
        desc = alert.get("description", "")

        return ft.Container(
            content=ft.Row(
                [
                    ft.Text(ts, color=TEXT_MUTED, width=65, size=11),
                    create_severity_badge(sev, width=75),
                    ft.Text(title, weight="bold", width=190, size=12, color=TEXT_WHITE, no_wrap=True),
                    ft.Text(src_ip, color=COLOR_LOW, width=110, size=11, no_wrap=True),
                    ft.Text(desc, color=TEXT_MUTED, expand=True, size=11, no_wrap=True),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=SURFACE_ALT,
            padding=ft.Padding(left=8, right=8, top=6, bottom=6),
            border_radius=4,
        )

    def _render_bar_list(self, data_dict: Dict[str, int], label_key: str, color: str) -> ft.Column:
        if not data_dict:
            return ft.Column([ft.Text("No telemetry recorded.", color=TEXT_MUTED, size=11)], spacing=4)

        items = list(data_dict.items())[:5]
        max_v = max((v for _, v in items), default=1)
        rows = []

        for label, val in items:
            frac = val / max_v if max_v else 0
            left_expand = max(int(frac * 100), 1)
            right_expand = max(int((1 - frac) * 100), 1)

            rows.append(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(str(label), size=12, color=COLOR_LOW if label_key == "ip" else TEXT_WHITE, expand=2, no_wrap=True),
                                ft.Text(f"{val:,}", size=12, color=TEXT_MUTED, weight="bold"),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.Container(bgcolor=color, height=4, border_radius=2, expand=left_expand),
                                    ft.Container(expand=right_expand),
                                ],
                                spacing=0,
                            ),
                        ),
                    ],
                    spacing=2,
                )
            )
        return ft.Column(rows, spacing=8)

    def _build_top_ips_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("Top Source IPs"),
                    ft.Container(content=self._render_bar_list({}, "ip", COLOR_CRITICAL), ref=self.top_ips_holder),
                ],
                spacing=8,
            ),
            expand=1,
        )

    def _build_top_rules_card(self) -> ft.Container:
        return create_card(
            ft.Column(
                [
                    create_section_header("Top Alerting Rules"),
                    ft.Container(content=self._render_bar_list({}, "rule", COLOR_HIGH), ref=self.top_rules_holder),
                ],
                spacing=8,
            ),
            expand=1,
        )

    def _build_quick_actions_card(self) -> ft.Container:
        def action_item(label: str, icon: str, color: str, route: str) -> ft.Container:
            return ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(icon, color=color, size=18),
                        ft.Text(label, size=12, weight="bold", color=TEXT_WHITE),
                    ],
                    spacing=8,
                ),
                bgcolor=SURFACE_ALT,
                border=app_border(1, BORDER_COLOR),
                border_radius=6,
                padding=ft.Padding(12, 10, 12, 10),
                on_click=lambda e, r=route: self._nav_to(r),
                ink=True,
                expand=1,
            )

        return create_card(
            ft.Column(
                [
                    create_section_header("SOC Analyst Quick Actions"),
                    ft.Row(
                        [
                            action_item("Add Log Source", ft.Icons.ADD_LINK_ROUNDED, COLOR_LOW, "sources"),
                            action_item("Create Detection Rule", ft.Icons.SECURITY_ROUNDED, COLOR_GREEN, "rules"),
                            action_item("Generate Security Report", ft.Icons.AUTO_FIX_HIGH, COLOR_PURPLE, "reports"),
                            action_item("Investigate Alerts", ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, COLOR_HIGH, "alerts"),
                        ],
                        spacing=12,
                    ),
                ],
                spacing=10,
            ),
            padding=15,
        )

    def _nav_to(self, route: str):
        if self.on_navigate:
            self.on_navigate(route)

    def update_system_time(self):
        if self.system_time_ref.current:
            self.system_time_ref.current.value = f"System Time: {datetime.now().strftime('%H:%M:%S')}"
            try:
                self.system_time_ref.current.update()
            except Exception:
                pass

    def refresh_data(self):
        """Pulls latest metrics from AlertManager & SQLite, updating all dashboard widgets."""
        metrics = self.alert_manager.get_soc_metrics()

        # 1. Update Top KPI Cards
        if self.ref_total_events.current:
            self.ref_total_events.current.value = f"{metrics['total_events']:,}"
        if self.ref_critical.current:
            self.ref_critical.current.value = str(metrics['critical_alerts'])
        if self.ref_high.current:
            self.ref_high.current.value = str(metrics['high_alerts'])
        if self.ref_sources.current:
            self.ref_sources.current.value = str(metrics['active_sources_count'])
        if self.ref_epm.current:
            self.ref_epm.current.value = str(metrics['events_per_minute'])

        # 2. Update Events Over Time Line Chart
        events_timeline = self.alert_manager.get_events_over_time(hours=self.selected_hours)
        if self.line_chart_holder.current:
            self.line_chart_holder.current.content = self._render_line_chart_canvas(events_timeline)

        # 3. Update Severity Donut Chart & Legend
        if self.donut_chart_holder.current:
            self.donut_chart_holder.current.content = self._render_donut_chart_canvas(metrics['severity_distribution'])
        if self.donut_legend_holder.current:
            self.donut_legend_holder.current.content = self._build_donut_legend(metrics['severity_distribution'])

        # 4. Update Top IPs & Rules
        if self.top_ips_holder.current:
            self.top_ips_holder.current.content = self._render_bar_list(metrics['top_source_ips'], "ip", COLOR_CRITICAL)
        if self.top_rules_holder.current:
            self.top_rules_holder.current.content = self._render_bar_list(metrics['top_rules'], "rule", COLOR_HIGH)

        # 5. Populate Incident Stream with latest alerts
        recent_alerts = self.alert_manager.get_alerts(limit=50)
        self.stream_list.controls = [self._render_alert_stream_row(a) for a in recent_alerts]

        try:
            self.update()
        except Exception:
            pass

    def handle_incoming_live_alert(self, alert: Dict[str, Any]):
        """Real-time push handler to append new alerts to the live incident stream immediately."""
        self.stream_list.controls.insert(0, self._render_alert_stream_row(alert))
        if len(self.stream_list.controls) > config.GUI_MAX_STREAM_ROWS:
            self.stream_list.controls.pop()
        self.refresh_data()