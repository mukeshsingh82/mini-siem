"""
Mini SIEM — Detection Rules Management View
============================================
Allows SOC engineers to view, toggle, configure, create, and delete
detection rules stored in SQLite.
"""

import sys
import flet as ft
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

# Adjust path to import central configuration, database, and detection engine
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn
from modules.detection_engine import DetectionEngine
from ui.theme import (
    SURFACE_COLOR, SURFACE_ALT, BORDER_COLOR, TEXT_WHITE, TEXT_MUTED,
    COLOR_LOW, COLOR_GREEN, COLOR_HIGH, COLOR_CRITICAL, COLOR_PURPLE,
    create_card, create_severity_badge, create_section_header, get_severity_color, app_border
)


# ═══════════════════════════════════════════════════════════════
#   RULES VIEW CLASS
# ═══════════════════════════════════════════════════════════════

class RulesView(ft.Container):
    """Main Detection Rules Management interface."""
    def __init__(self, page: ft.Page, detection_engine: Optional[DetectionEngine] = None):
        super().__init__()
        self.page_ref = page
        self.detection_engine = detection_engine
        self.expand = True
        self.padding = 20

        # State Variables
        self.rules_data: List[Dict[str, Any]] = []
        self.editing_rule_id: Optional[str] = None

        # Top KPI Metric Text Refs
        self.ref_total_rules    = ft.Ref[ft.Text]()
        self.ref_active_rules   = ft.Ref[ft.Text]()
        self.ref_inactive_rules = ft.Ref[ft.Text]()
        self.ref_total_triggers = ft.Ref[ft.Text]()

        # Filter Controls
        self.input_search = ft.TextField(
            hint_text="Search rule ID, name, description, or event type...",
            prefix_icon=ft.Icons.SEARCH,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=12,
            height=38,
            expand=True,
            on_submit=lambda e: self.load_rules(),
        )
        self.dd_severity_filter = ft.Dropdown(
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
        self.dd_status_filter = ft.Dropdown(
            label="Status",
            value="ALL",
            options=[ft.dropdown.Option("ALL"), ft.dropdown.Option("Enabled"), ft.dropdown.Option("Disabled")],
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            color=TEXT_WHITE,
            text_size=11,
            height=42,
            width=130,
        )

        # Rules List View
        self.rules_table_list = ft.ListView(expand=True, spacing=6)

        # Modals
        self.rule_form_modal = self._build_rule_form_modal()
        self.delete_confirm_modal = self._build_delete_confirm_modal()

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
                                ft.Icon(ft.Icons.SECURITY_ROUNDED, color=TEXT_WHITE, size=24),
                                ft.Text("Detection Rules", size=22, weight="bold", color=TEXT_WHITE),
                            ],
                            spacing=10,
                        ),
                        ft.Text("Configure threat detection logic, tune threshold windows, and manage custom rules", color=TEXT_MUTED, size=12),
                    ],
                    spacing=2,
                ),
                ft.Row(
                    [
                        ft.ElevatedButton(
                            "Add Custom Rule",
                            icon=ft.Icons.ADD_ROUNDED,
                            bgcolor=COLOR_LOW,
                            color="#FFFFFF",
                            on_click=lambda e: self._open_add_rule_modal(),
                        ),
                        ft.ElevatedButton(
                            "Refresh",
                            icon=ft.Icons.REFRESH,
                            bgcolor=SURFACE_ALT,
                            color=TEXT_WHITE,
                            on_click=lambda e: self.load_rules(),
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
                self._create_kpi_card("Total Rules", self.ref_total_rules, ft.Icons.POLICY, COLOR_LOW),
                self._create_kpi_card("Active Rules", self.ref_active_rules, ft.Icons.CHECK_CIRCLE_OUTLINE, COLOR_GREEN),
                self._create_kpi_card("Disabled Rules", self.ref_inactive_rules, ft.Icons.PAUSE_CIRCLE_OUTLINE, COLOR_HIGH),
                self._create_kpi_card("Total Detections", self.ref_total_triggers, ft.Icons.BOLT, COLOR_PURPLE),
            ],
            spacing=15,
        )

    def _build_filter_bar(self) -> ft.Container:
        return create_card(
            ft.Row(
                [
                    self.input_search,
                    self.dd_severity_filter,
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
                    ft.Text("Rule ID", color=TEXT_MUTED, size=11, weight="bold", width=95),
                    ft.Text("Severity", color=TEXT_MUTED, size=11, weight="bold", width=80),
                    ft.Text("Rule Name & Logic", color=TEXT_MUTED, size=11, weight="bold", expand=True),
                    ft.Text("Event Target", color=TEXT_MUTED, size=11, weight="bold", width=140),
                    ft.Text("Condition / Window", color=TEXT_MUTED, size=11, weight="bold", width=180),
                    ft.Text("Hits", color=TEXT_MUTED, size=11, weight="bold", width=55, text_align="center"),
                    ft.Text("Enabled", color=TEXT_MUTED, size=11, weight="bold", width=70, text_align="center"),
                    ft.Text("Actions", color=TEXT_MUTED, size=11, weight="bold", width=85, text_align="center"),
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
                    self.rules_table_list,
                ],
                spacing=6,
                expand=True,
            ),
            expand=True,
            padding=10,
        )

    # ───────────────────────────────────────────────────────────
    #   RULE ROW RENDERING
    # ───────────────────────────────────────────────────────────

    def _render_rule_row(self, rule: Dict[str, Any]) -> ft.Container:
        rid = rule.get("id", "")
        name = rule.get("name", "")
        desc = rule.get("description", "")
        sev = rule.get("severity", "LOW")
        evt_type = rule.get("event_type", "any")
        cond = rule.get("condition", "")
        thresh = rule.get("threshold", 1)
        window = rule.get("time_window", 0)
        is_enabled = bool(rule.get("enabled", 1))
        triggers = rule.get("trigger_count", 0)

        # Format condition text
        if window > 0:
            cond_display = f"{cond} (≥{thresh} in {window}s)"
        else:
            cond_display = f"{cond} (Immediate trigger)"

        return ft.Container(
            content=ft.Row(
                [
                    ft.Text(rid, weight="bold", color=COLOR_LOW, size=11, width=95),
                    create_severity_badge(sev, width=80),
                    ft.Column(
                        [
                            ft.Text(name, weight="bold", size=12, color=TEXT_WHITE, no_wrap=True),
                            ft.Text(desc, size=10, color=TEXT_MUTED, no_wrap=True),
                        ],
                        spacing=1,
                        expand=True,
                    ),
                    ft.Container(
                        content=ft.Text(evt_type, size=11, color=TEXT_WHITE, no_wrap=True),
                        bgcolor=SURFACE_COLOR,
                        padding=ft.Padding(6, 2, 6, 2),
                        border_radius=4,
                        border=app_border(1, BORDER_COLOR),
                        width=140,
                    ),
                    ft.Text(cond_display, size=11, color=COLOR_PURPLE, width=180, no_wrap=True),
                    ft.Container(
                        content=ft.Text(f"{triggers:,}", size=11, weight="bold", color=TEXT_WHITE, text_align="center"),
                        bgcolor=SURFACE_COLOR,
                        border=app_border(1, BORDER_COLOR),
                        border_radius=4,
                        width=45,
                        padding=2,
                        alignment=ft.Alignment(0.5, 0.5),
                    ),
                    ft.Container(
                        content=ft.Switch(
                            value=is_enabled,
                            active_color=COLOR_GREEN,
                            scale=0.75,
                            on_change=lambda e, r_id=rid: self._toggle_rule(r_id, e.control.value),
                        ),
                        width=70,
                        alignment=ft.Alignment(0.5, 0.5),
                    ),
                    ft.Row(
                        [
                            ft.IconButton(
                                ft.Icons.EDIT_OUTLINED,
                                icon_size=15,
                                icon_color=TEXT_MUTED,
                                tooltip="Edit Rule",
                                on_click=lambda e, r=rule: self._open_edit_rule_modal(r),
                            ),
                            ft.IconButton(
                                ft.Icons.DELETE_OUTLINE,
                                icon_size=15,
                                icon_color=COLOR_CRITICAL,
                                tooltip="Delete Rule",
                                on_click=lambda e, r=rule: self._open_delete_modal(r),
                            ),
                        ],
                        spacing=0,
                        width=85,
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
    #   RULE ADD / EDIT MODAL
    # ───────────────────────────────────────────────────────────

    def _build_rule_form_modal(self) -> ft.AlertDialog:
        self.form_title = ft.Text("Configure Detection Rule", size=16, weight="bold", color=TEXT_WHITE)
        
        self.form_id = ft.TextField(label="Rule ID (e.g. AUTH-009)", text_size=12, height=45, bgcolor=SURFACE_ALT, border_color=BORDER_COLOR)
        self.form_name = ft.TextField(label="Rule Name", text_size=12, height=45, bgcolor=SURFACE_ALT, border_color=BORDER_COLOR)
        self.form_desc = ft.TextField(label="Description", multiline=True, min_lines=2, max_lines=3, text_size=12, bgcolor=SURFACE_ALT, border_color=BORDER_COLOR)
        
        self.form_event_type = ft.Dropdown(
            label="Target Event Type",
            options=[
                ft.dropdown.Option("any"),
                ft.dropdown.Option("ssh_failed_login"),
                ft.dropdown.Option("ssh_successful_login"),
                ft.dropdown.Option("ssh_invalid_user"),
                ft.dropdown.Option("ssh_root_login"),
                ft.dropdown.Option("sudo_failure"),
                ft.dropdown.Option("sudo_to_root"),
                ft.dropdown.Option("sudo_execution"),
                ft.dropdown.Option("pam_auth_failure"),
                ft.dropdown.Option("http_404"),
                ft.dropdown.Option("http_request"),
                ft.dropdown.Option("connection_attempt"),
            ],
            value="ssh_failed_login",
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
        )

        self.form_condition = ft.Dropdown(
            label="Evaluation Condition",
            options=[
                ft.dropdown.Option("single_event"),
                ft.dropdown.Option("count_by_source_ip"),
                ft.dropdown.Option("count_by_username"),
                ft.dropdown.Option("distinct_ports_by_source_ip"),
                ft.dropdown.Option("success_after_failures"),
                ft.dropdown.Option("url_pattern_match"),
            ],
            value="count_by_source_ip",
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
        )

        self.form_threshold = ft.TextField(label="Threshold (Hits)", value="5", text_size=12, height=45, bgcolor=SURFACE_ALT, border_color=BORDER_COLOR, width=130)
        self.form_window = ft.TextField(label="Time Window (sec)", value="60", text_size=12, height=45, bgcolor=SURFACE_ALT, border_color=BORDER_COLOR, width=150)
        
        self.form_severity = ft.Dropdown(
            label="Severity",
            options=[ft.dropdown.Option(s) for s in config.SEVERITY_LEVELS],
            value="HIGH",
            text_size=12,
            bgcolor=SURFACE_ALT,
            border_color=BORDER_COLOR,
            width=140,
        )
        self.form_enabled = ft.Switch(label="Enabled immediately", value=True, active_color=COLOR_GREEN)

        modal_body = ft.Container(
            content=ft.Column(
                [
                    self.form_id,
                    self.form_name,
                    self.form_desc,
                    ft.Row([self.form_event_type, self.form_condition], spacing=10),
                    ft.Row([self.form_threshold, self.form_window, self.form_severity], spacing=10),
                    self.form_enabled,
                ],
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
            ),
            width=560,
            height=430,
            padding=5,
        )

        return ft.AlertDialog(
            modal=True,
            title=self.form_title,
            content=modal_body,
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self._close_modal(self.rule_form_modal)),
                ft.ElevatedButton("Save Rule", bgcolor=COLOR_LOW, color="#FFFFFF", on_click=lambda e: self._save_rule_from_form()),
            ],
            bgcolor=SURFACE_COLOR,
        )

    def _open_add_rule_modal(self):
        self.editing_rule_id = None
        self.form_title.value = "Create Custom Detection Rule"
        
        # Generate default custom ID
        new_id_num = len(self.rules_data) + 1
        self.form_id.value = f"CUSTOM-{new_id_num:03d}"
        self.form_id.disabled = False
        self.form_name.value = ""
        self.form_desc.value = ""
        self.form_event_type.value = "ssh_failed_login"
        self.form_condition.value = "count_by_source_ip"
        self.form_threshold.value = "5"
        self.form_window.value = "60"
        self.form_severity.value = "HIGH"
        self.form_enabled.value = True

        self.page_ref.dialog = self.rule_form_modal
        self.rule_form_modal.open = True
        self.page_ref.update()

    def _open_edit_rule_modal(self, rule: Dict[str, Any]):
        self.editing_rule_id = rule["id"]
        self.form_title.value = f"Edit Rule [{rule['id']}]"
        
        self.form_id.value = rule["id"]
        self.form_id.disabled = True  # Primary key locked on edit
        self.form_name.value = rule.get("name", "")
        self.form_desc.value = rule.get("description", "")
        self.form_event_type.value = rule.get("event_type", "any")
        self.form_condition.value = rule.get("condition", "single_event")
        self.form_threshold.value = str(rule.get("threshold", 1))
        self.form_window.value = str(rule.get("time_window", 0))
        self.form_severity.value = rule.get("severity", "MEDIUM")
        self.form_enabled.value = bool(rule.get("enabled", 1))

        self.page_ref.dialog = self.rule_form_modal
        self.rule_form_modal.open = True
        self.page_ref.update()

    def _save_rule_from_form(self):
        rule_id = self.form_id.value.strip()
        name = self.form_name.value.strip()
        desc = self.form_desc.value.strip()
        evt_type = self.form_event_type.value
        condition = self.form_condition.value
        severity = self.form_severity.value
        enabled = 1 if self.form_enabled.value else 0

        # Form Validation
        if not rule_id or not name:
            self._show_snack("Rule ID and Name cannot be empty.", is_error=True)
            return

        try:
            threshold = int(self.form_threshold.value)
            time_window = int(self.form_window.value)
            if threshold < 1 or time_window < 0:
                raise ValueError()
        except ValueError:
            self._show_snack("Threshold must be >= 1 and Time Window >= 0.", is_error=True)
            return

        try:
            with db_conn() as conn:
                if self.editing_rule_id:
                    # Update Existing
                    conn.execute(
                        """
                        UPDATE rules SET
                            name = ?, description = ?, event_type = ?,
                            condition = ?, threshold = ?, time_window = ?,
                            severity = ?, enabled = ?
                        WHERE id = ?
                        """,
                        (name, desc, evt_type, condition, threshold, time_window, severity, enabled, self.editing_rule_id)
                    )
                    msg = f"Rule [{self.editing_rule_id}] updated successfully."
                else:
                    # Insert New
                    conn.execute(
                        """
                        INSERT INTO rules (id, name, description, event_type, condition, threshold, time_window, severity, enabled, trigger_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                        """,
                        (rule_id, name, desc, evt_type, condition, threshold, time_window, severity, enabled)
                    )
                    msg = f"Rule [{rule_id}] created successfully."

            # Synchronize in-memory engine
            if self.detection_engine:
                self.detection_engine.reload_rules()

            self._close_modal(self.rule_form_modal)
            self._show_snack(msg)
            self.load_rules()

        except Exception as e:
            self._show_snack(f"Database error: {e}", is_error=True)

    # ───────────────────────────────────────────────────────────
    #   RULE DELETION MODAL
    # ───────────────────────────────────────────────────────────

    def _build_delete_confirm_modal(self) -> ft.AlertDialog:
        self.delete_msg = ft.Text("", size=13, color=TEXT_WHITE)
        return ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=COLOR_CRITICAL, size=22),
                ft.Text("Confirm Rule Deletion", size=16, weight="bold", color=TEXT_WHITE)
            ], spacing=8),
            content=ft.Container(content=self.delete_msg, width=420, padding=10),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self._close_modal(self.delete_confirm_modal)),
                ft.ElevatedButton("Delete Rule", bgcolor=COLOR_CRITICAL, color="#FFFFFF", on_click=lambda e: self._delete_active_rule()),
            ],
            bgcolor=SURFACE_COLOR,
        )

    def _open_delete_modal(self, rule: Dict[str, Any]):
        self.deleting_rule = rule
        self.delete_msg.value = f"Are you sure you want to delete rule [{rule['id']}] '{rule['name']}'? This action cannot be undone."
        self.page_ref.dialog = self.delete_confirm_modal
        self.delete_confirm_modal.open = True
        self.page_ref.update()

    def _delete_active_rule(self):
        rule_id = self.deleting_rule["id"]
        try:
            with db_conn() as conn:
                conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))

            if self.detection_engine:
                self.detection_engine.reload_rules()

            self._close_modal(self.delete_confirm_modal)
            self._show_snack(f"Rule [{rule_id}] deleted successfully.")
            self.load_rules()
        except Exception as e:
            self._show_snack(f"Failed to delete rule: {e}", is_error=True)

    # ───────────────────────────────────────────────────────────
    #   RULE TOGGLE & QUERY EXECUTION
    # ───────────────────────────────────────────────────────────

    def _toggle_rule(self, rule_id: str, new_val: bool):
        enabled_val = 1 if new_val else 0
        try:
            with db_conn() as conn:
                conn.execute("UPDATE rules SET enabled = ? WHERE id = ?", (enabled_val, rule_id))
            
            if self.detection_engine:
                self.detection_engine.reload_rules()

            status_str = "enabled" if new_val else "disabled"
            self._show_snack(f"Rule [{rule_id}] {status_str}.")
            self.load_rules(preserve_filter=True)
        except Exception as e:
            self._show_snack(f"Failed to toggle rule: {e}", is_error=True)

    def load_rules(self, preserve_filter: bool = False):
        """Fetches all rules from SQLite, updates KPI summary cards, and renders table."""
        try:
            with db_conn() as conn:
                rows = conn.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
                self.rules_data = [dict(r) for r in rows]

            # 1. Update KPI Summary Numbers
            total = len(self.rules_data)
            active = sum(1 for r in self.rules_data if r.get("enabled") == 1)
            inactive = total - active
            triggers = sum(r.get("trigger_count", 0) for r in self.rules_data)

            if self.ref_total_rules.current:
                self.ref_total_rules.current.value = str(total)
            if self.ref_active_rules.current:
                self.ref_active_rules.current.value = str(active)
            if self.ref_inactive_rules.current:
                self.ref_inactive_rules.current.value = str(inactive)
            if self.ref_total_triggers.current:
                self.ref_total_triggers.current.value = f"{triggers:,}"

            # 2. Apply In-Memory Filters for Display
            search = (self.input_search.value or "").lower().strip()
            sev = self.dd_severity_filter.value
            status = self.dd_status_filter.value

            filtered = self.rules_data
            if search:
                filtered = [
                    r for r in filtered
                    if search in r.get("id", "").lower()
                    or search in r.get("name", "").lower()
                    or search in r.get("description", "").lower()
                    or search in r.get("event_type", "").lower()
                ]

            if sev and sev != "ALL":
                filtered = [r for r in filtered if r.get("severity") == sev]

            if status and status != "ALL":
                is_active = (status == "Enabled")
                filtered = [r for r in filtered if bool(r.get("enabled")) == is_active]

            # 3. Render Table Rows
            if not filtered:
                self.rules_table_list.controls = [
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Icon(ft.Icons.RULE_FOLDER_OUTLINED, size=36, color=TEXT_MUTED),
                                ft.Text("No detection rules match the specified filters.", color=TEXT_MUTED, size=13),
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=6,
                        ),
                        padding=40,
                        alignment=ft.Alignment(0.5, 0.5),
                    )
                ]
            else:
                self.rules_table_list.controls = [self._render_rule_row(r) for r in filtered]

            self._safe_page_refresh()

        except Exception as e:
            print(f"[!] Error loading detection rules: {e}")

    # ───────────────────────────────────────────────────────────
    #   HELPERS
    # ───────────────────────────────────────────────────────────

    def _clear_filters(self):
        self.input_search.value = ""
        self.dd_severity_filter.value = "ALL"
        self.dd_status_filter.value = "ALL"
        self.load_rules()

    def _safe_page_refresh(self):
        if self.page_ref is None:
            return
        if getattr(self, "page", None) is None:
            return
        try:
            self.page_ref.update()
        except Exception:
            pass

    def _close_modal(self, modal: ft.AlertDialog):
        modal.open = False
        self._safe_page_refresh()

    def _show_snack(self, message: str, is_error: bool = False):
        if self.page_ref is None:
            return
        if getattr(self, "page", None) is None:
            return
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor=COLOR_CRITICAL if is_error else COLOR_GREEN,
            duration=3000,
        )
        self.page_ref.overlay.append(snack)
        snack.open = True
        self._safe_page_refresh()


# ═══════════════════════════════════════════════════════════════
#   STANDALONE RULES VIEW SELF-TEST
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Entry point for standalone Rules View test."""
    page.title = f"{config.APP_NAME} — Detection Rules Test"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0

    from modules.database import initialize_db, seed_rules
    initialize_db()
    seed_rules()

    detection_engine = DetectionEngine()

    from ui.sidebar import Sidebar
    sidebar = Sidebar(on_nav_change=lambda route: print(f"Navigated to: {route}"))
    rules_view = RulesView(page=page, detection_engine=detection_engine)

    page.add(
        ft.Row([sidebar, rules_view], expand=True, spacing=0)
    )


if __name__ == "__main__":
    print("[*] Launching Flet Rules View Standalone Window...")
    ft.app(target=main)
