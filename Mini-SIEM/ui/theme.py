"""
Mini SIEM — Theme & Design Tokens
==================================
Centralized color palette, typographic scales, card containers,
and severity styling. Uses solid, high-contrast dark SOC colors.
"""

import flet as ft
from typing import Optional

# ═══════════════════════════════════════════════════════════════
#   SOC DARK PALETTE
# ═══════════════════════════════════════════════════════════════
BG_COLOR       = "#0B1121"   # Deep navy-black canvas
SURFACE_COLOR  = "#161E2E"   # Primary card container
SURFACE_ALT    = "#1F2937"   # Secondary panel / input background
BORDER_COLOR   = "#2D3748"   # Subtle grid line & card border
TEXT_WHITE     = "#F9FAFB"   # High-contrast primary text
TEXT_MUTED     = "#9CA3AF"   # Secondary label / metadata text

# Severity Colors
COLOR_CRITICAL = "#EF4444"   # Red
COLOR_HIGH     = "#F59E0B"   # Orange
COLOR_MEDIUM   = "#EAB308"   # Yellow
COLOR_LOW      = "#3B82F6"   # Blue
COLOR_GREEN    = "#10B981"   # Healthy / Active
COLOR_PURPLE   = "#8B5CF6"   # Accent / Admin


# ═══════════════════════════════════════════════════════════════
#   BORDER HELPERS (Compatible across all Flet versions)
# ═══════════════════════════════════════════════════════════════

def app_border(width: float = 1, color: str = BORDER_COLOR) -> Optional[ft.Border]:
    """Universal fail-safe border helper."""
    try:
        return ft.Border.all(width, color)
    except Exception:
        try:
            side = ft.BorderSide(width, color)
            return ft.Border(top=side, bottom=side, left=side, right=side)
        except Exception:
            return None


def right_border(width: float = 1, color: str = BORDER_COLOR) -> Optional[ft.Border]:
    """Universal fail-safe right border helper."""
    try:
        return ft.Border(right=ft.BorderSide(width, color))
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
#   HELPER FORMATTERS & COLOR MAPPERS
# ═══════════════════════════════════════════════════════════════

def get_severity_color(severity: str) -> str:
    """Maps standard severity strings to theme hex colors."""
    s = (severity or "").upper()
    if s == "CRITICAL":
        return COLOR_CRITICAL
    elif s == "HIGH":
        return COLOR_HIGH
    elif s == "MEDIUM":
        return COLOR_MEDIUM
    elif s == "LOW":
        return COLOR_LOW
    return COLOR_LOW


def get_status_color(status: str) -> str:
    """Maps alert / source statuses to theme hex colors."""
    st = (status or "").upper()
    if st in ("ACTIVE", "RESOLVED"):
        return COLOR_GREEN
    elif st in ("WARNING", "INVESTIGATING"):
        return COLOR_HIGH
    elif st in ("OFFLINE", "FALSE_POSITIVE"):
        return TEXT_MUTED if st == "FALSE_POSITIVE" else COLOR_CRITICAL
    return COLOR_LOW


def create_card(
    content: ft.Control,
    expand: int | bool = False,
    height: Optional[int] = None,
    padding: int = 15,
    border_color: str = BORDER_COLOR
) -> ft.Container:
    """Standardized dark rounded card container with crisp border."""
    return ft.Container(
        content=content,
        bgcolor=SURFACE_COLOR,
        border=app_border(1, border_color),
        border_radius=8,
        padding=padding,
        expand=expand,
        height=height,
    )


def create_severity_badge(severity: str, width: int = 80) -> ft.Container:
    """Pill badge displaying severity with high-contrast text."""
    sev = (severity or "INFO").upper()
    color = get_severity_color(sev)
    return ft.Container(
        content=ft.Row(
            [ft.Text(sev, size=10, weight="bold", color="#FFFFFF")],
            alignment=ft.MainAxisAlignment.CENTER,
        ),
        bgcolor=color,
        padding=ft.Padding(left=6, right=6, top=2, bottom=2),
        border_radius=4,
        width=width,
    )


def create_section_header(title: str, right_control: Optional[ft.Control] = None) -> ft.Row:
    """Standardized card section header with title and optional right-aligned action."""
    controls = [ft.Text(title, weight="bold", size=15, color=TEXT_WHITE)]
    if right_control:
        return ft.Row(
            [controls[0], right_control],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
    return ft.Row(controls)