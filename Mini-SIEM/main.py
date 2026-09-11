"""
Mini SIEM — Unified Application Entry Point
============================================
Connects log collection, parsing, normalization, detection, alerting,
correlation, and the Flet SOC desktop interface into a single
thread-safe, real-time Linux security monitoring platform.

Usage:
    python3 main.py
"""

import os
import sys
import time
import asyncio
import threading
import logging
import flet as ft
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from modules.database import initialize_db, seed_rules, seed_default_log_sources
from modules.collector import LogCollector
from modules.parser import LogParser
from modules.normalizer import EventNormalizer
from modules.detection_engine import DetectionEngine
from modules.alert_manager import AlertManager
from modules.correlation_engine import CorrelationEngine

# UI Views
from ui.sidebar import Sidebar
from ui.dashboard_view import DashboardView
from ui.logs_view import LogsView
from ui.alerts_view import AlertsView
from ui.rules_view import RulesView
from ui.sources_view import SourcesView
from ui.reports_view import ReportsView
from ui.settings_view import SettingsView
from ui.about_view import AboutView

# Configure global logger
logging.basicConfig(
    level=config.APP_LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.APP_LOG_PATH, encoding="utf-8")
    ]
)
logger = logging.getLogger("MiniSIEM")

pipeline_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════
#   BACKEND PIPELINE HANDLER
# ═══════════════════════════════════════════════════════════════

class PipelineHandler:
    """Receives raw log lines from the collector and executes the SIEM workflow."""
    def __init__(self, detection_engine: DetectionEngine, alert_manager: AlertManager):
        self.detection_engine = detection_engine
        self.alert_manager = alert_manager

    def handle_raw_line(self, raw_line: str, source_name: str):
        try:
            with pipeline_lock:
                parsed = LogParser.parse_line(raw_line, source_name=source_name)
                normalized = EventNormalizer.normalize(parsed)
                EventNormalizer.save_to_db(normalized)
                
                generated_alerts = self.detection_engine.evaluate_event(normalized)
                for alert_data in generated_alerts:
                    self.alert_manager.process_alert(alert_data)

        except Exception as e:
            logger.error(f"Pipeline error on line from '{source_name}': {e}", exc_info=True)


# ═══════════════════════════════════════════════════════════════
#   VIEW ROUTER (Zero-Flicker Container Swapping)
# ═══════════════════════════════════════════════════════════════

class ViewRouter:
    """Seamlessly manages switching views in the main content container."""
    def __init__(self, page: ft.Page, sidebar: Sidebar, container: ft.Container, views: Dict[str, ft.Container]):
        self.page = page
        self.sidebar = sidebar
        self.container = container
        self.views = views
        self.current_route = "dashboard"

    def navigate(self, route: str):
        if route not in self.views:
            route = "dashboard"

        self.current_route = route
        self.sidebar.current_route = route
        self.sidebar.content = self.sidebar._build_content()
        self.sidebar.update()

        target_view = self.views[route]
        self.container.content = target_view
        self.container.update()

        # Trigger internal data loading for target view
        if route == "dashboard":
            target_view.refresh_data()
        elif route == "logs":
            target_view.load_events()
        elif route == "alerts":
            target_view.load_alerts()
        elif route == "rules":
            target_view.load_rules()
        elif route == "sources":
            target_view.probe_and_load_sources()
        elif route == "reports":
            target_view.refresh_archive_list()
        elif route == "settings":
            target_view.refresh_db_stats()


# ═══════════════════════════════════════════════════════════════
#   MAIN FLET APPLICATION
# ═══════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """Flet application main entrypoint."""
    page.title = f"{config.APP_NAME} — {config.APP_SUBTITLE}"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0B1121"
    page.padding = 0
    page.spacing = 0

    # Configure Desktop Window Constraints
    try:
        page.window.width = 1280
        page.window.height = 820
        page.window.min_width = 1100
        page.window.min_height = 700
    except Exception:
        pass

    # 1. Database & Rule Initialization
    initialize_db()
    seed_rules()
    seed_default_log_sources()

    # 2. Instantiate Backend Engines
    alert_manager = AlertManager(dedup_window_seconds=120)
    detection_engine = DetectionEngine()
    correlation_engine = CorrelationEngine(time_window_seconds=config.CORRELATION_WINDOW)

    # 3. Wire Alert Manager -> Correlation Engine
    def _forward_alert(alert):
        correlation_engine.process_incoming_alert(alert)
        return None

    alert_manager.subscribe(_forward_alert)

    # 4. Pipeline Handler
    pipeline = PipelineHandler(detection_engine, alert_manager)

    # 5. Load Active Log Sources from DB
    collected_sources = []
    try:
        from modules.database import db_conn
        with db_conn() as conn:
            rows = conn.execute("SELECT name, path, source_type FROM log_sources").fetchall()
            for r in rows:
                collected_sources.append({
                    "name": r["name"],
                    "path": r["path"],
                    "type": r["source_type"]
                })
    except Exception as e:
        logger.error(f"Failed to query log sources: {e}")

    if not collected_sources:
        collected_sources = config.DEFAULT_LOG_SOURCES

    # 6. Start Log Collector in Background
    collector = LogCollector(log_sources=collected_sources, line_callback=pipeline.handle_raw_line)
    collector.start()

    # 7. Instantiate UI Views
    router_holder = {"router": None}

    def nav_callback(route: str):
        if router_holder["router"]:
            router_holder["router"].navigate(route)

    sidebar = Sidebar(on_nav_change=nav_callback)

    dashboard_view = DashboardView(alert_manager=alert_manager, on_navigate=nav_callback)
    logs_view = LogsView(page=page)
    alerts_view = AlertsView(page=page, alert_manager=alert_manager)
    rules_view = RulesView(page=page, detection_engine=detection_engine)
    sources_view = SourcesView(page=page)
    reports_view = ReportsView(page=page)
    settings_view = SettingsView(page=page)
    about_view = AboutView(page=page)

    views_dict = {
        "dashboard": dashboard_view,
        "logs": logs_view,
        "alerts": alerts_view,
        "rules": rules_view,
        "sources": sources_view,
        "reports": reports_view,
        "settings": settings_view,
        "about": about_view,
    }

    main_content_container = ft.Container(
        content=dashboard_view,
        expand=True,
    )

    router = ViewRouter(
        page=page,
        sidebar=sidebar,
        container=main_content_container,
        views=views_dict
    )
    router_holder["router"] = router

    # 8. Assemble Root Layout
    page.add(
        ft.Row(
            [sidebar, main_content_container],
            expand=True,
            spacing=0,
        )
    )

    # 9. Real-Time Alert Event Subscription
    alert_manager.subscribe(dashboard_view.handle_incoming_live_alert)

    # 10. Initial Data Refresh
    dashboard_view.refresh_data()
    rules_view.load_rules()
    sources_view.probe_and_load_sources()

    # 11. Async Periodic Background UI Sync Task
    async def periodic_ui_sync():
        while True:
            await asyncio.sleep(config.GUI_REFRESH_INTERVAL)
            try:
                dashboard_view.update_system_time()
                if router.current_route == "dashboard":
                    dashboard_view.refresh_data()

                metrics = alert_manager.get_soc_metrics()
                sidebar.update_alert_count(metrics["new_alerts"])
            except Exception:
                pass

    page.run_task(periodic_ui_sync)

    # 12. Safe Window Shutdown
    def on_window_close(e):
        logger.info("Window close requested. Stopping background collector...")
        collector.stop()
        page.window_destroy()

    page.on_window_close = on_window_close
    logger.info(f"{config.APP_NAME} v{config.APP_VERSION} UI initialized.")


# ═══════════════════════════════════════════════════════════════
#   APPLICATION LAUNCHER
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"[*] Starting {config.APP_NAME} v{config.APP_VERSION} ({config.APP_SUBTITLE})")
    print(f"[*] Target OS: Linux (Ubuntu/Debian primary)")
    print(f"[*] Database: {config.DATABASE_PATH}")
    ft.app(target=main)