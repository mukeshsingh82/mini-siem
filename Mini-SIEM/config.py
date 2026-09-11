"""
Mini SIEM — Global Configuration
=================================
Centralized configuration for paths, log sources, detection thresholds,
and application behavior. All modules import from here.

Target OS: Linux (Ubuntu/Debian primary, adaptable to other distros)
"""

import os
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
#   APPLICATION METADATA
# ═══════════════════════════════════════════════════════════════
APP_NAME       = "Mini SIEM"
APP_SUBTITLE   = "SOC & Linux Security Monitoring Platform"
APP_VERSION    = "0.1.0"
APP_AUTHOR     = "Your Name"

# ═══════════════════════════════════════════════════════════════
#   PROJECT PATHS
# ═══════════════════════════════════════════════════════════════
BASE_DIR       = Path(__file__).resolve().parent
MODULES_DIR    = BASE_DIR / "modules"
RULES_DIR      = BASE_DIR / "rules"
LOGS_DIR       = BASE_DIR / "logs"
SAMPLES_DIR    = LOGS_DIR / "samples"
DATABASE_DIR   = BASE_DIR / "database"
REPORTS_DIR    = BASE_DIR / "reports"
ASSETS_DIR     = BASE_DIR / "assets"

# Ensure runtime directories exist (safe to call at import time)
for _dir in (LOGS_DIR, SAMPLES_DIR, DATABASE_DIR, REPORTS_DIR, ASSETS_DIR):
    _dir.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
#   DATABASE
# ═══════════════════════════════════════════════════════════════
DATABASE_PATH  = DATABASE_DIR / "siem.db"
DB_TIMEOUT     = 10.0   # seconds — SQLite lock timeout

# ═══════════════════════════════════════════════════════════════
#   LINUX LOG SOURCES
# ═══════════════════════════════════════════════════════════════
# Ordered list of candidate log file paths. The collector will
# probe each one at startup and skip those that don't exist or
# aren't readable (without crashing).
DEFAULT_LOG_SOURCES = [
    {
        "name": "auth.log",
        "path": "/var/log/auth.log",
        "type": "linux_auth",
        "description": "SSH, sudo, and PAM authentication events (Debian/Ubuntu)",
    },
    {
        "name": "syslog",
        "path": "/var/log/syslog",
        "type": "linux_syslog",
        "description": "General system messages (Debian/Ubuntu)",
    },
    {
        "name": "secure",
        "path": "/var/log/secure",
        "type": "linux_auth",
        "description": "Authentication events (RHEL/CentOS/Fedora)",
    },
    {
        "name": "messages",
        "path": "/var/log/messages",
        "type": "linux_syslog",
        "description": "General system messages (RHEL/CentOS/Fedora)",
    },
    {
        "name": "apache_access",
        "path": "/var/log/apache2/access.log",
        "type": "apache_access",
        "description": "Apache HTTP server access log",
    },
    {
        "name": "apache_error",
        "path": "/var/log/apache2/error.log",
        "type": "apache_error",
        "description": "Apache HTTP server error log",
    },
    {
        "name": "nginx_access",
        "path": "/var/log/nginx/access.log",
        "type": "nginx_access",
        "description": "Nginx HTTP server access log",
    },
    {
        "name": "nginx_error",
        "path": "/var/log/nginx/error.log",
        "type": "nginx_error",
        "description": "Nginx HTTP server error log",
    },
]

# Sample log file used by the built-in test generator (Step 3)
SAMPLE_LOG_PATH = SAMPLES_DIR / "sample_auth.log"

# ═══════════════════════════════════════════════════════════════
#   COLLECTOR SETTINGS
# ═══════════════════════════════════════════════════════════════
COLLECTOR_POLL_INTERVAL = 1.0   # seconds — fallback polling if watchdog fails
COLLECTOR_MAX_LINE_LEN  = 8192  # truncate absurdly long lines to prevent DoS

# ═══════════════════════════════════════════════════════════════
#   SEVERITY LEVELS
# ═══════════════════════════════════════════════════════════════
SEVERITY_LOW      = "LOW"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_HIGH     = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_LEVELS = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]

SEVERITY_RANK = {
    SEVERITY_LOW:      1,
    SEVERITY_MEDIUM:   2,
    SEVERITY_HIGH:     3,
    SEVERITY_CRITICAL: 4,
}

# ═══════════════════════════════════════════════════════════════
#   DETECTION ENGINE DEFAULTS
# ═══════════════════════════════════════════════════════════════
DETECTION_DEFAULT_WINDOW    = 60    # seconds
DETECTION_DEFAULT_THRESHOLD = 5     # occurrences
CORRELATION_WINDOW          = 300   # seconds — window for correlating related alerts

# ═══════════════════════════════════════════════════════════════
#   ALERT MANAGER
# ═══════════════════════════════════════════════════════════════
ALERT_STATUS_NEW           = "NEW"
ALERT_STATUS_INVESTIGATING = "INVESTIGATING"
ALERT_STATUS_RESOLVED      = "RESOLVED"
ALERT_STATUS_FALSE_POS     = "FALSE_POSITIVE"

ALERT_STATUSES = [
    ALERT_STATUS_NEW,
    ALERT_STATUS_INVESTIGATING,
    ALERT_STATUS_RESOLVED,
    ALERT_STATUS_FALSE_POS,
]

# ═══════════════════════════════════════════════════════════════
#   GUI SETTINGS
# ═══════════════════════════════════════════════════════════════
GUI_REFRESH_INTERVAL = 2.0   # seconds — dashboard auto-refresh
GUI_MAX_STREAM_ROWS  = 100   # max alerts in real-time incident stream
GUI_DATE_FORMAT      = "%Y-%m-%d %H:%M:%S"

# ═══════════════════════════════════════════════════════════════
#   LOGGING (application's own internal logger, not monitored logs)
# ═══════════════════════════════════════════════════════════════
APP_LOG_PATH  = LOGS_DIR / "mini_siem.log"
APP_LOG_LEVEL = "INFO"   # DEBUG, INFO, WARNING, ERROR

# ═══════════════════════════════════════════════════════════════
#   RETENTION
# ═══════════════════════════════════════════════════════════════
EVENT_RETENTION_DAYS = 30    # auto-purge events older than this
ALERT_RETENTION_DAYS = 90

# ═══════════════════════════════════════════════════════════════
#   ENVIRONMENT OVERRIDES
# ═══════════════════════════════════════════════════════════════
# Allow overriding via environment variables (useful for testing)
if os.getenv("SIEM_DB_PATH"):
    DATABASE_PATH = Path(os.environ["SIEM_DB_PATH"])

if os.getenv("SIEM_LOG_LEVEL"):
    APP_LOG_LEVEL = os.environ["SIEM_LOG_LEVEL"].upper()