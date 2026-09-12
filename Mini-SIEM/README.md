# 🛡️ Mini SIEM — SOC & Linux Security Monitoring Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white)](https://www.kernel.org/)
[![GUI](https://img.shields.io/badge/GUI-Flet%20(Flutter)-02569B?logo=flutter&logoColor=white)](https://flet.dev/)
[![Database](https://img.shields.io/badge/Database-SQLite%203%20(WAL)-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Mini SIEM** is a lightweight, fully functional Security Information and Event Management (SIEM) desktop application built specifically for **Linux** environments.

It continuously monitors Linux security logs (`/var/log/auth.log`, `syslog`, Apache/Nginx web logs), parses and normalizes them into structured schemas, runs configurable sliding-window detection rules, correlates multi-stage attack chains into critical incidents, and renders a live, dark SOC command center.

---

## 📑 Table of Contents

1. [Key Features](#-key-features)
2. [Processing Pipeline & Architecture](#-processing-pipeline--architecture)
3. [Detection Rules Catalog](#-detection-rules-catalog)
4. [Multi-Stage Incident Correlation](#-multi-stage-incident-correlation)
5. [Technology Stack](#-technology-stack)
6. [Installation & Setup](#-installation--setup)
7. [Linux Permissions & Hardening](#-linux-permissions--hardening)
8. [Usage & Workflow Guide](#-usage--workflow-guide)
9. [Automated Testing & Attack Simulation](#-automated-testing--attack-simulation)
10. [Project Structure](#-project-structure)
11. [Security & Defensive Disclaimer](#-security--defensive-disclaimer)
12. [License & Credits](#-license--credits)

---

## 🚀 Key Features

- **Real-Time Linux Log Collection**: Non-blocking background collector powered by `watchdog` and hybrid inode-tracking to handle log rotations (`logrotate`) and missing files gracefully.
- **Robust POSIX Log Parser**: Dissects standard Syslog (RFC 3164/5424), OpenSSH authentication events, PAM/Sudo privilege escalations, UFW firewall blocks, and Apache/Nginx access logs.
- **Standardized Normalization**: Strict type coercion, IPv4/IPv6 validation, port bounds-checking, payload sanitization, and baseline severity scoring.
- **Thread-Safe SQLite Layer**: Uses Write-Ahead Logging (`WAL` mode) and connection pooling with busy timeouts to support high-throughput concurrency.
- **Sliding-Window Detection Engine**: In-memory `deque` sliding time-windows capable of sub-millisecond rate calculations without database query overhead.
- **Multi-Stage Attack Correlation**: Identifies attack sequences across time windows (e.g., *SSH Brute Force → Successful Authentication → Sudo Privilege Escalation*).
- **Intelligent Deduplication & Triage**: Merges rapid alert bursts, maintains occurrence counters, and supports analyst triage lifecycles (`NEW` → `INVESTIGATING` → `RESOLVED` / `FALSE_POSITIVE`).
- **Executive Reporting Engine**: Generates HTML audit documents (with risk scores, attack graphs, and remediation advice), structured JSON, and CSV exports.
- **Professional Flet SOC Interface**: Custom high-contrast dark theme, Canvas-rendered line charts, interactive severity donuts, multi-parameter log search, and diagnostic sidebars.

---

## 📐 Processing Pipeline & Architecture

```
Linux Log Feeds (/var/log/auth.log, syslog, apache, custom logs)
        │
        ▼
[1] Log Collector (Watchdog Tailer + Inode State Tracker)
        │
        ▼
[2] Log Parser (Compiled Regex Extractors)
        │
        ▼
[3] Event Normalizer (Data Sanitization & Baseline Severity)
        │
        ▼
[4] SQLite Database (WAL Mode · Normalized 'events' Table)
        │
        ▼
[5] Detection Rule Engine (Sliding-Window Rate Calculators)
        │
        ▼
[6] Correlation Engine (Multi-Stage Attack Chain Identification)
        │
        ▼
[7] Alert Manager (Deduplication & Triage State Management)
        │
        ▼
[8] Flet Desktop SOC Dashboard (Telemetry, Investigation & Reports)
```

---

## 📏 Detection Rules Catalog

Mini SIEM includes 12 built-in detection rules:

| Rule ID | Rule Name | Event Target | Condition / Threshold | Severity |
|---|---|---|---|---|
| `AUTH-001` | Multiple Failed SSH Logins | `ssh_failed_login` | 5+ failures from same IP in 60s | `MEDIUM` |
| `AUTH-002` | SSH Brute Force | `ssh_failed_login` | 10+ failures from same IP in 120s | `HIGH` |
| `AUTH-003` | Success After Multiple Failures | `ssh_successful_login` | Succeeded after ≥3 failures in 300s | `CRITICAL` |
| `AUTH-004` | Invalid User Login Attempts | `ssh_invalid_user` | 3+ invalid users from same IP in 60s | `MEDIUM` |
| `AUTH-005` | Direct Root Login | `ssh_root_login` | Single event trigger | `HIGH` |
| `AUTH-006` | Suspicious sudo Activity | `sudo_failure` | 3+ sudo failures in 120s | `HIGH` |
| `AUTH-007` | Privilege Escalation Indicator | `sudo_to_root` | Single event trigger | `HIGH` |
| `AUTH-008` | Repeated Authentication Failures| `pam_auth_failure` | 5+ PAM failures in 300s | `MEDIUM` |
| `NET-001` | Suspicious IP Activity | `any` | 50+ total events from same IP in 300s | `MEDIUM` |
| `NET-002` | Possible Port Scan Activity | `connection_attempt`| 15+ distinct ports targeted in 60s | `HIGH` |
| `WEB-001` | Repeated HTTP 404 Scanning | `http_404` | 20+ 404 responses from same IP in 60s | `MEDIUM` |
| `WEB-002` | Suspicious URL Pattern | `http_request` | SQLi, XSS, or Traversal pattern match | `HIGH` |

*New custom rules can be configured, toggled, or deleted directly through the Detection Rules interface.*

---

## 🔗 Multi-Stage Incident Correlation

Instead of treating alerts in isolation, the Correlation Engine continuously links contributing events across a 300-second window to detect complex attack patterns:

### 1. Possible Account Compromise (`CRITICAL`)
- **Tactic**: Credential Brute Force followed by Privilege Escalation.
- **Progression**:
  1. `AUTH-001` / `AUTH-002`: Multiple SSH authentication failures.
  2. `AUTH-003`: Accepted authentication on valid user account.
  3. `AUTH-007`: Immediate execution of unauthorized `sudo` commands.
- **Action**: Correlates all contributing alert IDs, elevates status to `CRITICAL`, and generates an incident record in the `correlations` table.

### 2. Web Attack Pivoting to Host Access (`CRITICAL`)
- **Tactic**: Initial Access via Web Exploit → SSH Pivot.
- **Progression**:
  1. `WEB-001` / `WEB-002`: SQL injection or directory scanning.
  2. `AUTH-001` / `AUTH-005`: Subsequent SSH connection attempts from the same source IP.

### 3. Reconnaissance Leading to Privilege Escalation (`CRITICAL`)
- **Tactic**: Network Discovery → Direct Root Takeover.
- **Progression**:
  1. `NET-002`: Horizontal port scan across multiple firewall ports.
  2. `AUTH-005`: Direct root login attempt.

---

## 💻 Technology Stack

- **Core Runtime**: Python 3.10+
- **Desktop GUI Framework**: [Flet](https://flet.dev/) (Flutter-backed Python UI Engine)
- **Database Engine**: SQLite 3 (Configured with `PRAGMA journal_mode=WAL;` and foreign key enforcement)
- **File Monitoring**: `watchdog` API with non-blocking polling fallback
- **Data Science & Regex**: Standard Library POSIX regex and `ipaddress` validation
- **Testing & Simulation**: Built-in dynamic Linux log generator

---

## 📦 Installation & Setup

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, Fedora 38+, Arch Linux)
- **Python**: Version `3.10` or newer

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/Mini-SIEM.git
cd Mini-SIEM
```

### 2. Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch Mini SIEM
```bash
python3 main.py
```

---

## 🐧 Linux Permissions & Hardening

On many Linux distributions (such as Ubuntu and Debian), security logs located under `/var/log/auth.log` are restricted to `root` and members of the `adm` group.

### Recommended Access Configuration (Non-Root Execution)
Mini SIEM is intentionally designed to run **without root privileges**. To permit your user account to read system logs safely:

```bash
# Add your user to the administrative log reader group:
sudo usermod -a -G adm $USER

# Log out and log back in, or run:
newgrp adm
```

### Non-Blocking Diagnostic Guard
If a configured log source is missing or unreadable, Mini SIEM:
1. Marks the source as `WARNING` (Permission Denied) or `OFFLINE` (File Missing) on the **Log Sources** page.
2. Continues monitoring all other accessible files without crashing.
3. Automatically transitions the source to `ACTIVE` once permissions are granted.

---

## 🖥️ Usage & Workflow Guide

### 📊 Dashboard
The primary landing view provides a real-time SOC overview:
- KPI cards for Total Events, Critical Alerts, High Alerts, Active Sources, and Events Per Minute.
- Canvas line charts with selectable time filters (`1 Hour`, `6 Hours`, `24 Hours`, `7 Days`).
- Live incident stream auto-scrolling on incoming detections.
- Quick action shortcuts to register feeds, tune rules, or generate audit reports.

### 📄 Logs Investigation
- Search through ingested log records with free-text keyword search.
- Filter by Severity, Log Source, Service, Event Type, IP, or Username.
- Click any row to view normalized attributes and the raw monospace log string.
- Export filtered views to **CSV** or **JSON**.

### 🚨 Alerts & Incident Triage
- Review alerts with deduplication occurrence counters.
- Inspect an alert to review its **Contributing System Events** timeline.
- Transition lifecycle status using analyst triage buttons: **Investigating**, **Resolve**, or **False Positive**.

### 📏 Detection Rules
- Enable or disable detection rules on the fly with in-line toggle switches.
- Modify threshold counts and time windows.
- Create custom detection rules using the built-in rule builder.

### 📡 Log Sources
- Inspect monitored filesystem paths, event volumes, and last-activity timestamps.
- Run live diagnostic permission probes on paths.
- Register custom log files.

### 📑 Security Reports
- Generate executive-level security audit reports in **HTML**, **JSON**, or **CSV**.
- Built-in Threat Risk Score calculation (0–100) and heuristic Linux hardening recommendations.
- Open HTML reports in your system browser or inspect archives in the built-in viewer.

---

## 🧪 Automated Testing & Attack Simulation

Mini SIEM includes a testing utility and an automated test suite.

### 1. Run the End-to-End Test Suite
Executes the full pipeline and verifies assertions against SQLite:
```bash
python3 test_pipeline.py
```

### 2. Standalone Attack Simulator
Generate mock attacks to test detection without altering system logs:

```bash
# Generate a batch of attacks (Brute force, account takeover, port scan, SQLi, XSS):
python3 modules/sample_generator.py --mode once --clear

# Run continuous background attack traffic:
python3 modules/sample_generator.py --mode continuous --interval 2.0
```

---

## 🗂️ Project Structure

```
Mini-SIEM/
├── main.py                          # Unified application entry point & router
├── config.py                        # Centralized configuration & constants
├── requirements.txt                 # Python dependencies
├── test_pipeline.py                 # End-to-end integration test suite
├── README.md                        # Documentation
├── .gitignore                       # Git ignore rules
│
├── modules/
│   ├── __init__.py
│   ├── collector.py                 # Multi-threaded Watchdog log tailer
│   ├── parser.py                    # Regular expression log parser
│   ├── normalizer.py                # Schema standardizer & DB ingestion
│   ├── database.py                  # Thread-safe SQLite WAL context manager
│   ├── detection_engine.py          # Sliding-window detection rule engine
│   ├── alert_manager.py             # Deduplication, triage & subscriber broker
│   ├── correlation_engine.py        # Multi-stage incident correlation
│   └── report_generator.py          # HTML/JSON/CSV security report compiler
│
├── rules/
│   ├── authentication_rules.json    # SSH, sudo & PAM detection rules
│   ├── network_rules.json           # Port scan & traffic volume rules
│   └── web_rules.json               # HTTP 404, SQLi & XSS rules
│
├── ui/
│   ├── __init__.py
│   ├── theme.py                     # SOC color palette, badges & card containers
│   ├── sidebar.py                   # Persistent navigation & health diagnostics
│   ├── dashboard_view.py            # Overview telemetry & Canvas charts
│   ├── logs_view.py                 # Log search, filters & raw inspection modal
│   ├── alerts_view.py               # Alert triage & contributing events
│   ├── rules_view.py                # Rule management & CRUD modal
│   ├── sources_view.py              # Log source telemetry & permission prober
│   ├── reports_view.py              # Report generation & archive viewer
│   ├── settings_view.py             # Retention policy & database maintenance
│   └── about_view.py                # Architecture diagrams & threat matrix
│
├── logs/
│   └── samples/                     # Simulated mock log files for testing
│
├── database/
│   └── siem.db                      # Primary SQLite database (auto-created)
│
└── reports/                         # Compiled security audit reports
```

---

## 🔐 Security & Defensive Disclaimer

Mini SIEM is a **defensive cybersecurity monitoring platform** designed for educational, research, and portfolio demonstration purposes.

- **Untrusted Input Handling**: All log lines are treated as untrusted data. Strings are sanitized to prevent log injection or terminal escape sequence execution.
- **No Command Execution**: The application never executes shell commands based on log content.
- **Non-Privileged Operation**: Does not require root privileges to operate.
- **Local Data Processing**: All log collection, database operations, and report generation occur entirely on the local system with zero external network transmission.

---

## 👤 License & Credits

Distributed under the **MIT License**. See `LICENSE` for more information.

Developed by Mukesh Singh — [GitHub Profile](https://github.com/mukeshsingh82)
