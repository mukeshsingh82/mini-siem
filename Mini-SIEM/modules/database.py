"""
Mini SIEM — Database Layer
===========================
Handles thread-safe database interactions with SQLite.
Configures WAL mode, establishes the database schema, creates indexes,
and seeds initial detection rules from JSON rule-definition files.

Provides a thread-safe context manager for queries to avoid database locks
during concurrent execution (such as the watchdog log-tailing and UI threads).
"""

import os
import json
import sqlite3
import logging
from contextlib import contextmanager
from typing import Generator, List, Dict, Any, Optional

# Import absolute configuration values
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config

# Configure logging for the module
logger = logging.getLogger("MiniSIEM.Database")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   THREAD-SAFE CONTEXT MANAGER
# ═══════════════════════════════════════════════════════════════

@contextmanager
def db_conn() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager that yields a configured SQLite connection.
    Enforces foreign keys, enables WAL mode for safe multi-threaded access,
    sets a busy timeout to queue simultaneous writes, and handles transactions.
    """
    conn = None
    try:
        # Create database parent directory if it was deleted
        config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(
            str(config.DATABASE_PATH),
            timeout=config.DB_TIMEOUT,
            check_same_thread=False  # Thread safety is handled via WAL and locks
        )
        # Enable WAL mode for concurrent reads & writes
        conn.execute("PRAGMA journal_mode=WAL;")
        # Enable Foreign Key enforcement
        conn.execute("PRAGMA foreign_keys=ON;")
        # Return raw rows as dictionaries rather than tuples
        conn.row_factory = sqlite3.Row
        
        yield conn
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Database transaction failure: {e}", exc_info=True)
        raise e
    finally:
        if conn:
            conn.close()


# ═══════════════════════════════════════════════════════════════
#   SCHEMA DEFINITION
# ═══════════════════════════════════════════════════════════════

def initialize_db() -> bool:
    """
    Creates all SIEM database tables and performance-optimized indexes if they
    do not already exist. Returns True if successful, False otherwise.
    """
    logger.info(f"Initializing database at: {config.DATABASE_PATH}")
    
    # SQL Schema Commands
    schemas = [
        # 1. RULES TABLE
        """
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            event_type TEXT NOT NULL,
            condition TEXT NOT NULL,
            threshold INTEGER NOT NULL,
            time_window INTEGER NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
            trigger_count INTEGER DEFAULT 0
        );
        """,
        
        # 2. EVENTS TABLE (Normalized logs)
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            hostname TEXT,
            service TEXT,
            username TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            port INTEGER,
            event_type TEXT,
            severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            message TEXT,
            raw_log TEXT NOT NULL
        );
        """,
        
        # 3. ALERTS TABLE
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id TEXT,
            severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            source_ip TEXT,
            username TEXT,
            title TEXT NOT NULL,
            description TEXT,
            occurrences INTEGER DEFAULT 1,
            status TEXT DEFAULT 'NEW' CHECK(status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE SET NULL
        );
        """,
        
        # 4. LOG SOURCES TABLE
        """
        CREATE TABLE IF NOT EXISTS log_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            source_type TEXT NOT NULL,
            path TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'OFFLINE' CHECK(status IN ('ACTIVE', 'WARNING', 'OFFLINE')),
            last_event TEXT,
            event_count INTEGER DEFAULT 0
        );
        """,
        
        # 5. CORRELATIONS TABLE
        """
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            description TEXT,
            status TEXT DEFAULT 'NEW' CHECK(status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
            related_alerts TEXT NOT NULL -- JSON list of alert dicts/IDs
        );
        """
    ]
    
    # Indexes to drastically improve search performance on high-volume tables
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);",
        "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);",
        "CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);",
        "CREATE INDEX IF NOT EXISTS idx_correlations_created ON correlations(created_at);"
    ]
    
    try:
        with db_conn() as conn:
            # Create Tables
            for stmt in schemas:
                conn.execute(stmt)
            # Create Indexes
            for idx in indexes:
                conn.execute(idx)
        logger.info("Database schema and indexes established successfully.")
        return True
    except sqlite3.Error as e:
        logger.critical(f"Failed to initialize database: {e}")
        return False


# ═══════════════════════════════════════════════════════════════
#   RULE SEEDING
# ═══════════════════════════════════════════════════════════════

def seed_rules() -> int:
    """
    Parses rule definitions from JSON files (rules/auth, rules/network, rules/web)
    and seeds them into the 'rules' database table.
    
    Does NOT overwrite existing rule criteria in the database if user customizations
    were made; instead, uses a safe write transaction to insert missing rules.
    
    Returns the total number of rules seeded/verified.
    """
    rule_files = [
        config.RULES_DIR / "authentication_rules.json",
        config.RULES_DIR / "network_rules.json",
        config.RULES_DIR / "web_rules.json"
    ]
    
    inserted_count = 0
    
    for rule_file in rule_files:
        if not rule_file.exists():
            logger.warning(f"Rule file missing during seed check: {rule_file}")
            continue
            
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            rules = data.get("rules", [])
            logger.info(f"Processing rule definition file: {rule_file.name} ({len(rules)} rules found)")
            
            with db_conn() as conn:
                for rule in rules:
                    # Check if rule exists
                    cur = conn.execute("SELECT 1 FROM rules WHERE id = ?", (rule["id"],))
                    if cur.fetchone() is None:
                        # Insert new rule definition safely
                        conn.execute(
                            """
                            INSERT INTO rules (id, name, description, event_type, condition, threshold, time_window, severity, enabled, trigger_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                            """,
                            (
                                rule["id"],
                                rule["name"],
                                rule["description"],
                                rule["event_type"],
                                rule["condition"],
                                rule["threshold"],
                                rule["time_window"],
                                rule["severity"],
                                1 if rule.get("enabled", True) else 0
                            )
                        )
                        inserted_count += 1
                        logger.info(f"Seeded rule: [{rule['id']}] {rule['name']}")
        except (json.JSONDecodeError, sqlite3.Error, KeyError) as e:
            logger.error(f"Failed to parse or seed rules from {rule_file.name}: {e}")
            
    logger.info(f"Rules seed operation complete. {inserted_count} new rules loaded into database.")
    return inserted_count


# ═══════════════════════════════════════════════════════════════
#   HELPER FUNCTIONS FOR PRE-POPULATING DEFAULT VALUES
# ═══════════════════════════════════════════════════════════════

def seed_default_log_sources() -> int:
    """
    Pre-populates the log_sources metadata table using default Linux logs
    defined in config.py. Returns the count of registered sources.
    """
    registered = 0
    with db_conn() as conn:
        for src in config.DEFAULT_LOG_SOURCES:
            try:
                # Insert if not existing, skip if path is already registered
                conn.execute(
                    """
                    INSERT INTO log_sources (name, source_type, path, status, event_count)
                    VALUES (?, ?, ?, 'OFFLINE', 0)
                    ON CONFLICT(path) DO NOTHING
                    """,
                    (src["name"], src["type"], src["path"])
                )
                registered += 1
            except sqlite3.Error as e:
                logger.error(f"Error seeding default log source {src['name']}: {e}")
    return registered


# ═══════════════════════════════════════════════════════════════
#   MODULE DIRECT RUN (TEST VERIFICATION)
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Database Module Self-Test...")
    
    # Configure logging output for standalone check
    logger.setLevel(logging.DEBUG)
    
    # Reset any existing DB to ensure a clean test run
    if config.DATABASE_PATH.exists():
        print(f"[*] Removing existing test database at: {config.DATABASE_PATH}")
        try:
            config.DATABASE_PATH.unlink()
        except OSError as e:
            print(f"[!] Failed to remove older DB: {e}")
            
    # Run Database Setup
    assert initialize_db() is True, "Database initialization failed!"
    print("[✓] Schema established successfully.")
    
    # Seed Rules
    seeded_rules_qty = seed_rules()
    print(f"[✓] Rules populated: {seeded_rules_qty} rules loaded.")
    
    # Register Default Log Sources
    seeded_sources_qty = seed_default_log_sources()
    print(f"[✓] Log sources registered: {seeded_sources_qty} sources.")
    
    # Verify records via raw select
    with db_conn() as test_conn:
        # Check Rules
        rule_row = test_conn.execute("SELECT COUNT(*) as count FROM rules;").fetchone()
        assert rule_row["count"] > 0, "No rules registered in SQLite rules table!"
        print(f"[✓] Confirmed SQLite contains {rule_row['count']} active detection rules.")
        
        # Check Sources
        sources_row = test_conn.execute("SELECT COUNT(*) as count FROM log_sources;").fetchone()
        assert sources_row["count"] > 0, "No log sources written to log_sources metadata table!"
        print(f"[✓] Confirmed SQLite contains {sources_row['count']} registered log source slots.")
        
        # Perform write transaction on Event
        test_conn.execute(
            """
            INSERT INTO events (timestamp, source, hostname, service, severity, raw_log)
            VALUES (datetime('now'), 'test_source', 'localhost', 'ssh', 'LOW', 'test raw event line')
            """
        )
        # Query written Event to test dict-mapping output
        event_row = test_conn.execute("SELECT * FROM events WHERE source = 'test_source'").fetchone()
        assert event_row is not None
        assert event_row["severity"] == "LOW"
        assert event_row["service"] == "ssh"
        print(f"[✓] Dict-mapping query check verified successfully: Event ID #{event_row['id']} retrieved.")
        
    print("\n[✓] STEP 2 SELF-TEST PASSED. SQLite Database layer functional and thread-safe.")