"""
Mini SIEM — Linux Log Collector
================================
Monitors configured Linux log files (real system paths and mock files) in real-time.
Uses background threads and the watchdog library to capture new appends instantly.

Optimized to handle:
- Log rotation (detects inode changes or file truncation).
- Missing files (periodically checks for their creation).
- Restricted read permissions (non-blocking warning, continues on other logs).
- In-memory offset tracking to prevent log duplication.
"""

import os
import sys
import time
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Callable, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Adjust path to import central configuration and database
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from modules.database import db_conn

logger = logging.getLogger("MiniSIEM.Collector")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(config.APP_LOG_LEVEL)


# ═══════════════════════════════════════════════════════════════
#   FILE TRACKER STATE REPRESENTATION
# ═══════════════════════════════════════════════════════════════

class FileState:
    """Tracks the internal OS state of a monitored file to handle rotations and offsets."""
    def __init__(self, path: Path):
        self.path = path
        self.last_offset: int = 0
        self.inode: int = 0
        self.device: int = 0
        self.size: int = 0
        self.is_readable: bool = False
        self.update_state()

    def update_state(self) -> bool:
        """Queries the filesystem to check if the file exists, is readable, and its size/inode."""
        if not self.path.exists():
            self.is_readable = False
            return False
        
        try:
            stat_info = os.stat(self.path)
            self.inode = stat_info.st_ino
            self.device = stat_info.st_dev
            self.size = stat_info.st_size
            self.is_readable = os.access(self.path, os.R_OK)
            return True
        except Exception as e:
            logger.debug(f"Could not read stat for {self.path}: {e}")
            self.is_readable = False
            return False


# ═══════════════════════════════════════════════════════════════
#   WATCHDOG EVENT HANDLER
# ═══════════════════════════════════════════════════════════════

class LogDirectoryWatcher(FileSystemEventHandler):
    """Listens for directory modification events and triggers matching log tailers."""
    def __init__(self, on_modified_callback: Callable[[Path], None]):
        self.callback = on_modified_callback

    def on_modified(self, event):
        if event.is_directory:
            return
        # Forward the path of the modified file
        self.callback(Path(event.src_path))


# ═══════════════════════════════════════════════════════════════
#   LOG COLLECTOR CORE ENGINE
# ═══════════════════════════════════════════════════════════════

class LogCollector:
    """
    Spins up background workers to tail configured Linux logs.
    Communicates new log entries back to the primary pipeline via callbacks.
    """
    def __init__(self, log_sources: List[Dict[str, Any]], line_callback: Callable[[str, str], None]):
        """
        :param log_sources: List of dicts with {"name", "path", "type"}
        :param line_callback: Callback receiving (raw_line, source_name)
        """
        self.sources = log_sources
        self.line_callback = line_callback
        
        self.active_trackers: Dict[str, FileState] = {}
        self.running = False
        self.lock = threading.Lock()
        
        # Watchdog observer to monitor directories containing target logs
        self.observer = Observer()
        self._watcher_threads: List[threading.Thread] = []

    def _update_source_status_in_db(self, name: str, status: str):
        """Helper to safely sync dynamic collector states back to the SQLite metadata table."""
        try:
            with db_conn() as conn:
                conn.execute(
                    "UPDATE log_sources SET status = ? WHERE name = ?",
                    (status, name)
                )
        except Exception as e:
            logger.debug(f"Failed to update status in DB for {name}: {e}")

    def _tail_file(self, tracker: FileState, source_name: str):
        """Reads any newly written bytes since the last known offset."""
        if not tracker.is_readable:
            return

        try:
            with open(tracker.path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                curr_pos = f.tell()

                # If last_offset is 0 and the file has data, decide where to start.
                # To prevent flooding the DB with megabytes of old logs at boot, 
                # we start reading from the END of real system logs, but from the 
                # START (offset 0) for our mock test logs.
                if tracker.last_offset == 0:
                    if "sample" in source_name or "test" in source_name:
                        # For testing, read everything
                        tracker.last_offset = 0
                    else:
                        tracker.last_offset = curr_pos

                # If the file shrank, a rotation or truncation occurred. Reset offset.
                if curr_pos < tracker.last_offset:
                    logger.info(f"Log rotation/truncation detected on {tracker.path} (size decreased).")
                    tracker.last_offset = 0

                # Read new data
                f.seek(tracker.last_offset)
                content = f.read()
                tracker.last_offset = f.tell()

                if content:
                    lines = content.splitlines()
                    for line in lines:
                        cleaned = line.strip()
                        if cleaned:
                            # Enforce maximum line length to prevent buffer-flooding attacks
                            if len(cleaned) > config.COLLECTOR_MAX_LINE_LEN:
                                cleaned = cleaned[:config.COLLECTOR_MAX_LINE_LEN] + " ... [TRUNCATED]"
                            self.line_callback(cleaned, source_name)
                    
                    # Update DB metadata metrics
                    try:
                        with db_conn() as conn:
                            conn.execute(
                                """
                                UPDATE log_sources 
                                SET event_count = event_count + ?, last_event = datetime('now')
                                WHERE name = ?
                                """,
                                (len(lines), source_name)
                            )
                    except Exception as e:
                        logger.debug(f"Failed to update event count metadata for {source_name}: {e}")

        except Exception as e:
            logger.error(f"Error reading appends on {tracker.path}: {e}")

    def _handle_file_event(self, path: Path):
        """Triggered by watchdog when any file in target directory changes."""
        with self.lock:
            for name, tracker in self.active_trackers.items():
                if tracker.path.resolve() == path.resolve():
                    # Update physical properties
                    old_inode = tracker.inode
                    exists = tracker.update_state()

                    if exists:
                        # Inode changed -> Log rotation occured
                        if tracker.inode != old_inode and old_inode != 0:
                            logger.info(f"Log rotation detected on {name} via Inode swap.")
                            # Reset offset to read the new file from the start
                            tracker.last_offset = 0
                            self._update_source_status_in_db(name, "ACTIVE")
                        
                        # Process new lines
                        self._tail_file(tracker, name)
                    else:
                        self._update_source_status_in_db(name, "OFFLINE")

    def _monitor_loop(self):
        """
        Fallback loop running on a background thread.
        Periodically checks missing files to see if they've been created,
        verifies permissions, and polls files if watchdog fails.
        """
        logger.info("Collector fallback monitoring loop started.")
        while self.running:
            with self.lock:
                for src in self.sources:
                    name = src["name"]
                    path = Path(src["path"])

                    if name not in self.active_trackers:
                        self.active_trackers[name] = FileState(path)

                    tracker = self.active_trackers[name]
                    existed_before = tracker.is_readable
                    exists = tracker.update_state()

                    if not exists:
                        if existed_before:
                            logger.warning(f"Log file went missing or unreadable: {path}")
                            self._update_source_status_in_db(name, "OFFLINE")
                    else:
                        # File is present and readable
                        if not existed_before:
                            logger.info(f"Log file successfully detected and opened: {path}")
                            self._update_source_status_in_db(name, "ACTIVE")
                            # Trigger initial read
                            self._tail_file(tracker, name)
                        
                        # Fallback poll (in case OS fails to dispatch filesystem events)
                        if tracker.size != os.path.getsize(path):
                            self._tail_file(tracker, name)

            time.sleep(config.COLLECTOR_POLL_INTERVAL)

    def start(self):
        """Starts background file-system monitors and watchdog observers."""
        with self.lock:
            if self.running:
                return
            self.running = True

        logger.info("Starting Log Collector Engine...")

        # 1. Initialize states & verify readable paths
        for src in self.sources:
            name = src["name"]
            path = Path(src["path"])
            tracker = FileState(path)
            
            self.active_trackers[name] = tracker
            
            if tracker.is_readable:
                logger.info(f"Monitoring active source [{name}]: {path}")
                self._update_source_status_in_db(name, "ACTIVE")
                # Prime the file offset
                self._tail_file(tracker, name)
            else:
                if not path.exists():
                    logger.warning(f"Source [{name}] is OFFLINE (file does not exist): {path}")
                    self._update_source_status_in_db(name, "OFFLINE")
                else:
                    logger.critical(f"Permission Denied reading source [{name}] at {path}. "
                                    f"Run with appropriate read permissions or configure access.")
                    self._update_source_status_in_db(name, "WARNING")

        # 2. Register directories with Watchdog
        watched_directories = set()
        for tracker in self.active_trackers.values():
            # Watch the parent directory of target log file
            parent_dir = tracker.path.parent
            if parent_dir.exists():
                watched_directories.add(parent_dir)

        watcher_handler = LogDirectoryWatcher(self._handle_file_event)
        for directory in watched_directories:
            try:
                self.observer.schedule(watcher_handler, str(directory), recursive=False)
                logger.debug(f"Watchdog registering directory: {directory}")
            except Exception as e:
                logger.error(f"Failed to register watchdog directory {directory}: {e}")

        try:
            self.observer.start()
        except Exception as e:
            logger.error(f"Failed to start watchdog observer: {e}. Falling back entirely to polling.")

        # 3. Start background polling thread
        self._watcher_threads.append(
            threading.Thread(target=self._monitor_loop, name="SIEM-CollectorFallback", daemon=True)
        )
        for thread in self._watcher_threads:
            thread.start()

        logger.info("Log Collector Engine successfully spawned in background.")

    def stop(self):
        """Safely stops background monitoring processes."""
        logger.info("Stopping Log Collector Engine...")
        self.running = False
        
        try:
            self.observer.stop()
            self.observer.join(timeout=2.0)
        except Exception as e:
            logger.debug(f"Error stopping watchdog observer: {e}")

        for thread in self._watcher_threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
                
        logger.info("Log Collector Engine stopped.")


# ═══════════════════════════════════════════════════════════════
#   STANDALONE MONITORING SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Running Collector Module Self-Test...")
    
    # Enable debugging logs
    logger.setLevel(logging.DEBUG)

    # 1. Set up a temporary mock database table
    from modules.database import initialize_db, seed_default_log_sources
    initialize_db()
    seed_default_log_sources()

    # 2. Add local mock files to configuration for testing
    from modules.sample_generator import MOCK_AUTH_LOG, MOCK_WEB_LOG
    
    test_sources = [
        {"name": "mock_auth", "path": str(MOCK_AUTH_LOG), "type": "linux_auth"},
        {"name": "mock_web", "path": str(MOCK_WEB_LOG), "type": "apache_access"},
        {"name": "restricted_test", "path": "/var/log/auth.log", "type": "linux_auth"} # Test permission warning
    ]

    # Ensure mock files exist
    MOCK_AUTH_LOG.parent.mkdir(parents=True, exist_ok=True)
    open(MOCK_AUTH_LOG, "a").close()
    open(MOCK_WEB_LOG, "a").close()

    lines_received = []

    def mock_pipeline_callback(raw_line: str, source: str):
        print(f" [!] COLLECTED -> Source: [{source}] | Line: {raw_line[:90]}")
        lines_received.append(raw_line)

    # Initialize Collector
    collector = LogCollector(test_sources, mock_pipeline_callback)
    collector.start()

    print("[*] Monitoring active. Appending mock lines to trigger file events...")
    time.sleep(1)

    # Simulate dynamic writes to trigger file events
    try:
        with open(MOCK_AUTH_LOG, "a") as f:
            f.write("Feb 28 12:00:00 ubuntu-srv sshd[1234]: Failed password for invalid user hacker from 1.2.3.4 port 22 ssh2\n")
            f.flush()
        
        time.sleep(2)  # Give watchdog a moment to capture the update
        
        with open(MOCK_WEB_LOG, "a") as f:
            f.write('1.2.3.4 - - [28/Feb/202X:12:00:01 +0000] "GET /wp-login.php HTTP/1.1" 404 120\n')
            f.flush()

        time.sleep(2)

        # Assertions
        assert len(lines_received) >= 2, "Collector failed to capture new appends!"
        print(f"[✓] Successfully captured {len(lines_received)} live appends.")
        
        # Test Log Rotation simulation
        print("[*] Simulating log rotation (file recreation)...")
        MOCK_AUTH_LOG.unlink() # Delete file
        time.sleep(1)
        
        with open(MOCK_AUTH_LOG, "w") as f: # Re-create file (new inode)
            f.write("Feb 28 12:00:05 ubuntu-srv sshd[1235]: Failed password for root from 1.2.3.4 port 22\n")
            f.flush()
            
        time.sleep(2)
        assert len(lines_received) >= 3, "Collector failed to handle log rotation and trace the new file!"
        print("[✓] Rotation recovery verified.")

    finally:
        collector.stop()
        
    print("\n[✓] STEP 4 SELF-TEST PASSED. Linux Log Collector functional, non-blocking, and rotation-safe.")