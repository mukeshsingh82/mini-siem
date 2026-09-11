"""
Mini SIEM — Sample Linux Log Generator
=======================================
A testing utility to simulate realistic Linux system and network attacks.
Generates live logs with accurate real-time timestamps and appends them
to local files in logs/samples/.

Supported Simulations:
- SSH Brute Force / Failed Logins
- Successful Login after Multiple Failures (Correlation Engine Test)
- Invalid User Login Attempts
- Direct Root Logins
- Suspicious Sudo & Privilege Escalation attempts
- Web Attacks (HTTP 404 Scanning & SQLi/XSS Injection payloads)
"""

import os
import sys
import time
import random
import argparse
from datetime import datetime
from pathlib import Path

# Adjust path to import central configuration
sys.path.append(str(Path(__file__).resolve().parent.parent))
import config

# Define local mock paths for generated log outputs
MOCK_AUTH_LOG = config.SAMPLES_DIR / "sample_auth.log"
MOCK_SYSLOG   = config.SAMPLES_DIR / "sample_syslog.log"
MOCK_WEB_LOG  = config.SAMPLES_DIR / "sample_web.log"


# ═══════════════════════════════════════════════════════════════
#   HELPER CLASS FOR TIME FORMATTING
# ═══════════════════════════════════════════════════════════════

class LogTemplates:
    """Templates modeling authentic Linux OS and service log lines."""

    @staticmethod
    def get_syslog_time() -> str:
        """Returns traditional syslog date format: 'Mmm dd hh:mm:ss' (e.g. Oct 24 14:02:11)"""
        # Ensure single digit days have an extra space for strict syslog alignment
        now = datetime.now()
        day = now.strftime("%d")
        if day.startswith("0"):
            day = " " + day[1]
        return f"{now.strftime('%b')}{day} {now.strftime('%H:%M:%S')}"

    @staticmethod
    def get_web_time() -> str:
        """Returns Apache/Nginx log time: 'dd/Mmm/yyyy:hh:mm:ss +0000'"""
        return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")

    # --- SSH Log Formats ---
    
    @staticmethod
    def ssh_failed(ip: str, user: str, port: int = 51210) -> str:
        timestamp = LogTemplates.get_syslog_time()
        pid = random.randint(3000, 32000)
        return f"{timestamp} ubuntu-srv sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"

    @staticmethod
    def ssh_invalid_user(ip: str, user: str, port: int = 51212) -> str:
        timestamp = LogTemplates.get_syslog_time()
        pid = random.randint(3000, 32000)
        return f"{timestamp} ubuntu-srv sshd[{pid}]: Invalid user {user} from {ip} port {port} ssh2"

    @staticmethod
    def ssh_accepted(ip: str, user: str, port: int = 51215) -> str:
        timestamp = LogTemplates.get_syslog_time()
        pid = random.randint(3000, 32000)
        return f"{timestamp} ubuntu-srv sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"

    @staticmethod
    def ssh_disconnect(ip: str, user: str) -> str:
        timestamp = LogTemplates.get_syslog_time()
        pid = random.randint(3000, 32000)
        return f"{timestamp} ubuntu-srv sshd[{pid}]: Received disconnect from {ip} port {random.randint(40000,60000)}:11: user sent quit"

    # --- Sudo/PAM Log Formats ---

    @staticmethod
    def sudo_failure(user: str, target_user: str = "root", cmd: str = "/bin/su") -> str:
        timestamp = LogTemplates.get_syslog_time()
        return f"{timestamp} ubuntu-srv sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser={user} rhost= user={target_user}"

    @staticmethod
    def sudo_success(user: str, target_user: str = "root", cmd: str = "/usr/bin/apt-get update") -> str:
        timestamp = LogTemplates.get_syslog_time()
        pwd = f"/home/{user}" if user != "root" else "/root"
        return f"{timestamp} ubuntu-srv sudo:    {user} : TTY=pts/1 ; PWD={pwd} ; USER={target_user} ; COMMAND={cmd}"

    # --- Syslog General Logs ---

    @staticmethod
    def syslog_generic(service: str, message: str) -> str:
        timestamp = LogTemplates.get_syslog_time()
        pid = random.randint(100, 1500)
        return f"{timestamp} ubuntu-srv {service}[{pid}]: {message}"

    # --- Apache / Nginx Web Server Logs ---

    @staticmethod
    def web_access(ip: str, status: int, url: str, method: str = "GET", bytes_sent: int = 240, ua: str = "Mozilla/5.0") -> str:
        timestamp = LogTemplates.get_web_time()
        return f'{ip} - - [{timestamp}] "{method} {url} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"'


# ═══════════════════════════════════════════════════════════════
#   ATTACK GENERATOR SCRIPTING ENGINE
# ═══════════════════════════════════════════════════════════════

class AttackGenerator:
    """Assembles and writes sequences of simulated log events."""

    def __init__(self, slow: bool = False):
        self.slow = slow  # True introduces minor sleeps between events for realism
        self._ensure_files()

    def _ensure_files(self):
        """Creates target test logs directory if missing."""
        config.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    def _write_log(self, path: Path, log_line: str):
        """Appends log line to target file and prints tracking info."""
        with open(path, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
        print(f" [+] APPENDED -> [{path.name}] {log_line[:110]}...")
        if self.slow:
            time.sleep(random.uniform(0.1, 0.5))

    # --- Simulation Targets ---

    def simulate_normal_ssh(self, ip: str, user: str):
        """Simulates a quick normal login and logout workflow."""
        self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_accepted(ip, user))
        self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_disconnect(ip, user))

    def simulate_brute_force_ssh(self, ip: str, user: str, attempts: int = 6):
        """Simulates rapid SSH authentication failures from a single IP."""
        print(f"\n[*] Starting SSH Brute Force simulation: {attempts} failures from {ip} user: {user}")
        for _ in range(attempts):
            self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_failed(ip, user))

    def simulate_account_compromise(self, ip: str, user: str, brute_attempts: int = 4):
        """
        Simulates an account takeover.
        Brute force attempts, followed immediately by a successful login.
        This provides a target payload for our Correlation Engine.
        """
        print(f"\n[*] Starting Account Compromise simulation from {ip} target: {user}")
        for _ in range(brute_attempts):
            self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_failed(ip, user))
        
        # Succeeded after failures
        time.sleep(1)
        self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_accepted(ip, user))
        
        # Followed by a privilege escalation attempt
        self._write_log(MOCK_AUTH_LOG, LogTemplates.sudo_failure(user, "root", "/bin/bash"))

    def simulate_invalid_user_brute(self, ip: str, attempts: int = 5):
        """Simulates a credential stuffing attack hitting non-existent system users."""
        fake_users = ["dbuser", "oracle", "ftpclient", "backup", "jenkins", "tomcat"]
        print(f"\n[*] Starting Credential Stuffing simulation from {ip}")
        for _ in range(attempts):
            user = random.choice(fake_users)
            self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_invalid_user(ip, user))

    def simulate_direct_root_login(self, ip: str):
        """Simulates direct root SSH access (high severity indicator on hard systems)."""
        print(f"\n[*] Simulating Root login from {ip}")
        self._write_log(MOCK_AUTH_LOG, LogTemplates.ssh_accepted(ip, "root"))

    def simulate_suspicious_sudo(self, user: str):
        """Simulates a developer executing unauthorized sudo actions."""
        print(f"\n[*] Simulating unauthorized root escalation actions by {user}")
        self._write_log(MOCK_AUTH_LOG, LogTemplates.sudo_success(user, "root", "/bin/cat /etc/shadow"))
        self._write_log(MOCK_AUTH_LOG, LogTemplates.sudo_success(user, "root", "rm -rf /var/log/audit"))

    def simulate_port_scan(self, ip: str):
        """Simulates a quick horizontal port scan captured via standard firewalls/syslog."""
        print(f"\n[*] Simulating firewall port scan detections from {ip}")
        scanned_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
        random.shuffle(scanned_ports)
        for port in scanned_ports[:10]:
            msg = f"Inbound connection blocked: PROTO=TCP SPT={random.randint(30000, 65000)} DPT={port} on interface eth0"
            self._write_log(MOCK_SYSLOG, LogTemplates.syslog_generic("ufw", msg))

    def simulate_web_404_scan(self, ip: str, requests_count: int = 15):
        """Simulates directory brute-forcing (seeking backup or config directories)."""
        paths = ["/wp-admin", "/admin", "/phpmyadmin", "/config.php", "/backup.zip", "/.env", "/db.sql"]
        print(f"\n[*] Simulating HTTP Directory Discovery Scan from {ip}")
        for _ in range(requests_count):
            target = random.choice(paths) + f"?t={random.randint(10,99)}"
            self._write_log(MOCK_WEB_LOG, LogTemplates.web_access(ip, 404, target, ua="Nikto/Web Scanner"))

    def simulate_web_sqli(self, ip: str):
        """Simulates common SQL Injection probing on query parameters."""
        print(f"\n[*] Simulating SQL Injection exploit payloads from {ip}")
        payloads = [
            "/products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
            "/login.php?user=admin'%20OR%20'1'='1",
            "/search.jsp?q=';%20DROP%20TABLE%20orders;--"
        ]
        for url in payloads:
            self._write_log(MOCK_WEB_LOG, LogTemplates.web_access(ip, 200, url, ua="sqlmap/1.4"))

    def simulate_web_xss(self, ip: str):
        """Simulates cross-site scripting payload injection."""
        print(f"\n[*] Simulating XSS validation exploits from {ip}")
        payloads = [
            "/comments.php?post=1&body=<script>alert(document.cookie)</script>",
            "/search?q=<svg/onload=alert(1)>"
        ]
        for url in payloads:
            self._write_log(MOCK_WEB_LOG, LogTemplates.web_access(ip, 200, url, ua="XSSProbe"))


# ═══════════════════════════════════════════════════════════════
#   CONTINUOUS SIMULATION ENGINE
# ═══════════════════════════════════════════════════════════════

def run_continuous_simulation(interval: float = 3.0):
    """
    Spins in an infinite loop, writing standard normal events and
    intermittently injecting high-severity attacks to simulate active SOC traffic.
    """
    gen = AttackGenerator(slow=False)
    print(f"[i] Starting continuous mock security traffic loop. Interval: {interval}s")
    print(f"[-] Writing logs to directory: {config.SAMPLES_DIR}")
    print("[i] Press Ctrl+C to terminate.")
    
    ips = ["192.168.1.100", "10.0.0.45", "172.16.5.12", "198.51.100.12", "203.0.113.88"]
    users = ["alice", "bob", "developer", "guest", "operator"]
    
    tick = 0
    try:
        while True:
            tick += 1
            choice = random.random()
            
            # 70% chance of standard/normal operations
            if choice < 0.70:
                ip = random.choice(ips)
                user = random.choice(users)
                if choice < 0.35:
                    # Normal SSH Successful authentication
                    gen.simulate_normal_ssh(ip, user)
                elif choice < 0.55:
                    # Normal Web hits
                    gen._write_log(MOCK_WEB_LOG, LogTemplates.web_access(ip, 200, "/index.html", ua="Mozilla/5.0 Chrome"))
                else:
                    # Normal Cron/Syslog noise
                    gen._write_log(MOCK_SYSLOG, LogTemplates.syslog_generic("cron", "pam_unix(cron:session): session opened for user root by (uid=0)"))
            
            # 30% chance of an attack simulation trigger
            else:
                attacker_ip = random.choice(["198.51.100.200", "203.0.113.111", "192.168.1.250"])
                attack_type = random.randint(1, 7)
                
                if attack_type == 1:
                    # SSH brute force
                    gen.simulate_brute_force_ssh(attacker_ip, "root", attempts=5)
                elif attack_type == 2:
                    # Credential stuffing
                    gen.simulate_invalid_user_brute(attacker_ip, attempts=4)
                elif attack_type == 3:
                    # Direct Root Login attempt
                    gen.simulate_direct_root_login(attacker_ip)
                elif attack_type == 4:
                    # Compromise simulation (brute + success + sudo action)
                    gen.simulate_account_compromise(attacker_ip, random.choice(users))
                elif attack_type == 5:
                    # Port scan
                    gen.simulate_port_scan(attacker_ip)
                elif attack_type == 6:
                    # Web directory scan (HTTP 404 brute force)
                    gen.simulate_web_404_scan(attacker_ip, requests_count=8)
                else:
                    # Web injections (SQLi / XSS)
                    if random.choice([True, False]):
                        gen.simulate_web_sqli(attacker_ip)
                    else:
                        gen.simulate_web_xss(attacker_ip)
                        
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Simulation terminated by user request.")


# ═══════════════════════════════════════════════════════════════
#   CLI ENTRYPOINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mini SIEM Mock Log Security Generator")
    parser.add_argument("--mode", choices=["once", "continuous"], default="once",
                        help="Execution mode: 'once' triggers a broad array of immediate attacks; 'continuous' runs an ongoing simulation loop.")
    parser.add_argument("--interval", type=float, default=2.5,
                        help="Delay in seconds between events when running in continuous mode.")
    parser.add_argument("--clear", action="store_true",
                        help="Deletes existing sample log files before starting.")
    
    args = parser.parse_args()
    
    if args.clear:
        print("[*] Flushing older sample log files...")
        for path in (MOCK_AUTH_LOG, MOCK_SYSLOG, MOCK_WEB_LOG):
            if path.exists():
                path.unlink()
                print(f" [x] DELETED: {path.name}")
                
    if args.mode == "continuous":
        run_continuous_simulation(args.interval)
    else:
        print("[*] Triggering standalone SIEM attack sequence simulation...")
        g = AttackGenerator(slow=True)
        
        # Dispatch one of each major attack scenario
        g.simulate_brute_force_ssh("198.51.100.77", "admin", attempts=5)
        g.simulate_account_compromise("203.0.113.14", "alice", brute_attempts=4)
        g.simulate_invalid_user_brute("198.51.100.80", attempts=3)
        g.simulate_direct_root_login("203.0.113.25")
        g.simulate_suspicious_sudo("bob")
        g.simulate_port_scan("198.51.100.95")
        g.simulate_web_404_scan("192.168.1.115", requests_count=12)
        g.simulate_web_sqli("192.168.1.115")
        g.simulate_web_xss("192.168.1.115")
        
        print("\n[✓] Standalone attack sequence generated. Target files written successfully:")
        print(f"  └─ Auth logs: {MOCK_AUTH_LOG}")
        print(f"  └─ Syslog:    {MOCK_SYSLOG}")
        print(f"  └─ Web logs:  {MOCK_WEB_LOG}")
        print("\n[✓] STEP 3 COMPLETE.")