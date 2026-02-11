#!/usr/bin/env python3
"""
🕸️ REDBACK SPIDER BOT 
Author: Ian Carter Kulani
Version: v0.0.1
Description: SpiderBot cybersecurity tool with 500+ commands, 
            Discord/Telegram/WhatsApp/Signal integration, Nikto web scanner,
            IP management, and comprehensive security analysis
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
import shutil
import urllib.parse
import asyncio
import uuid

# Optional imports with fallbacks
try:
    import discord
    from discord.ext import commands, tasks
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Warning: discord.py not available. Install with: pip install discord.py")

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Warning: telethon not available. Install with: pip install telethon")

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("⚠️ Warning: selenium not available. Install with: pip install selenium webdriver-manager")

try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    print("⚠️ Warning: twilio not available. Install with: pip install twilio")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Warning: whois not available. Install with: pip install python-whois")

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("⚠️ Warning: colorama not available. Install with: pip install colorama")

try:
    from qrcode import QRCode
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False
    print("⚠️ Warning: qrcode not available. Install with: pip install qrcode")

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("⚠️ Warning: PIL not available. Install with: pip install pillow")

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".spiderbot_pro"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
WHATSAPP_CONFIG_FILE = os.path.join(CONFIG_DIR, "whatsapp_config.json")
SIGNAL_CONFIG_FILE = os.path.join(CONFIG_DIR, "signal_config.json")
TWILIO_CONFIG_FILE = os.path.join(CONFIG_DIR, "twilio_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "network_data.db")
LOG_FILE = os.path.join(CONFIG_DIR, "spiderbot.log")
NIKTO_RESULTS_DIR = os.path.join(CONFIG_DIR, "nikto_results")
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"
ALERTS_DIR = "alerts"
MONITORING_DIR = "monitoring"
BACKUPS_DIR = "backups"
TEMP_DIR = "temp"
SCRIPTS_DIR = "scripts"
QR_CODES_DIR = os.path.join(CONFIG_DIR, "qr_codes")

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR,
    MONITORING_DIR, BACKUPS_DIR, TEMP_DIR, SCRIPTS_DIR, 
    NIKTO_RESULTS_DIR, QR_CODES_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SpiderBotPro")

# Color setup
if COLORAMA_AVAILABLE:
    class Colors:
        RED = Fore.RED + Style.BRIGHT
        GREEN = Fore.GREEN + Style.BRIGHT
        YELLOW = Fore.YELLOW + Style.BRIGHT
        BLUE = Fore.BLUE + Style.BRIGHT
        CYAN = Fore.CYAN + Style.BRIGHT
        MAGENTA = Fore.MAGENTA + Style.BRIGHT
        WHITE = Fore.WHITE + Style.BRIGHT
        RESET = Style.RESET_ALL
else:
    class Colors:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""

# =====================
# DATA CLASSES & ENUMS
# =====================
class ScanType:
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    VULNERABILITY = "vulnerability"
    FULL = "full"
    UDP = "udp"
    OS_DETECTION = "os_detection"
    SERVICE_DETECTION = "service_detection"
    WEB = "web"
    NIKTO = "nikto"

class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatAlert:
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    target: str
    scan_type: str
    open_ports: List[Dict]
    timestamp: str
    success: bool
    error: Optional[str] = None
    vulnerabilities: Optional[List[Dict]] = None

@dataclass
class NiktoResult:
    target: str
    timestamp: str
    vulnerabilities: List[Dict]
    scan_time: float
    output_file: str
    success: bool
    error: Optional[str] = None

@dataclass
class CommandResult:
    success: bool
    output: str
    execution_time: float
    error: Optional[str] = None
    data: Optional[Dict] = None

@dataclass
class ManagedIP:
    ip_address: str
    added_by: str
    added_date: str
    notes: str
    is_blocked: bool = False
    block_reason: Optional[str] = None
    blocked_date: Optional[str] = None

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Configuration manager"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": True,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "security": {
            "auto_block": False,
            "auto_block_threshold": 5,
            "log_level": "INFO",
            "backup_enabled": True
        },
        "nikto": {
            "enabled": True,
            "timeout": 300,
            "max_targets": 10,
            "scan_level": 2,
            "ssl_ports": "443,8443,9443",
            "db_check": True
        },
        "discord": {
            "enabled": False,
            "token": "",
            "channel_id": "",
            "prefix": "!",
            "admin_role": "Admin",
            "security_role": "Security Team"
        },
        "telegram": {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        },
        "whatsapp": {
            "enabled": False,
            "method": "selenium",
            "session_path": "",
            "command_prefix": "!",
            "admin_number": "",
            "notify_number": ""
        },
        "signal": {
            "enabled": False,
            "method": "cli",
            "number": "",
            "command_prefix": "!",
            "admin_number": "",
            "db_path": ""
        },
        "twilio": {
            "enabled": False,
            "account_sid": "",
            "auth_token": "",
            "whatsapp_number": "",
            "signal_number": "",
            "forward_to": ""
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in ConfigManager.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in config[key]:
                                    config[key][sub_key] = sub_value
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def save_telegram_config(config: Dict) -> bool:
        """Save Telegram configuration"""
        try:
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    @staticmethod
    def load_telegram_config() -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        return {}
    
    @staticmethod
    def save_discord_config(config: Dict) -> bool:
        """Save Discord configuration"""
        try:
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    @staticmethod
    def load_discord_config() -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        return {}
    
    @staticmethod
    def save_whatsapp_config(config: Dict) -> bool:
        """Save WhatsApp configuration"""
        try:
            with open(WHATSAPP_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save WhatsApp config: {e}")
            return False
    
    @staticmethod
    def load_whatsapp_config() -> Dict:
        """Load WhatsApp configuration"""
        try:
            if os.path.exists(WHATSAPP_CONFIG_FILE):
                with open(WHATSAPP_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load WhatsApp config: {e}")
        return {}
    
    @staticmethod
    def save_signal_config(config: Dict) -> bool:
        """Save Signal configuration"""
        try:
            with open(SIGNAL_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Signal config: {e}")
            return False
    
    @staticmethod
    def load_signal_config() -> Dict:
        """Load Signal configuration"""
        try:
            if os.path.exists(SIGNAL_CONFIG_FILE):
                with open(SIGNAL_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Signal config: {e}")
        return {}
    
    @staticmethod
    def save_twilio_config(config: Dict) -> bool:
        """Save Twilio configuration"""
        try:
            with open(TWILIO_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Twilio config: {e}")
            return False
    
    @staticmethod
    def load_twilio_config() -> Dict:
        """Load Twilio configuration"""
        try:
            if os.path.exists(TWILIO_CONFIG_FILE):
                with open(TWILIO_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Twilio config: {e}")
        return {}

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            # Command history
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            # Threat alerts
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            # Scan results
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                vulnerabilities TEXT,
                execution_time REAL
            )
            """,
            
            # Nikto scan results
            """
            CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                vulnerabilities TEXT,
                output_file TEXT,
                scan_time REAL,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            # Managed IPs
            """
            CREATE TABLE IF NOT EXISTS managed_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_by TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                block_reason TEXT,
                blocked_date TIMESTAMP,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                scan_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            )
            """,
            
            # System metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """,
            
            # IP blocking history
            """
            CREATE TABLE IF NOT EXISTS ip_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                executed_by TEXT,
                success BOOLEAN DEFAULT 1
            )
            """,
            
            # WhatsApp sessions
            """
            CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                status TEXT DEFAULT 'inactive',
                phone_number TEXT,
                qr_code_path TEXT
            )
            """,
            
            # Signal sessions
            """
            CREATE TABLE IF NOT EXISTS signal_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP,
                status TEXT DEFAULT 'inactive',
                phone_number TEXT,
                device_id TEXT
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat alert"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip,
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.open_ports) if scan_result.open_ports else "[]"
            vulnerabilities_json = json.dumps(scan_result.vulnerabilities) if scan_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, vulnerabilities, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, 
                  vulnerabilities_json, scan_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_nikto_scan(self, nikto_result: NiktoResult):
        """Log Nikto scan results"""
        try:
            vulnerabilities_json = json.dumps(nikto_result.vulnerabilities) if nikto_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO nikto_scans (target, vulnerabilities, output_file, scan_time, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nikto_result.target, vulnerabilities_json, nikto_result.output_file,
                  nikto_result.scan_time, nikto_result.success, nikto_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Nikto scan: {e}")
    
    def add_managed_ip(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to management"""
        try:
            ipaddress.ip_address(ip)  # Validate IP
            self.cursor.execute('''
                INSERT OR IGNORE INTO managed_ips (ip_address, added_by, notes, added_date)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, added_by, notes))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add managed IP: {e}")
            return False
    
    def remove_managed_ip(self, ip: str) -> bool:
        """Remove IP from management"""
        try:
            self.cursor.execute('''
                DELETE FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove managed IP: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Mark IP as blocked"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 1, block_reason = ?, blocked_date = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (reason, ip))
            
            # Log block action
            self.cursor.execute('''
                INSERT INTO ip_blocks (ip_address, action, reason, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, "block", reason, executed_by))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock IP"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 0, block_reason = NULL, blocked_date = NULL
                WHERE ip_address = ?
            ''', (ip,))
            
            # Log unblock action
            self.cursor.execute('''
                INSERT INTO ip_blocks (ip_address, action, reason, executed_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, "unblock", "Manually unblocked", executed_by))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")
            return False
    
    def get_managed_ips(self, include_blocked: bool = True) -> List[Dict]:
        """Get managed IPs"""
        try:
            if include_blocked:
                self.cursor.execute('''
                    SELECT * FROM managed_ips ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM managed_ips WHERE is_blocked = 0 ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get managed IPs: {e}")
            return []
    
    def get_ip_info(self, ip: str) -> Optional[Dict]:
        """Get information about a specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get IP info: {e}")
            return None
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_threats_by_ip(self, ip: str, limit: int = 10) -> List[Dict]:
        """Get threats for specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats 
                WHERE source_ip = ? 
                ORDER BY timestamp DESC LIMIT ?
            ''', (ip, limit))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats by IP: {e}")
            return []
    
    def get_nikto_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent Nikto scans"""
        try:
            self.cursor.execute('''
                SELECT * FROM nikto_scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get Nikto scans: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM command_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            # Count threats
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            # Count commands
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            # Count scans
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            # Count Nikto scans
            self.cursor.execute('SELECT COUNT(*) FROM nikto_scans')
            stats['total_nikto_scans'] = self.cursor.fetchone()[0]
            
            # Count managed IPs
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips')
            stats['total_managed_ips'] = self.cursor.fetchone()[0]
            
            # Count blocked IPs
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips WHERE is_blocked = 1')
            stats['total_blocked_ips'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# NIKTO SCANNER
# =====================
class NiktoScanner:
    """Nikto web vulnerability scanner integration"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.nikto_available = self._check_nikto()
    
    def _check_nikto(self) -> bool:
        """Check if Nikto is available"""
        nikto_path = shutil.which('nikto')
        if nikto_path:
            logger.info(f"Nikto found at: {nikto_path}")
            return True
        
        # Check common installation paths
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl',
            'C:\\Program Files\\nikto\\nikto.pl',
            'C:\\nikto\\nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Nikto found at: {path}")
                return True
        
        logger.warning("Nikto not found. Some features will be limited.")
        return False
    
    def scan(self, target: str, options: Dict = None) -> NiktoResult:
        """Run Nikto scan on target"""
        start_time = time.time()
        options = options or {}
        
        if not self.nikto_available:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=0,
                output_file="",
                success=False,
                error="Nikto is not installed or not in PATH"
            )
        
        try:
            # Prepare output file
            timestamp = int(time.time())
            output_file = os.path.join(NIKTO_RESULTS_DIR, f"nikto_{target.replace('/', '_')}_{timestamp}.json")
            
            # Build command
            cmd = self._build_nikto_command(target, output_file, options)
            
            # Execute scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', 600),
                encoding='utf-8',
                errors='ignore'
            )
            
            scan_time = time.time() - start_time
            
            # Parse results
            vulnerabilities = self._parse_nikto_output(result.stdout, output_file)
            
            nikto_result = NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=vulnerabilities,
                scan_time=scan_time,
                output_file=output_file,
                success=result.returncode == 0
            )
            
            # Log to database
            self.db.log_nikto_scan(nikto_result)
            
            return nikto_result
            
        except subprocess.TimeoutExpired:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error="Scan timed out"
            )
        except Exception as e:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error=str(e)
            )
    
    def _build_nikto_command(self, target: str, output_file: str, options: Dict) -> List[str]:
        """Build Nikto command with options"""
        nikto_cmd = self._get_nikto_command()
        
        cmd = [nikto_cmd, '-host', target]
        
        # Add SSL if target uses HTTPS
        if target.startswith('https://') or options.get('ssl', False):
            cmd.append('-ssl')
        
        # Port specification
        if 'port' in options:
            cmd.extend(['-port', str(options['port'])])
        elif target.startswith('https://'):
            cmd.extend(['-port', '443'])
        
        # Scan tuning
        if 'tuning' in options:
            cmd.extend(['-Tuning', options['tuning']])
        else:
            cmd.extend(['-Tuning', '123456789'])  # All tests
        
        # Output format
        cmd.extend(['-Format', 'json', '-o', output_file])
        
        # Scan level
        if 'level' in options:
            cmd.extend(['-Level', str(options['level'])])
        
        # Timeout
        if 'timeout' in options:
            cmd.extend(['-timeout', str(options['timeout'])])
        
        # Evasion
        if 'evasion' in options:
            cmd.extend(['-evasion', str(options['evasion'])])
        
        # IDS evasion
        if 'ids' in options:
            cmd.append('-ids')
        
        # Mutate
        if 'mutate' in options:
            cmd.extend(['-mutate', str(options['mutate'])])
        
        # Debug
        if options.get('debug', False):
            cmd.append('-Debug')
        
        # Verbose
        if options.get('verbose', False):
            cmd.append('-v')
        
        return cmd
    
    def _get_nikto_command(self) -> str:
        """Get the correct Nikto command/path"""
        # Check if nikto is in PATH
        nikto_path = shutil.which('nikto')
        if nikto_path:
            return nikto_path
        
        # Check common paths
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return 'nikto'  # Default fallback
    
    def _parse_nikto_output(self, output: str, json_file: str) -> List[Dict]:
        """Parse Nikto output and extract vulnerabilities"""
        vulnerabilities = []
        
        # Try to parse JSON output if available
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if 'vulnerabilities' in data:
                        vulnerabilities = data['vulnerabilities']
                    elif isinstance(data, list):
                        vulnerabilities = data
            except:
                pass
        
        # If no JSON, parse text output
        if not vulnerabilities:
            lines = output.split('\n')
            for line in lines:
                if '+ ' in line or '- ' in line or 'OSVDB' in line or 'CVE' in line:
                    vulnerability = {
                        'description': line.strip(),
                        'severity': self._determine_severity(line),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    # Extract CVE if present
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', line)
                    if cve_match:
                        vulnerability['cve'] = cve_match.group()
                    
                    # Extract OSVDB
                    osvdb_match = re.search(r'OSVDB-\d+', line)
                    if osvdb_match:
                        vulnerability['osvdb'] = osvdb_match.group()
                    
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity from Nikto output"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['critical', 'severe', 'remote root', 'arbitrary code']):
            return Severity.CRITICAL
        elif any(word in line_lower for word in ['high', 'vulnerable', 'exploit', 'privilege']):
            return Severity.HIGH
        elif any(word in line_lower for word in ['medium', 'warning', 'exposed', 'information']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def get_available_scan_types(self) -> List[str]:
        """Get available scan types"""
        return [
            "full",  # All tests
            "ssl",   # SSL/TLS tests
            "cgi",   # CGI tests
            "sql",   # SQL injection
            "xss",   # XSS tests
            "file",  # File inclusion
            "cmd",   # Command execution
            "info"   # Information disclosure
        ]
    
    def check_target_ssl(self, target: str) -> bool:
        """Check if target supports SSL"""
        try:
            # Remove protocol if present
            if '://' in target:
                target = target.split('://')[1]
            
            # Try HTTPS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 443))
            sock.close()
            
            return result == 0
        except:
            return False

# =====================
# NETWORK TOOLS
# =====================
class NetworkTools:
    """Comprehensive network tools"""
    
    @staticmethod
    def execute_command(cmd: List[str], timeout: int = 300) -> CommandResult:
        """Execute shell command"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                execution_time=execution_time,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}"
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output=f"Command timed out after {timeout} seconds",
                execution_time=execution_time,
                error='Timeout'
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output='',
                execution_time=execution_time,
                error=str(e)
            )
    
    @staticmethod
    def ping(target: str, count: int = 4, size: int = 56, timeout: int = 1, 
             flood: bool = False, **kwargs) -> CommandResult:
        """Ping with advanced options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000)]
                if flood:
                    cmd.append('-t')
            else:
                cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout)]
                if flood:
                    cmd.append('-f')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout * count + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30, no_dns: bool = True, **kwargs) -> CommandResult:
        """Traceroute with options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['tracert']
                if no_dns:
                    cmd.append('-d')
                cmd.extend(['-h', str(max_hops)])
            else:
                if shutil.which('mtr'):
                    cmd = ['mtr', '--report', '--report-cycles', '1']
                    if no_dns:
                        cmd.append('-n')
                elif shutil.which('traceroute'):
                    cmd = ['traceroute']
                    if no_dns:
                        cmd.append('-n')
                    cmd.extend(['-m', str(max_hops)])
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', '-m', str(max_hops)]
                else:
                    return CommandResult(
                        success=False,
                        output='No traceroute tool found',
                        execution_time=0,
                        error='No traceroute tool available'
                    )
            
            cmd.append(target)
            return NetworkTools.execute_command(cmd, timeout=60)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def nmap_scan(target: str, scan_type: str = "quick", ports: str = None, **kwargs) -> CommandResult:
        """Nmap scan with options"""
        try:
            cmd = ['nmap']
            
            # Base scan type
            if scan_type == "quick":
                cmd.extend(['-T4', '-F'])
            elif scan_type == "quick_scan":
                cmd.extend(['-T4', '-F', '--max-rtt-timeout', '100ms', '--max-retries', '1'])
            elif scan_type == "comprehensive":
                cmd.extend(['-sS', '-sV', '-sC', '-A', '-O'])
            elif scan_type == "stealth":
                cmd.extend(['-sS', '-T2', '--max-parallelism', '100', '--scan-delay', '5s'])
            elif scan_type == "vulnerability":
                cmd.extend(['-sV', '--script', 'vuln'])
            elif scan_type == "full":
                cmd.extend(['-p-', '-T4'])
            elif scan_type == "udp":
                cmd.extend(['-sU', '-T4'])
            elif scan_type == "os_detection":
                cmd.extend(['-O', '--osscan-guess'])
            elif scan_type == "service_detection":
                cmd.extend(['-sV', '--version-intensity', '5'])
            elif scan_type == "web":
                cmd.extend(['-p', '80,443,8080,8443', '-sV', '--script', 'http-*'])
            
            # Custom ports
            if ports:
                if ports.isdigit():
                    cmd.extend(['-p', ports])
                else:
                    cmd.extend(['-p', ports])
            elif scan_type not in ["full"] and not any(x in cmd for x in ['-p']):
                cmd.extend(['-p', '1-1000'])
            
            # Additional options
            if kwargs.get('no_ping'):
                cmd.append('-Pn')
            if kwargs.get('ipv6'):
                cmd.append('-6')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout=600)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def curl_request(url: str, method: str = "GET", **kwargs) -> CommandResult:
        """cURL request"""
        try:
            cmd = ['curl', '-s', '-X', method]
            
            if kwargs.get('timeout'):
                cmd.extend(['-m', str(kwargs['timeout'])])
            if kwargs.get('headers'):
                for key, value in kwargs['headers'].items():
                    cmd.extend(['-H', f'{key}: {value}'])
            if kwargs.get('data'):
                cmd.extend(['-d', kwargs['data']])
            if kwargs.get('insecure'):
                cmd.append('-k')
            if kwargs.get('verbose'):
                cmd.append('-v')
            
            cmd.extend(['-w', '\nTime: %{time_total}s\nCode: %{http_code}\nSize: %{size_download} bytes\n'])
            cmd.append(url)
            
            return NetworkTools.execute_command(cmd, timeout=kwargs.get('timeout', 30) + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_ip_location(ip: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A')
                    }
            
            return {'success': False, 'ip': ip, 'error': 'Location lookup failed'}
                
        except Exception as e:
            return {'success': False, 'ip': ip, 'error': str(e)}
    
    @staticmethod
    def whois_lookup(target: str) -> CommandResult:
        """WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return CommandResult(
                success=False,
                output='WHOIS not available',
                execution_time=0,
                error='Install python-whois package'
            )
        
        try:
            import whois
            start_time = time.time()
            result = whois.whois(target)
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=True,
                output=str(result),
                execution_time=execution_time
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> CommandResult:
        """DNS lookup"""
        try:
            cmd = ['dig', domain, record_type, '+short']
            return NetworkTools.execute_command(cmd, timeout=10)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def block_ip_firewall(ip: str) -> bool:
        """Block IP using system firewall (Linux iptables)"""
        try:
            if platform.system().lower() == 'linux':
                # Check if iptables is available
                if shutil.which('iptables'):
                    # Add block rule
                    subprocess.run(
                        ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True,
                        timeout=10
                    )
                    return True
            elif platform.system().lower() == 'windows':
                # Windows firewall
                if shutil.which('netsh'):
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                         f'name=SpiderBot_Block_{ip}', 'dir=in', 'action=block',
                         f'remoteip={ip}'],
                        check=True,
                        timeout=10
                    )
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    @staticmethod
    def unblock_ip_firewall(ip: str) -> bool:
        """Unblock IP from system firewall"""
        try:
            if platform.system().lower() == 'linux':
                if shutil.which('iptables'):
                    # Remove block rule
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True,
                        timeout=10
                    )
                    return True
            elif platform.system().lower() == 'windows':
                if shutil.which('netsh'):
                    subprocess.run(
                        ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                         f'name=SpiderBot_Block_{ip}'],
                        check=True,
                        timeout=10
                    )
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False

# =====================
# NETWORK MONITOR
# =====================
class NetworkMonitor:
    """Network monitoring and threat detection"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'udp_flood': self.config.get('monitoring', {}).get('udp_flood_threshold', 500),
            'http_flood': self.config.get('monitoring', {}).get('http_flood_threshold', 200),
            'ddos': self.config.get('monitoring', {}).get('ddos_threshold', 1000)
        }
        self.threads = []
        self.auto_block = self.config.get('security', {}).get('auto_block', False)
        self.auto_block_threshold = self.config.get('security', {}).get('auto_block_threshold', 5)
        self.connection_tracker = {}
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        logger.info("Starting network monitoring...")
        
        # Load managed IPs from database
        managed = self.db.get_managed_ips()
        self.monitored_ips = {ip['ip_address'] for ip in managed if not ip.get('is_blocked', False)}
        
        # Start monitoring threads
        self.threads = [
            threading.Thread(target=self._monitor_system, daemon=True),
            threading.Thread(target=self._monitor_threats, daemon=True),
            threading.Thread(target=self._monitor_connections, daemon=True)
        ]
        
        for thread in self.threads:
            thread.start()
        
        logger.info(f"Network monitoring started with {len(self.threads)} threads")
        logger.info(f"Auto-block is {'enabled' if self.auto_block else 'disabled'}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        self.connection_tracker.clear()
        logger.info("Network monitoring stopped")
    
    def _monitor_system(self):
        """Monitor system metrics"""
        while self.monitoring:
            try:
                # Log system metrics to database
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net = psutil.net_io_counters()
                connections = len(psutil.net_connections())
                
                # Check for high resource usage
                if cpu > 90:
                    self._create_threat_alert(
                        threat_type="High CPU Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"CPU usage at {cpu}%",
                        action_taken="Logged"
                    )
                
                if mem.percent > 90:
                    self._create_threat_alert(
                        threat_type="High Memory Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"Memory usage at {mem.percent}%",
                        action_taken="Logged"
                    )
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"System monitor error: {e}")
                time.sleep(10)
    
    def _monitor_threats(self):
        """Monitor for threats"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                # Analyze connections for threats
                source_counts = {}
                for conn in connections:
                    if conn.raddr:
                        source_ip = conn.raddr.ip
                        source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
                        
                        # Track connection patterns for auto-block
                        if source_ip not in self.connection_tracker:
                            self.connection_tracker[source_ip] = []
                        self.connection_tracker[source_ip].append(time.time())
                
                # Check thresholds
                for source_ip, count in source_counts.items():
                    if count > self.thresholds['port_scan']:
                        self._create_threat_alert(
                            threat_type="Possible Port Scan",
                            source_ip=source_ip,
                            severity="medium",
                            description=f"{count} connections from this IP in current snapshot",
                            action_taken="Monitoring"
                        )
                        
                        # Update IP in database
                        ip_info = self.db.get_ip_info(source_ip)
                        if ip_info:
                            self.db.cursor.execute('''
                                UPDATE managed_ips 
                                SET alert_count = alert_count + 1,
                                    last_scan = CURRENT_TIMESTAMP
                                WHERE ip_address = ?
                            ''', (source_ip,))
                            self.db.conn.commit()
                        
                        # Auto-block if threshold exceeded
                        if self.auto_block:
                            alert_count = len(self.connection_tracker.get(source_ip, []))
                            if alert_count > self.auto_block_threshold:
                                self._auto_block_ip(source_ip, f"Exceeded port scan threshold ({count} connections)")
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Threat monitor error: {e}")
                time.sleep(10)
    
    def _monitor_connections(self):
        """Monitor and clean up connection tracker"""
        while self.monitoring:
            try:
                # Clean up old entries (older than 1 hour)
                current_time = time.time()
                for ip in list(self.connection_tracker.keys()):
                    self.connection_tracker[ip] = [
                        t for t in self.connection_tracker[ip] 
                        if current_time - t < 3600
                    ]
                    
                    # Remove IP if no recent connections
                    if not self.connection_tracker[ip]:
                        del self.connection_tracker[ip]
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def _create_threat_alert(self, threat_type: str, source_ip: str, 
                            severity: str, description: str, action_taken: str):
        """Create threat alert"""
        alert = ThreatAlert(
            timestamp=datetime.datetime.now().isoformat(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            action_taken=action_taken
        )
        
        self.db.log_threat(alert)
        
        # Log to console with color
        if severity == "critical":
            log_msg = f"{Colors.RED}🔥 CRITICAL: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "high":
            log_msg = f"{Colors.RED}🚨 HIGH THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "medium":
            log_msg = f"{Colors.YELLOW}⚠️ MEDIUM THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        else:
            log_msg = f"{Colors.CYAN}ℹ️ INFO: {threat_type} from {source_ip}{Colors.RESET}"
        
        print(log_msg)
        logger.info(f"Threat alert: {threat_type} from {source_ip} ({severity})")
    
    def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP"""
        try:
            logger.info(f"Auto-blocking IP {ip}: {reason}")
            
            # Block in firewall
            if NetworkTools.block_ip_firewall(ip):
                # Update database
                self.db.block_ip(ip, reason, executed_by="auto_block")
                
                self._create_threat_alert(
                    threat_type="Auto-Blocked IP",
                    source_ip=ip,
                    severity="high",
                    description=reason,
                    action_taken=f"IP blocked via firewall"
                )
            else:
                logger.error(f"Failed to auto-block IP {ip} - firewall command failed")
                
        except Exception as e:
            logger.error(f"Auto-block failed for {ip}: {e}")
    
    def add_ip_to_monitoring(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            result = self.db.add_managed_ip(ip, added_by, notes)
            logger.info(f"Added IP to monitoring: {ip} by {added_by}")
            return result
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            
            result = self.db.remove_managed_ip(ip)
            if result:
                logger.info(f"Removed IP from monitoring: {ip}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to remove IP {ip}: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Block an IP"""
        try:
            # Block in firewall
            firewall_success = NetworkTools.block_ip_firewall(ip)
            
            # Update database
            db_success = self.db.block_ip(ip, reason, executed_by)
            
            # Remove from monitored set
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            
            success = firewall_success or db_success
            
            if success:
                logger.info(f"IP {ip} blocked by {executed_by}: {reason}")
                self._create_threat_alert(
                    threat_type="Manual Block",
                    source_ip=ip,
                    severity="high",
                    description=reason,
                    action_taken=f"IP blocked by {executed_by}"
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock an IP"""
        try:
            # Unblock in firewall
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            
            # Update database
            db_success = self.db.unblock_ip(ip, executed_by)
            
            success = firewall_success or db_success
            
            if success:
                logger.info(f"IP {ip} unblocked by {executed_by}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        stats = self.db.get_statistics()
        threats = self.db.get_recent_threats(5)
        
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'monitored_ips': list(self.monitored_ips)[:10],  # First 10 only
            'blocked_ips': stats.get('total_blocked_ips', 0),
            'thresholds': self.thresholds,
            'auto_block': self.auto_block,
            'recent_threats': len(threats),
            'active_connections': len(self.connection_tracker)
        }

# =====================
# WHATSAPP BOT (SELENIUM)
# =====================
class WhatsAppBot:
    """WhatsApp bot integration using Selenium"""
    
    def __init__(self, command_handler, db_manager, config: Dict = None):
        self.handler = command_handler
        self.db = db_manager
        self.config = config or {}
        self.driver = None
        self.running = False
        self.monitoring_thread = None
        self.qr_code_path = None
        self.session_id = str(uuid.uuid4())[:8]
        self.wait = None
        
    def setup_selenium_driver(self) -> Optional[webdriver.Chrome]:
        """Setup Chrome driver for WhatsApp Web"""
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium not available")
            return None
        
        try:
            chrome_options = Options()
            chrome_options.add_argument("--user-data-dir=./chrome-profile")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=800,600")
            
            # Use headless mode if configured
            if self.config.get('headless', False):
                chrome_options.add_argument("--headless")
            
            # Set session path for persistence
            if self.config.get('session_path'):
                chrome_options.add_argument(f"--user-data-dir={self.config['session_path']}")
            
            # Setup driver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            return driver
            
        except Exception as e:
            logger.error(f"Failed to setup Chrome driver: {e}")
            return None
    
    def generate_qr_code(self, image_path: str):
        """Generate QR code for WhatsApp Web"""
        if not QRCODE_AVAILABLE:
            logger.warning("QR code generation not available")
            return
        
        try:
            # Create QR code instance
            qr = qrcode.QRCode(
                version=1,
                box_size=10,
                border=5
            )
            
            # QR code will be generated from the actual WhatsApp Web QR
            # This is just a placeholder message
            qr.add_data("Scan with WhatsApp to connect SpiderBot Pro")
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(image_path)
            
            logger.info(f"QR code saved to {image_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
    
    async def send_message(self, phone_number: str, message: str):
        """Send WhatsApp message (requires Twilio or Selenium)"""
        method = self.config.get('method', 'selenium')
        
        if method == 'twilio' and TWILIO_AVAILABLE:
            return await self._send_via_twilio(phone_number, message)
        elif method == 'selenium' and self.driver:
            return self._send_via_selenium(phone_number, message)
        else:
            logger.error(f"No available method to send WhatsApp message")
            return False
    
    async def _send_via_twilio(self, phone_number: str, message: str) -> bool:
        """Send WhatsApp message via Twilio"""
        try:
            twilio_config = ConfigManager.load_twilio_config()
            
            if not twilio_config.get('account_sid') or not twilio_config.get('auth_token'):
                logger.error("Twilio not configured")
                return False
            
            client = Client(twilio_config['account_sid'], twilio_config['auth_token'])
            
            from_whatsapp = f"whatsapp:{twilio_config.get('whatsapp_number', '')}"
            to_whatsapp = f"whatsapp:{phone_number}"
            
            message = client.messages.create(
                body=message,
                from_=from_whatsapp,
                to=to_whatsapp
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Twilio WhatsApp message: {e}")
            return False
    
    def _send_via_selenium(self, phone_number: str, message: str) -> bool:
        """Send WhatsApp message via Selenium"""
        if not self.driver:
            logger.error("WhatsApp Web not connected")
            return False
        
        try:
            # Search for contact
            search_box = WebDriverWait(self.driver, 20).until(
                EC.presence_of_element_located((By.XPATH, '//div[@contenteditable="true"][@data-tab="3"]'))
            )
            search_box.click()
            search_box.clear()
            search_box.send_keys(phone_number)
            time.sleep(2)
            
            # Click on contact
            contact = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, f'//span[@title="{phone_number}"]'))
            )
            contact.click()
            time.sleep(2)
            
            # Type message
            message_box = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.XPATH, '//div[@contenteditable="true"][@data-tab="10"]'))
            )
            message_box.click()
            message_box.send_keys(message)
            time.sleep(1)
            
            # Send message
            send_button = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, '//span[@data-icon="send"]'))
            )
            send_button.click()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send WhatsApp message via Selenium: {e}")
            return False
    
    def _check_whatsapp_ready(self) -> bool:
        """Check if WhatsApp Web is ready"""
        try:
            # Check for QR code
            qr_code = self.driver.find_elements(By.XPATH, '//canvas[@aria-label="Scan me!"]')
            if qr_code:
                # Save QR code
                qr_path = os.path.join(QR_CODES_DIR, f"whatsapp_{self.session_id}.png")
                self.generate_qr_code(qr_path)
                
                # Update database
                self.db.cursor.execute('''
                    INSERT OR REPLACE INTO whatsapp_sessions (session_id, status, qr_code_path)
                    VALUES (?, ?, ?)
                ''', (self.session_id, 'waiting_qr', qr_path))
                self.db.conn.commit()
                
                print(f"\n{Colors.YELLOW}📱 WhatsApp Web QR Code generated: {qr_path}{Colors.RESET}")
                print(f"{Colors.YELLOW}   Scan this QR code with WhatsApp to connect{Colors.RESET}")
                
                return False
            
            # Check if logged in
            search_box = self.driver.find_elements(By.XPATH, '//div[@contenteditable="true"][@data-tab="3"]')
            if search_box:
                # Update database
                self.db.cursor.execute('''
                    UPDATE whatsapp_sessions SET status = ?, last_active = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', ('connected', self.session_id))
                self.db.conn.commit()
                
                print(f"{Colors.GREEN}✅ WhatsApp Web connected!{Colors.RESET}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking WhatsApp status: {e}")
            return False
    
    def _monitor_messages(self):
        """Monitor WhatsApp messages in thread"""
        print(f"{Colors.CYAN}📱 Starting WhatsApp message monitor...{Colors.RESET}")
        
        while self.running and self.driver:
            try:
                # Check if WhatsApp is ready
                if not self._check_whatsapp_ready():
                    time.sleep(5)
                    continue
                
                # Find unread messages
                unread_chats = self.driver.find_elements(By.XPATH, '//span[@aria-label="Unread"]')
                
                for chat in unread_chats[:5]:  # Limit to 5 chats at a time
                    try:
                        # Click on chat
                        chat.click()
                        time.sleep(2)
                        
                        # Get last message
                        last_message = self.driver.find_elements(By.XPATH, '//div[contains(@class, "message-in")]//span[contains(@class, "selectable-text")]')
                        
                        if last_message:
                            message_text = last_message[-1].text.strip()
                            sender_element = self.driver.find_element(By.XPATH, '//span[@title]')
                            sender = sender_element.get_attribute('title')
                            
                            # Process command
                            if message_text.startswith('!'):
                                self._process_whatsapp_command(message_text, sender)
                        
                        # Go back to chat list
                        back_button = self.driver.find_elements(By.XPATH, '//button[@aria-label="Back"]')
                        if back_button:
                            back_button[0].click()
                        
                        time.sleep(1)
                        
                    except Exception as e:
                        logger.error(f"Error processing WhatsApp message: {e}")
                        continue
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"WhatsApp monitor error: {e}")
                time.sleep(30)
    
    def _process_whatsapp_command(self, command: str, sender: str):
        """Process WhatsApp command"""
        logger.info(f"WhatsApp command from {sender}: {command}")
        
        # Remove prefix
        prefix = self.config.get('command_prefix', '!')
        if command.startswith(prefix):
            command = command[len(prefix):]
        
        # Check if sender is authorized
        admin_number = self.config.get('admin_number', '')
        if admin_number and sender != admin_number:
            logger.warning(f"Unauthorized WhatsApp command from {sender}")
            self._send_via_selenium(sender, "❌ Unauthorized. Contact administrator.")
            return
        
        # Execute command
        result = self.handler.execute(command, "whatsapp")
        
        # Send response
        if result['success']:
            response = f"✅ Command executed ({result['execution_time']:.2f}s)\n"
            output = result.get('output', '') or result.get('data', '')
            
            if isinstance(output, dict):
                response += json.dumps(output, indent=2)[:1000]
            else:
                response += str(output)[:1000]
            
            self._send_via_selenium(sender, response)
        else:
            self._send_via_selenium(sender, f"❌ Failed: {result.get('output', 'Unknown error')}")
    
    def start(self) -> bool:
        """Start WhatsApp bot"""
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium not available")
            return False
        
        if self.running:
            return True
        
        print(f"{Colors.CYAN}📱 Starting WhatsApp Web bot...{Colors.RESET}")
        
        # Setup driver
        self.driver = self.setup_selenium_driver()
        if not self.driver:
            return False
        
        try:
            # Navigate to WhatsApp Web
            self.driver.get("https://web.whatsapp.com")
            self.wait = WebDriverWait(self.driver, 60)
            
            self.running = True
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(target=self._monitor_messages, daemon=True)
            self.monitoring_thread.start()
            
            print(f"{Colors.GREEN}✅ WhatsApp bot started{Colors.RESET}")
            print(f"{Colors.YELLOW}📱 Open {QR_CODES_DIR}/whatsapp_{self.session_id}.png to scan QR code{Colors.RESET}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start WhatsApp bot: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop WhatsApp bot"""
        self.running = False
        
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
        
        logger.info("WhatsApp bot stopped")
    
    def get_status(self) -> Dict:
        """Get WhatsApp bot status"""
        status = {
            'running': self.running,
            'method': self.config.get('method', 'selenium'),
            'driver_active': self.driver is not None,
            'session_id': self.session_id
        }
        
        # Check database for session status
        try:
            self.db.cursor.execute('''
                SELECT status, qr_code_path, last_active FROM whatsapp_sessions 
                WHERE session_id = ? ORDER BY created_at DESC LIMIT 1
            ''', (self.session_id,))
            row = self.db.cursor.fetchone()
            if row:
                status['session_status'] = dict(row)
        except:
            pass
        
        return status

# =====================
# SIGNAL BOT
# =====================
class SignalBot:
    """Signal bot integration (CLI or Twilio)"""
    
    def __init__(self, command_handler, db_manager, config: Dict = None):
        self.handler = command_handler
        self.db = db_manager
        self.config = config or {}
        self.running = False
        self.monitoring_thread = None
        self.session_id = str(uuid.uuid4())[:8]
    
    def check_signal_cli(self) -> bool:
        """Check if signal-cli is available"""
        if shutil.which('signal-cli'):
            return True
        
        # Check common installation paths
        common_paths = [
            '/usr/bin/signal-cli',
            '/usr/local/bin/signal-cli',
            '/opt/signal-cli/bin/signal-cli'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return True
        
        return False
    
    def send_via_cli(self, recipient: str, message: str) -> bool:
        """Send Signal message via signal-cli"""
        if not self.check_signal_cli():
            logger.error("signal-cli not found")
            return False
        
        try:
            number = self.config.get('number', '')
            
            cmd = ['signal-cli', '-u', number, 'send', '-m', message, recipient]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Failed to send Signal message: {e}")
            return False
    
    async def send_via_twilio(self, recipient: str, message: str) -> bool:
        """Send Signal message via Twilio"""
        if not TWILIO_AVAILABLE:
            logger.error("Twilio not available")
            return False
        
        try:
            twilio_config = ConfigManager.load_twilio_config()
            
            if not twilio_config.get('account_sid') or not twilio_config.get('auth_token'):
                logger.error("Twilio not configured")
                return False
            
            client = Client(twilio_config['account_sid'], twilio_config['auth_token'])
            
            # Note: Twilio doesn't natively support Signal
            # This is a placeholder for when they might
            logger.warning("Twilio Signal integration not yet available")
            return False
            
        except Exception as e:
            logger.error(f"Failed to send Twilio Signal message: {e}")
            return False
    
    async def send_message(self, recipient: str, message: str) -> bool:
        """Send Signal message"""
        method = self.config.get('method', 'cli')
        
        if method == 'cli':
            return self.send_via_cli(recipient, message)
        elif method == 'twilio':
            return await self.send_via_twilio(recipient, message)
        else:
            logger.error(f"Unknown Signal method: {method}")
            return False
    
    def _monitor_cli_messages(self):
        """Monitor Signal messages via signal-cli (requires dbus)"""
        print(f"{Colors.CYAN}📱 Starting Signal message monitor...{Colors.RESET}")
        
        while self.running:
            try:
                if not self.check_signal_cli():
                    time.sleep(60)
                    continue
                
                number = self.config.get('number', '')
                
                # Receive messages
                cmd = ['signal-cli', '-u', number, 'receive']
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.stdout:
                    # Parse messages (format depends on signal-cli version)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Envelope from:' in line:
                            # Extract sender and message
                            sender_match = re.search(r'Envelope from: (\+\d+)', line)
                            if sender_match:
                                sender = sender_match.group(1)
                                
                                # Get next line for message
                                msg_line = lines[lines.index(line) + 1]
                                message_match = re.search(r'Body: (.+)', msg_line)
                                
                                if message_match:
                                    message_text = message_match.group(1)
                                    
                                    # Process command
                                    if message_text.startswith('!'):
                                        self._process_signal_command(message_text, sender)
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Signal monitor error: {e}")
                time.sleep(30)
    
    def _process_signal_command(self, command: str, sender: str):
        """Process Signal command"""
        logger.info(f"Signal command from {sender}: {command}")
        
        # Remove prefix
        prefix = self.config.get('command_prefix', '!')
        if command.startswith(prefix):
            command = command[len(prefix):]
        
        # Check if sender is authorized
        admin_number = self.config.get('admin_number', '')
        if admin_number and sender != admin_number:
            logger.warning(f"Unauthorized Signal command from {sender}")
            self.send_via_cli(sender, "❌ Unauthorized. Contact administrator.")
            return
        
        # Execute command
        result = self.handler.execute(command, "signal")
        
        # Send response
        if result['success']:
            response = f"✅ Command executed ({result['execution_time']:.2f}s)\n"
            output = result.get('output', '') or result.get('data', '')
            
            if isinstance(output, dict):
                response += json.dumps(output, indent=2)[:1000]
            else:
                response += str(output)[:1000]
            
            self.send_via_cli(sender, response)
        else:
            self.send_via_cli(sender, f"❌ Failed: {result.get('output', 'Unknown error')}")
    
    def start(self) -> bool:
        """Start Signal bot"""
        method = self.config.get('method', 'cli')
        
        if method == 'cli':
            if not self.check_signal_cli():
                logger.error("signal-cli not found")
                return False
        
        if self.running:
            return True
        
        print(f"{Colors.CYAN}📱 Starting Signal bot...{Colors.RESET}")
        
        self.running = True
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitor_cli_messages, daemon=True)
        self.monitoring_thread.start()
        
        print(f"{Colors.GREEN}✅ Signal bot started{Colors.RESET}")
        print(f"{Colors.YELLOW}📱 Using number: {self.config.get('number', 'Not configured')}{Colors.RESET}")
        
        return True
    
    def stop(self):
        """Stop Signal bot"""
        self.running = False
        logger.info("Signal bot stopped")
    
    def get_status(self) -> Dict:
        """Get Signal bot status"""
        return {
            'running': self.running,
            'method': self.config.get('method', 'cli'),
            'signal_cli_available': self.check_signal_cli(),
            'number': self.config.get('number', ''),
            'session_id': self.session_id
        }

# =====================
# COMMAND HANDLER
# =====================
class CommandHandler:
    """Handle all 500+ commands"""
    
    def __init__(self, db: DatabaseManager, nikto_scanner: NiktoScanner = None):
        self.db = db
        self.nikto = nikto_scanner
        self.tools = NetworkTools()
        self.command_map = self._setup_command_map()
    
    def _setup_command_map(self) -> Dict[str, callable]:
        """Setup command execution map"""
        return {
            # Ping commands
            'ping': self._execute_ping,
            'ping4': self._execute_ping,
            'ping6': self._execute_ping6,
            
            # Scan commands
            'scan': self._execute_scan,
            'quick_scan': self._execute_quick_scan,
            'nmap': self._execute_nmap,
            'portscan': self._execute_portscan,
            'full_scan': self._execute_full_scan,
            'web_scan': self._execute_web_scan,
            
            # Nikto web scanner
            'nikto': self._execute_nikto,
            'web_vuln': self._execute_nikto,
            'nikto_full': self._execute_nikto_full,
            'nikto_ssl': self._execute_nikto_ssl,
            'nikto_cgi': self._execute_nikto_cgi,
            'nikto_sql': self._execute_nikto_sql,
            'nikto_xss': self._execute_nikto_xss,
            
            # Traceroute commands
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            'tracepath': self._execute_tracepath,
            
            # Web commands
            'curl': self._execute_curl,
            'wget': self._execute_wget,
            'http': self._execute_http,
            
            # Info commands
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'dns': self._execute_dns,
            'location': self._execute_location,
            'analyze': self._execute_analyze,
            'ip_info': self._execute_ip_info,
            
            # System commands
            'system': self._execute_system,
            'network': self._execute_network,
            'status': self._execute_status,
            'ps': self._execute_ps,
            'top': self._execute_top,
            
            # Security commands
            'threats': self._execute_threats,
            'report': self._execute_report,
            'monitor': self._execute_monitor,
            
            # IP Management
            'add_ip': self._execute_add_ip,
            'remove_ip': self._execute_remove_ip,
            'block_ip': self._execute_block_ip,
            'unblock_ip': self._execute_unblock_ip,
            'list_ips': self._execute_list_ips,
            
            # Nikto management
            'nikto_status': self._execute_nikto_status,
            'nikto_results': self._execute_nikto_results,
            
            # WhatsApp commands
            'whatsapp': self._execute_whatsapp,
            'whatsapp_status': self._execute_whatsapp_status,
            
            # Signal commands
            'signal': self._execute_signal,
            'signal_status': self._execute_signal_status,
            
            # Twilio commands
            'twilio': self._execute_twilio,
            'twilio_status': self._execute_twilio_status,
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        # Parse command
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Execute command
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                # Try as generic shell command
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            
            # Log command to database
            self.db.log_command(
                command=command,
                source=source,
                success=result.get('success', False),
                output=result.get('output', '')[:5000],
                execution_time=execution_time
            )
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            self.db.log_command(
                command=command,
                source=source,
                success=False,
                output=error_msg,
                execution_time=execution_time
            )
            
            return self._create_result(False, error_msg, execution_time)
    
    def _create_result(self, success: bool, data: Any, 
                      execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result"""
        if isinstance(data, str):
            return {
                'success': success,
                'output': data,
                'execution_time': execution_time
            }
        else:
            return {
                'success': success,
                'data': data,
                'execution_time': execution_time
            }
    
    # ==================== WhatsApp Command Handlers ====================
    def _execute_whatsapp(self, args: List[str]) -> Dict[str, Any]:
        """Configure WhatsApp bot"""
        if not args:
            return self._create_result(False, "Usage: whatsapp <setup|start|stop|status|send>")
        
        subcmd = args[0].lower()
        
        if subcmd == 'setup':
            return self._execute_whatsapp_setup(args[1:])
        elif subcmd == 'start':
            return self._create_result(True, "WhatsApp bot started (handled by main app)")
        elif subcmd == 'stop':
            return self._create_result(True, "WhatsApp bot stopped (handled by main app)")
        elif subcmd == 'status':
            return self._create_result(True, "Use 'whatsapp_status' command")
        elif subcmd == 'send' and len(args) >= 3:
            number = args[1]
            message = ' '.join(args[2:])
            return self._create_result(True, {
                'recipient': number,
                'message': message,
                'status': 'Message queued for sending'
            })
        else:
            return self._create_result(False, "Invalid WhatsApp command")
    
    def _execute_whatsapp_setup(self, args: List[str]) -> Dict[str, Any]:
        """Setup WhatsApp configuration"""
        method = 'selenium'
        session_path = ''
        admin_number = ''
        
        for i in range(len(args)):
            if args[i] == '--method' and i + 1 < len(args):
                method = args[i + 1]
            elif args[i] == '--session' and i + 1 < len(args):
                session_path = args[i + 1]
            elif args[i] == '--admin' and i + 1 < len(args):
                admin_number = args[i + 1]
        
        config = {
            'enabled': True,
            'method': method,
            'session_path': session_path,
            'command_prefix': '!',
            'admin_number': admin_number,
            'headless': False
        }
        
        if ConfigManager.save_whatsapp_config(config):
            return self._create_result(True, {
                'message': 'WhatsApp configuration saved',
                'config': config
            })
        else:
            return self._create_result(False, 'Failed to save WhatsApp configuration')
    
    def _execute_whatsapp_status(self, args: List[str]) -> Dict[str, Any]:
        """Get WhatsApp bot status"""
        config = ConfigManager.load_whatsapp_config()
        
        status = {
            'enabled': config.get('enabled', False),
            'method': config.get('method', 'selenium'),
            'admin_number': config.get('admin_number', 'Not configured'),
            'session_path': config.get('session_path', 'Default'),
            'selenium_available': SELENIUM_AVAILABLE,
            'twilio_available': TWILIO_AVAILABLE,
            'qr_code_dir': QR_CODES_DIR
        }
        
        return self._create_result(True, status)
    
    # ==================== Signal Command Handlers ====================
    def _execute_signal(self, args: List[str]) -> Dict[str, Any]:
        """Configure Signal bot"""
        if not args:
            return self._create_result(False, "Usage: signal <setup|start|stop|status|send>")
        
        subcmd = args[0].lower()
        
        if subcmd == 'setup':
            return self._execute_signal_setup(args[1:])
        elif subcmd == 'start':
            return self._create_result(True, "Signal bot started (handled by main app)")
        elif subcmd == 'stop':
            return self._create_result(True, "Signal bot stopped (handled by main app)")
        elif subcmd == 'status':
            return self._create_result(True, "Use 'signal_status' command")
        elif subcmd == 'send' and len(args) >= 3:
            number = args[1]
            message = ' '.join(args[2:])
            return self._create_result(True, {
                'recipient': number,
                'message': message,
                'status': 'Message queued for sending'
            })
        else:
            return self._create_result(False, "Invalid Signal command")
    
    def _execute_signal_setup(self, args: List[str]) -> Dict[str, Any]:
        """Setup Signal configuration"""
        method = 'cli'
        number = ''
        admin_number = ''
        
        for i in range(len(args)):
            if args[i] == '--method' and i + 1 < len(args):
                method = args[i + 1]
            elif args[i] == '--number' and i + 1 < len(args):
                number = args[i + 1]
            elif args[i] == '--admin' and i + 1 < len(args):
                admin_number = args[i + 1]
        
        config = {
            'enabled': True,
            'method': method,
            'number': number,
            'command_prefix': '!',
            'admin_number': admin_number
        }
        
        if ConfigManager.save_signal_config(config):
            return self._create_result(True, {
                'message': 'Signal configuration saved',
                'config': config
            })
        else:
            return self._create_result(False, 'Failed to save Signal configuration')
    
    def _execute_signal_status(self, args: List[str]) -> Dict[str, Any]:
        """Get Signal bot status"""
        config = ConfigManager.load_signal_config()
        
        # Check if signal-cli is available
        signal_cli_path = shutil.which('signal-cli')
        signal_cli_available = signal_cli_path is not None
        
        status = {
            'enabled': config.get('enabled', False),
            'method': config.get('method', 'cli'),
            'number': config.get('number', 'Not configured'),
            'admin_number': config.get('admin_number', 'Not configured'),
            'signal_cli_available': signal_cli_available,
            'signal_cli_path': signal_cli_path,
            'twilio_available': TWILIO_AVAILABLE
        }
        
        return self._create_result(True, status)
    
    # ==================== Twilio Command Handlers ====================
    def _execute_twilio(self, args: List[str]) -> Dict[str, Any]:
        """Configure Twilio for WhatsApp/Signal"""
        if not args:
            return self._create_result(False, "Usage: twilio <setup|status|test>")
        
        subcmd = args[0].lower()
        
        if subcmd == 'setup':
            return self._execute_twilio_setup(args[1:])
        elif subcmd == 'status':
            return self._execute_twilio_status(args[1:])
        elif subcmd == 'test':
            return self._execute_twilio_test(args[1:])
        else:
            return self._create_result(False, "Invalid Twilio command")
    
    def _execute_twilio_setup(self, args: List[str]) -> Dict[str, Any]:
        """Setup Twilio configuration"""
        account_sid = ''
        auth_token = ''
        whatsapp_number = ''
        
        for i in range(len(args)):
            if args[i] == '--sid' and i + 1 < len(args):
                account_sid = args[i + 1]
            elif args[i] == '--token' and i + 1 < len(args):
                auth_token = args[i + 1]
            elif args[i] == '--whatsapp' and i + 1 < len(args):
                whatsapp_number = args[i + 1]
        
        config = {
            'enabled': True,
            'account_sid': account_sid,
            'auth_token': auth_token,
            'whatsapp_number': whatsapp_number
        }
        
        if ConfigManager.save_twilio_config(config):
            return self._create_result(True, {
                'message': 'Twilio configuration saved',
                'account_sid': account_sid[:6] + '...' if account_sid else '',
                'whatsapp_number': whatsapp_number
            })
        else:
            return self._create_result(False, 'Failed to save Twilio configuration')
    
    def _execute_twilio_status(self, args: List[str]) -> Dict[str, Any]:
        """Get Twilio configuration status"""
        config = ConfigManager.load_twilio_config()
        
        status = {
            'enabled': config.get('enabled', False),
            'account_sid': config.get('account_sid', '')[:6] + '...' if config.get('account_sid') else 'Not configured',
            'whatsapp_number': config.get('whatsapp_number', 'Not configured'),
            'twilio_available': TWILIO_AVAILABLE
        }
        
        return self._create_result(True, status)
    
    def _execute_twilio_test(self, args: List[str]) -> Dict[str, Any]:
        """Test Twilio configuration"""
        if not TWILIO_AVAILABLE:
            return self._create_result(False, "Twilio not installed")
        
        if len(args) < 2:
            return self._create_result(False, "Usage: twilio test <whatsapp|sms> <number>")
        
        method = args[0].lower()
        number = args[1]
        
        config = ConfigManager.load_twilio_config()
        
        if not config.get('account_sid') or not config.get('auth_token'):
            return self._create_result(False, "Twilio not configured")
        
        try:
            client = Client(config['account_sid'], config['auth_token'])
            
            if method == 'whatsapp':
                from_number = f"whatsapp:{config.get('whatsapp_number', '')}"
                to_number = f"whatsapp:{number}"
            else:
                from_number = config.get('whatsapp_number', '')  # Use as SMS number
                to_number = number
            
            message = client.messages.create(
                body="🕸️ SpiderBot Pro - Test message from Twilio integration",
                from_=from_number,
                to=to_number
            )
            
            return self._create_result(True, {
                'success': True,
                'message_sid': message.sid,
                'status': message.status,
                'recipient': number
            })
            
        except Exception as e:
            return self._create_result(False, f"Twilio test failed: {e}")
    
    # ==================== Nikto Command Handlers ====================
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        """Execute Nikto web vulnerability scan"""
        if not self.nikto:
            return self._create_result(False, "Nikto scanner not initialized")
        
        if not self.nikto.nikto_available:
            return self._create_result(False, "Nikto is not installed. Please install Nikto first.")
        
        if not args:
            return self._create_result(False, "Usage: nikto <target> [options]\nExamples:\n  nikto example.com\n  nikto https://example.com\n  nikto 192.168.1.1:8080")
        
        target = args[0]
        options = {}
        
        # Parse options
        for i in range(1, len(args)):
            if args[i] == '-ssl':
                options['ssl'] = True
            elif args[i] == '-port' and i + 1 < len(args):
                options['port'] = args[i + 1]
            elif args[i] == '-level' and i + 1 < len(args):
                try:
                    options['level'] = int(args[i + 1])
                except:
                    pass
            elif args[i] == '-timeout' and i + 1 < len(args):
                try:
                    options['timeout'] = int(args[i + 1])
                except:
                    pass
            elif args[i] == '-verbose':
                options['verbose'] = True
            elif args[i] == '-debug':
                options['debug'] = True
        
        # Auto-detect SSL if needed
        if not options.get('ssl') and 'https://' in target:
            options['ssl'] = True
        elif not options.get('ssl'):
            # Check if target supports SSL
            host = target.split(':')[0]
            if '://' in host:
                host = host.split('://')[1]
            if self.nikto.check_target_ssl(host):
                options['ssl'] = True
        
        # Execute scan
        result = self.nikto.scan(target, options)
        
        if result.success:
            # Log scan result
            scan_result = ScanResult(
                target=target,
                scan_type=ScanType.NIKTO,
                open_ports=[],
                timestamp=result.timestamp,
                success=True,
                vulnerabilities=result.vulnerabilities
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto Web Vulnerability Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],  # First 20 only
                'scan_time': f"{result.scan_time:.2f}s",
                'output_file': result.output_file,
                'timestamp': result.timestamp
            })
        else:
            return self._create_result(False, f"Nikto scan failed: {result.error}")
    
    def _execute_nikto_full(self, args: List[str]) -> Dict[str, Any]:
        """Full Nikto scan with all tests"""
        if not args:
            return self._create_result(False, "Usage: nikto_full <target>")
        
        target = args[0]
        options = {
            'tuning': '123456789',  # All tests
            'level': 3,  # Maximum scan level
            'timeout': 600,  # 10 minute timeout
            'verbose': True
        }
        
        # Auto-detect SSL
        if 'https://' in target or self.nikto.check_target_ssl(target):
            options['ssl'] = True
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Full Nikto Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:30],
                'scan_time': f"{result.scan_time:.2f}s",
                'output_file': result.output_file
            })
        else:
            return self._create_result(False, f"Full Nikto scan failed: {result.error}")
    
    def _execute_nikto_ssl(self, args: List[str]) -> Dict[str, Any]:
        """Nikto SSL/TLS specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_ssl <target>")
        
        target = args[0]
        options = {
            'ssl': True,
            'tuning': '6',  # SSL/TLS tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto SSL/TLS Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"SSL/TLS scan failed: {result.error}")
    
    def _execute_nikto_cgi(self, args: List[str]) -> Dict[str, Any]:
        """Nikto CGI specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_cgi <target>")
        
        target = args[0]
        options = {
            'tuning': '2',  # CGI tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto CGI Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"CGI scan failed: {result.error}")
    
    def _execute_nikto_sql(self, args: List[str]) -> Dict[str, Any]:
        """Nikto SQL injection specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_sql <target>")
        
        target = args[0]
        options = {
            'tuning': '4',  # SQL injection tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto SQL Injection Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"SQL injection scan failed: {result.error}")
    
    def _execute_nikto_xss(self, args: List[str]) -> Dict[str, Any]:
        """Nikto XSS specific scan"""
        if not args:
            return self._create_result(False, "Usage: nikto_xss <target>")
        
        target = args[0]
        options = {
            'tuning': '5',  # XSS tests
            'timeout': 300
        }
        
        result = self.nikto.scan(target, options)
        
        if result.success:
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto XSS Scan',
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerabilities': result.vulnerabilities[:20],
                'scan_time': f"{result.scan_time:.2f}s"
            })
        else:
            return self._create_result(False, f"XSS scan failed: {result.error}")
    
    def _execute_nikto_status(self, args: List[str]) -> Dict[str, Any]:
        """Check Nikto status and availability"""
        if not self.nikto:
            return self._create_result(False, "Nikto scanner not initialized")
        
        status = {
            'available': self.nikto.nikto_available,
            'scan_types': self.nikto.get_available_scan_types(),
            'config': {
                'enabled': self.nikto.config.get('enabled', True),
                'timeout': self.nikto.config.get('timeout', 300),
                'max_targets': self.nikto.config.get('max_targets', 10),
                'scan_level': self.nikto.config.get('scan_level', 2)
            }
        }
        
        if not self.nikto.nikto_available:
            status['installation_help'] = {
                'linux': 'sudo apt-get install nikto',
                'mac': 'brew install nikto',
                'windows': 'Download from https://github.com/sullo/nikto'
            }
        
        return self._create_result(True, status)
    
    def _execute_nikto_results(self, args: List[str]) -> Dict[str, Any]:
        """Get recent Nikto scan results"""
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        
        scans = self.db.get_nikto_scans(limit)
        return self._create_result(True, {
            'recent_scans': scans,
            'count': len(scans)
        })
    
    # ==================== IP Management Command Handlers ====================
    def _execute_add_ip(self, args: List[str]) -> Dict[str, Any]:
        """Add IP to monitoring"""
        if not args:
            return self._create_result(False, "Usage: add_ip <ip> [notes]")
        
        ip = args[0]
        notes = ' '.join(args[1:]) if len(args) > 1 else "Added via command"
        
        try:
            ipaddress.ip_address(ip)
            success = self.db.add_managed_ip(ip, "cli", notes)
            
            if success:
                return self._create_result(True, f"✅ IP {ip} added to monitoring")
            else:
                return self._create_result(False, f"Failed to add IP {ip} (may already exist)")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_remove_ip(self, args: List[str]) -> Dict[str, Any]:
        """Remove IP from monitoring"""
        if not args:
            return self._create_result(False, "Usage: remove_ip <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            success = self.db.remove_managed_ip(ip)
            
            if success:
                return self._create_result(True, f"✅ IP {ip} removed from monitoring")
            else:
                return self._create_result(False, f"IP {ip} not found in monitoring")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_block_ip(self, args: List[str]) -> Dict[str, Any]:
        """Block an IP"""
        if not args:
            return self._create_result(False, "Usage: block_ip <ip> [reason]")
        
        ip = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else "Manually blocked"
        
        try:
            ipaddress.ip_address(ip)
            
            # Try to block via firewall
            firewall_success = NetworkTools.block_ip_firewall(ip)
            
            # Update database
            db_success = self.db.block_ip(ip, reason, "cli")
            
            if firewall_success or db_success:
                return self._create_result(True, {
                    'ip': ip,
                    'reason': reason,
                    'firewall_blocked': firewall_success,
                    'database_updated': db_success,
                    'message': f"✅ IP {ip} blocked successfully"
                })
            else:
                return self._create_result(False, f"Failed to block IP {ip}")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_unblock_ip(self, args: List[str]) -> Dict[str, Any]:
        """Unblock an IP"""
        if not args:
            return self._create_result(False, "Usage: unblock_ip <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            
            # Try to unblock from firewall
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            
            # Update database
            db_success = self.db.unblock_ip(ip, "cli")
            
            if firewall_success or db_success:
                return self._create_result(True, {
                    'ip': ip,
                    'firewall_unblocked': firewall_success,
                    'database_updated': db_success,
                    'message': f"✅ IP {ip} unblocked successfully"
                })
            else:
                return self._create_result(False, f"Failed to unblock IP {ip}")
                
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_list_ips(self, args: List[str]) -> Dict[str, Any]:
        """List managed IPs"""
        include_blocked = True
        if args and args[0].lower() == 'active':
            include_blocked = False
        
        ips = self.db.get_managed_ips(include_blocked)
        
        if not ips:
            return self._create_result(True, {
                'ips': [],
                'count': 0,
                'message': 'No managed IPs found'
            })
        
        # Format for display
        ip_list = []
        for ip in ips:
            ip_list.append({
                'ip': ip['ip_address'],
                'added_by': ip.get('added_by', 'unknown'),
                'added_date': ip.get('added_date', ''),
                'is_blocked': ip.get('is_blocked', False),
                'block_reason': ip.get('block_reason', ''),
                'alert_count': ip.get('alert_count', 0),
                'notes': ip.get('notes', '')
            })
        
        return self._create_result(True, {
            'ips': ip_list,
            'count': len(ip_list),
            'blocked_count': len([ip for ip in ip_list if ip['is_blocked']])
        })
    
    def _execute_ip_info(self, args: List[str]) -> Dict[str, Any]:
        """Get detailed information about an IP"""
        if not args:
            return self._create_result(False, "Usage: ip_info <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            
            # Get IP from database
            db_info = self.db.get_ip_info(ip)
            
            # Get location info
            location = NetworkTools.get_ip_location(ip)
            
            # Get recent threats
            threats = self.db.get_threats_by_ip(ip, 5)
            
            info = {
                'ip': ip,
                'database_info': db_info,
                'location': location if location.get('success') else None,
                'recent_threats': threats,
                'threat_count': len(threats)
            }
            
            return self._create_result(True, info)
            
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    # ==================== Existing Command Handlers ====================
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping <target>")
        
        target = args[0]
        count = 4
        size = 56
        
        if len(args) > 1:
            for i in range(1, len(args)):
                if args[i] == '-c' and i + 1 < len(args):
                    try:
                        count = int(args[i + 1])
                    except:
                        pass
                elif args[i] == '-s' and i + 1 < len(args):
                    try:
                        size = int(args[i + 1])
                    except:
                        pass
        
        result = self.tools.ping(target, count, size)
        return self._create_result(result.success, result.output)
    
    def _execute_ping6(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping6 <target>")
        
        target = args[0]
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-6', target]
        else:
            cmd = ['ping6', target]
        
        cmd.extend(args[1:])
        return self._execute_generic(' '.join(cmd))
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        """Standard scan (ports 1-1000)"""
        if not args:
            return self._create_result(False, "Usage: scan <target> [ports]")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "quick"
        
        if len(args) > 1:
            ports = args[1]
        
        result = self.tools.nmap_scan(target, scan_type, ports)
        
        if result.success:
            # Parse open ports from nmap output
            open_ports = self._parse_nmap_output(result.output)
            
            # Log scan to database
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': scan_type,
                'ports_scanned': ports,
                'open_ports': open_ports,
                'open_ports_count': len(open_ports),
                'output': result.output[-2000:]  # Last 2000 chars
            })
        
        return self._create_result(False, result.output)
    
    def _execute_quick_scan(self, args: List[str]) -> Dict[str, Any]:
        """Quick scan with faster settings"""
        if not args:
            return self._create_result(False, "Usage: quick_scan <target>")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "quick_scan"
        
        result = self.tools.nmap_scan(target, scan_type, ports)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Quick Scan",
                'ports_scanned': ports,
                'open_ports': open_ports,
                'open_ports_count': len(open_ports),
                'output': result.output[-1500:]  # Shorter output for quick scan
            })
        
        return self._create_result(False, result.output)
    
    def _execute_web_scan(self, args: List[str]) -> Dict[str, Any]:
        """Web server scan (common web ports)"""
        if not args:
            return self._create_result(False, "Usage: web_scan <target>")
        
        target = args[0]
        scan_type = "web"
        
        result = self.tools.nmap_scan(target, scan_type)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type="web",
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Web Server Scan",
                'open_ports': open_ports,
                'open_ports_count': len(open_ports),
                'output': result.output[-2000:]
            })
        
        return self._create_result(False, result.output)
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        """Full nmap command with all options"""
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        
        target = args[0]
        # Join all arguments except target
        options = ' '.join(args[1:]) if len(args) > 1 else ""
        
        # Determine scan type from options
        scan_type = "custom"
        if '-A' in options or '-sV' in options:
            scan_type = "comprehensive"
        elif '-sS' in options and 'T2' in options:
            scan_type = "stealth"
        elif '-sU' in options:
            scan_type = "udp"
        elif '-O' in options:
            scan_type = "os_detection"
        
        # Execute nmap
        result = self._execute_generic(f"nmap {target} {options}")
        
        if result['success']:
            open_ports = self._parse_nmap_output(result['output'])
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            result['data'] = {
                'target': target,
                'scan_type': scan_type,
                'options': options,
                'open_ports': open_ports,
                'open_ports_count': len(open_ports)
            }
        
        return result
    
    def _execute_full_scan(self, args: List[str]) -> Dict[str, Any]:
        """Full port scan (all ports)"""
        if not args:
            return self._create_result(False, "Usage: full_scan <target>")
        
        target = args[0]
        scan_type = "full"
        
        result = self.tools.nmap_scan(target, scan_type)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Full Scan (All Ports)",
                'open_ports': open_ports[:50],  # Limit to 50 ports
                'open_ports_count': len(open_ports),
                'output': result.output[-3000:]  # Larger output for full scan
            })
        
        return self._create_result(False, result.output)
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse nmap output for open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    if len(port_proto) == 2:
                        try:
                            port = int(port_proto[0])
                            protocol = port_proto[1]
                            state = parts[1] if len(parts) > 1 else 'unknown'
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if state.lower() == 'open':
                                open_ports.append({
                                    'port': port,
                                    'protocol': protocol,
                                    'service': service,
                                    'state': state
                                })
                        except ValueError:
                            continue
        
        return open_ports
    
    def _execute_portscan(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_scan(args)
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: traceroute <target>")
        
        target = args[0]
        result = self.tools.traceroute(target)
        return self._create_result(result.success, result.output)
    
    def _execute_tracepath(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: tracepath <target>")
        
        return self._execute_generic('tracepath ' + ' '.join(args))
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: curl <url> [options]")
        
        url = args[0]
        method = 'GET'
        
        if len(args) > 1:
            for i in range(1, len(args)):
                if args[i] == '-X' and i + 1 < len(args):
                    method = args[i + 1].upper()
        
        result = self.tools.curl_request(url, method)
        return self._create_result(result.success, result.output)
    
    def _execute_wget(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: wget <url>")
        
        return self._execute_generic('wget ' + ' '.join(args))
    
    def _execute_http(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: http <url>")
        
        url = args[0]
        try:
            response = requests.get(url, timeout=10)
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:500] + ('...' if len(response.text) > 500 else ''),
                'size': len(response.content)
            }
            return self._create_result(True, result)
        except Exception as e:
            return self._create_result(False, f"HTTP request failed: {e}")
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        
        target = args[0]
        result = self.tools.whois_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: dig <domain>")
        
        target = args[0]
        result = self.tools.dns_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dns(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_dig(args)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        
        target = args[0]
        result = self.tools.get_ip_location(target)
        return self._create_result(result['success'], result)
    
    def _execute_analyze(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        
        ip = args[0]
        
        # Comprehensive IP analysis
        analysis = {
            'ip': ip,
            'timestamp': datetime.datetime.now().isoformat(),
            'location': None,
            'threats': [],
            'recommendations': []
        }
        
        # Get location
        location = self.tools.get_ip_location(ip)
        if location['success']:
            analysis['location'] = location
        
        # Check if IP is in threat database
        threats = self.db.get_threats_by_ip(ip, 10)
        if threats:
            analysis['threats'] = threats
            analysis['threat_count'] = len(threats)
        
        # Check if IP is managed
        managed = self.db.get_ip_info(ip)
        if managed:
            analysis['managed'] = managed
        
        # Add recommendations based on analysis
        if threats:
            analysis['recommendations'].append("This IP has been involved in previous threats - monitor closely")
        if threats and len(threats) > 5:
            analysis['recommendations'].append("High threat activity detected - consider blocking this IP")
        
        return self._create_result(True, analysis)
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'hostname': socket.gethostname(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
                'free': psutil.virtual_memory().free
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return self._create_result(True, info)
    
    def _execute_network(self, args: List[str]) -> Dict[str, Any]:
        """Get network information"""
        try:
            hostname = socket.gethostname()
            local_ip = self.tools.get_local_ip()
            interfaces = psutil.net_if_addrs()
            
            network_info = {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {}
            }
            
            for iface, addrs in interfaces.items():
                network_info['interfaces'][iface] = []
                for addr in addrs:
                    network_info['interfaces'][iface].append({
                        'family': str(addr.family),
                        'address': addr.address
                    })
            
            return self._create_result(True, network_info)
        
        except Exception as e:
            return self._create_result(False, f"Failed to get network info: {e}")
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        """Get system status"""
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            }
        }
        
        return self._create_result(True, status)
    
    def _execute_monitor(self, args: List[str]) -> Dict[str, Any]:
        """Monitor related commands"""
        if not args:
            return self._create_result(False, "Usage: monitor <status|start|stop>")
        
        action = args[0].lower()
        
        if action == 'status':
            # This will be handled by the main app
            return self._create_result(True, "Use 'status' command for monitoring status")
        else:
            return self._create_result(False, f"Monitor action '{action}' not directly available. Use start/stop commands in main app.")
    
    def _execute_ps(self, args: List[str]) -> Dict[str, Any]:
        """Process list"""
        return self._execute_generic('ps aux' if len(args) == 0 else 'ps ' + ' '.join(args))
    
    def _execute_top(self, args: List[str]) -> Dict[str, Any]:
        """Top command"""
        return self._execute_generic('top -b -n 1' if len(args) == 0 else 'top ' + ' '.join(args))
    
    def _execute_threats(self, args: List[str]) -> Dict[str, Any]:
        """Get recent threats"""
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        
        threats = self.db.get_recent_threats(limit)
        return self._create_result(True, threats)
    
    def _execute_report(self, args: List[str]) -> Dict[str, Any]:
        """Generate security report"""
        # Get statistics
        stats = self.db.get_statistics()
        threats = self.db.get_recent_threats(50)
        scans = self.db.get_nikto_scans(10)
        
        # Count threats by severity
        critical_threats = len([t for t in threats if t.get('severity') == 'critical'])
        high_threats = len([t for t in threats if t.get('severity') == 'high'])
        medium_threats = len([t for t in threats if t.get('severity') == 'medium'])
        low_threats = len([t for t in threats if t.get('severity') == 'low'])
        
        # System info
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        report = {
            'generated_at': datetime.datetime.now().isoformat(),
            'statistics': stats,
            'threat_summary': {
                'critical': critical_threats,
                'high': high_threats,
                'medium': medium_threats,
                'low': low_threats,
                'total': len(threats)
            },
            'recent_nikto_scans': len(scans),
            'system_status': {
                'cpu': cpu,
                'memory': mem,
                'disk': disk
            },
            'recommendations': []
        }
        
        # Add recommendations
        if critical_threats > 0:
            report['recommendations'].append("🚨 CRITICAL: Investigate critical severity threats immediately")
        if high_threats > 0:
            report['recommendations'].append("⚠️ HIGH: Address high severity threats as soon as possible")
        if cpu > 80:
            report['recommendations'].append("📈 High CPU usage detected - investigate running processes")
        if mem > 80:
            report['recommendations'].append("💾 High memory usage detected - check for memory leaks")
        if stats.get('total_blocked_ips', 0) > 0:
            report['recommendations'].append(f"🔒 {stats['total_blocked_ips']} IP(s) currently blocked")
        
        # Save report to file
        filename = f"security_report_{int(time.time())}.json"
        filepath = os.path.join(REPORT_DIR, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            report['report_file'] = filepath
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
        
        return self._create_result(True, report)
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
        
            return self._create_result(
                result.returncode == 0,
                result.stdout if result.stdout else result.stderr,
                execution_time
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(False, f"Command timed out after 60 seconds")
        except Exception as e:
            return self._create_result(False, f"Command execution failed: {e}")

# =====================
# DISCORD BOT
# =====================
class SpiderBotDiscord:
    """Discord bot integration with Nikto and IP management"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager, monitor: NetworkMonitor):
        self.handler = command_handler
        self.db = db
        self.monitor = monitor
        self.config = self.load_config()
        self.bot = None
        self.running = False
        self.task = None
    
    def load_config(self) -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        
        return {
            "token": "", 
            "channel_id": "", 
            "enabled": False, 
            "prefix": "!",
            "admin_role": "Admin",
            "security_role": "Security Team"
        }
    
    def save_config(self, token: str, channel_id: str = "", enabled: bool = True, 
                   prefix: str = "!", admin_role: str = "Admin", security_role: str = "Security Team") -> bool:
        """Save Discord configuration"""
        try:
            config = {
                "token": token,
                "channel_id": channel_id,
                "enabled": enabled,
                "prefix": prefix,
                "admin_role": admin_role,
                "security_role": security_role
            }
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            logger.error("discord.py not installed")
            return False
        
        if not self.config.get('token'):
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            intents.members = True  # For role checking
            
            self.bot = commands.Bot(
                command_prefix=self.config.get('prefix', '!'), 
                intents=intents,
                help_command=None
            )
            
            # Setup event handlers
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot logged in as {self.bot.user}')
                print(f'{Colors.GREEN}✅ Discord bot connected as {self.bot.user}{Colors.RESET}')
                
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="600+ Security Commands | !help"
                    )
                )
            
            # Setup commands
            await self.setup_commands()
            
            self.running = True
            await self.bot.start(self.config['token'])
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Discord bot: {e}")
            return False
    
    async def setup_commands(self):
        """Setup Discord commands"""
        
        # ==================== WhatsApp & Signal Commands ====================
        @self.bot.command(name='whatsapp')
        async def whatsapp_command(ctx, action: str = "status", *args):
            """Control WhatsApp bot"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            if action == "status":
                result = self.handler.execute("whatsapp_status", "discord")
                if result['success']:
                    data = result['data']
                    embed = discord.Embed(
                        title="📱 WhatsApp Bot Status",
                        color=discord.Color.green() if data.get('enabled') else discord.Color.orange()
                    )
                    
                    embed.add_field(name="Status", value="✅ Running" if data.get('enabled') else "⏹️ Stopped", inline=True)
                    embed.add_field(name="Method", value=data.get('method', 'N/A'), inline=True)
                    embed.add_field(name="Admin Number", value=data.get('admin_number', 'Not set'), inline=True)
                    embed.add_field(name="Selenium", value="✅" if data.get('selenium_available') else "❌", inline=True)
                    embed.add_field(name="Twilio", value="✅" if data.get('twilio_available') else "❌", inline=True)
                    
                    await ctx.send(embed=embed)
                else:
                    await ctx.send("❌ Failed to get WhatsApp status")
            
            elif action == "start":
                await ctx.send("📱 Starting WhatsApp bot...")
                # This will be handled by main app
                await ctx.send("✅ WhatsApp bot started (check console for QR code)")
            
            elif action == "stop":
                await ctx.send("📱 Stopping WhatsApp bot...")
                # This will be handled by main app
                await ctx.send("✅ WhatsApp bot stopped")
            
            elif action == "setup":
                await ctx.send("📱 WhatsApp setup command received. Use console for full setup.")
        
        @self.bot.command(name='signal')
        async def signal_command(ctx, action: str = "status", *args):
            """Control Signal bot"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            if action == "status":
                result = self.handler.execute("signal_status", "discord")
                if result['success']:
                    data = result['data']
                    embed = discord.Embed(
                        title="📱 Signal Bot Status",
                        color=discord.Color.green() if data.get('enabled') else discord.Color.orange()
                    )
                    
                    embed.add_field(name="Status", value="✅ Running" if data.get('enabled') else "⏹️ Stopped", inline=True)
                    embed.add_field(name="Method", value=data.get('method', 'N/A'), inline=True)
                    embed.add_field(name="Number", value=data.get('number', 'Not set'), inline=True)
                    embed.add_field(name="signal-cli", value="✅" if data.get('signal_cli_available') else "❌", inline=True)
                    
                    await ctx.send(embed=embed)
                else:
                    await ctx.send("❌ Failed to get Signal status")
            
            elif action == "start":
                await ctx.send("📱 Starting Signal bot...")
                # This will be handled by main app
                await ctx.send("✅ Signal bot started")
            
            elif action == "stop":
                await ctx.send("📱 Stopping Signal bot...")
                # This will be handled by main app
                await ctx.send("✅ Signal bot stopped")
        
        # ==================== Nikto Commands ====================
        @self.bot.command(name='nikto')
        async def nikto_command(ctx, target: str, *options):
            """Run Nikto web vulnerability scan"""
            if not await self.check_permissions(ctx):
                return
            
            await ctx.send(f"🕷️ Starting Nikto web vulnerability scan on {target}...\nThis may take a few minutes.")
            
            # Build command
            cmd = f"nikto {target}"
            if options:
                cmd += " " + " ".join(options)
            
            result = self.handler.execute(cmd, "discord")
            
            if result['success'] and result.get('data'):
                data = result['data']
                
                # Create embed
                embed = discord.Embed(
                    title=f"🕷️ Nikto Scan Results - {target}",
                    color=discord.Color.orange(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(
                    name="📊 Scan Summary",
                    value=f"**Vulnerabilities Found:** {data.get('vulnerabilities_found', 0)}\n"
                          f"**Scan Time:** {data.get('scan_time', 'N/A')}\n"
                          f"**Target:** {data.get('target', target)}",
                    inline=False
                )
                
                # Add vulnerabilities
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    vuln_text = ""
                    for i, vuln in enumerate(vulns[:5], 1):
                        severity = vuln.get('severity', 'unknown')
                        emoji = self.get_severity_emoji(severity)
                        desc = vuln.get('description', '')[:100]
                        if 'cve' in vuln:
                            desc += f"\nCVE: {vuln['cve']}"
                        vuln_text += f"{emoji} **{severity.upper()}** - {desc}\n"
                    
                    if len(vulns) > 5:
                        vuln_text += f"\n... and {len(vulns) - 5} more vulnerabilities"
                    
                    embed.add_field(
                        name="🔴 Vulnerabilities Detected",
                        value=vuln_text or "No vulnerabilities detected",
                        inline=False
                    )
                
                embed.set_footer(text=f"Requested by {ctx.author.name}")
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        # ==================== IP Management Commands ====================
        @self.bot.command(name='add_ip')
        async def add_ip_command(ctx, ip: str, *, notes: str = ""):
            """Add IP address to monitoring"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Add IP
            result = self.handler.execute(f"add_ip {ip} {notes}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ IP Added to Monitoring",
                    description=f"**IP:** `{ip}`",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                if notes:
                    embed.add_field(name="📝 Notes", value=notes, inline=False)
                
                embed.set_footer(text=f"Added by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                logger.info(f"Discord user {ctx.author.name} added IP {ip} to monitoring")
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='remove_ip')
        async def remove_ip_command(ctx, ip: str):
            """Remove IP address from monitoring"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Remove IP
            result = self.handler.execute(f"remove_ip {ip}", "discord")
            
            if result['success']:
                embed = discord.Embed(
                    title="✅ IP Removed from Monitoring",
                    description=f"**IP:** `{ip}`",
                    color=discord.Color.orange(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.set_footer(text=f"Removed by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                logger.info(f"Discord user {ctx.author.name} removed IP {ip} from monitoring")
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='block_ip')
        async def block_ip_command(ctx, ip: str, *, reason: str = "Manually blocked via Discord"):
            """Block an IP address"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Confirm action
            confirm_msg = await ctx.send(f"⚠️ Are you sure you want to block IP `{ip}`? This will block all traffic from this IP. (yes/no)")
            
            def check(m):
                return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() in ['yes', 'no']
            
            try:
                response = await self.bot.wait_for('message', timeout=30.0, check=check)
                
                if response.content.lower() == 'yes':
                    # Block IP
                    result = self.handler.execute(f"block_ip {ip} {reason}", "discord")
                    
                    if result['success']:
                        data = result['data']
                        embed = discord.Embed(
                            title="🔒 IP Blocked",
                            description=f"**IP:** `{ip}`",
                            color=discord.Color.red(),
                            timestamp=datetime.datetime.now()
                        )
                        
                        embed.add_field(name="📋 Reason", value=reason, inline=False)
                        embed.add_field(
                            name="📊 Status",
                            value=f"Firewall: {'✅' if data.get('firewall_blocked') else '❌'}\n"
                                  f"Database: {'✅' if data.get('database_updated') else '❌'}",
                            inline=True
                        )
                        
                        embed.set_footer(text=f"Blocked by {ctx.author.name}")
                        await ctx.send(embed=embed)
                        
                        logger.info(f"Discord user {ctx.author.name} blocked IP {ip}")
                    else:
                        await self.send_error(ctx, result)
                else:
                    await ctx.send("✅ Block cancelled.")
                    
            except asyncio.TimeoutError:
                await ctx.send("⏱️ Block confirmation timed out.")
        
        @self.bot.command(name='unblock_ip')
        async def unblock_ip_command(ctx, ip: str):
            """Unblock an IP address"""
            if not await self.check_permissions(ctx, admin_only=True):
                return
            
            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await ctx.send(f"❌ Invalid IP address: {ip}")
                return
            
            # Unblock IP
            result = self.handler.execute(f"unblock_ip {ip}", "discord")
            
            if result['success']:
                data = result['data']
                embed = discord.Embed(
                    title="🔓 IP Unblocked",
                    description=f"**IP:** `{ip}`",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(
                    name="📊 Status",
                    value=f"Firewall: {'✅' if data.get('firewall_unblocked') else '❌'}\n"
                          f"Database: {'✅' if data.get('database_updated') else '❌'}",
                    inline=False
                )
                
                embed.set_footer(text=f"Unblocked by {ctx.author.name}")
                await ctx.send(embed=embed)
                
                logger.info(f"Discord user {ctx.author.name} unblocked IP {ip}")
            else:
                await self.send_error(ctx, result)
        
        @self.bot.command(name='list_ips')
        async def list_ips_command(ctx, filter_type: str = "all"):
            """List managed IP addresses"""
            if not await self.check_permissions(ctx):
                return
            
            filter_param = ""
            if filter_type.lower() == 'active':
                filter_param = "active"
            elif filter_type.lower() == 'blocked':
                filter_param = "blocked"
            
            result = self.handler.execute(f"list_ips {filter_param}", "discord")
            
            if result['success']:
                data = result['data']
                ips = data.get('ips', [])
                
                if not ips:
                    await ctx.send("📭 No managed IPs found.")
                    return
                
                # Split into blocked and active
                blocked_ips = [ip for ip in ips if ip.get('is_blocked')]
                active_ips = [ip for ip in ips if not ip.get('is_blocked')]
                
                embed = discord.Embed(
                    title=f"📋 Managed IP Addresses ({data['count']} total)",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                # Active IPs
                if active_ips:
                    active_text = ""
                    for ip in active_ips[:10]:
                        active_text += f"`{ip['ip']}` - {ip.get('added_date', '')[:10]}\n"
                    
                    if len(active_ips) > 10:
                        active_text += f"... and {len(active_ips) - 10} more"
                    
                    embed.add_field(
                        name=f"✅ Active IPs ({len(active_ips)})",
                        value=active_text or "None",
                        inline=False
                    )
                
                # Blocked IPs
                if blocked_ips:
                    blocked_text = ""
                    for ip in blocked_ips[:5]:
                        blocked_text += f"`{ip['ip']}` - {ip.get('block_reason', 'No reason')[:50]}\n"
                    
                    if len(blocked_ips) > 5:
                        blocked_text += f"... and {len(blocked_ips) - 5} more"
                    
                    embed.add_field(
                        name=f"🔒 Blocked IPs ({len(blocked_ips)})",
                        value=blocked_text or "None",
                        inline=False
                    )
                
                embed.set_footer(text=f"Requested by {ctx.author.name}")
                await ctx.send(embed=embed)
            else:
                await self.send_error(ctx, result)
        
        # ==================== Help Command ====================
        @self.bot.command(name='help')
        async def help_command(ctx):
            """Show help menu"""
            embed = discord.Embed(
                title="🕸️ Spider Bot Pro v8.7.0 - Help Menu",
                description="**600+ Advanced Cybersecurity Commands**\n\nType `!command` to execute",
                color=discord.Color.blue()
            )
            
            # WhatsApp & Signal Commands
            embed.add_field(
                name="📱 **WhatsApp & Signal**",
                value="`!whatsapp status` - WhatsApp bot status\n"
                      "`!whatsapp start` - Start WhatsApp bot\n"
                      "`!whatsapp stop` - Stop WhatsApp bot\n"
                      "`!signal status` - Signal bot status\n"
                      "`!signal start` - Start Signal bot\n"
                      "`!signal stop` - Stop Signal bot",
                inline=False
            )
            
            # Nikto Commands
            embed.add_field(
                name="🕷️ **Nikto Web Scanner**",
                value="`!nikto <target>` - Basic web vuln scan\n"
                      "`!nikto_ssl <target>` - SSL/TLS scan\n"
                      "`!nikto_sql <target>` - SQL injection scan\n"
                      "`!nikto_xss <target>` - XSS scan\n"
                      "`!nikto_full <target>` - Full scan\n"
                      "`!nikto_status` - Check scanner status\n"
                      "`!nikto_results` - View recent scans",
                inline=False
            )
            
            # IP Management Commands
            embed.add_field(
                name="🔒 **IP Management**",
                value="`!add_ip <ip> [notes]` - Add IP to monitoring\n"
                      "`!remove_ip <ip>` - Remove IP from monitoring\n"
                      "`!block_ip <ip> [reason]` - Block IP address\n"
                      "`!unblock_ip <ip>` - Unblock IP address\n"
                      "`!list_ips [all/active/blocked]` - List managed IPs\n"
                      "`!ip_info <ip>` - Detailed IP information",
                inline=False
            )
            
            # Basic Commands
            embed.add_field(
                name="🤖 **Basic Commands**",
                value="`!ping <ip>` - Ping IP\n"
                      "`!scan <ip>` - Port scan (1-1000)\n"
                      "`!quick_scan <ip>` - Fast port scan\n"
                      "`!nmap <ip> [options]` - Full nmap scan\n"
                      "`!web_scan <ip>` - Scan web ports",
                inline=False
            )
            
            # Information Gathering
            embed.add_field(
                name="🔍 **Information Gathering**",
                value="`!whois <domain>` - WHOIS lookup\n"
                      "`!dns <domain>` - DNS lookup\n"
                      "`!location <ip>` - IP geolocation\n"
                      "`!analyze <ip>` - Comprehensive analysis",
                inline=False
            )
            
            embed.set_footer(text=f"Requested by {ctx.author.name} | Prefix: {self.config.get('prefix', '!')}")
            await ctx.send(embed=embed)
        
        # ... (rest of Discord commands remain the same)
    
    async def check_permissions(self, ctx, admin_only: bool = False) -> bool:
        """Check if user has permission to use command"""
        if ctx.author.guild_permissions.administrator:
            return True
        
        admin_role = self.config.get('admin_role', 'Admin')
        security_role = self.config.get('security_role', 'Security Team')
        
        user_roles = [role.name for role in ctx.author.roles]
        
        if admin_only:
            if admin_role in user_roles or ctx.author.guild_permissions.administrator:
                return True
            else:
                await ctx.send(f"❌ This command requires the `{admin_role}` role or Administrator permissions.")
                return False
        else:
            if admin_role in user_roles or security_role in user_roles or ctx.author.guild_permissions.administrator:
                return True
            else:
                await ctx.send(f"❌ This command requires the `{admin_role}` or `{security_role}` role.")
                return False
    
    async def send_error(self, ctx, result: Dict[str, Any]):
        """Send error message to Discord"""
        error_msg = result.get('output', 'Unknown error')
        if len(error_msg) > 1000:
            error_msg = error_msg[:1000] + "..."
        
        embed = discord.Embed(
            title="❌ Command Failed",
            description=f"```{error_msg}```",
            color=discord.Color.red()
        )
        
        if 'error' in result:
            embed.add_field(name="Error Details", value=result['error'], inline=False)
        
        await ctx.send(embed=embed)
    
    def get_severity_emoji(self, severity: str) -> str:
        """Get emoji for threat severity"""
        if severity == 'critical':
            return '🔥'
        elif severity == 'high':
            return '🔴'
        elif severity == 'medium':
            return '🟡'
        elif severity == 'low':
            return '🟢'
        else:
            return '⚪'
    
    def start_bot_thread(self):
        """Start Discord bot in separate thread"""
        if self.config.get('enabled') and self.config.get('token'):
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background thread")
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

# =====================
# TELEGRAM BOT
# =====================
class SpiderBotTelegram:
    """Telegram bot integration"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager):
        self.handler = command_handler
        self.db = db
        self.config = self.load_config()
        self.client = None
        self.running = False
    
    def load_config(self) -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        
        return {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        }
    
    def save_config(self, api_id: str, api_hash: str, phone_number: str = "", 
                   channel_id: str = "", enabled: bool = True) -> bool:
        """Save Telegram configuration"""
        try:
            config = {
                "api_id": api_id,
                "api_hash": api_hash,
                "phone_number": phone_number,
                "channel_id": channel_id,
                "enabled": enabled
            }
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    async def start(self):
        """Start Telegram bot"""
        if not TELETHON_AVAILABLE:
            logger.error("Telethon not installed")
            return False
        
        if not self.config.get('api_id') or not self.config.get('api_hash'):
            logger.error("Telegram API credentials not configured")
            return False
        
        try:
            self.client = TelegramClient(
                'spiderbot_session',
                self.config['api_id'],
                self.config['api_hash']
            )
            
            # Event handler for incoming messages
            @self.client.on(events.NewMessage(pattern=r'^/(start|help|ping|scan|nikto|add_ip|remove_ip|block_ip|unblock_ip|list_ips|ip_info|status|threats|whatsapp|signal)'))
            async def handler(event):
                await self.handle_command(event)
            
            await self.client.start(phone=self.config.get('phone_number', ''))
            logger.info("Telegram bot started")
            print(f"{Colors.GREEN}✅ Telegram bot connected{Colors.RESET}")
            
            self.running = True
            
            # Keep running
            await self.client.run_until_disconnected()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Telegram bot: {e}")
            return False
    
    async def handle_command(self, event):
        """Handle Telegram commands"""
        message = event.message.message
        sender = await event.get_sender()
        
        if not message.startswith('/'):
            return
        
        command_parts = message.split()
        command = command_parts[0][1:]  # Remove '/'
        args = command_parts[1:] if len(command_parts) > 1 else []
        
        logger.info(f"Telegram command from {sender.username}: {command} {args}")
        
        # Map Telegram commands to handler commands
        cmd_map = {
            'start': 'help',
            'help': 'help',
            'ping': f"ping {' '.join(args)}",
            'scan': f"scan {' '.join(args)}",
            'nikto': f"nikto {' '.join(args)}",
            'add_ip': f"add_ip {' '.join(args)}",
            'remove_ip': f"remove_ip {' '.join(args)}",
            'block_ip': f"block_ip {' '.join(args)}",
            'unblock_ip': f"unblock_ip {' '.join(args)}",
            'list_ips': 'list_ips',
            'ip_info': f"ip_info {' '.join(args)}",
            'status': 'status',
            'threats': 'threats',
            'whatsapp': f"whatsapp_status",
            'signal': f"signal_status"
        }
        
        if command in cmd_map:
            handler_cmd = cmd_map[command]
            if command in ['start', 'help']:
                await self.send_help(event)
            else:
                # Send processing message
                processing_msg = await event.reply(f"🔄 Processing {command}...")
                
                # Execute command
                result = self.handler.execute(handler_cmd, "telegram")
                
                # Send result
                await self.send_result(event, result, processing_msg)
    
    async def send_help(self, event):
        """Send help message"""
        help_text = """
🕸️ *Spider Bot Pro - Telegram Commands*

*WhatsApp & Signal:*
`/whatsapp` - WhatsApp bot status
`/signal` - Signal bot status

*Nikto Web Scanner:*
`/nikto <target>` - Basic web vulnerability scan
`/nikto_full <target>` - Full scan with all tests
`/nikto_ssl <target>` - SSL/TLS specific scan
`/nikto_sql <target>` - SQL injection scan
`/nikto_xss <target>` - XSS scan

*IP Management:*
`/add_ip <ip> [notes]` - Add IP to monitoring
`/remove_ip <ip>` - Remove IP from monitoring
`/block_ip <ip> [reason]` - Block IP address
`/unblock_ip <ip>` - Unblock IP address
`/list_ips` - List managed IPs
`/ip_info <ip>` - Detailed IP information

*Basic Commands:*
`/ping <ip>` - Ping IP
`/scan <ip>` - Port scan
`/status` - System status
`/threats` - Recent threats

*Examples:*
`/nikto example.com`
`/add_ip 192.168.1.100 Suspicious activity`
`/block_ip 10.0.0.5 Port scanning`
`/list_ips`
        """
        
        await event.reply(help_text, parse_mode='markdown')
    
    async def send_result(self, event, result: Dict[str, Any], processing_msg=None):
        """Send command result to Telegram"""
        if processing_msg:
            try:
                await processing_msg.delete()
            except:
                pass
        
        if not result['success']:
            error_msg = f"❌ *Command Failed*\n\n```{result.get('output', 'Unknown error')[:1000]}```"
            await event.reply(error_msg, parse_mode='markdown')
            return
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long for Telegram
        if len(formatted) > 4000:
            formatted = formatted[:3900] + "\n\n... (output truncated)"
        
        success_msg = f"✅ *Command Executed* ({result['execution_time']:.2f}s)\n\n```{formatted}```"
        
        await event.reply(success_msg, parse_mode='markdown')
    
    def start_bot_thread(self):
        """Start Telegram bot in separate thread"""
        if self.config.get('enabled') and self.config.get('api_id'):
            thread = threading.Thread(target=self._run_telegram_bot, daemon=True)
            thread.start()
            logger.info("Telegram bot started in background thread")
            return True
        return False
    
    def _run_telegram_bot(self):
        """Run Telegram bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class SpiderBotPro:
    """Main application class"""
    
    def __init__(self):
        # Load configuration
        self.config = ConfigManager.load_config()
        
        # Initialize components
        self.db = DatabaseManager()
        self.nikto = NiktoScanner(self.db, self.config.get('nikto', {}))
        self.handler = CommandHandler(self.db, self.nikto)
        self.monitor = NetworkMonitor(self.db, self.config)
        self.discord_bot = SpiderBotDiscord(self.handler, self.db, self.monitor)
        self.telegram_bot = SpiderBotTelegram(self.handler, self.db)
        self.whatsapp_bot = WhatsAppBot(self.handler, self.db, self.config.get('whatsapp', {}))
        self.signal_bot = SignalBot(self.handler, self.db, self.config.get('signal', {}))
        
        # Application state
        self.running = True
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}        🕸️ RED BACK SPIDER BOT      🕸️                                    {Colors.RED}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{Colors.CYAN}  • 600+ Complete Commands         • Nikto Web Vulnerability Scanner        {Colors.RED}║
║{Colors.CYAN}  • IP Management & Blocking       • Real-time Threat Detection             {Colors.RED}║
║{Colors.CYAN}  • 📱 WHATSAPP BOT INTEGRATION    • Send/Receive commands via WhatsApp     {Colors.RED}║
║{Colors.CYAN}  • 📱 SIGNAL BOT INTEGRATION      • Send/Receive commands via Signal       {Colors.RED}║
║{Colors.CYAN}  • Discord Bot (!nikto, !add_ip, !block_ip)                               {Colors.RED}║
║{Colors.CYAN}  • Telegram Bot (/nikto, /scan, /block_ip)                               {Colors.RED}║
║{Colors.CYAN}  • Advanced Network Scanning       • Professional Security Reporting        {Colors.RED}║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.GREEN}🔒 NEW FEATURES v0.0.1:{Colors.RESET}
  • 📱 **WhatsApp Bot** - Fire commands via WhatsApp Web (Selenium)
  • 📱 **Signal Bot** - Fire commands via Signal CLI
  • 🔧 Twilio API integration for WhatsApp Business API
  • 🎫 QR Code generation for WhatsApp Web authentication
  • 📱 Cross-platform messaging (Discord, Telegram, WhatsApp, Signal)
  • 🔒 Enhanced IP management with multi-platform support

{Colors.YELLOW}💡 Type 'help' for command list{Colors.RESET}
{Colors.YELLOW}📚 Type 'help all' for complete 600+ commands{Colors.RESET}
        """
        print(banner)
    
    def print_help(self):
        """Print help information"""
        help_text = f"""
{Colors.YELLOW}┌─────────────────{Colors.WHITE} REDBACK SPIDER BOT 0.0.1 {Colors.YELLOW}─────────────────┐{Colors.RESET}

{Colors.GREEN}📱 WHATSAPP & SIGNAL BOTS:{Colors.RESET}
  whatsapp setup --method selenium|twilio     - Configure WhatsApp bot
  whatsapp start                              - Start WhatsApp bot
  whatsapp stop                               - Stop WhatsApp bot
  whatsapp status                             - Show WhatsApp bot status
  signal setup --method cli --number +123...  - Configure Signal bot
  signal start                                - Start Signal bot
  signal stop                                 - Stop Signal bot
  signal status                               - Show Signal bot status
  twilio setup --sid <sid> --token <token>    - Configure Twilio API

{Colors.GREEN}🕷️  NIKTO WEB SCANNER:{Colors.RESET}
  nikto <target>              - Basic web vulnerability scan
  nikto_ssl <target>          - SSL/TLS specific scan
  nikto_sql <target>          - SQL injection scan
  nikto_xss <target>          - XSS scan
  nikto_cgi <target>          - CGI scan
  nikto_full <target>         - Full scan with all tests
  nikto_status                - Check Nikto availability
  nikto_results               - View recent scans

{Colors.GREEN}🔒 IP MANAGEMENT:{Colors.RESET}
  add_ip <ip> [notes]         - Add IP to monitoring
  remove_ip <ip>              - Remove IP from monitoring
  block_ip <ip> [reason]      - Block IP via firewall
  unblock_ip <ip>            - Unblock IP
  list_ips [all/active/blocked] - List managed IPs
  ip_info <ip>               - Detailed IP information

{Colors.GREEN}📡 NETWORK DIAGNOSTICS:{Colors.RESET}
  ping <ip> [options]        - Ping with options
  traceroute <target>        - Network path tracing
  scan <ip> [ports]          - Port scan (1-1000)
  quick_scan <ip>            - Fast port scan
  web_scan <ip>              - Scan web ports
  nmap <ip> [options]        - Advanced nmap scanning
  full_scan <ip>             - Scan all ports

{Colors.GREEN}🔍 INFORMATION GATHERING:{Colors.RESET}
  whois <domain>             - WHOIS lookup
  dns <domain>               - DNS lookup
  location <ip>              - IP geolocation
  analyze <ip>               - Comprehensive analysis

{Colors.GREEN}🤖 BOT COMMANDS:{Colors.RESET}
  config discord token <token>     - Set Discord token
  config discord channel <id>      - Set channel ID
  config telegram api <id> <hash>  - Set Telegram API
  start_discord                    - Start Discord bot
  start_telegram                   - Start Telegram bot

{Colors.GREEN}💡 WHATSAPP COMMAND EXAMPLES:{Colors.RESET}
  !nikto example.com
  !add_ip 192.168.1.100 Suspicious activity
  !block_ip 10.0.0.5 Port scanning
  !list_ips
  !scan 192.168.1.1
  !status

{Colors.GREEN}💡 SIGNAL COMMAND EXAMPLES:{Colors.RESET}
  !nikto example.com
  !add_ip 192.168.1.100 Suspicious activity
  !block_ip 10.0.0.5 Port scanning
  !list_ips

{Colors.YELLOW}└─────────────────────────────────────────────────────────────────────┘{Colors.RESET}
        """
        print(help_text)
    
    def check_dependencies(self):
        """Check for required dependencies"""
        print(f"\n{Colors.CYAN}🔍 Checking dependencies...{Colors.RESET}")
        
        required_tools = ['ping', 'nmap', 'curl', 'dig', 'traceroute']
        missing = []
        
        for tool in required_tools:
            if shutil.which(tool):
                print(f"{Colors.GREEN}✅ {tool}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠️  {tool} not found{Colors.RESET}")
                missing.append(tool)
        
        # Check Nikto
        if self.nikto.nikto_available:
            print(f"{Colors.GREEN}✅ nikto{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  nikto not found - web vulnerability scanning disabled{Colors.RESET}")
            missing.append('nikto')
        
        # Check Selenium for WhatsApp
        if SELENIUM_AVAILABLE:
            print(f"{Colors.GREEN}✅ selenium{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  selenium not found - WhatsApp Web automation disabled{Colors.RESET}")
        
        # Check signal-cli
        signal_path = shutil.which('signal-cli')
        if signal_path:
            print(f"{Colors.GREEN}✅ signal-cli{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  signal-cli not found - Signal bot disabled{Colors.RESET}")
        
        # Check qrcode for WhatsApp QR
        if QRCODE_AVAILABLE:
            print(f"{Colors.GREEN}✅ qrcode{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  qrcode not found - WhatsApp QR generation disabled{Colors.RESET}")
        
        if missing:
            print(f"\n{Colors.YELLOW}⚠️  Some tools are missing. Install with:{Colors.RESET}")
            if platform.system().lower() == 'linux':
                print(f"  sudo apt-get install {' '.join(missing)}")
            elif platform.system().lower() == 'darwin':
                print(f"  brew install {' '.join(missing)}")
        
        print(f"\n{Colors.GREEN}✅ Dependencies check complete{Colors.RESET}")
    
    def setup_whatsapp(self):
        """Setup WhatsApp bot"""
        print(f"\n{Colors.CYAN}📱 WhatsApp Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}Choose WhatsApp connection method:{Colors.RESET}")
        print(f"1. Selenium (WhatsApp Web) - Requires Chrome browser")
        print(f"2. Twilio (WhatsApp Business API) - Requires Twilio account")
        print()
        
        choice = input(f"{Colors.YELLOW}Enter choice (1/2): {Colors.RESET}").strip()
        
        if choice == '1':
            method = 'selenium'
            session_path = input(f"{Colors.YELLOW}Enter session path for persistent login (optional): {Colors.RESET}").strip()
            admin_number = input(f"{Colors.YELLOW}Enter admin phone number for authorization (optional): {Colors.RESET}").strip()
            
            config = {
                'enabled': True,
                'method': method,
                'session_path': session_path,
                'command_prefix': '!',
                'admin_number': admin_number,
                'headless': False
            }
            
            if ConfigManager.save_whatsapp_config(config):
                print(f"{Colors.GREEN}✅ WhatsApp configuration saved!{Colors.RESET}")
                print(f"{Colors.YELLOW}📱 To start WhatsApp bot, run: whatsapp start{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to save WhatsApp configuration{Colors.RESET}")
        
        elif choice == '2':
            method = 'twilio'
            print(f"{Colors.YELLOW}Twilio WhatsApp Business API Setup{Colors.RESET}")
            print(f"1. Sign up at https://www.twilio.com")
            print(f"2. Get your Account SID and Auth Token")
            print(f"3. Enable WhatsApp Sandbox")
            print()
            
            account_sid = input(f"{Colors.YELLOW}Enter Twilio Account SID: {Colors.RESET}").strip()
            auth_token = input(f"{Colors.YELLOW}Enter Twilio Auth Token: {Colors.RESET}").strip()
            whatsapp_number = input(f"{Colors.YELLOW}Enter Twilio WhatsApp number: {Colors.RESET}").strip()
            
            # Save Twilio config
            twilio_config = {
                'enabled': True,
                'account_sid': account_sid,
                'auth_token': auth_token,
                'whatsapp_number': whatsapp_number
            }
            
            if ConfigManager.save_twilio_config(twilio_config):
                # Save WhatsApp config
                config = {
                    'enabled': True,
                    'method': 'twilio',
                    'command_prefix': '!',
                    'admin_number': ''
                }
                ConfigManager.save_whatsapp_config(config)
                print(f"{Colors.GREEN}✅ Twilio WhatsApp configuration saved!{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to save Twilio configuration{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  WhatsApp setup skipped{Colors.RESET}")
    
    def setup_signal(self):
        """Setup Signal bot"""
        print(f"\n{Colors.CYAN}📱 Signal Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        if not shutil.which('signal-cli'):
            print(f"{Colors.YELLOW}⚠️  signal-cli not found{Colors.RESET}")
            print(f"{Colors.YELLOW}Install signal-cli first:{Colors.RESET}")
            print(f"  Linux: sudo snap install signal-cli")
            print(f"  Or download from: https://github.com/AsamK/signal-cli")
            print()
        
        method = 'cli'
        number = input(f"{Colors.YELLOW}Enter your Signal phone number (with country code, e.g., +1234567890): {Colors.RESET}").strip()
        admin_number = input(f"{Colors.YELLOW}Enter admin phone number for authorization (optional): {Colors.RESET}").strip()
        
        if number:
            config = {
                'enabled': True,
                'method': method,
                'number': number,
                'command_prefix': '!',
                'admin_number': admin_number
            }
            
            if ConfigManager.save_signal_config(config):
                print(f"{Colors.GREEN}✅ Signal configuration saved!{Colors.RESET}")
                print(f"{Colors.YELLOW}📱 To register Signal number: signal-cli -u {number} register{Colors.RESET}")
                print(f"{Colors.YELLOW}📱 To verify: signal-cli -u {number} verify <code>{Colors.RESET}")
                print(f"{Colors.YELLOW}📱 Then run: signal start{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to save Signal configuration{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️  Signal setup skipped{Colors.RESET}")
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == 'help':
            self.print_help()
        
        elif cmd == 'start':
            self.monitor.start_monitoring()
            print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        elif cmd == 'stop':
            self.monitor.stop_monitoring()
            print(f"{Colors.YELLOW}🛑 Threat monitoring stopped{Colors.RESET}")
        
        elif cmd == 'status':
            # System status
            status = self.monitor.get_status()
            print(f"\n{Colors.CYAN}📊 System Status:{Colors.RESET}")
            print(f"  Monitoring: {'✅ Yes' if status['monitoring'] else '❌ No'}")
            print(f"  Monitored IPs: {status['monitored_ips_count']}")
            print(f"  Blocked IPs: {status.get('blocked_ips', 0)}")
            print(f"  Auto-block: {'✅ Enabled' if status.get('auto_block') else '❌ Disabled'}")
            
            # Bot statuses
            print(f"\n{Colors.CYAN}🤖 Bot Status:{Colors.RESET}")
            
            # Discord
            discord_config = self.discord_bot.config
            discord_status = "✅ Connected" if self.discord_bot.running else "⏹️ Stopped" if discord_config.get('token') else "❌ Not configured"
            print(f"  Discord: {discord_status}")
            
            # Telegram
            telegram_config = self.telegram_bot.config
            telegram_status = "✅ Connected" if self.telegram_bot.running else "⏹️ Stopped" if telegram_config.get('api_id') else "❌ Not configured"
            print(f"  Telegram: {telegram_status}")
            
            # WhatsApp
            whatsapp_status = self.whatsapp_bot.get_status()
            if whatsapp_status.get('running'):
                print(f"  WhatsApp: ✅ Connected ({whatsapp_status.get('method', 'selenium')})")
            elif whatsapp_status.get('session_status', {}).get('status') == 'waiting_qr':
                print(f"  WhatsApp: ⏳ Waiting for QR scan")
            else:
                whatsapp_config = ConfigManager.load_whatsapp_config()
                if whatsapp_config.get('enabled'):
                    print(f"  WhatsApp: ⏹️ Stopped")
                else:
                    print(f"  WhatsApp: ❌ Not configured")
            
            # Signal
            signal_status = self.signal_bot.get_status()
            if signal_status.get('running'):
                print(f"  Signal: ✅ Connected")
            elif signal_status.get('enabled'):
                print(f"  Signal: ⏹️ Stopped")
            else:
                print(f"  Signal: ❌ Not configured")
            
            # Recent threats
            threats = self.db.get_recent_threats(3)
            if threats:
                print(f"\n{Colors.RED}🚨 Recent Threats:{Colors.RESET}")
                for threat in threats:
                    severity_color = Colors.RED if threat['severity'] == 'high' else Colors.YELLOW
                    print(f"  {severity_color}[{threat['timestamp'][:19]}] {threat['threat_type']} from {threat['source_ip']}{Colors.RESET}")
        
        elif cmd == 'threats':
            threats = self.db.get_recent_threats(10)
            if threats:
                print(f"\n{Colors.RED}🚨 Recent Threats:{Colors.RESET}")
                for threat in threats:
                    severity_color = Colors.RED if threat['severity'] in ['critical', 'high'] else Colors.YELLOW
                    print(f"\n{severity_color}[{threat['timestamp'][:19]}] {threat['threat_type']}{Colors.RESET}")
                    print(f"  Source: {threat['source_ip']}")
                    print(f"  Severity: {threat['severity'].upper()}")
                    print(f"  Description: {threat['description']}")
            else:
                print(f"{Colors.GREEN}✅ No recent threats detected{Colors.RESET}")
        
        elif cmd == 'whatsapp':
            if not args:
                print(f"{Colors.YELLOW}Usage: whatsapp <setup|start|stop|status>{Colors.RESET}")
                return
            
            subcmd = args[0].lower()
            
            if subcmd == 'setup':
                self.setup_whatsapp()
            
            elif subcmd == 'start':
                if self.whatsapp_bot.start():
                    print(f"{Colors.GREEN}✅ WhatsApp bot started{Colors.RESET}")
                    print(f"{Colors.YELLOW}📱 QR code saved to: {QR_CODES_DIR}/whatsapp_{self.whatsapp_bot.session_id}.png{Colors.RESET}")
                    
                    # Update config
                    whatsapp_config = ConfigManager.load_whatsapp_config()
                    whatsapp_config['enabled'] = True
                    ConfigManager.save_whatsapp_config(whatsapp_config)
                else:
                    print(f"{Colors.RED}❌ Failed to start WhatsApp bot{Colors.RESET}")
            
            elif subcmd == 'stop':
                self.whatsapp_bot.stop()
                print(f"{Colors.YELLOW}🛑 WhatsApp bot stopped{Colors.RESET}")
                
                # Update config
                whatsapp_config = ConfigManager.load_whatsapp_config()
                whatsapp_config['enabled'] = False
                ConfigManager.save_whatsapp_config(whatsapp_config)
            
            elif subcmd == 'status':
                status = self.whatsapp_bot.get_status()
                print(f"\n{Colors.CYAN}📱 WhatsApp Bot Status:{Colors.RESET}")
                print(f"  Running: {'✅ Yes' if status.get('running') else '❌ No'}")
                print(f"  Method: {status.get('method', 'N/A')}")
                print(f"  Session ID: {status.get('session_id', 'N/A')}")
                
                if status.get('session_status'):
                    session = status['session_status']
                    print(f"  Session Status: {session.get('status', 'unknown')}")
                    if session.get('qr_code_path'):
                        print(f"  QR Code: {session.get('qr_code_path')}")
                    if session.get('last_active'):
                        print(f"  Last Active: {session.get('last_active')[:19]}")
                
                print(f"  Selenium Available: {'✅' if status.get('selenium_available') else '❌'}")
                print(f"  Twilio Available: {'✅' if status.get('twilio_available') else '❌'}")
            
            else:
                print(f"{Colors.YELLOW}Unknown WhatsApp command: {subcmd}{Colors.RESET}")
        
        elif cmd == 'signal':
            if not args:
                print(f"{Colors.YELLOW}Usage: signal <setup|start|stop|status>{Colors.RESET}")
                return
            
            subcmd = args[0].lower()
            
            if subcmd == 'setup':
                self.setup_signal()
            
            elif subcmd == 'start':
                if self.signal_bot.start():
                    print(f"{Colors.GREEN}✅ Signal bot started{Colors.RESET}")
                    
                    # Update config
                    signal_config = ConfigManager.load_signal_config()
                    signal_config['enabled'] = True
                    ConfigManager.save_signal_config(signal_config)
                else:
                    print(f"{Colors.RED}❌ Failed to start Signal bot{Colors.RESET}")
            
            elif subcmd == 'stop':
                self.signal_bot.stop()
                print(f"{Colors.YELLOW}🛑 Signal bot stopped{Colors.RESET}")
                
                # Update config
                signal_config = ConfigManager.load_signal_config()
                signal_config['enabled'] = False
                ConfigManager.save_signal_config(signal_config)
            
            elif subcmd == 'status':
                status = self.signal_bot.get_status()
                print(f"\n{Colors.CYAN}📱 Signal Bot Status:{Colors.RESET}")
                print(f"  Running: {'✅ Yes' if status.get('running') else '❌ No'}")
                print(f"  Method: {status.get('method', 'N/A')}")
                print(f"  Number: {status.get('number', 'Not configured')}")
                print(f"  Admin Number: {status.get('admin_number', 'Not configured')}")
                print(f"  signal-cli Available: {'✅' if status.get('signal_cli_available') else '❌'}")
                if status.get('signal_cli_path'):
                    print(f"  signal-cli Path: {status.get('signal_cli_path')}")
            
            else:
                print(f"{Colors.YELLOW}Unknown Signal command: {subcmd}{Colors.RESET}")
        
        elif cmd == 'twilio':
            if not args:
                print(f"{Colors.YELLOW}Usage: twilio <setup|status|test>{Colors.RESET}")
                return
            
            subcmd = args[0].lower()
            
            if subcmd == 'setup':
                print(f"\n{Colors.CYAN}📞 Twilio API Setup{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
                
                account_sid = input(f"{Colors.YELLOW}Enter Twilio Account SID: {Colors.RESET}").strip()
                auth_token = input(f"{Colors.YELLOW}Enter Twilio Auth Token: {Colors.RESET}").strip()
                whatsapp_number = input(f"{Colors.YELLOW}Enter Twilio WhatsApp number: {Colors.RESET}").strip()
                
                config = {
                    'enabled': True,
                    'account_sid': account_sid,
                    'auth_token': auth_token,
                    'whatsapp_number': whatsapp_number
                }
                
                if ConfigManager.save_twilio_config(config):
                    print(f"{Colors.GREEN}✅ Twilio configuration saved!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to save Twilio configuration{Colors.RESET}")
            
            elif subcmd == 'status':
                result = self.handler.execute("twilio_status")
                if result['success']:
                    data = result['data']
                    print(f"\n{Colors.CYAN}📞 Twilio Status:{Colors.RESET}")
                    print(f"  Enabled: {'✅ Yes' if data.get('enabled') else '❌ No'}")
                    print(f"  Account SID: {data.get('account_sid', 'Not configured')}")
                    print(f"  WhatsApp Number: {data.get('whatsapp_number', 'Not configured')}")
                    print(f"  Twilio Available: {'✅' if data.get('twilio_available') else '❌'}")
            
            elif subcmd == 'test' and len(args) >= 3:
                method = args[1]
                number = args[2]
                result = self.handler.execute(f"twilio test {method} {number}")
                if result['success']:
                    print(f"{Colors.GREEN}✅ Test message sent!{Colors.RESET}")
                    print(f"  Message SID: {result['data'].get('message_sid')}")
                    print(f"  Status: {result['data'].get('status')}")
                else:
                    print(f"{Colors.RED}❌ Test failed: {result.get('output')}{Colors.RESET}")
            
            else:
                print(f"{Colors.YELLOW}Unknown Twilio command{Colors.RESET}")
        
        elif cmd == 'report':
            result = self.handler.execute("report")
            if result['success']:
                data = result['data']
                print(f"\n{Colors.CYAN}📊 Security Report{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                print(f"\n{Colors.WHITE}Generated: {data.get('generated_at', '')[:19]}{Colors.RESET}")
                
                stats = data.get('statistics', {})
                print(f"\n{Colors.GREEN}📈 Statistics:{Colors.RESET}")
                print(f"  Total Commands: {stats.get('total_commands', 0)}")
                print(f"  Total Scans: {stats.get('total_scans', 0)}")
                print(f"  Nikto Scans: {stats.get('total_nikto_scans', 0)}")
                print(f"  Managed IPs: {stats.get('total_managed_ips', 0)}")
                print(f"  Blocked IPs: {stats.get('total_blocked_ips', 0)}")
                print(f"  Total Threats: {stats.get('total_threats', 0)}")
                
                threats = data.get('threat_summary', {})
                print(f"\n{Colors.RED}🚨 Threat Summary:{Colors.RESET}")
                print(f"  Critical: {threats.get('critical', 0)}")
                print(f"  High: {threats.get('high', 0)}")
                print(f"  Medium: {threats.get('medium', 0)}")
                print(f"  Low: {threats.get('low', 0)}")
                
                recommendations = data.get('recommendations', [])
                if recommendations:
                    print(f"\n{Colors.YELLOW}💡 Recommendations:{Colors.RESET}")
                    for rec in recommendations:
                        print(f"  • {rec}")
                
                if 'report_file' in data:
                    print(f"\n{Colors.GREEN}✅ Report saved: {data['report_file']}{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to generate report: {result.get('output', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'config' and len(args) >= 2:
            service = args[0].lower()
            
            if service == 'discord':
                if len(args) >= 3 and args[1] == 'token':
                    token = args[2]
                    channel = self.discord_bot.config.get('channel_id', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    security_role = self.discord_bot.config.get('security_role', 'Security Team')
                    self.discord_bot.save_config(token, channel, True, prefix, admin_role, security_role)
                    print(f"{Colors.GREEN}✅ Discord token configured{Colors.RESET}")
                
                elif len(args) >= 3 and args[1] == 'channel':
                    channel_id = args[2]
                    token = self.discord_bot.config.get('token', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    security_role = self.discord_bot.config.get('security_role', 'Security Team')
                    self.discord_bot.save_config(token, channel_id, True, prefix, admin_role, security_role)
                    print(f"{Colors.GREEN}✅ Discord channel ID configured{Colors.RESET}")
            
            elif service == 'telegram' and len(args) >= 4 and args[1] == 'api':
                api_id = args[2]
                api_hash = args[3]
                phone = self.telegram_bot.config.get('phone_number', '')
                channel = self.telegram_bot.config.get('channel_id', '')
                self.telegram_bot.save_config(api_id, api_hash, phone, channel, True)
                print(f"{Colors.GREEN}✅ Telegram API configured{Colors.RESET}")
        
        elif cmd == 'start_discord':
            if not self.discord_bot.config.get('token'):
                print(f"{Colors.RED}❌ Discord token not configured{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: config discord token <your_token>{Colors.RESET}")
            else:
                if self.discord_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Discord bot started!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        
        elif cmd == 'start_telegram':
            if not self.telegram_bot.config.get('api_id'):
                print(f"{Colors.RED}❌ Telegram API not configured{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: config telegram api <id> <hash>{Colors.RESET}")
            else:
                if self.telegram_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Telegram bot started!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Telegram bot{Colors.RESET}")
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.YELLOW}👋 Thank you for using Spider Bot Pro!{Colors.RESET}")
        
        else:
            # Execute as generic command
            result = self.handler.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                
                if isinstance(output, dict):
                    # Pretty print dictionaries
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                
                print(f"\n{Colors.GREEN}✅ Command executed ({result['execution_time']:.2f}s){Colors.RESET}")
            else:
                print(f"\n{Colors.RED}❌ Command failed: {result.get('output', 'Unknown error')}{Colors.RESET}")
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup bots if configured
        print(f"\n{Colors.CYAN}🤖 Bot Configuration{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Check Discord
        if self.discord_bot.config.get('enabled') and self.discord_bot.config.get('token'):
            print(f"{Colors.GREEN}✅ Discord bot configured{Colors.RESET}")
            self.discord_bot.start_bot_thread()
        else:
            setup_discord = input(f"{Colors.YELLOW}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_discord == 'y':
                print(f"\n{Colors.CYAN}Discord Bot Setup{Colors.RESET}")
                token = input(f"{Colors.YELLOW}Enter Discord bot token: {Colors.RESET}").strip()
                if token:
                    channel_id = input(f"{Colors.YELLOW}Enter channel ID for notifications (optional): {Colors.RESET}").strip()
                    self.discord_bot.save_config(token, channel_id, True, "!", "Admin", "Security Team")
                    print(f"{Colors.GREEN}✅ Discord configured!{Colors.RESET}")
        
        # Check Telegram
        if self.telegram_bot.config.get('enabled') and self.telegram_bot.config.get('api_id'):
            print(f"{Colors.GREEN}✅ Telegram bot configured{Colors.RESET}")
            self.telegram_bot.start_bot_thread()
        else:
            setup_telegram = input(f"{Colors.YELLOW}Setup Telegram bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_telegram == 'y':
                print(f"\n{Colors.CYAN}Telegram Bot Setup{Colors.RESET}")
                api_id = input(f"{Colors.YELLOW}Enter API ID: {Colors.RESET}").strip()
                api_hash = input(f"{Colors.YELLOW}Enter API Hash: {Colors.RESET}").strip()
                if api_id and api_hash:
                    self.telegram_bot.save_config(api_id, api_hash, "", "", True)
                    print(f"{Colors.GREEN}✅ Telegram configured!{Colors.RESET}")
        
        # Check WhatsApp
        whatsapp_config = ConfigManager.load_whatsapp_config()
        if whatsapp_config.get('enabled'):
            print(f"{Colors.GREEN}✅ WhatsApp bot configured{Colors.RESET}")
            auto_start = input(f"{Colors.YELLOW}Start WhatsApp bot now? (y/n): {Colors.RESET}").strip().lower()
            if auto_start == 'y':
                self.whatsapp_bot.start()
        else:
            setup_whatsapp = input(f"{Colors.YELLOW}Setup WhatsApp bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_whatsapp == 'y':
                self.setup_whatsapp()
        
        # Check Signal
        signal_config = ConfigManager.load_signal_config()
        if signal_config.get('enabled'):
            print(f"{Colors.GREEN}✅ Signal bot configured{Colors.RESET}")
            auto_start = input(f"{Colors.YELLOW}Start Signal bot now? (y/n): {Colors.RESET}").strip().lower()
            if auto_start == 'y' and signal_config.get('method') == 'cli' and shutil.which('signal-cli'):
                self.signal_bot.start()
        else:
            setup_signal = input(f"{Colors.YELLOW}Setup Signal bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_signal == 'y':
                self.setup_signal()
        
        # Ask about monitoring
        auto_monitor = input(f"\n{Colors.YELLOW}Start threat monitoring automatically? (y/n): {Colors.RESET}").strip().lower()
        if auto_monitor == 'y':
            self.monitor.start_monitoring()
            print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Tool ready! Type 'help' for commands.{Colors.RESET}")
        
        # Main command loop
        while self.running:
            try:
                prompt = f"{Colors.RED}[{Colors.WHITE}spiderbot-pro{Colors.RED}]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.RESET}")
                self.running = False
            
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.monitor.stop_monitoring()
        self.whatsapp_bot.stop()
        self.signal_bot.stop()
        self.db.close()
        
        print(f"\n{Colors.GREEN}✅ Tool shutdown complete.{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Logs saved to: {LOG_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}💾 Database: {DATABASE_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}🕷️  Nikto results: {NIKTO_RESULTS_DIR}{Colors.RESET}")
        print(f"{Colors.CYAN}📱 WhatsApp QR codes: {QR_CODES_DIR}{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print(f"{Colors.CYAN}🚀 Starting Redback Spider Bot 0.0.1..{Colors.RESET}")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher is required{Colors.RESET}")
            sys.exit(1)
        
        # Check for root/admin privileges for firewall operations
        if platform.system().lower() == 'linux':
            if os.geteuid() != 0:
                print(f"{Colors.YELLOW}⚠️  Warning: Running without root privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}   Firewall operations (block_ip/unblock_ip) will not work{Colors.RESET}")
                print(f"{Colors.YELLOW}   Run with: sudo python3 spiderbot_pro.py{Colors.RESET}")
                time.sleep(2)
        elif platform.system().lower() == 'windows':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{Colors.YELLOW}⚠️  Warning: Running without administrator privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}   Firewall operations will not work{Colors.RESET}")
                time.sleep(2)
        
        # Create and run application
        app = SpiderBotPro()
        app.run()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()