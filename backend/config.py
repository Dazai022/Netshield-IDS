"""
Configuration file for NetShield IDS/IPS
Contains detection thresholds and system settings
"""

import os

# Detection Thresholds
DOS_PACKET_RATE_THRESHOLD = 1000  # packets per second
SYN_FLOOD_RATIO = 0.8  # 80% SYN packets without ACK
DDOS_SOURCE_THRESHOLD = 50  # unique source IPs targeting one host
DNS_TUNNEL_LENGTH = 50  # suspicious domain name length
DNS_ENTROPY_THRESHOLD = 3.5  # entropy threshold for DNS tunneling
BEACON_INTERVAL_VARIANCE = 5  # seconds variance for HTTP beaconing
HTTP_BEACON_MIN_REQUESTS = 5  # minimum requests to detect beaconing

# IPS Settings
AUTO_BLOCKING_ENABLED = False
WHITELIST_IPS = ["127.0.0.1", "::1", "192.168.1.1"]

import shutil

def find_executable(name, default_paths):
    found = shutil.which(name)
    if found:
        return found
    for path in default_paths:
        if os.path.exists(path):
            return path
    return name

# Tool Paths
SNORT_PATH = find_executable("snort", ["C:\\Snort\\bin\\snort.exe", "C:\\Program Files\\Snort\\bin\\snort.exe"])
TSHARK_PATH = find_executable("tshark", ["C:\\Program Files\\Wireshark\\tshark.exe", "C:\\Program Files (x86)\\Wireshark\\tshark.exe"])


# File Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
ALERT_STORAGE = os.path.join(DATA_DIR, "alerts.json")
SNORT_RULES_DIR = os.path.join(BASE_DIR, "snort_rules")
SAMPLE_PCAPS_DIR = os.path.join(BASE_DIR, "sample_pcaps")

# Snort Configuration
SNORT_ALERT_FILE = os.path.join(DATA_DIR, "snort_alert.txt")
SNORT_LOG_DIR = os.path.join(DATA_DIR, "snort_logs")

# Severity Mapping
SEVERITY_MAPPING = {
    "sql injection": "high",
    "rce": "high",
    "remote code execution": "high",
    "dos": "high",
    "ddos": "high",
    "arp spoofing": "high",
    "mitm": "high",
    "port scan": "medium",
    "brute force": "medium",
    "dns tunneling": "medium",
    "malware beacon": "medium",
    "suspicious traffic": "low",
    "policy violation": "low",
}

# Dashboard Settings
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
DEBUG_MODE = True
