"""
Snort Integration Module
Runs Snort on PCAP files and parses alert outputs
"""

import subprocess
import os
import re
from datetime import datetime
from backend.config import SNORT_PATH, SNORT_ALERT_FILE, SNORT_LOG_DIR, SNORT_RULES_DIR


class SnortEngine:
    """Snort signature-based detection engine"""
    
    def __init__(self, pcap_file, rules_file=None):
        self.pcap_file = pcap_file
        self.rules_file = rules_file or os.path.join(SNORT_RULES_DIR, "custom.rules")
        self.alerts = []
        
    def run_snort(self):
        """
        Execute Snort on the PCAP file
        Returns list of alert dictionaries
        """
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        if not os.path.exists(self.rules_file):
            print(f"Warning: Rules file not found: {self.rules_file}")
            print("Continuing without custom rules...")
            return []
        
        # Ensure log directory exists
        os.makedirs(SNORT_LOG_DIR, exist_ok=True)
        
        try:
            # Run Snort in packet logger mode with custom rules
            cmd = [
                SNORT_PATH,
                "-r", self.pcap_file,
                "-c", self.rules_file,
                "-A", "fast",
                "-l", SNORT_LOG_DIR,
                "-K", "ascii"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Parse alert file
            alert_file = os.path.join(SNORT_LOG_DIR, "alert")
            if os.path.exists(alert_file):
                self.alerts = self._parse_alert_file(alert_file)
            
            return self.alerts
            
        except subprocess.TimeoutExpired:
            raise Exception("Snort execution timed out")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Snort error: {e.stderr}")
        except Exception as e:
            print(f"Warning: Snort execution failed: {e}")
            return []
    
    def _parse_alert_file(self, alert_file):
        """
        Parse Snort alert.fast file
        Format: [**] [gid:sid:rev] Message [**] [Classification: class] [Priority: pri] {proto} src_ip:port -> dst_ip:port
        """
        alerts = []
        
        try:
            with open(alert_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split by alert entries (each starts with timestamp)
            alert_pattern = r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+'
            alert_blocks = re.split(f'({alert_pattern})', content)
            
            for i in range(1, len(alert_blocks), 2):
                if i + 1 < len(alert_blocks):
                    timestamp = alert_blocks[i]
                    alert_text = alert_blocks[i + 1]
                    
                    alert = self._parse_alert_block(timestamp, alert_text)
                    if alert:
                        alerts.append(alert)
        
        except Exception as e:
            print(f"Error parsing alert file: {e}")
        
        return alerts
    
    def _parse_alert_block(self, timestamp, alert_text):
        """Parse individual alert block"""
        try:
            # Extract message
            msg_match = re.search(r'\[\*\*\]\s*\[.*?\]\s*(.*?)\s*\[\*\*\]', alert_text)
            message = msg_match.group(1).strip() if msg_match else "Unknown Alert"
            
            # Extract classification
            class_match = re.search(r'\[Classification:\s*(.*?)\]', alert_text)
            classification = class_match.group(1).strip() if class_match else "Unknown"
            
            # Extract priority
            pri_match = re.search(r'\[Priority:\s*(\d+)\]', alert_text)
            priority = int(pri_match.group(1)) if pri_match else 3
            
            # Extract IPs and ports
            ip_match = re.search(r'\{(\w+)\}\s*([\d\.]+):?(\d*)\s*->\s*([\d\.]+):?(\d*)', alert_text)
            
            if ip_match:
                protocol = ip_match.group(1)
                src_ip = ip_match.group(2)
                src_port = ip_match.group(3) or ""
                dst_ip = ip_match.group(4)
                dst_port = ip_match.group(5) or ""
            else:
                protocol = "Unknown"
                src_ip = "Unknown"
                src_port = ""
                dst_ip = "Unknown"
                dst_port = ""
            
            # Determine severity based on priority
            severity = self._priority_to_severity(priority)
            
            return {
                "type": "signature",
                "attack": message,
                "classification": classification,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "timestamp": self._format_timestamp(timestamp),
                "severity": severity,
                "source": "snort",
                "priority": priority
            }
        
        except Exception as e:
            print(f"Error parsing alert block: {e}")
            return None
    
    def _priority_to_severity(self, priority):
        """Convert Snort priority to severity level"""
        if priority == 1:
            return "high"
        elif priority == 2:
            return "medium"
        else:
            return "low"
    
    def _format_timestamp(self, timestamp):
        """Format Snort timestamp to standard format"""
        try:
            # Snort format: MM/DD-HH:MM:SS.microsec
            dt = datetime.strptime(timestamp.split('.')[0], "%m/%d-%H:%M:%S")
            # Add current year
            dt = dt.replace(year=datetime.now().year)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return timestamp


def run_snort_analysis(pcap_file, rules_file=None):
    """Convenience function to run Snort analysis"""
    engine = SnortEngine(pcap_file, rules_file)
    return engine.run_snort()
