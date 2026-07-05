"""
IPS Auto-Blocking Module
Automatic IP blocking for high-severity threats (Windows Firewall)
"""

import subprocess
import os
from datetime import datetime
from backend.config import AUTO_BLOCKING_ENABLED, WHITELIST_IPS, DATA_DIR


class IPSBlocker:
    """IPS auto-blocking functionality"""
    
    def __init__(self):
        self.enabled = AUTO_BLOCKING_ENABLED
        self.blocked_ips = []
        self.whitelist = WHITELIST_IPS
        self.log_file = os.path.join(DATA_DIR, "ips_blocks.log")
    
    def is_blocking_enabled(self):
        """Check if auto-blocking is enabled"""
        return self.enabled
    
    def enable_blocking(self):
        """Enable auto-blocking"""
        self.enabled = True
        self._log_action("Auto-blocking enabled")
    
    def disable_blocking(self):
        """Disable auto-blocking"""
        self.enabled = False
        self._log_action("Auto-blocking disabled")
    
    def block_ip(self, ip_address, reason="High severity threat"):
        """
        Block an IP address using Windows Firewall
        Returns True if successful, False otherwise
        """
        if not self.enabled:
            print(f"Auto-blocking disabled. Would block: {ip_address}")
            return False
        
        # Check whitelist
        if ip_address in self.whitelist:
            print(f"IP {ip_address} is whitelisted. Skipping block.")
            return False
        
        # Check if already blocked
        if ip_address in self.blocked_ips:
            print(f"IP {ip_address} already blocked")
            return True
        
        try:
            # Windows Firewall command
            rule_name = f"NetShield_Block_{ip_address.replace('.', '_')}"
            
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}",
                "enable=yes"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            self.blocked_ips.append(ip_address)
            self._log_action(f"Blocked IP: {ip_address} - Reason: {reason}")
            
            print(f"Successfully blocked IP: {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip_address}: {e.stderr}")
            self._log_action(f"Failed to block IP: {ip_address} - Error: {e.stderr}")
            return False
        except Exception as e:
            print(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """
        Unblock an IP address
        Returns True if successful, False otherwise
        """
        if ip_address not in self.blocked_ips:
            print(f"IP {ip_address} is not blocked")
            return False
        
        try:
            rule_name = f"NetShield_Block_{ip_address.replace('.', '_')}"
            
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            self.blocked_ips.remove(ip_address)
            self._log_action(f"Unblocked IP: {ip_address}")
            
            print(f"Successfully unblocked IP: {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            print(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        return self.blocked_ips.copy()
    
    def process_alert(self, alert):
        """
        Process an alert and block if necessary
        Blocks high-severity threats automatically
        """
        if not self.enabled:
            return False
        
        severity = alert.get("severity", "low")
        src_ip = alert.get("src_ip", "")
        
        if severity == "high" and src_ip and src_ip != "Unknown":
            attack_type = alert.get("attack", "Unknown threat")
            return self.block_ip(src_ip, reason=attack_type)
        
        return False
    
    def _log_action(self, message):
        """Log blocking actions"""
        os.makedirs(DATA_DIR, exist_ok=True)
        
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {message}\n"
            
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Error logging action: {e}")


# Global IPS blocker instance
ips_blocker = IPSBlocker()


def get_ips_blocker():
    """Get the global IPS blocker instance"""
    return ips_blocker
