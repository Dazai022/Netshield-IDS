"""
Alert Management System
Central alert processor combining Snort and custom detections
"""

import json
import os
from datetime import datetime
from collections import defaultdict, Counter
from backend.config import ALERT_STORAGE, SEVERITY_MAPPING, DATA_DIR


class AlertManager:
    """Unified alert management system"""
    
    def __init__(self):
        self.alerts = []
        self.load_alerts()
    
    def add_alert(self, alert_data):
        """Add a new alert to the system"""
        # Ensure required fields
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Classify severity if not provided
        if "severity" not in alert_data or not alert_data["severity"]:
            alert_data["severity"] = self.classify_severity(alert_data)
        
        # Add unique ID
        alert_data["id"] = len(self.alerts) + 1
        
        self.alerts.append(alert_data)
        return alert_data
    
    def add_alerts(self, alerts_list):
        """Add multiple alerts"""
        for alert in alerts_list:
            self.add_alert(alert)
    
    def classify_severity(self, alert):
        """
        Classify alert severity based on attack type
        Returns: 'high', 'medium', or 'low'
        """
        attack_type = alert.get("attack", "").lower()
        
        # Check against severity mapping
        for keyword, severity in SEVERITY_MAPPING.items():
            if keyword in attack_type:
                return severity
        
        # Default based on source
        if alert.get("source") == "snort":
            # Use Snort priority if available
            priority = alert.get("priority", 3)
            if priority == 1:
                return "high"
            elif priority == 2:
                return "medium"
        
        return "low"
    
    def get_alerts(self, filters=None):
        """
        Get alerts with optional filtering
        Filters: severity, source, src_ip, dst_ip, attack_type, limit
        """
        filtered = self.alerts
        
        if filters:
            if "severity" in filters:
                filtered = [a for a in filtered if a.get("severity") == filters["severity"]]
            
            if "source" in filters:
                filtered = [a for a in filtered if a.get("source") == filters["source"]]
            
            if "src_ip" in filters:
                filtered = [a for a in filtered if a.get("src_ip") == filters["src_ip"]]
            
            if "dst_ip" in filters:
                filtered = [a for a in filtered if a.get("dst_ip") == filters["dst_ip"]]
            
            if "attack_type" in filters:
                filtered = [a for a in filtered if filters["attack_type"].lower() in a.get("attack", "").lower()]
            
            if "limit" in filters:
                filtered = filtered[:filters["limit"]]
        
        return filtered
    
    def get_statistics(self):
        """Calculate comprehensive alert statistics"""
        if not self.alerts:
            return {
                "total_alerts": 0,
                "severity_distribution": {},
                "attack_type_distribution": {},
                "top_attackers": [],
                "top_targets": [],
                "timeline": [],
                "source_distribution": {}
            }
        
        # Severity distribution
        severity_count = Counter(a.get("severity", "low") for a in self.alerts)
        
        # Attack type distribution
        attack_count = Counter(a.get("attack", "Unknown") for a in self.alerts)
        
        # Top attackers
        attacker_count = Counter(a.get("src_ip", "Unknown") for a in self.alerts if a.get("src_ip"))
        top_attackers = [{"ip": ip, "count": count} for ip, count in attacker_count.most_common(10)]
        
        # Top targets
        target_count = Counter(a.get("dst_ip", "Unknown") for a in self.alerts if a.get("dst_ip"))
        top_targets = [{"ip": ip, "count": count} for ip, count in target_count.most_common(10)]
        
        # Timeline (hourly)
        timeline = self._generate_timeline()
        
        # Source distribution
        source_count = Counter(a.get("source", "unknown") for a in self.alerts)
        
        return {
            "total_alerts": len(self.alerts),
            "severity_distribution": dict(severity_count),
            "attack_type_distribution": dict(attack_count.most_common(10)),
            "top_attackers": top_attackers,
            "top_targets": top_targets,
            "timeline": timeline,
            "source_distribution": dict(source_count)
        }
    
    def _generate_timeline(self):
        """Generate hourly timeline of attacks"""
        hourly_count = defaultdict(int)
        
        for alert in self.alerts:
            timestamp = alert.get("timestamp", "")
            try:
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                hourly_count[hour_key] += 1
            except:
                continue
        
        # Sort by time
        timeline = [{"time": time, "count": count} for time, count in sorted(hourly_count.items())]
        return timeline
    
    def save_alerts(self):
        """Persist alerts to JSON file"""
        os.makedirs(DATA_DIR, exist_ok=True)
        
        try:
            with open(ALERT_STORAGE, 'w') as f:
                json.dump(self.alerts, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving alerts: {e}")
            return False
    
    def load_alerts(self):
        """Load alerts from JSON file"""
        if os.path.exists(ALERT_STORAGE):
            try:
                with open(ALERT_STORAGE, 'r') as f:
                    self.alerts = json.load(f)
            except Exception as e:
                print(f"Error loading alerts: {e}")
                self.alerts = []
        else:
            self.alerts = []
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts = []
        self.save_alerts()
    
    def get_alert_by_id(self, alert_id):
        """Get specific alert by ID"""
        for alert in self.alerts:
            if alert.get("id") == alert_id:
                return alert
        return None
    
    def get_high_severity_alerts(self):
        """Get all high severity alerts"""
        return [a for a in self.alerts if a.get("severity") == "high"]


# Global alert manager instance
alert_manager = AlertManager()


def get_alert_manager():
    """Get the global alert manager instance"""
    return alert_manager
