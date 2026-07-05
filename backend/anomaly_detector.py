"""
Anomaly Detection Module
Custom detection logic for DoS/DDoS, MITM, and malware traffic
"""

import math
from collections import defaultdict, Counter
from datetime import datetime
from backend.config import (
    DOS_PACKET_RATE_THRESHOLD,
    SYN_FLOOD_RATIO,
    DDOS_SOURCE_THRESHOLD,
    DNS_TUNNEL_LENGTH,
    DNS_ENTROPY_THRESHOLD,
    BEACON_INTERVAL_VARIANCE,
    HTTP_BEACON_MIN_REQUESTS
)


class AnomalyDetector:
    """Custom anomaly-based detection engine"""
    
    def __init__(self, packets):
        self.packets = packets
        self.alerts = []
    
    def detect_all(self):
        """Run all detection modules"""
        self.alerts = []
        
        # DoS/DDoS Detection
        self.alerts.extend(self.detect_dos())
        self.alerts.extend(self.detect_syn_flood())
        self.alerts.extend(self.detect_ddos())
        
        # MITM Detection
        self.alerts.extend(self.detect_arp_spoofing())
        
        # Malware Traffic Detection
        self.alerts.extend(self.detect_dns_tunneling())
        self.alerts.extend(self.detect_http_beaconing())
        
        return self.alerts
    
    def detect_dos(self):
        """
        Detect DoS attacks based on high packet rate from single IP
        Threshold: > 1000 packets/sec
        """
        alerts = []
        src_ip_packets = defaultdict(list)
        
        # Group packets by source IP
        for pkt in self.packets:
            if pkt.get("src_ip"):
                src_ip_packets[pkt["src_ip"]].append(pkt)
        
        # Analyze packet rate per IP
        for src_ip, pkts in src_ip_packets.items():
            if len(pkts) < 50:  # Skip low-volume sources
                continue
            
            # Calculate time span safely
            parsed = [self._parse_timestamp(p.get("timestamp")) for p in pkts]
            timestamps = [t for t in parsed if t is not None]
            
            if not timestamps:
                continue
            
            timestamps.sort()
            time_span = (timestamps[-1] - timestamps[0]).total_seconds()
            
            if time_span <= 0:
                time_span = 0.001  # Sub-second burst fallback
                
            packet_rate = len(pkts) / time_span
            
            if packet_rate > DOS_PACKET_RATE_THRESHOLD:
                # Find target IP
                dst_ips = [p.get("dst_ip") for p in pkts if p.get("dst_ip")]
                target = Counter(dst_ips).most_common(1)[0][0] if dst_ips else "Multiple"
                
                alerts.append({
                    "type": "anomaly",
                    "attack": "DoS Attack Detected",
                    "description": f"High packet rate: {packet_rate:.0f} packets/sec",
                    "src_ip": src_ip,
                    "dst_ip": target,
                    "timestamp": timestamps[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "high",
                    "source": "anomaly_detector",
                    "details": {
                        "packet_count": len(pkts),
                        "packet_rate": packet_rate,
                        "time_span": time_span
                    }
                })
        
        return alerts
    
    def detect_syn_flood(self):
        """
        Detect SYN flood attacks
        High ratio of SYN packets without corresponding ACK
        """
        alerts = []
        src_ip_syn_ack = defaultdict(lambda: {"syn": 0, "ack": 0})
        
        # Count SYN and ACK flags per source IP
        for pkt in self.packets:
            if pkt.get("protocol") == "TCP" and pkt.get("src_ip"):
                if pkt.get("tcp_syn"):
                    src_ip_syn_ack[pkt["src_ip"]]["syn"] += 1
                if pkt.get("tcp_ack"):
                    src_ip_syn_ack[pkt["src_ip"]]["ack"] += 1
        
        # Analyze SYN/ACK ratio
        for src_ip, counts in src_ip_syn_ack.items():
            total = counts["syn"] + counts["ack"]
            if total < 50:  # Skip low-volume sources
                continue
            
            syn_ratio = counts["syn"] / total if total > 0 else 0
            
            if syn_ratio > SYN_FLOOD_RATIO:
                # Find target
                target_pkts = [p for p in self.packets if p.get("src_ip") == src_ip and p.get("tcp_syn")]
                dst_ips = [p.get("dst_ip") for p in target_pkts if p.get("dst_ip")]
                target = Counter(dst_ips).most_common(1)[0][0] if dst_ips else "Unknown"
                
                alerts.append({
                    "type": "anomaly",
                    "attack": "SYN Flood Attack",
                    "description": f"SYN ratio: {syn_ratio*100:.1f}%",
                    "src_ip": src_ip,
                    "dst_ip": target,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "high",
                    "source": "anomaly_detector",
                    "details": {
                        "syn_count": counts["syn"],
                        "ack_count": counts["ack"],
                        "syn_ratio": syn_ratio
                    }
                })
        
        return alerts
    
    def detect_ddos(self):
        """
        Detect DDoS attacks
        Multiple source IPs targeting single host
        """
        alerts = []
        dst_ip_sources = defaultdict(set)
        
        # Track unique sources per destination
        for pkt in self.packets:
            if pkt.get("src_ip") and pkt.get("dst_ip"):
                dst_ip_sources[pkt["dst_ip"]].add(pkt["src_ip"])
        
        # Check for excessive sources
        for dst_ip, sources in dst_ip_sources.items():
            if len(sources) > DDOS_SOURCE_THRESHOLD:
                alerts.append({
                    "type": "anomaly",
                    "attack": "DDoS Attack Detected",
                    "description": f"{len(sources)} unique sources targeting single host",
                    "src_ip": f"{len(sources)} sources",
                    "dst_ip": dst_ip,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "high",
                    "source": "anomaly_detector",
                    "details": {
                        "source_count": len(sources),
                        "top_sources": list(sources)[:10]
                    }
                })
        
        return alerts
    
    def detect_arp_spoofing(self):
        """
        Detect ARP spoofing / MITM attacks
        Same MAC address claiming multiple IP addresses
        """
        alerts = []
        mac_to_ips = defaultdict(set)
        
        # Track MAC-to-IP mappings from ARP packets
        for pkt in self.packets:
            if pkt.get("arp_src_mac") and pkt.get("arp_src_ip"):
                mac_to_ips[pkt["arp_src_mac"]].add(pkt["arp_src_ip"])
        
        # Check for MAC claiming multiple IPs
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                alerts.append({
                    "type": "anomaly",
                    "attack": "ARP Spoofing / MITM Attack",
                    "description": f"MAC {mac} claiming {len(ips)} IP addresses",
                    "src_ip": ", ".join(ips),
                    "dst_ip": "Network",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "high",
                    "source": "anomaly_detector",
                    "details": {
                        "mac_address": mac,
                        "claimed_ips": list(ips)
                    }
                })
        
        return alerts
    
    def detect_dns_tunneling(self):
        """
        Detect DNS tunneling
        Long domain names or high entropy domain names
        """
        alerts = []
        suspicious_queries = []
        
        for pkt in self.packets:
            if pkt.get("dns_query"):
                domain = pkt["dns_query"]
                
                # Check length
                if len(domain) > DNS_TUNNEL_LENGTH:
                    suspicious_queries.append((pkt, "Long domain name"))
                    continue
                
                # Check entropy
                entropy = self._calculate_entropy(domain)
                if entropy > DNS_ENTROPY_THRESHOLD:
                    suspicious_queries.append((pkt, f"High entropy: {entropy:.2f}"))
        
        # Group by source IP
        src_ip_queries = defaultdict(list)
        for pkt, reason in suspicious_queries:
            if pkt.get("src_ip"):
                src_ip_queries[pkt["src_ip"]].append((pkt, reason))
        
        # Create alerts for IPs with multiple suspicious queries
        for src_ip, queries in src_ip_queries.items():
            if len(queries) >= 3:  # At least 3 suspicious queries
                sample_query = queries[0][0].get("dns_query", "")
                
                alerts.append({
                    "type": "anomaly",
                    "attack": "DNS Tunneling Detected",
                    "description": f"{len(queries)} suspicious DNS queries",
                    "src_ip": src_ip,
                    "dst_ip": queries[0][0].get("dst_ip", "DNS Server"),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "medium",
                    "source": "anomaly_detector",
                    "details": {
                        "query_count": len(queries),
                        "sample_query": sample_query[:100]
                    }
                })
        
        return alerts
    
    def detect_http_beaconing(self):
        """
        Detect HTTP beaconing (malware C2 communication)
        Periodic HTTP requests with consistent intervals
        """
        alerts = []
        http_requests = defaultdict(list)
        
        # Collect HTTP requests by source IP
        for pkt in self.packets:
            if pkt.get("http_uri") and pkt.get("src_ip"):
                timestamp = self._parse_timestamp(pkt.get("timestamp"))
                if timestamp:
                    http_requests[pkt["src_ip"]].append({
                        "timestamp": timestamp,
                        "uri": pkt["http_uri"],
                        "dst_ip": pkt.get("dst_ip", "")
                    })
        
        # Analyze request patterns
        for src_ip, requests in http_requests.items():
            if len(requests) < HTTP_BEACON_MIN_REQUESTS:
                continue
            
            # Sort by timestamp
            requests.sort(key=lambda x: x["timestamp"])
            
            # Calculate intervals
            intervals = []
            for i in range(1, len(requests)):
                interval = (requests[i]["timestamp"] - requests[i-1]["timestamp"]).total_seconds()
                intervals.append(interval)
            
            if not intervals:
                continue
            
            # Check for consistent intervals (low variance)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            
            # Beaconing detected if intervals are consistent
            if std_dev < BEACON_INTERVAL_VARIANCE and avg_interval > 1:
                alerts.append({
                    "type": "anomaly",
                    "attack": "HTTP Beaconing / Malware C2",
                    "description": f"Periodic HTTP requests every {avg_interval:.1f}s",
                    "src_ip": src_ip,
                    "dst_ip": requests[0]["dst_ip"],
                    "timestamp": requests[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "medium",
                    "source": "anomaly_detector",
                    "details": {
                        "request_count": len(requests),
                        "avg_interval": avg_interval,
                        "std_deviation": std_dev,
                        "sample_uri": requests[0]["uri"][:100]
                    }
                })
        
        return alerts
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        counter = Counter(string)
        length = len(string)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp string or float to datetime object"""
        if not timestamp_str:
            return None
        
        if isinstance(timestamp_str, datetime):
            return timestamp_str
            
        if isinstance(timestamp_str, (int, float)):
            try:
                return datetime.fromtimestamp(timestamp_str)
            except:
                return None
        
        timestamp_str = str(timestamp_str).strip()
        
        # Try numeric timestamp
        try:
            val = float(timestamp_str)
            return datetime.fromtimestamp(val)
        except ValueError:
            pass
        
        # Try common datetime string formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d, %Y %H:%M:%S.%f %Z",
            "%b %d, %Y %H:%M:%S %Z",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ]
        
        clean_str = timestamp_str.split('.')[0]
        for fmt in formats:
            try:
                return datetime.strptime(clean_str, fmt.split('.')[0])
            except ValueError:
                continue
                
        return None


def detect_anomalies(packets):
    """Convenience function to run anomaly detection"""
    detector = AnomalyDetector(packets)
    return detector.detect_all()
