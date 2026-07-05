"""
PCAP Parser Module
Uses Tshark to parse PCAP files and extract packet metadata, with Scapy fallback.
"""

import subprocess
import json
import os
from datetime import datetime
from collections import defaultdict
from backend.config import TSHARK_PATH


class PCAPParser:
    """Parse PCAP files using Tshark with Scapy fallback"""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.statistics = {}
        
    def parse_pcap(self):
        """
        Parse PCAP file and extract packet information
        Returns list of packet dictionaries
        """
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        try:
            # Use tshark to extract packet details in JSON format
            cmd = [
                TSHARK_PATH,
                "-r", self.pcap_file,
                "-T", "json",
                "-e", "frame.time",
                "-e", "frame.number",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "eth.src",
                "-e", "eth.dst",
                "-e", "ip.proto",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "tcp.flags.syn",
                "-e", "tcp.flags.ack",
                "-e", "arp.src.proto_ipv4",
                "-e", "arp.src.hw_mac",
                "-e", "dns.qry.name",
                "-e", "http.request.uri",
                "-e", "frame.len"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if result.stdout:
                raw_packets = json.loads(result.stdout)
                self.packets = self._process_packets(raw_packets)
            
            self._calculate_statistics()
            return self.packets
            
        except Exception as e:
            print(f"Tshark unavailable or failed ({e}). Falling back to Scapy parser...")
            return self._parse_with_scapy()
    
    def _parse_with_scapy(self):
        """Fallback parser using Scapy"""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ARP, DNS, DNSQR, Raw
            scapy_packets = rdpcap(self.pcap_file)
            self.packets = []
            
            for idx, pkt in enumerate(scapy_packets, start=1):
                timestamp = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")
                src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else ""
                src_mac = pkt.src if hasattr(pkt, 'src') else ""
                dst_mac = pkt.dst if hasattr(pkt, 'dst') else ""
                
                protocol = "Other"
                if pkt.haslayer(TCP):
                    protocol = "TCP"
                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                elif pkt.haslayer(ARP):
                    protocol = "ARP"
                
                src_port = str(pkt[TCP].sport) if pkt.haslayer(TCP) else (str(pkt[UDP].sport) if pkt.haslayer(UDP) else "")
                dst_port = str(pkt[TCP].dport) if pkt.haslayer(TCP) else (str(pkt[UDP].dport) if pkt.haslayer(UDP) else "")
                
                tcp_syn = False
                tcp_ack = False
                if pkt.haslayer(TCP):
                    flags = str(pkt[TCP].flags)
                    tcp_syn = 'S' in flags
                    tcp_ack = 'A' in flags
                
                arp_src_ip = pkt[ARP].psrc if pkt.haslayer(ARP) else ""
                arp_src_mac = pkt[ARP].hwsrc if pkt.haslayer(ARP) else ""
                
                dns_query = ""
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    dns_query = qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(qname, bytes) else str(qname).rstrip('.')
                
                http_uri = ""
                raw_payload = ""
                if pkt.haslayer(Raw):
                    load = pkt[Raw].load.decode('utf-8', errors='ignore')
                    raw_payload = load
                    if load.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                        lines = load.split('\r\n')
                        if lines:
                            parts = lines[0].split(' ')
                            if len(parts) > 1:
                                http_uri = parts[1]
                
                processed_pkt = {
                    "timestamp": timestamp,
                    "frame_number": str(idx),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "tcp_syn": tcp_syn,
                    "tcp_ack": tcp_ack,
                    "arp_src_ip": arp_src_ip,
                    "arp_src_mac": arp_src_mac,
                    "dns_query": dns_query,
                    "http_uri": http_uri,
                    "raw_payload": raw_payload,
                    "length": len(pkt)
                }
                self.packets.append(processed_pkt)
            
            self._calculate_statistics()
            return self.packets
        except Exception as e:
            raise Exception(f"Failed to parse PCAP with both Tshark and Scapy: {e}")
    
    def _process_packets(self, raw_packets):
        """Process raw tshark JSON output into structured packet data"""
        processed = []
        
        for pkt in raw_packets:
            layers = pkt.get("_source", {}).get("layers", {})
            
            packet = {
                "timestamp": layers.get("frame.time", [""])[0],
                "frame_number": layers.get("frame.number", [""])[0],
                "src_ip": layers.get("ip.src", [""])[0],
                "dst_ip": layers.get("ip.dst", [""])[0],
                "src_mac": layers.get("eth.src", [""])[0],
                "dst_mac": layers.get("eth.dst", [""])[0],
                "protocol": self._get_protocol(layers),
                "src_port": layers.get("tcp.srcport", layers.get("udp.srcport", [""]))[0],
                "dst_port": layers.get("tcp.dstport", layers.get("udp.dstport", [""]))[0],
                "tcp_syn": layers.get("tcp.flags.syn", ["0"])[0] == "1",
                "tcp_ack": layers.get("tcp.flags.ack", ["0"])[0] == "1",
                "arp_src_ip": layers.get("arp.src.proto_ipv4", [""])[0],
                "arp_src_mac": layers.get("arp.src.hw_mac", [""])[0],
                "dns_query": layers.get("dns.qry.name", [""])[0],
                "http_uri": layers.get("http.request.uri", [""])[0],
                "length": int(layers.get("frame.len", ["0"])[0]) if layers.get("frame.len", ["0"])[0] else 0
            }
            
            processed.append(packet)
        
        return processed
    
    def _get_protocol(self, layers):
        """Determine protocol from packet layers"""
        proto_num = layers.get("ip.proto", [""])[0]
        
        protocol_map = {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP"
        }
        
        return protocol_map.get(proto_num, proto_num)
    
    def _calculate_statistics(self):
        """Calculate traffic statistics from parsed packets"""
        if not self.packets:
            return
        
        protocol_count = defaultdict(int)
        src_ip_count = defaultdict(int)
        dst_ip_count = defaultdict(int)
        total_bytes = 0
        
        for pkt in self.packets:
            protocol_count[pkt["protocol"]] += 1
            if pkt["src_ip"]:
                src_ip_count[pkt["src_ip"]] += 1
            if pkt["dst_ip"]:
                dst_ip_count[pkt["dst_ip"]] += 1
            total_bytes += pkt["length"]
        
        self.statistics = {
            "total_packets": len(self.packets),
            "total_bytes": total_bytes,
            "protocol_distribution": dict(protocol_count),
            "unique_src_ips": len(src_ip_count),
            "unique_dst_ips": len(dst_ip_count),
            "top_src_ips": sorted(src_ip_count.items(), key=lambda x: x[1], reverse=True)[:10],
            "top_dst_ips": sorted(dst_ip_count.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def get_statistics(self):
        """Return calculated statistics"""
        return self.statistics
    
    def get_packets_by_protocol(self, protocol):
        """Filter packets by protocol"""
        return [pkt for pkt in self.packets if pkt["protocol"] == protocol]
    
    def get_packets_by_ip(self, ip_address):
        """Get all packets involving a specific IP"""
        return [pkt for pkt in self.packets if pkt["src_ip"] == ip_address or pkt["dst_ip"] == ip_address]


def parse_pcap_file(pcap_file):
    """Convenience function to parse a PCAP file"""
    parser = PCAPParser(pcap_file)
    return parser.parse_pcap(), parser.get_statistics()
