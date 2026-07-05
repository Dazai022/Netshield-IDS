"""
Sample PCAP Generator for NetShield IDS/IPS
Generates test PCAP files containing simulated attacks for testing and viva demos.
"""

import os
import sys
from datetime import datetime, timedelta

try:
    from scapy.all import Ether, IP, TCP, UDP, ARP, Raw, wrpcap
except ImportError:
    print("Scapy is required to generate sample PCAPs. Install with: pip install scapy")
    sys.exit(1)

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_sample_attack_pcap():
    """Generate sample_attack.pcap with SQLi, XSS, Command Injection, and Port Scans"""
    packets = []
    base_time = datetime.now() - timedelta(minutes=10)

    # 1. SQL Injection Packets
    sqli_payloads = [
        "GET /login.php?user=admin' UNION SELECT 1,username,password FROM users-- HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "GET /products.php?id=1 OR 1=1 HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "POST /db.php HTTP/1.1\r\nHost: target.local\r\nContent-Length: 25\r\n\r\nquery=DROP TABLE users;"
    ]
    for i, payload in enumerate(sqli_payloads):
        pkt = Ether()/IP(src="192.168.1.105", dst="192.168.1.10")/TCP(sport=45000+i, dport=80, flags="PA")/Raw(load=payload)
        pkt.time = (base_time + timedelta(seconds=i*5)).timestamp()
        packets.append(pkt)

    # 2. XSS Attack Packets
    xss_payloads = [
        "GET /comment.php?msg=<script>alert('XSS')</script> HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "GET /profile?name=javascript:alert(document.cookie) HTTP/1.1\r\nHost: target.local\r\n\r\n"
    ]
    for i, payload in enumerate(xss_payloads):
        pkt = Ether()/IP(src="192.168.1.108", dst="192.168.1.10")/TCP(sport=46000+i, dport=80, flags="PA")/Raw(load=payload)
        pkt.time = (base_time + timedelta(seconds=20 + i*5)).timestamp()
        packets.append(pkt)

    # 3. Command Injection & Directory Traversal
    cmdi_payloads = [
        "GET /exec?cmd=/bin/bash HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "GET /read?file=../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "POST /run HTTP/1.1\r\nHost: target.local\r\n\r\ncommand=powershell.exe -ExecutionPolicy Bypass"
    ]
    for i, payload in enumerate(cmdi_payloads):
        pkt = Ether()/IP(src="192.168.1.110", dst="192.168.1.10")/TCP(sport=47000+i, dport=80, flags="PA")/Raw(load=payload)
        pkt.time = (base_time + timedelta(seconds=40 + i*5)).timestamp()
        packets.append(pkt)

    # 4. Port Scan Simulation (SYN scan on ports 20 to 100)
    for port in range(20, 45):
        pkt = Ether()/IP(src="192.168.1.200", dst="192.168.1.10")/TCP(sport=50000+port, dport=port, flags="S")
        pkt.time = (base_time + timedelta(seconds=60)).timestamp()
        packets.append(pkt)

    # 5. ARP Spoofing Packets
    arp_spoof_1 = Ether(src="aa:bb:cc:dd:ee:ff")/ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.10")
    arp_spoof_2 = Ether(src="aa:bb:cc:dd:ee:ff")/ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.2", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.10")
    arp_spoof_1.time = (base_time + timedelta(seconds=70)).timestamp()
    arp_spoof_2.time = (base_time + timedelta(seconds=71)).timestamp()
    packets.extend([arp_spoof_1, arp_spoof_2])

    output_path = os.path.join(OUTPUT_DIR, "sample_attack.pcap")
    wrpcap(output_path, packets)
    print(f"Generated: {output_path} ({len(packets)} packets)")


def generate_dos_pcap():
    """Generate dos_attack.pcap with high packet rate flood"""
    packets = []
    base_time = datetime.now() - timedelta(minutes=5)

    for i in range(1200):
        pkt = Ether()/IP(src="10.0.0.50", dst="192.168.1.10")/TCP(sport=10000+i, dport=80, flags="S")
        # All within 1 second to trigger DoS rate threshold (>1000 pkts/sec)
        pkt.time = (base_time + timedelta(microseconds=i*500)).timestamp()
        packets.append(pkt)

    output_path = os.path.join(OUTPUT_DIR, "dos_attack.pcap")
    wrpcap(output_path, packets)
    print(f"Generated: {output_path} ({len(packets)} packets)")


if __name__ == "__main__":
    print("Generating sample PCAP files for NetShield testing...")
    generate_sample_attack_pcap()
    generate_dos_pcap()
    print("Sample PCAP generation complete!")
