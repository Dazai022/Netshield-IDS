# NetShield IDS/IPS - Detection Logic Documentation

This document explains the technical details of the detection algorithms used in NetShield.

---

## Table of Contents
1. [Signature-Based Detection (Snort)](#signature-based-detection)
2. [Anomaly-Based Detection](#anomaly-based-detection)
3. [Alert Management](#alert-management)
4. [IPS Auto-Blocking](#ips-auto-blocking)

---

## Signature-Based Detection (Snort)

### Overview
Snort uses pattern matching against known attack signatures defined in rule files.

### Rule Format
```
alert tcp any any -> any 80 (msg:"Attack Description"; content:"pattern"; sid:1000001;)
```

### Detection Categories

#### 1. SQL Injection
**Patterns Detected**:
- `UNION SELECT` - Union-based injection
- `OR 1=1` - Boolean-based injection
- `DROP TABLE` - Destructive commands

**Example Rule**:
```
alert tcp any any -> any 80 (msg:"SQL Injection - UNION SELECT"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:1000001;)
```

#### 2. Cross-Site Scripting (XSS)
**Patterns Detected**:
- `<script>` tags
- `javascript:` protocol
- Event handlers (`onerror=`, `onclick=`)

#### 3. Port Scanning
**Detection Method**: Threshold-based
- Tracks SYN packets from same source
- Triggers on >20 SYN packets in 60 seconds

**Rule**:
```
alert tcp any any -> any any (msg:"Port Scan"; flags:S; threshold:type both, track by_src, count 20, seconds 60; sid:1000007;)
```

#### 4. Brute Force Attacks
**Protocols Monitored**:
- SSH (port 22)
- RDP (port 3389)
- FTP (port 21)

**Threshold**: >10 connection attempts in 60 seconds

---

## Anomaly-Based Detection

### 1. DoS Attack Detection

#### Algorithm
```python
def detect_dos(packets):
    # Group packets by source IP
    src_ip_packets = group_by_source(packets)
    
    for src_ip, pkts in src_ip_packets.items():
        # Calculate time span
        time_span = last_timestamp - first_timestamp
        
        # Calculate packet rate
        packet_rate = len(pkts) / time_span
        
        # Alert if exceeds threshold
        if packet_rate > 1000:  # packets/sec
            create_alert("DoS Attack", src_ip)
```

#### Threshold
- **Default**: 1000 packets/second
- **Configurable**: `DOS_PACKET_RATE_THRESHOLD` in `config.py`

#### Why This Works
- Normal traffic: 10-100 packets/sec
- DoS attack: >1000 packets/sec from single source

---

### 2. SYN Flood Detection

#### Algorithm
```python
def detect_syn_flood(packets):
    # Count SYN and ACK flags per source
    for src_ip in unique_sources:
        syn_count = count_syn_packets(src_ip)
        ack_count = count_ack_packets(src_ip)
        
        # Calculate SYN ratio
        syn_ratio = syn_count / (syn_count + ack_count)
        
        # Alert if ratio exceeds threshold
        if syn_ratio > 0.8:  # 80%
            create_alert("SYN Flood", src_ip)
```

#### Threshold
- **Default**: 80% SYN packets without ACK
- **Configurable**: `SYN_FLOOD_RATIO`

#### Technical Explanation
- **Normal TCP**: SYN → SYN-ACK → ACK (balanced ratio)
- **SYN Flood**: Only SYN packets sent (high ratio)

---

### 3. DDoS Detection

#### Algorithm
```python
def detect_ddos(packets):
    # Track unique sources per destination
    dst_sources = {}
    for pkt in packets:
        dst_sources[pkt.dst_ip].add(pkt.src_ip)
    
    # Alert if too many sources target one host
    for dst_ip, sources in dst_sources.items():
        if len(sources) > 50:
            create_alert("DDoS Attack", dst_ip)
```

#### Threshold
- **Default**: >50 unique source IPs
- **Configurable**: `DDOS_SOURCE_THRESHOLD`

#### Difference from DoS
- **DoS**: Single attacker, high packet rate
- **DDoS**: Multiple attackers, distributed sources

---

### 4. ARP Spoofing Detection

#### Algorithm
```python
def detect_arp_spoofing(packets):
    # Track MAC-to-IP mappings
    mac_to_ips = {}
    for pkt in arp_packets:
        mac_to_ips[pkt.src_mac].add(pkt.src_ip)
    
    # Alert if one MAC claims multiple IPs
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            create_alert("ARP Spoofing", mac)
```

#### Why This Works
- **Normal**: One MAC address = One IP address
- **ARP Spoofing**: Attacker's MAC claims victim's IP

#### MITM Attack Detection
ARP spoofing is the primary technique for Man-in-the-Middle attacks on local networks.

---

### 5. DNS Tunneling Detection

#### Algorithm
```python
def detect_dns_tunneling(packets):
    for pkt in dns_packets:
        domain = pkt.dns_query
        
        # Check 1: Domain length
        if len(domain) > 50:
            create_alert("DNS Tunneling - Long Domain")
        
        # Check 2: Entropy (randomness)
        entropy = calculate_shannon_entropy(domain)
        if entropy > 3.5:
            create_alert("DNS Tunneling - High Entropy")
```

#### Shannon Entropy Calculation
```python
def calculate_entropy(string):
    counter = Counter(string)
    length = len(string)
    entropy = -sum((count/length) * log2(count/length) 
                   for count in counter.values())
    return entropy
```

#### Thresholds
- **Length**: >50 characters
- **Entropy**: >3.5 (scale: 0-5)

#### Examples
- **Normal**: `google.com` (entropy ≈ 2.5)
- **Tunneling**: `a8f3b2c9d1e4f5a6b7c8d9e0f1a2b3c4.example.com` (entropy ≈ 4.2)

---

### 6. HTTP Beaconing Detection

#### Algorithm
```python
def detect_http_beaconing(packets):
    # Group HTTP requests by source IP
    http_requests = group_by_source(http_packets)
    
    for src_ip, requests in http_requests.items():
        # Calculate intervals between requests
        intervals = []
        for i in range(1, len(requests)):
            interval = requests[i].time - requests[i-1].time
            intervals.append(interval)
        
        # Calculate standard deviation
        avg_interval = mean(intervals)
        std_dev = standard_deviation(intervals)
        
        # Alert if intervals are too consistent
        if std_dev < 5 and avg_interval > 1:
            create_alert("HTTP Beaconing", src_ip)
```

#### Thresholds
- **Variance**: <5 seconds
- **Minimum Requests**: 5
- **Minimum Interval**: >1 second

#### Why This Works
- **Normal Browsing**: Random intervals (0.1s, 5s, 30s, etc.)
- **Malware C2**: Consistent intervals (every 60s, every 120s)

---

## Alert Management

### Severity Classification

#### Algorithm
```python
def classify_severity(alert):
    attack_type = alert.attack.lower()
    
    # High severity keywords
    if any(keyword in attack_type for keyword in 
           ['sql injection', 'rce', 'dos', 'ddos', 'arp spoofing']):
        return "high"
    
    # Medium severity keywords
    elif any(keyword in attack_type for keyword in 
             ['port scan', 'brute force', 'dns tunneling']):
        return "medium"
    
    # Default to low
    else:
        return "low"
```

### Alert Deduplication
- Alerts with same source IP + attack type within 60 seconds are grouped
- Prevents alert flooding

### Statistics Generation
```python
def get_statistics():
    return {
        "total_alerts": count_all_alerts(),
        "severity_distribution": count_by_severity(),
        "attack_type_distribution": count_by_attack_type(),
        "top_attackers": get_top_n_sources(10),
        "top_targets": get_top_n_destinations(10),
        "timeline": group_by_hour()
    }
```

---

## IPS Auto-Blocking

### Decision Logic

```python
def process_alert(alert):
    # Only block high-severity threats
    if alert.severity != "high":
        return
    
    # Check whitelist
    if alert.src_ip in WHITELIST:
        return
    
    # Block the IP
    block_ip(alert.src_ip)
```

### Windows Firewall Integration

```powershell
# Block command
netsh advfirewall firewall add rule name="NetShield_Block_192_168_1_100" dir=in action=block remoteip=192.168.1.100

# Unblock command
netsh advfirewall firewall delete rule name="NetShield_Block_192_168_1_100"
```

### Safety Features
1. **Whitelist**: Localhost and gateway IPs never blocked
2. **Manual Toggle**: Disabled by default
3. **Logging**: All blocking actions logged to `data/ips_blocks.log`

---

## Performance Considerations

### PCAP Parsing
- **Tshark**: Processes ~10,000 packets/second
- **Memory**: ~1MB per 1000 packets

### Detection Speed
- **Snort**: ~5,000 packets/second
- **Anomaly Detection**: ~20,000 packets/second (pure Python)

### Dashboard Updates
- **Auto-refresh**: Every 30 seconds
- **API Response**: <100ms for statistics

---

## Tuning Recommendations

### Reduce False Positives
- Increase thresholds in `config.py`
- Add known-good IPs to whitelist
- Adjust Snort rule sensitivity

### Increase Detection Rate
- Lower thresholds (may increase false positives)
- Add more Snort rules
- Implement additional anomaly detectors

### Optimal Thresholds (Lab Environment)
```python
DOS_PACKET_RATE_THRESHOLD = 500   # More sensitive
SYN_FLOOD_RATIO = 0.7              # Catch earlier
DDOS_SOURCE_THRESHOLD = 30         # Lower threshold
DNS_TUNNEL_LENGTH = 40             # Shorter domains
```

---

## References

1. **Snort Documentation**: https://www.snort.org/documents
2. **Shannon Entropy**: https://en.wikipedia.org/wiki/Entropy_(information_theory)
3. **TCP SYN Flood**: https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/
4. **ARP Spoofing**: https://www.veracode.com/security/arp-spoofing
5. **DNS Tunneling**: https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling

---

**Last Updated**: 2026-02-10  
**Version**: 1.0
