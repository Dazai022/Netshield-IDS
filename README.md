# 🛡️ NetShield IDS/IPS

**Hybrid Intrusion Detection and Prevention System**

A lightweight, lab-friendly IDS/IPS that combines **Snort signature-based detection** with **custom anomaly-based detection** to analyze network traffic and identify security threats in real-time.

---

## 📋 Features

### Core Capabilities
- ✅ **PCAP Traffic Analysis** - Analyze offline network captures using Tshark
- ✅ **Snort Integration** - Signature-based detection with 30+ custom rules
- ✅ **Anomaly Detection** - Statistical threshold-based detection for:
  - DoS/DDoS attacks (packet rate, SYN flood, multi-source attacks)
  - MITM attacks (ARP spoofing detection)
  - Malware traffic (HTTP beaconing, DNS tunneling)
- ✅ **Unified Alert System** - Centralized processing with severity classification
- ✅ **Real-Time Dashboard** - Modern web interface with live alerts and visualizations
- ✅ **Security Reports** - Downloadable HTML reports with attack analytics
- ✅ **IPS Auto-Blocking** - Optional automatic IP blocking for high-severity threats

---

## 🏗️ Project Structure

```
netshield-ids/
├── backend/                    # Core detection engines
│   ├── pcap_parser.py         # Tshark PCAP parsing
│   ├── snort_engine.py        # Snort integration
│   ├── anomaly_detector.py    # Custom anomaly detection
│   ├── alert_manager.py       # Unified alert processing
│   ├── report_generator.py    # HTML report generation
│   ├── ips_blocker.py         # Auto-blocking (Windows Firewall)
│   └── config.py              # Configuration & thresholds
├── dashboard/                  # Web interface
│   ├── app.py                 # Flask web server
│   ├── static/
│   │   ├── css/style.css      # Modern cybersecurity theme
│   │   └── js/dashboard.js    # Real-time updates & charts
│   └── templates/
│       └── index.html         # Main dashboard
├── snort_rules/
│   └── custom.rules           # 30+ Snort detection rules
├── sample_pcaps/              # Sample PCAP files (add your own)
├── data/                      # Alert storage & logs
├── main.py                    # CLI entry point
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

---

## 🚀 Installation & Setup

### Prerequisites

1. **Python 3.8+**
2. **Snort** (installed and accessible via command line)
   ```powershell
   snort --version
   ```
3. **Wireshark/Tshark** (for PCAP parsing)
   ```powershell
   tshark --version
   ```

### Installation Steps

1. **Clone/Download the project**
   ```powershell
   cd C:\Users\rishi\.gemini\antigravity\scratch\netshield-ids
   ```

2. **Create virtual environment** (recommended)
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate
   ```

3. **Install dependencies**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Verify Snort and Tshark paths**
   - Edit `backend/config.py` if needed:
   ```python
   SNORT_PATH = "snort"      # Or full path: "C:\\Snort\\bin\\snort.exe"
   TSHARK_PATH = "tshark"    # Or full path: "C:\\Program Files\\Wireshark\\tshark.exe"
   ```

---

## 💻 Usage

### Option 1: Web Dashboard (Recommended)

Start the interactive web dashboard:

```powershell
python main.py dashboard
```

Then open your browser to: **http://127.0.0.1:5000**

**Dashboard Features:**
- 📁 Drag-and-drop PCAP file upload
- 📊 Real-time attack statistics and charts
- 🚨 Live alert table with severity color-coding
- 📈 Attack timeline visualization
- 📄 One-click report generation
- 🔒 IPS auto-blocking toggle

### Option 2: Command-Line Analysis

Analyze a PCAP file directly:

```powershell
# Basic analysis
python main.py analyze sample.pcap

# With HTML report generation
python main.py analyze sample.pcap --report output_report.html
```

---

## 🔍 Detection Logic Explained

### 1. Signature-Based Detection (Snort)

Uses **30+ custom Snort rules** to detect:
- SQL Injection (`UNION SELECT`, `OR 1=1`, `DROP TABLE`)
- XSS Attacks (`<script>`, `javascript:`, event handlers)
- Port Scanning (SYN scans, NULL scans)
- Brute Force (SSH, RDP, FTP)
- Command Injection (`/bin/sh`, `powershell`)
- Directory Traversal (`../`, `..\\`)
- Malware C2 Communication
- File Upload Attacks

**How it works:**
1. Snort processes the PCAP file with custom rules
2. Alerts are parsed from Snort's output
3. Severity is assigned based on Snort priority levels

### 2. Anomaly-Based Detection (Custom)

Statistical threshold-based detection for patterns Snort might miss:

#### DoS/DDoS Detection
- **High Packet Rate**: >1000 packets/sec from single IP
- **SYN Flood**: >80% SYN packets without ACK
- **DDoS**: >50 unique source IPs targeting one host

#### MITM Detection
- **ARP Spoofing**: Same MAC address claiming multiple IPs

#### Malware Traffic Fingerprinting
- **HTTP Beaconing**: Periodic requests with consistent intervals (±5 sec)
- **DNS Tunneling**: 
  - Domain names >50 characters
  - High entropy domains (>3.5 Shannon entropy)

**Thresholds are configurable** in `backend/config.py`

### 3. Alert Management

All alerts (Snort + Anomaly) are:
1. **Unified** into a single alert stream
2. **Classified** by severity (High/Medium/Low)
3. **Stored** persistently in JSON
4. **Displayed** in real-time on dashboard

**Severity Classification:**
- **High**: SQL injection, RCE, DoS/DDoS, ARP spoofing
- **Medium**: Port scans, brute force, DNS tunneling, malware beaconing
- **Low**: Policy violations, unusual traffic patterns

---

## 🛡️ IPS Auto-Blocking

**Optional feature** to automatically block high-severity threats using Windows Firewall.

### How to Enable

1. **Via Dashboard**: Toggle "IPS Auto-Block" switch
2. **Via Config**: Set `AUTO_BLOCKING_ENABLED = True` in `backend/config.py`

### How It Works

- Monitors all alerts in real-time
- Automatically blocks source IPs for **high-severity** attacks
- Uses Windows Firewall (`netsh advfirewall`) to create block rules
- Respects whitelist (localhost, gateway IPs)

**⚠️ Important Notes:**
- Requires **administrator privileges**
- Disabled by default to prevent false positives
- Review alerts before enabling in production

---

## 📊 Sample Output

### CLI Analysis Output
```
============================================================
🛡️  NetShield IDS/IPS - Traffic Analysis
============================================================
Analyzing: sample.pcap

[1/4] Parsing PCAP file with Tshark...
  ✓ Parsed 15,432 packets
  ✓ Total bytes: 8,234,567
  ✓ Unique source IPs: 47

[2/4] Running Snort signature-based detection...
  ✓ Snort detected 12 threats

[3/4] Running custom anomaly detection...
  ✓ Anomaly detector found 5 suspicious patterns

[4/4] Generating results...
  ✓ Total alerts: 17
  ✓ High severity: 8

============================================================
📊 ANALYSIS SUMMARY
============================================================

Severity Distribution:
  HIGH: 8
  MEDIUM: 6
  LOW: 3

Top Attack Types:
  SQL Injection Attempt: 4
  DoS Attack Detected: 2
  Port Scan Detected: 3
  ...
```

### Dashboard Screenshots

*(Upload sample PCAP to see live dashboard with charts and alerts)*

---

## 🧪 Testing with Sample PCAPs

### Where to Get Sample PCAPs

1. **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures
2. **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
3. **Create Your Own**: Use Wireshark to capture live traffic

### Recommended Test Files

Place PCAP files in the `sample_pcaps/` directory:
- `dos_attack.pcap` - SYN flood simulation
- `arp_spoof.pcap` - MITM attack sample
- `malware_beacon.pcap` - C2 communication
- `normal_traffic.pcap` - Baseline traffic

---

## 🎓 Academic Use & Viva Preparation

### Key Points to Explain

1. **Hybrid Approach**: Combines signature-based (Snort) + anomaly-based detection
2. **Detection Algorithms**: 
   - Statistical thresholds (packet rate, SYN ratio)
   - Entropy calculation for DNS tunneling
   - Interval analysis for HTTP beaconing
3. **Architecture**: Modular design with separate parsers, detectors, and alert manager
4. **Real-World Application**: Dashboard suitable for SOC (Security Operations Center) monitoring

### Demo Flow

1. Start dashboard (`python main.py dashboard`)
2. Upload a malicious PCAP file
3. Show real-time alerts appearing
4. Explain detection logic for specific alerts
5. Generate and show HTML report
6. Demonstrate IPS auto-blocking (optional)

---

## ⚙️ Configuration

Edit `backend/config.py` to customize:

```python
# Detection Thresholds
DOS_PACKET_RATE_THRESHOLD = 1000  # packets/sec
SYN_FLOOD_RATIO = 0.8              # 80% SYN packets
DDOS_SOURCE_THRESHOLD = 50         # unique sources
DNS_TUNNEL_LENGTH = 50             # domain name length
DNS_ENTROPY_THRESHOLD = 3.5        # Shannon entropy
BEACON_INTERVAL_VARIANCE = 5       # seconds

# IPS Settings
AUTO_BLOCKING_ENABLED = False
WHITELIST_IPS = ["127.0.0.1", "192.168.1.1"]

# Dashboard
DASHBOARD_PORT = 5000
```

---

## 🐛 Troubleshooting

### Snort Not Found
```
Error: Snort not found
```
**Solution**: Install Snort or update `SNORT_PATH` in `config.py`

### Tshark Not Found
```
Error: Tshark not found
```
**Solution**: Install Wireshark or update `TSHARK_PATH` in `config.py`

### No Alerts Detected
- Verify PCAP file contains actual attack traffic
- Check Snort rules are loaded (`snort_rules/custom.rules`)
- Lower detection thresholds in `config.py` for testing

### IPS Blocking Fails
- Run terminal as **Administrator**
- Check Windows Firewall is enabled
- Verify IP is not in whitelist

---

## 📚 Technology Stack

- **Backend**: Python 3.8+
- **Detection**: Snort (signature-based), Custom algorithms (anomaly-based)
- **Parsing**: Tshark (Wireshark CLI)
- **Web Framework**: Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Visualization**: Chart.js
- **Firewall**: Windows Firewall (netsh)

---

## 📝 License

This project is created for **academic and educational purposes**. Feel free to use, modify, and extend for learning and research.

---

## 👨‍💻 Author

**NetShield Team**  
Hybrid IDS/IPS Project  
Version 1.0

---

## 🙏 Acknowledgments

- **Snort** - Open-source IDS/IPS engine
- **Wireshark** - Network protocol analyzer
- **Flask** - Lightweight web framework
- **Chart.js** - Beautiful JavaScript charts

---

## 📞 Support

For issues or questions:
1. Check the Troubleshooting section
2. Review detection logic in `backend/` modules
3. Verify Snort and Tshark installation

---

**Happy Threat Hunting! 🛡️🔍**
