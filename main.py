"""
NetShield IDS/IPS - Main Entry Point
Hybrid Intrusion Detection and Prevention System
"""

import sys
import os
import argparse

# Reconfigure stdout for Windows console emoji support
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from backend.pcap_parser import parse_pcap_file
from backend.snort_engine import run_snort_analysis
from backend.anomaly_detector import detect_anomalies
from backend.alert_manager import get_alert_manager
from backend.report_generator import generate_report
from backend.ips_blocker import get_ips_blocker
from backend.config import DASHBOARD_HOST, DASHBOARD_PORT


def analyze_pcap(pcap_file, output_report=None):
    """Analyze a PCAP file and generate alerts"""
    print("=" * 60)
    print("🛡️  NetShield IDS/IPS - Traffic Analysis")
    print("=" * 60)
    print(f"Analyzing: {pcap_file}")
    print()
    
    alert_manager = get_alert_manager()
    alert_manager.clear_alerts()
    
    try:
        # Step 1: Parse PCAP
        print("[1/4] Parsing PCAP file with Tshark...")
        packets, stats = parse_pcap_file(pcap_file)
        print(f"  ✓ Parsed {stats['total_packets']} packets")
        print(f"  ✓ Total bytes: {stats['total_bytes']:,}")
        print(f"  ✓ Unique source IPs: {stats['unique_src_ips']}")
        print()
        
        # Step 2: Run Snort
        print("[2/4] Running Snort signature-based detection...")
        snort_alerts = run_snort_analysis(pcap_file)
        alert_manager.add_alerts(snort_alerts)
        print(f"  ✓ Snort detected {len(snort_alerts)} threats")
        print()
        
        # Step 3: Run Anomaly Detection
        print("[3/4] Running custom anomaly detection...")
        anomaly_alerts = detect_anomalies(packets)
        alert_manager.add_alerts(anomaly_alerts)
        print(f"  ✓ Anomaly detector found {len(anomaly_alerts)} suspicious patterns")
        print()
        
        # Step 4: Save and Report
        print("[4/4] Generating results...")
        alert_manager.save_alerts()
        
        total_alerts = len(alert_manager.get_alerts())
        high_severity = len([a for a in alert_manager.get_alerts() if a.get('severity') == 'high'])
        
        print(f"  ✓ Total alerts: {total_alerts}")
        print(f"  ✓ High severity: {high_severity}")
        print()
        
        # Display summary
        print("=" * 60)
        print("📊 ANALYSIS SUMMARY")
        print("=" * 60)
        
        stats = alert_manager.get_statistics()
        
        print("\nSeverity Distribution:")
        for severity, count in stats['severity_distribution'].items():
            print(f"  {severity.upper()}: {count}")
        
        print("\nTop Attack Types:")
        for attack, count in list(stats['attack_type_distribution'].items())[:5]:
            print(f"  {attack}: {count}")
        
        print("\nTop Attacker IPs:")
        for attacker in stats['top_attackers'][:5]:
            print(f"  {attacker['ip']}: {attacker['count']} attacks")
        
        # Generate report if requested
        if output_report:
            print(f"\nGenerating HTML report: {output_report}")
            report_file = generate_report(alert_manager, output_report)
            if report_file:
                print(f"  ✓ Report saved: {report_file}")
        
        print("\n" + "=" * 60)
        print("✅ Analysis complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        sys.exit(1)


def start_dashboard():
    """Start the web dashboard"""
    print("=" * 60)
    print("🛡️  NetShield IDS/IPS - Starting Dashboard")
    print("=" * 60)
    print(f"Dashboard URL: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()
    
    # Import and run Flask app
    from dashboard.app import app
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NetShield IDS/IPS - Hybrid Intrusion Detection and Prevention System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a PCAP file
  python main.py analyze sample.pcap
  
  # Analyze and generate report
  python main.py analyze sample.pcap --report report.html
  
  # Start web dashboard
  python main.py dashboard
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a PCAP file')
    analyze_parser.add_argument('pcap_file', help='Path to PCAP file')
    analyze_parser.add_argument('--report', '-r', help='Output HTML report file', default=None)
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    
    args = parser.parse_args()
    
    if args.command == 'analyze':
        analyze_pcap(args.pcap_file, args.report)
    elif args.command == 'dashboard':
        start_dashboard()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
