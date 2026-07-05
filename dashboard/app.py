"""
NetShield IDS/IPS Dashboard
Flask web server providing API and dashboard interface
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
import sys

# Reconfigure stdout for Windows console emoji support
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from backend.pcap_parser import parse_pcap_file
from backend.snort_engine import run_snort_analysis
from backend.anomaly_detector import detect_anomalies
from backend.alert_manager import get_alert_manager
from backend.report_generator import generate_report
from backend.ips_blocker import get_ips_blocker
from backend.config import DASHBOARD_HOST, DASHBOARD_PORT, DEBUG_MODE

dashboard_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(dashboard_dir, 'templates')
static_dir = os.path.join(dashboard_dir, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
CORS(app)


# Get global instances
alert_manager = get_alert_manager()
ips_blocker = get_ips_blocker()


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with optional filtering"""
    filters = {}
    
    if request.args.get('severity'):
        filters['severity'] = request.args.get('severity')
    
    if request.args.get('source'):
        filters['source'] = request.args.get('source')
    
    if request.args.get('limit'):
        filters['limit'] = int(request.args.get('limit'))
    
    alerts = alert_manager.get_alerts(filters)
    
    return jsonify({
        'success': True,
        'alerts': alerts,
        'count': len(alerts)
    })


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get alert statistics"""
    stats = alert_manager.get_statistics()
    
    return jsonify({
        'success': True,
        'statistics': stats
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    """Analyze uploaded PCAP file"""
    if 'pcap_file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No PCAP file provided'
        }), 400
    
    file = request.files['pcap_file']
    
    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400
    
    # Save uploaded file
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    
    filepath = os.path.join(upload_dir, file.filename)
    file.save(filepath)
    
    try:
        # Clear previous alerts
        alert_manager.clear_alerts()
        
        # Parse PCAP
        packets, stats = parse_pcap_file(filepath)
        
        # Run Snort analysis
        snort_alerts = run_snort_analysis(filepath)
        alert_manager.add_alerts(snort_alerts)
        
        # Run anomaly detection
        anomaly_alerts = detect_anomalies(packets)
        alert_manager.add_alerts(anomaly_alerts)
        
        # Save alerts
        alert_manager.save_alerts()
        
        # Process high-severity alerts for IPS
        if ips_blocker.is_blocking_enabled():
            for alert in alert_manager.get_high_severity_alerts():
                ips_blocker.process_alert(alert)
        
        return jsonify({
            'success': True,
            'message': 'Analysis complete',
            'alerts_found': len(alert_manager.get_alerts()),
            'snort_alerts': len(snort_alerts),
            'anomaly_alerts': len(anomaly_alerts)
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/report', methods=['GET'])
def download_report():
    """Generate and download security report"""
    try:
        report_file = generate_report(alert_manager)
        
        if report_file and os.path.exists(report_file):
            return send_file(
                report_file,
                as_attachment=True,
                download_name='netshield_report.html',
                mimetype='text/html'
            )
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to generate report'
            }), 500
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/ips/toggle', methods=['POST'])
def toggle_ips():
    """Enable or disable IPS auto-blocking"""
    data = request.get_json()
    enabled = data.get('enabled', False)
    
    if enabled:
        ips_blocker.enable_blocking()
    else:
        ips_blocker.disable_blocking()
    
    return jsonify({
        'success': True,
        'enabled': ips_blocker.is_blocking_enabled()
    })


@app.route('/api/ips/blocked', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    blocked = ips_blocker.get_blocked_ips()
    
    return jsonify({
        'success': True,
        'blocked_ips': blocked,
        'count': len(blocked)
    })


@app.route('/api/ips/unblock', methods=['POST'])
def unblock_ip():
    """Unblock a specific IP"""
    data = request.get_json()
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({
            'success': False,
            'error': 'No IP address provided'
        }), 400
    
    success = ips_blocker.unblock_ip(ip_address)
    
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} {"unblocked" if success else "could not be unblocked"}'
    })


@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    alert_manager.clear_alerts()
    
    return jsonify({
        'success': True,
        'message': 'All alerts cleared'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  NetShield IDS/IPS Dashboard Starting...")
    print("=" * 60)
    print(f"Dashboard URL: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"IPS Auto-Blocking: {'Enabled' if ips_blocker.is_blocking_enabled() else 'Disabled'}")
    print("=" * 60)
    
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=DEBUG_MODE)
