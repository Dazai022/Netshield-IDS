"""
Report Generation Module
Generate HTML and PDF security reports
"""

import os
from datetime import datetime
from backend.config import DATA_DIR


class ReportGenerator:
    """Generate security reports from alerts"""
    
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
    
    def generate_html_report(self, output_file=None):
        """Generate comprehensive HTML report"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(DATA_DIR, f"security_report_{timestamp}.html")
        
        stats = self.alert_manager.get_statistics()
        alerts = self.alert_manager.get_alerts()
        
        html_content = self._create_html_template(stats, alerts)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return output_file
        except Exception as e:
            print(f"Error generating report: {e}")
            return None
    
    def _create_html_template(self, stats, alerts):
        """Create HTML report template"""
        
        # Executive summary
        total_alerts = stats["total_alerts"]
        high_severity = stats["severity_distribution"].get("high", 0)
        medium_severity = stats["severity_distribution"].get("medium", 0)
        low_severity = stats["severity_distribution"].get("low", 0)
        
        # Top attack types
        attack_types_html = ""
        for attack, count in list(stats["attack_type_distribution"].items())[:10]:
            attack_types_html += f"<tr><td>{attack}</td><td>{count}</td></tr>\n"
        
        # Top attackers
        attackers_html = ""
        for attacker in stats["top_attackers"][:10]:
            attackers_html += f"<tr><td>{attacker['ip']}</td><td>{attacker['count']}</td></tr>\n"
        
        # Top targets
        targets_html = ""
        for target in stats["top_targets"][:10]:
            targets_html += f"<tr><td>{target['ip']}</td><td>{target['count']}</td></tr>\n"
        
        # Recent alerts
        alerts_html = ""
        for alert in alerts[-50:]:  # Last 50 alerts
            severity_class = f"severity-{alert.get('severity', 'low')}"
            alerts_html += f"""
            <tr class="{severity_class}">
                <td>{alert.get('timestamp', 'N/A')}</td>
                <td>{alert.get('attack', 'Unknown')}</td>
                <td>{alert.get('src_ip', 'N/A')}</td>
                <td>{alert.get('dst_ip', 'N/A')}</td>
                <td><span class="badge {severity_class}">{alert.get('severity', 'low').upper()}</span></td>
                <td>{alert.get('source', 'N/A')}</td>
            </tr>
            """
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetShield IDS/IPS Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .summary-card h3 {{
            font-size: 2em;
            margin-bottom: 5px;
            color: #667eea;
        }}
        
        .summary-card.high h3 {{
            color: #e74c3c;
        }}
        
        .summary-card.medium h3 {{
            color: #f39c12;
        }}
        
        .summary-card.low h3 {{
            color: #3498db;
        }}
        
        .summary-card p {{
            color: #555;
            font-size: 0.9em;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .severity-high {{
            background: #ffe5e5;
        }}
        
        .severity-high .badge {{
            background: #e74c3c;
            color: white;
        }}
        
        .severity-medium {{
            background: #fff5e5;
        }}
        
        .severity-medium .badge {{
            background: #f39c12;
            color: white;
        }}
        
        .severity-low {{
            background: #e5f5ff;
        }}
        
        .severity-low .badge {{
            background: #3498db;
            color: white;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ NetShield IDS/IPS</h1>
            <p>Security Analysis Report</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card">
                    <h3>{total_alerts}</h3>
                    <p>Total Alerts</p>
                </div>
                <div class="summary-card high">
                    <h3>{high_severity}</h3>
                    <p>High Severity</p>
                </div>
                <div class="summary-card medium">
                    <h3>{medium_severity}</h3>
                    <p>Medium Severity</p>
                </div>
                <div class="summary-card low">
                    <h3>{low_severity}</h3>
                    <p>Low Severity</p>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Top Attack Types</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Attack Type</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {attack_types_html if attack_types_html else '<tr><td colspan="2">No data available</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🎯 Top Attacker IPs</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Attack Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {attackers_html if attackers_html else '<tr><td colspan="2">No data available</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🎯 Top Target IPs</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Times Targeted</th>
                        </tr>
                    </thead>
                    <tbody>
                        {targets_html if targets_html else '<tr><td colspan="2">No data available</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🚨 Recent Alerts</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Attack Type</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Severity</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alerts_html if alerts_html else '<tr><td colspan="6">No alerts detected</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>NetShield IDS/IPS - Hybrid Intrusion Detection and Prevention System</p>
            <p>Report generated automatically by NetShield</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html


def generate_report(alert_manager, output_file=None):
    """Convenience function to generate report"""
    generator = ReportGenerator(alert_manager)
    return generator.generate_html_report(output_file)
