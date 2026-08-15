import csv
import os

def get_app_name(isp_org):
    org_lower = isp_org.lower()
    if "facebook" in org_lower or "meta" in org_lower: return "WhatsApp/Meta"
    elif "telegram" in org_lower: return "Telegram"
    elif "reliance jio" in org_lower: return "Jio Network"
    elif "airtel" in org_lower: return "Airtel"
    elif any(p in org_lower for p in ["ovh", "digitalocean", "amazon", "aws", "hetzner", "linode", "choopa", "vultr"]): return "Datacenter/Hosting"
    elif any(p in org_lower for p in ["proton", "nordvpn", "expressvpn", "surfshark", "mullvad", "private internet access"]): return "VPN Provider"
    else: return isp_org

def generate():
    csv_file = "calls_log.csv"
    html_file = "dashboard.html"

    calls = []
    if os.path.exists(csv_file):
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            calls = list(reader)

    total_calls = len(calls)
    high_risk_anomalies = sum(1 for c in calls if c.get('risk_level', '').lower() in ['high', 'medium'])

    risk_colors = {
        "low": "#2ea043",
        "medium": "#d29922",
        "high": "#f85149"
    }

    rows_html = ""
    for c in calls:
        service_name = get_app_name(c.get('isp_org', 'Unknown'))
        level = c.get('risk_level', 'Low')
        color = risk_colors.get(level.lower(), "#888888")
        reason = c.get('risk_reason', '')
        
        rows_html += f"""
        <tr>
            <td>{c.get('timestamp', '')}</td>
            <td>{service_name}</td>
            <td><span style="font-family: Consolas, monospace; color: #8b949e;">{c.get('source_ip', '')} &rarr; {c.get('destination_ip', '')}</span></td>
            <td>{c.get('country', '')}</td>
            <td>{c.get('duration_sec', '')}s</td>
            <td>{c.get('protocol', '')}</td>
            <td><span style="background-color: {color}; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;">{level.upper()} RISK</span></td>
            <td style="font-size: 13px; color: #8b949e;">{reason}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoIP Sentinel — Investigation Dashboard</title>
    <style>
        body {{
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
        }}
        h1 {{
            color: #00d9ff;
            border-bottom: 1px solid #30363d;
            padding-bottom: 15px;
            margin-bottom: 30px;
            font-weight: 600;
        }}
        .stats-container {{
            display: flex;
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 25px;
            flex: 1;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .stat-title {{
            font-size: 14px;
            color: #8b949e;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #00d9ff;
        }}
        .high-risk-val {{
            color: #f85149;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        th, td {{
            padding: 16px 20px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}
        th {{
            background-color: #21262d;
            color: #8b949e;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        tr:hover {{
            background-color: #1f2428;
        }}
    </style>
</head>
<body>
    <h1>🛡️ VoIP Sentinel — Investigation Dashboard</h1>
    
    <div class="stats-container">
        <div class="stat-card">
            <div class="stat-title">Total Calls</div>
            <div class="stat-value">{total_calls}</div>
        </div>
        <div class="stat-card">
            <div class="stat-title">High Risk Anomalies</div>
            <div class="stat-value {'high-risk-val' if high_risk_anomalies > 0 else ''}">{high_risk_anomalies}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Service/ISP</th>
                <th>IP Address</th>
                <th>Country</th>
                <th>Duration</th>
                <th>Protocol</th>
                <th>Risk Level</th>
                <th>Risk Reason</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else '<tr><td colspan="8" style="text-align:center; padding: 40px; color:#8b949e;">No calls recorded yet.</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return html_file

if __name__ == "__main__":
    generate()