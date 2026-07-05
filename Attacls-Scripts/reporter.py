#!/usr/bin/env python3
"""
SUDOIT Report Generator Module
Professional report generation in multiple formats.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class ReportGenerator:
    """
    Multi-format Report Generator.
    
    Features:
        - JSON reports
        - HTML reports
        - PDF reports (requires fpdf)
        - CSV export
        - Executive summary
        - Technical details
        - Statistics & charts
        - Customizable templates
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self._report_data: Dict[str, Any] = {}
    
    def set_data(self, data: Dict[str, Any]):
        """Set the data to be included in report."""
        self._report_data = data
    
    def add_section(self, section_name: str, data: Any):
        """Add a section to the report data."""
        self._report_data[section_name] = data
    
    def generate_json(self, filepath: str, pretty: bool = True) -> str:
        """
        Generate JSON report.
        
        Args:
            filepath: Output file path
            pretty: Pretty-print JSON
        
        Returns:
            Path to generated report
        """
        report = {
            "report_title": "SUDOIT WiFi Security Assessment",
            "generated_at": datetime.now().isoformat(),
            "generator": "SUDOIT Framework v1.0",
            **self._report_data
        }
        
        with open(filepath, 'w') as f:
            if pretty:
                json.dump(report, f, indent=4, default=str)
            else:
                json.dump(report, f, default=str)
        
        self.logger.info(f"JSON report saved: {filepath}")
        print(f"[✓] JSON report: {filepath}")
        return filepath
    
    def generate_html(self, filepath: str) -> str:
        """
        Generate HTML report with styling.
        
        Args:
            filepath: Output file path
        
        Returns:
            Path to generated report
        """
        html = self._build_html()
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        self.logger.info(f"HTML report saved: {filepath}")
        print(f"[✓] HTML report: {filepath}")
        return filepath
    
    def _build_html(self) -> str:
        """Build HTML report content."""
        networks = self._report_data.get("scan_results", {})
        statistics = self._report_data.get("statistics", {})
        attacks = self._report_data.get("attacks", [])
        handshakes = self._report_data.get("handshakes", [])
        
        # Build network table rows
        network_rows = ""
        for bssid, net in networks.items():
            enc = net.get('encryption', '?')
            enc_class = 'open' if enc == 'OPEN' else 'wpa' if 'WPA' in enc else 'unknown'
            
            network_rows += f"""
            <tr>
                <td>{net.get('ssid', '?')}</td>
                <td><code>{bssid}</code></td>
                <td>{net.get('channel', '?')}</td>
                <td class="{enc_class}">{enc}</td>
                <td>{net.get('signal', '?')} dBm</td>
                <td>{net.get('vendor', '?')}</td>
                <td>{net.get('first_seen', '?')}</td>
            </tr>"""
        
        # Build attack rows
        attack_rows = ""
        for attack in attacks:
            attack_rows += f"""
            <tr>
                <td>{attack.get('type', '?')}</td>
                <td><code>{attack.get('target', '?')}</code></td>
                <td class="{'success' if attack.get('success') else 'failed'}">{attack.get('status', '?')}</td>
                <td>{attack.get('timestamp', '?')}</td>
            </tr>"""
        
        # Build handshake rows
        handshake_rows = ""
        for hs in handshakes:
            handshake_rows += f"""
            <tr>
                <td><code>{hs.get('bssid', '?')}</code></td>
                <td>{hs.get('ssid', '?')}</td>
                <td>{hs.get('file', '?')}</td>
                <td class="{'success' if hs.get('cracked') else 'pending'}">{hs.get('status', '?')}</td>
            </tr>"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SUDOIT WiFi Security Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #1a1a1a;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,255,0,0.1);
        }}
        h1 {{
            color: #00ff00;
            text-align: center;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        h2 {{
            color: #00cc00;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
            margin: 30px 0 15px 0;
        }}
        .subtitle {{
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background: #2a2a2a;
            color: #00ff00;
            padding: 12px;
            text-align: left;
            border: 1px solid #333;
        }}
        td {{
            padding: 10px;
            border: 1px solid #333;
        }}
        tr:nth-child(even) {{ background: #1f1f1f; }}
        tr:hover {{ background: #2a2a2a; }}
        code {{
            background: #333;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        .open {{ color: #ff4444; font-weight: bold; }}
        .wpa {{ color: #ffaa00; font-weight: bold; }}
        .unknown {{ color: #888; }}
        .success {{ color: #00ff00; }}
        .failed {{ color: #ff4444; }}
        .pending {{ color: #ffaa00; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #00ff00;
        }}
        .stat-number {{
            font-size: 2em;
            color: #00ff00;
            font-weight: bold;
        }}
        .stat-label {{
            color: #888;
            margin-top: 5px;
        }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SUDOIT WiFi Security Assessment</h1>
        <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="stat-card">
                <div class="stat-number">{len(networks)}</div>
                <div class="stat-label">Networks Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{statistics.get('open_networks', 0)}</div>
                <div class="stat-label">Open Networks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(handshakes)}</div>
                <div class="stat-label">Handshakes Captured</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(attacks)}</div>
                <div class="stat-label">Attacks Performed</div>
            </div>
        </div>
        
        <h2>Discovered Networks</h2>
        <table>
            <tr>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Channel</th>
                <th>Encryption</th>
                <th>Signal</th>
                <th>Vendor</th>
                <th>First Seen</th>
            </tr>
            {network_rows}
        </table>
        
        <h2>Captured Handshakes</h2>
        <table>
            <tr>
                <th>BSSID</th>
                <th>SSID</th>
                <th>File</th>
                <th>Status</th>
            </tr>
            {handshake_rows}
        </table>
        
        <h2>Attack History</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Target</th>
                <th>Status</th>
                <th>Timestamp</th>
            </tr>
            {attack_rows}
        </table>
        
        <div class="footer">
            <p>SUDOIT Framework v1.0 | Ethical Use Only | {datetime.now().year}</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def generate_csv(self, filepath: str) -> str:
        """Generate CSV report of networks."""
        networks = self._report_data.get("scan_results", {})
        
        with open(filepath, 'w') as f:
            f.write("SSID,BSSID,Channel,Encryption,Signal,Vendor,First Seen,Last Seen\n")
            
            for bssid, net in networks.items():
                f.write(f'"{net.get("ssid", "?")}",'
                       f'{bssid},'
                       f'{net.get("channel", "?")},'
                       f'{net.get("encryption", "?")},'
                       f'{net.get("signal", "?")},'
                       f'{net.get("vendor", "?")},'
                       f'{net.get("first_seen", "?")},'
                       f'{net.get("last_seen", "?")}\n')
        
        self.logger.info(f"CSV report saved: {filepath}")
        print(f"[✓] CSV report: {filepath}")
        return filepath
    
    def generate_pdf(self, filepath: str) -> Optional[str]:
        """Generate PDF report (requires fpdf)."""
        try:
            from fpdf import FPDF
        except ImportError:
            print(f"[✗] fpdf not installed. Install: pip install fpdf")
            return None
        
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 20)
        pdf.cell(0, 15, "SUDOIT WiFi Security Assessment", ln=True, align="C")
        
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(10)
        
        # Networks section
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Discovered Networks", ln=True)
        pdf.set_font("Arial", "", 9)
        
        # Table header
        pdf.set_fill_color(50, 50, 50)
        pdf.set_text_color(0, 255, 0)
        pdf.cell(45, 8, "SSID", 1, 0, fill=True)
        pdf.cell(35, 8, "BSSID", 1, 0, fill=True)
        pdf.cell(15, 8, "Ch", 1, 0, fill=True)
        pdf.cell(25, 8, "Encryption", 1, 0, fill=True)
        pdf.cell(15, 8, "Signal", 1, 0, fill=True)
        pdf.cell(35, 8, "Vendor", 1, 1, fill=True)
        
        # Table rows
        pdf.set_text_color(200, 200, 200)
        networks = self._report_data.get("scan_results", {})
        for bssid, net in list(networks.items())[:30]:  # Max 30 rows
            pdf.cell(45, 7, str(net.get('ssid', '?'))[:22], 1)
            pdf.cell(35, 7, bssid, 1)
            pdf.cell(15, 7, str(net.get('channel', '?')), 1)
            pdf.cell(25, 7, str(net.get('encryption', '?')), 1)
            pdf.cell(15, 7, str(net.get('signal', '?')), 1)
            pdf.cell(35, 7, str(net.get('vendor', '?'))[:17], 1, 1)
        
        pdf.output(filepath)
        self.logger.info(f"PDF report saved: {filepath}")
        print(f"[✓] PDF report: {filepath}")
        return filepath
    
    def generate_all(self, output_dir: str = "./reports") -> Dict[str, str]:
        """Generate all report formats."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        reports = {}
        
        # JSON
        json_path = os.path.join(output_dir, f"report_{timestamp}.json")
        reports['json'] = self.generate_json(json_path)
        
        # HTML
        html_path = os.path.join(output_dir, f"report_{timestamp}.html")
        reports['html'] = self.generate_html(html_path)
        
        # CSV
        csv_path = os.path.join(output_dir, f"report_{timestamp}.csv")
        reports['csv'] = self.generate_csv(csv_path)
        
        #
