#!/usr/bin/env python3
"""
SUDOIT Web Dashboard Module
Real-time web-based monitoring interface using Flask.
"""

import os
import time
import json
import threading
from datetime import datetime
from typing import Dict, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)

try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class WebDashboard:
    """
    Real-time Web Dashboard for SUDOIT Framework.
    
    Features:
        - Live network monitoring
        - Real-time scan results
        - Attack status tracking
        - Network details view
        - Statistics dashboard
        - WebSocket updates
        - Responsive design
    """
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SUDOIT Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px;
            border-bottom: 2px solid #00ff00;
            margin-bottom: 20px;
        }
        .header h1 {
            font-size: 2em;
            text-shadow: 0 0 10px #00ff00;
        }
        .header .subtitle {
            color: #008800;
            margin-top: 5px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #1a1a1a;
            border: 1px solid #00ff00;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff00;
        }
        .stat-card .label {
            color: #008800;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .table-container {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            overflow: hidden;
        }
        .table-header {
            background: #111;
            padding: 15px;
            border-bottom: 1px solid #333;
            font-size: 1.2em;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #222;
            color: #00ff00;
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
            position: sticky;
            top: 0;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #1a1a1a;
        }
        tr:hover {
            background: #222;
        }
        .signal-bar {
            display: inline-block;
            height: 10px;
            border-radius: 5px;
            margin-right: 5px;
        }
        .signal-strong { background: #00ff00; }
        .signal-good { background: #88ff00; }
        .signal-fair { background: #ffaa00; }
        .signal-weak { background: #ff4400; }
        .enc-open { color: #ff4444; font-weight: bold; }
        .enc-wpa { color: #ffaa00; }
        .enc-wpa2 { color: #ffaa00; }
        .enc-wpa3 { color: #00ff00; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #555;
            margin-top: 20px;
            border-top: 1px solid #333;
        }
        .blink {
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .attack-log {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            max-height: 300px;
            overflow-y: auto;
        }
        .attack-log .log-entry {
            padding: 8px;
            border-bottom: 1px solid #222;
            font-size: 0.85em;
        }
        .log-time { color: #888; }
        .log-success { color: #00ff00; }
        .log-fail { color: #ff4444; }
        .log-info { color: #00aaff; }
        .log-warn { color: #ffaa00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SUDOIT Dashboard</h1>
        <p class="subtitle">Real-Time WiFi Security Monitor</p>
        <p class="subtitle blink">● LIVE</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number" id="total-networks">0</div>
            <div class="label">Networks Found</div>
        </div>
        <div class="stat-card">
            <div class="number" id="open-networks">0</div>
            <div class="label">Open Networks</div>
        </div>
        <div class="stat-card">
            <div class="number" id="handshakes-count">0</div>
            <div class="label">Handshakes</div>
        </div>
        <div class="stat-card">
            <div class="number" id="attacks-count">0</div>
            <div class="label">Attacks</div>
        </div>
        <div class="stat-card">
            <div class="number" id="uptime">0s</div>
            <div class="label">Uptime</div>
        </div>
    </div>

    <div class="table-container">
        <div class="table-header">Discovered Networks</div>
        <div style="max-height: 400px; overflow-y: auto;">
            <table>
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>BSSID</th>
                        <th>Ch</th>
                        <th>Encryption</th>
                        <th>Signal</th>
                        <th>Vendor</th>
                    </tr>
                </thead>
                <tbody id="networks-table">
                    <tr><td colspan="6" style="text-align:center;color:#555;">Waiting for scan data...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="attack-log">
        <div class="table-header">Activity Log</div>
        <div id="attack-log">
            <div class="log-entry"><span class="log-time">--:--:--</span> <span class="log-info">Waiting for activity...</span></div>
        </div>
    </div>

    <div class="footer">
        SUDOIT Framework v1.0 | Ethical Use Only
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        const socket = io();

        socket.on('connect', function() {
            console.log('Connected to SUDOIT Dashboard');
        });

        socket.on('update', function(data) {
            // Update stats
            document.getElementById('total-networks').textContent = data.total_networks || 0;
            document.getElementById('open-networks').textContent = data.open_networks || 0;
            document.getElementById('handshakes-count').textContent = data.handshakes || 0;
            document.getElementById('attacks-count').textContent = data.attacks || 0;
            document.getElementById('uptime').textContent = data.uptime || '0s';

            // Update networks table
            if (data.networks && data.networks.length > 0) {
                var tableHtml = '';
                data.networks.forEach(function(net) {
                    var encClass = 'enc-open';
                    if (net.encryption === 'WPA2') encClass = 'enc-wpa2';
                    else if (net.encryption === 'WPA3') encClass = 'enc-wpa3';
                    else if (net.encryption === 'WPA') encClass = 'enc-wpa';

                    var signalClass = 'signal-weak';
                    if (net.signal > -50) signalClass = 'signal-strong';
                    else if (net.signal > -65) signalClass = 'signal-good';
                    else if (net.signal > -75) signalClass = 'signal-fair';

                    var signalWidth = Math.max(5, (100 + net.signal));
                    
                    tableHtml += '<tr>';
                    tableHtml += '<td>' + (net.ssid || '?') + '</td>';
                    tableHtml += '<td><code>' + (net.bssid || '?') + '</code></td>';
                    tableHtml += '<td>' + (net.channel || '?') + '</td>';
                    tableHtml += '<td class="' + encClass + '">' + (net.encryption || '?') + '</td>';
                    tableHtml += '<td><span class="signal-bar ' + signalClass + '" style="width:' + signalWidth + 'px"></span>' + (net.signal || '?') + ' dBm</td>';
                    tableHtml += '<td>' + (net.vendor || '?') + '</td>';
                    tableHtml += '</tr>';
                });
                document.getElementById('networks-table').innerHTML = tableHtml;
            }

            // Update log
            if (data.logs && data.logs.length > 0) {
                var logHtml = '';
                data.logs.forEach(function(log) {
                    var logClass = 'log-info';
                    if (log.type === 'success') logClass = 'log-success';
                    else if (log.type === 'error') logClass = 'log-fail';
                    else if (log.type === 'warning') logClass = 'log-warn';
                    
                    logHtml += '<div class="log-entry"><span class="log-time">' + log.time + '</span> <span class="' + logClass + '">' + log.message + '</span></div>';
                });
                document.getElementById('attack-log').innerHTML = logHtml;
            }
        });

        socket.on('disconnect', function() {
            console.log('Disconnected from dashboard');
        });
    </script>
</body>
</html>
"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, logger=None):
        self.host = host
        self.port = port
        self.logger = logger or get_logger()
        self.running = False
        self._app = None
        self._socketio = None
        self._server_thread = None
        self._data_provider: Optional[callable] = None
        self._start_time = None
    
    def set_data_provider(self, provider: callable):
        """Set function that provides dashboard data."""
        self._data_provider = provider
    
    def start(self):
        """Start the web dashboard server."""
        if not FLASK_AVAILABLE:
            print(f"[✗] Flask not installed. Install: pip install flask flask-socketio")
            self.logger.error("Flask not available")
            return
        
        self._app = Flask(__name__)
        self._app.config['SECRET_KEY'] = 'sudoit_secret'
        self._socketio = SocketIO(self._app, cors_allowed_origins="*")
        
        @self._app.route('/')
        def index():
            return render_template_string(self.HTML_TEMPLATE)
        
        @self._app.route('/api/networks')
        def api_networks():
            if self._data_provider:
                data = self._data_provider()
                return jsonify(data.get('networks', []))
            return jsonify([])
        
        @self._app.route('/api/stats')
        def api_stats():
            if self._data_provider:
                data = self._data_provider()
                return jsonify({
                    "total_networks": data.get('total_networks', 0),
                    "open_networks": data.get('open_networks', 0),
                    "handshakes": data.get('handshakes', 0),
                    "attacks": data.get('attacks', 0),
                    "uptime": data.get('uptime', '0s')
                })
            return jsonify({})
        
        # Start background data emitter
        self.running = True
        self._start_time = time.time()
        
        def emit_data():
            while self.running:
                if self._data_provider:
                    data = self._data_provider()
                    self._socketio.emit('update', data)
                time.sleep(3)
        
        emit_thread = threading.Thread(target=emit_data, daemon=True)
        emit_thread.start()
        
        print(f"\n[*] Web Dashboard started!")
        print(f"    URL: http://{self.host}:{self.port}")
        print(f"    Press Ctrl+C to stop\n")
        
        self.logger.info(f"Web dashboard started on {self.host}:{self.port}")
        
        try:
            self._socketio.run(
                self._app,
                host=self.host,
                port=self.port,
                allow_unsafe_werkzeug=True,
                use_reloader=False
            )
        except Exception as e:
            self.logger.error(f"Dashboard error: {e}")
        finally:
            self.running = False
    
    def start_background(self):
        """Start dashboard in background thread."""
        self._server_thread = threading.Thread(target=self.start, daemon=True)
        self._server_thread.start()
        time.sleep(2)  # Wait for startup
    
    def stop(self):
        """Stop the dashboard."""
        self.running = False
        self.logger.info("Web dashboard stopped")
    
    def is_running(self) -> bool:
        """Check if dashboard is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get dashboard status."""
        return {
            "running": self.running,
            "url": f"http://{self.host}:{self.port}",
            "uptime": time.time() - self._start_time if self._start_time else 0
        }
    
    def get_default_data(self) -> Dict:
        """Get default dashboard data structure."""
        return {
            "total_networks": 0,
            "open_networks": 0,
            "handshakes": 0,
            "attacks": 0,
            "uptime": "0s",
            "networks": [],
            "logs": []
        }
