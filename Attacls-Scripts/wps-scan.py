#!/usr/bin/env python3
"""
SUDOIT WPS Scanner Module
Detect WPS-enabled access points and check vulnerabilities.
"""

import time
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class WPSScanner:
    """
    WPS Scanner Module.
    
    Features:
        - WPS detection via wash
        - WPS version detection
        - Lock status check
        - Manufacturer identification
        - Vulnerability assessment
        - Reaver-compatible output
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self.wps_networks: List[Dict] = []
        self._start_time = None
    
    def scan(self, duration: int = 30, save_output: bool = True) -> List[Dict]:
        """
        Scan for WPS-enabled networks.
        
        Args:
            duration: Scan duration in seconds
            save_output: Save results to file
        
        Returns:
            List of WPS-enabled APs
        """
        self.logger.info(f"Starting WPS scan for {duration}s")
        self.running = True
        self._start_time = time.time()
        self.wps_networks.clear()
        
        print(f"\n[*] Scanning for WPS-enabled APs...")
        print(f"    Duration: {duration}s\n")
        
        # Run wash
        cmd = ["wash", "-i", self.interface]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            start = time.time()
            
            # Read header
            header = proc.stdout.readline()
            if header:
                print(f"  {header.strip()}")
            
            print(f"  {'-'*70}")
            
            while time.time() - start < duration:
                if not self.running:
                    break
                
                line = proc.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # Skip header separator
                if all(c == '-' for c in line):
                    continue
                
                # Parse wash output
                parts = line.split()
                if len(parts) >= 5:
                    bssid = parts[0]
                    channel = parts[1] if len(parts) > 1 else "?"
                    signal = parts[2] if len(parts) > 2 else "?"
                    wps_ver = parts[3] if len(parts) > 3 else "?"
                    locked = "Locked" in line
                    ssid = parts[-1] if len(parts) > 5 else "Unknown"
                    
                    # Check if already seen
                    if bssid not in [n['bssid'] for n in self.wps_networks]:
                        network = {
                            "bssid": bssid,
                            "channel": channel,
                            "signal": signal,
                            "wps_version": wps_ver,
                            "locked": locked,
                            "ssid": ssid,
                            "vulnerable": not locked and wps_ver != "?",
                            "found_at": datetime.now().isoformat()
                        }
                        
                        self.wps_networks.append(network)
                        
                        # Status indicator
                        status = "[!]" if network['vulnerable'] else "[ ]"
                        lock_str = "LOCKED" if locked else "unlocked"
                        
                        print(f"  {status} {bssid}  Ch:{channel:>3}  {signal:>4}dBm  "
                              f"WPS:{wps_ver}  {lock_str:>8}  {ssid}")
            
            proc.terminate()
            
        except FileNotFoundError:
            print(f"[✗] wash not found! Install: apt install reaver")
            return []
        except Exception as e:
            self.logger.error(f"WPS scan error: {e}")
            return []
        finally:
            self.running = False
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        # Summary
        vulnerable = [n for n in self.wps_networks if n['vulnerable']]
        locked = [n for n in self.wps_networks if n['locked']]
        
        print(f"\n[*] WPS Scan Complete ({elapsed:.1f}s)")
        print(f"    Total WPS APs:   {len(self.wps_networks)}")
        print(f"    Vulnerable:      {len(vulnerable)}")
        print(f"    Locked:          {len(locked)}")
        
        if save_output:
            self._save_results()
        
        return self.wps_networks
    
    def _save_results(self):
        """Save scan results to JSON."""
        import json
        from pathlib import Path
        
        output_dir = Path("./output")
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / f"wps_scan_{datetime.now():%Y%m%d_%H%M%S}.json"
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "total": len(self.wps_networks),
            "vulnerable": len([n for n in self.wps_networks if n['vulnerable']]),
            "networks": self.wps_networks
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[✓] Results saved: {filepath}")
    
    def get_vulnerable(self) -> List[Dict]:
        """Get vulnerable (unlocked) WPS APs."""
        return [n for n in self.wps_networks if n['vulnerable']]
    
    def get_locked(self) -> List[Dict]:
        """Get locked WPS APs."""
        return [n for n in self.wps_networks if n['locked']]
    
    def stop(self):
        """Stop scanning."""
        self.running = False
        self.logger.info("WPS scan stopped")
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "running": self.running,
            "wps_found": len(self.wps_networks),
            "vulnerable": len(self.get_vulnerable()),
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
