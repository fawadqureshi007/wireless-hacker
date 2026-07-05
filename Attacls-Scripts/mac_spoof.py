#!/usr/bin/env python3
"""
SUDOIT MAC Spoofing Module
MAC address manipulation and randomization tools.
"""

import os
import re
import random
import subprocess
from typing import Optional, List, Dict

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class MACSpoofer:
    """
    MAC Address Spoofing Module.
    
    Features:
        - Random MAC generation
        - Vendor-specific MAC cloning
        - MAC address validation
        - Interface MAC changing
        - Original MAC backup/restore
        - OUI-based generation
    """
    
    # Common vendor OUIs
    VENDORS = {
        "Apple": "FCA621",
        "Samsung": "001377",
        "Intel": "0013CE",
        "Cisco": "00036C",
        "TP-Link": "001D7E",
        "D-Link": "00A0C5",
        "NETGEAR": "080030",
        "Ubiquiti": "DC9FDB",
        "Google": "ACF1DF",
        "Microsoft": "E8DE27",
        "Xiaomi": "60A4B7",
        "Huawei": "003065",
        "Sony": "0015E9",
        "Nintendo": "0018F8"
    }
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self._original_mac: Optional[str] = None
        self._current_mac: Optional[str] = None
    
    def backup_original(self):
        """Backup original MAC address before spoofing."""
        self._original_mac = self.get_current_mac()
        if self._original_mac:
            self.logger.info(f"Original MAC backed up: {self._original_mac}")
            print(f"[*] Original MAC: {self._original_mac}")
    
    def get_current_mac(self) -> Optional[str]:
        """Get current MAC address of interface."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                capture_output=True, text=True
            )
            
            match = re.search(r'link/ether ([0-9a-fA-F:]{17})', result.stdout)
            if match:
                return match.group(1).lower()
        except Exception as e:
            self.logger.error(f"Failed to get MAC: {e}")
        
        return None
    
    def generate_random(self, locally_administered: bool = True) -> str:
        """
        Generate a random MAC address.
        
        Args:
            locally_administered: Set locally administered bit
        
        Returns:
            Random MAC address string
        """
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        
        if locally_administered:
            mac[0] = (mac[0] | 0x02) & ~0x01  # Set bit 1, clear bit 0
        
        return ":".join(f"{b:02x}" for b in mac)
    
    def generate_from_vendor(self, vendor: str) -> Optional[str]:
        """
        Generate MAC with specific vendor OUI prefix.
        
        Args:
            vendor: Vendor name (must be in VENDORS dict)
        
        Returns:
            MAC address with vendor OUI
        """
        if vendor not in self.VENDORS:
            print(f"[!] Unknown vendor: {vendor}")
            print(f"    Available: {', '.join(self.VENDORS.keys())}")
            return None
        
        oui = self.VENDORS[vendor]
        # Generate random last 3 bytes
        suffix = [random.randint(0x00, 0xff) for _ in range(3)]
        
        # Parse OUI into bytes
        oui_bytes = [int(oui[i:i+2], 16) for i in range(0, 6, 2)]
        
        mac = oui_bytes + suffix
        return ":".join(f"{b:02x}" for b in mac)
    
    def generate_clone(self, target_mac: str, randomize_last: bool = True) -> str:
        """
        Clone a MAC with optional last byte randomization.
        
        Args:
            target_mac: MAC to clone
            randomize_last: Randomize last byte
        
        Returns:
            Cloned MAC address
        """
        try:
            parts = target_mac.split(":")
            if len(parts) != 6:
                raise ValueError("Invalid MAC format")
            
            if randomize_last:
                parts[5] = f"{random.randint(0x00, 0xff):02x}"
            
            return ":".join(parts)
        except Exception:
            return target_mac
    
    def spoof(self, new_mac: Optional[str] = None, vendor: Optional[str] = None):
        """
        Change interface MAC address.
        
        Args:
            new_mac: Specific MAC to set
            vendor: Generate MAC for specific vendor
        """
        if not new_mac:
            if vendor:
                new_mac = self.generate_from_vendor(vendor)
            else:
                new_mac = self.generate_random()
        
        if not new_mac:
            print(f"[✗] Failed to generate MAC")
            return
        
        # Validate MAC format
        if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', new_mac):
            print(f"[✗] Invalid MAC format: {new_mac}")
            return
        
        # Backup original first
        if not self._original_mac:
            self.backup_original()
        
        print(f"[*] Changing MAC on {self.interface}...")
        print(f"    Current: {self.get_current_mac()}")
        print(f"    New:     {new_mac}")
        
        # Bring interface down
        subprocess.run(["ip", "link", "set", "dev", self.interface, "down"], 
                      capture_output=True)
        
        # Change MAC
        result = subprocess.run(
            ["ip", "link", "set", "dev", self.interface, "address", new_mac],
            capture_output=True
        )
        
        # Bring interface up
        subprocess.run(["ip", "link", "set", "dev", self.interface, "up"], 
                      capture_output=True)
        
        # Verify
        self._current_mac = self.get_current_mac()
        
        if self._current_mac and self._current_mac.lower() == new_mac.lower():
            print(f"[✓] MAC changed successfully!")
            print(f"    New MAC: {self._current_mac}")
            self.logger.info(f"MAC spoofed: {new_mac}")
        else:
            print(f"[✗] MAC change failed!")
            print(f"    Expected: {new_mac}")
            print(f"    Got:      {self._current_mac}")
    
    def restore(self):
        """Restore original MAC address."""
        if not self._original_mac:
            print(f"[!] No original MAC backed up")
            return
        
        print(f"[*] Restoring original MAC: {self._original_mac}")
        self.spoof(self._original_mac)
    
    def randomize_continuous(self, interval: int = 30, duration: int = 300):
        """
        Continuously randomize MAC at intervals.
        
        Args:
            interval: Seconds between changes
            duration: Total duration in seconds
        """
        import time
        
        print(f"\n[*] Continuous MAC Randomization")
        print(f"    Interval: {interval}s")
        print(f"    Duration: {duration}s\n")
        
        start = time.time()
        changes = 0
        
        while time.time() - start < duration:
            new_mac = self.generate_random()
            self.spoof(new_mac)
            changes += 1
            time.sleep(interval)
        
        print(f"\n[*] Randomization complete: {changes} changes")
    
    def validate_mac(self, mac: str) -> bool:
        """Validate MAC address format."""
        return bool(re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac))
    
    def get_vendor_from_mac(self, mac: str) -> str:
        """Try to identify vendor from MAC OUI."""
        oui = mac.replace(":", "").upper()[:6]
        
        for vendor, vendor_oui in self.VENDORS.items():
            if vendor_oui.upper() == oui:
                return vendor
        
        return "Unknown"
    
    def list_vendors(self) -> List[str]:
        """List available vendor OUIs."""
        return list(self.VENDORS.keys())
    
    def get_status(self) -> Dict:
        """Get current MAC status."""
        return {
            "interface": self.interface,
            "original_mac": self._original_mac,
            "current_mac": self.get_current_mac(),
            "vendor": self.get_vendor_from_mac(self.get_current_mac() or "")
        }
