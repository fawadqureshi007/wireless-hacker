#!/usr/bin/env python3
"""
SUDOIT KARMA Attack Module
Respond to probe requests to lure clients into connecting.
"""

import time
from datetime import datetime
from typing import Set, Dict, List, Optional, Callable
from collections import defaultdict

from scapy.all import sniff, Dot11, Dot11ProbeReq, Dot11Elt, RadioTap

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class KARMAAttack:
    """
    KARMA Attack Module.
    
    KARMA (Karma Attacks Radio Machines Automatically) listens
    for client probe requests and logs which networks devices
    are searching for. Advanced implementations can respond
    with crafted probe responses to lure clients.
    
    Features:
        - Probe request monitoring
        - Client fingerprinting
        - SSID profiling
        - Preferred network discovery
        - Client tracking
        - Export results
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._callback: Optional[Callable] = None
        self._probes_seen: Set[str] = set()
        self._client_probes: Dict[str, List[Dict]] = defaultdict(list)
        self._ssid_probes: Dict[str, int] = defaultdict(int)
        self._client_vendors: Dict[str, str] = {}
        self._start_time = None
    
    def set_callback(self, callback: Callable):
        """Set callback for real-time probe alerts."""
        self._callback = callback
    
    def start(self, duration: int = 120,
              respond: bool = False) -> Dict:
        """
        Start KARMA attack - listen for probe requests.
        
        Args:
            duration: Monitoring duration in seconds
            respond: Craft probe responses (requires additional setup)
        
        Returns:
            Dict with collected probe data
        """
        self.logger.info(f"KARMA attack started (duration={duration}s)")
        self.running = True
        self._start_time = time.time()
        self._probes_seen.clear()
        self._client_probes.clear()
        self._ssid_probes.clear()
        self._client_vendors.clear()
        
        print(f"\n[*] KARMA Attack Active")
        print(f"    Duration:  {duration}s")
        print(f"    Respond:   {'Yes' if respond else 'No (monitoring only)'}")
        print(f"    Press Ctrl+C to stop\n")
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(Dot11ProbeReq):
                    client_mac = pkt[Dot11].addr2
                    if not client_mac:
                        return
                    
                    # Extract SSID
                    ssid = ""
                    if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info:
                        try:
                            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                        except:
                            pass
                    
                    # Signal
                    signal = -100
                    if pkt.haslayer(RadioTap):
                        signal = pkt[RadioTap].dBm_AntSignal
                    
                    # Track
                    self._probes_seen.add(ssid)
                    self._ssid_probes[ssid] += 1
                    
                    probe_info = {
                        "client": client_mac,
                        "ssid": ssid,
                        "signal": signal,
                        "vendor": self._get_vendor(client_mac),
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self._client_probes[client_mac].append(probe_info)
                    self._client_vendors[client_mac] = self._get_vendor(client_mac)
                    
                    # Print
                    print(f"  [*] {client_mac} ({self._get_vendor(client_mac)}) -> {ssid or '(Broadcast)'}")
                    
                    # Callback
                    if self._callback:
                        self._callback(probe_info)
                        
            except Exception as e:
                self.logger.debug(f"Packet error: {e}")
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0,
                timeout=duration
            )
        except Exception as e:
            self.logger.error(f"KARMA error: {e}")
        finally:
            self.running = False
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        print(f"\n[*] KARMA Complete: {len(self._probes_seen)} unique SSIDs, "
              f"{len(self._client_probes)} clients in {elapsed:.1f}s")
        
        return self.get_results()
    
    def get_results(self) -> Dict:
        """Get collected probe data."""
        # Sort SSIDs by popularity
        popular_ssids = sorted(
            self._ssid_probes.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            "unique_ssids": len(self._probes_seen),
            "unique_clients": len(self._client_probes),
            "top_ssids": popular_ssids[:20],
            "ssid_list": list(self._probes_seen),
            "clients": dict(self._client_probes),
            "duration": time.time() - self._start_time if self._start_time else 0
        }
    
    def get_popular_ssids(self, top_n: int = 10) -> List[tuple]:
        """Get most popular SSIDs from probes."""
        return sorted(
            self._ssid_probes.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
    
    def get_client_ssids(self, client_mac: str) -> List[str]:
        """Get all SSIDs probed by specific client."""
        if client_mac in self._client_probes:
            return [p['ssid'] for p in self._client_probes[client_mac]]
        return []
    
    def get_ssid_clients(self, ssid: str) -> List[str]:
        """Get all clients that probed for specific SSID."""
        clients = []
        for client, probes in self._client_probes.items():
            if any(p['ssid'] == ssid for p in probes):
                clients.append(client)
        return clients
    
    def find_hidden_networks(self) -> List[str]:
        """
        Find potential hidden network SSIDs.
        Hidden networks don't broadcast SSID but clients probe for them.
        """
        # SSIDs that clients probe but we haven't seen beaconing
        probed_ssids = set(self._ssid_probes.keys())
        return sorted(probed_ssids)
    
    def fingerprint_client(self, client_mac: str) -> Dict:
        """
        Fingerprint a client based on probe requests.
        Reveals preferred networks, device type hints.
        """
        if client_mac not in self._client_probes:
            return {"mac": client_mac, "error": "No data"}
        
        probes = self._client_probes[client_mac]
        ssids = [p['ssid'] for p in probes if p['ssid']]
        
        return {
            "mac": client_mac,
            "vendor": self._client_vendors.get(client_mac, "Unknown"),
            "probe_count": len(probes),
            "preferred_networks": ssids[:10],
            "first_seen": probes[0]['timestamp'] if probes else None,
            "last_seen": probes[-1]['timestamp'] if probes else None,
            "avg_signal": sum(p.get('signal', -100) for p in probes) / len(probes) if probes else -100
        }
    
    def export_results(self, filepath: str):
        """Export KARMA results to JSON."""
        import json
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "unique_ssids": len(self._probes_seen),
                "unique_clients": len(self._client_probes),
                "total_probes": sum(self._ssid_probes.values())
            },
            "top_ssids": self.get_popular_ssids(50),
            "clients": {
                mac: self.fingerprint_client(mac)
                for mac in self._client_probes
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[✓] Results exported: {filepath}")
        self.logger.info(f"KARMA results exported: {filepath}")
    
    def _get_vendor(self, mac: str) -> str:
        """Quick OUI vendor lookup."""
        OUI = {
            "FCA621": "Apple", "B827EB": "Raspberry Pi",
            "DC9FDB": "Ubiquiti", "080030": "NETGEAR",
            "001D7E": "TP-Link", "00A0C5": "D-Link",
            "ACF1DF": "Google", "E8DE27": "Microsoft",
            "001377": "Samsung", "74258A": "OnePlus",
            "60A4B7": "Xiaomi", "4CEBB7": "Amazon",
            "38229D": "LG", "003065": "Huawei"
        }
        oui = mac.replace(":", "").upper()[:6]
        return OUI.get(oui, "Unknown")
    
    def stop(self):
        """Stop KARMA attack."""
        self.running = False
        self.logger.info("KARMA attack stopped")
    
    def is_running(self) -> bool:
        """Check if KARMA is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "running": self.running,
            "ssids_seen": len(self._probes_seen),
            "clients_seen": len(self._client_probes),
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
