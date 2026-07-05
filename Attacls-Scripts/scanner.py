#!/usr/bin/env python3
"""
SUDOIT WiFi Scanner Module
Advanced WiFi network discovery with OUI fingerprinting,
signal analysis, and real-time monitoring.
"""

import time
import threading
import subprocess
from datetime import datetime
from typing import Dict, Optional, Callable
from collections import defaultdict

from scapy.all import (
    sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp,
    Dot11ProbeReq, RadioTap
)

# Try to import core logger
try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class WiFiScanner:
    """
    Advanced WiFi Scanner with multi-band support.
    
    Features:
        - 2.4 GHz and 5 GHz scanning
        - Channel hopping
        - OUI vendor fingerprinting
        - Signal strength tracking
        - Hidden SSID detection
        - WPA/WPA2/WPA3 detection
        - Client discovery
        - Real-time result callback
    """
    
    # Full OUI Database
    OUI_DB = {
        "00036C": "Cisco Systems",
        "001377": "Samsung Electronics",
        "080030": "NETGEAR Inc.",
        "001D7E": "TP-Link Technologies",
        "00A0C5": "D-Link Corporation",
        "DC9FDB": "Ubiquiti Networks",
        "FCA621": "Apple Inc.",
        "0050F1": "Hewlett Packard",
        "00802D": "Compaq Computer",
        "0013CE": "Intel Corporate",
        "003065": "Huawei Technologies",
        "ACF1DF": "Google Inc.",
        "B827EB": "Raspberry Pi Foundation",
        "E8DE27": "Microsoft Corporation",
        "74258A": "OnePlus Technology",
        "60A4B7": "Xiaomi Communications",
        "4CEBB7": "Amazon Technologies",
        "38229D": "LG Electronics",
        "0015E9": "SONY Corporation",
        "0050BA": "ASUSTek Computer",
        "001217": "Cisco-Linksys",
        "0018F8": "Nintendo Co.",
        "0024E8": "Dell Inc.",
        "003A9D": "NEC Corporation",
        "0040F4": "Nokia Corporation",
        "0060B3": "Hewlett Packard Enterprise",
        "049162": "Xiaomi Communications",
        "08F1EA": "Motorola Mobility",
        "10683B": "HTC Corporation",
        "14ABF0": "Panasonic Corporation",
        "182666": "Samsung Electronics",
        "1C5CF2": "ASUSTek Computer",
        "206432": "SAGEMCOM",
        "28E347": "Xiaomi Communications",
        "38EC0D": "ZTE Corporation",
        "48D705": "Huawei Technologies",
        "5C5188": "Motorola Mobility",
        "6C19C0": "Apple Inc.",
        "70F35C": "Samsung Electronics",
        "78D75F": "Huawei Technologies",
        "80E650": "Apple Inc.",
        "841B5E": "NETGEAR Inc.",
        "8CAED3": "Google Inc.",
        "90671C": "Samsung Electronics",
        "94877B": "TP-Link Technologies",
        "9C9726": "Xiaomi Communications",
        "A4C361": "Xiaomi Communications",
        "ACD074": "Apple Inc.",
        "B0E5F9": "Huawei Technologies",
        "C49DED": "Microsoft Corporation",
        "CCB255": "D-Link Corporation",
        "D8D1CB": "Apple Inc.",
        "E4F042": "Google Inc.",
        "F0B429": "Xiaomi Communications",
        "FC019E": "Samsung Electronics"
    }
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.scan_results: Dict[str, Dict] = {}
        self.clients: Dict[str, list] = defaultdict(list)
        self.running = False
        self.current_channel = 1
        self._callback: Optional[Callable] = None
        self._lock = threading.Lock()
        self._packet_count = 0
        self._network_count = 0
        self._start_time = None
    
    def set_callback(self, callback: Callable):
        """Set a callback function for real-time result updates."""
        self._callback = callback
    
    def scan(self, duration: int = 60, channel_hop: bool = True,
             hop_interval: float = 0.3, include_clients: bool = False) -> Dict:
        """
        Perform WiFi scan.
        
        Args:
            duration: Scan duration in seconds (0 = continuous)
            channel_hop: Enable channel hopping
            hop_interval: Time between channel hops
            include_clients: Also capture client devices
        
        Returns:
            Dictionary of discovered networks
        """
        self.logger.info(f"Starting WiFi scan on {self.interface} for {duration}s")
        self.scan_results.clear()
        self.clients.clear()
        self.running = True
        self._packet_count = 0
        self._network_count = 0
        self._start_time = time.time()
        
        # Start channel hopper
        hopper = None
        if channel_hop:
            hopper = threading.Thread(
                target=self._channel_hopper,
                args=(hop_interval,),
                daemon=True
            )
            hopper.start()
        
        # Start sniffing
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
        finally:
            self.running = False
            if hopper:
                hopper.join(timeout=1)
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        self.logger.info(
            f"Scan complete: {len(self.scan_results)} networks, "
            f"{self._packet_count} packets in {elapsed:.1f}s"
        )
        
        return self.scan_results
    
    def _channel_hopper(self, interval: float):
        """Hop through WiFi channels."""
        channels_24 = list(range(1, 14))
        channels_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        all_channels = channels_24 + channels_5
        
        while self.running:
            for ch in all_channels:
                if not self.running:
                    break
                try:
                    subprocess.run(
                        ["iwconfig", self.interface, "channel", str(ch)],
                        capture_output=True, timeout=0.5
                    )
                    self.current_channel = ch
                except Exception:
                    pass
                time.sleep(interval)
    
    def _packet_handler(self, pkt):
        """Process captured packets."""
        self._packet_count += 1
        
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                self._process_ap_packet(pkt)
            elif pkt.haslayer(Dot11ProbeReq):
                self._process_probe_request(pkt)
        except Exception as e:
            self.logger.debug(f"Packet handler error: {e}")
    
    def _process_ap_packet(self, pkt):
        """Extract AP information from beacon/probe response."""
        bssid = pkt[Dot11].addr2
        if not bssid:
            return
        
        # SSID
        ssid = "<Hidden>"
        if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info:
            try:
                decoded = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                if decoded.strip():
                    ssid = decoded
            except:
                pass
        
        # Channel
        channel = None
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3:  # DS Parameter Set
                    channel = ord(elt.info)
                    break
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
        except:
            pass
        
        # Encryption
        encryption = self._detect_encryption(pkt)
        
        # Signal
        signal_strength = -100
        if pkt.haslayer(RadioTap):
            signal_strength = pkt[RadioTap].dBm_AntSignal
        
        # Vendor
        vendor = self._get_vendor(bssid)
        
        with self._lock:
            is_new = bssid not in self.scan_results
            
            if is_new:
                self._network_count += 1
                self.scan_results[bssid] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": channel or 0,
                    "encryption": encryption,
                    "signal": signal_strength,
                    "max_signal": signal_strength,
                    "vendor": vendor,
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "beacon_count": 1
                }
            else:
                net = self.scan_results[bssid]
                net["signal"] = signal_strength
                net["last_seen"] = datetime.now().isoformat()
                net["beacon_count"] += 1
                if signal_strength > net["max_signal"]:
                    net["max_signal"] = signal_strength
            
            # Callback
            if self._callback and is_new:
                self._callback(self.scan_results[bssid])
    
    def _process_probe_request(self, pkt):
        """Process client probe requests."""
        client_mac = pkt[Dot11].addr2
        if not client_mac:
            return
        
        bssid = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else None
        
        ssid = ""
        if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info:
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            except:
                pass
        
        signal = -100
        if pkt.haslayer(RadioTap):
            signal = pkt[RadioTap].dBm_AntSignal
        
        client_info = {
            "mac": client_mac,
            "ssid_probed": ssid,
            "signal": signal,
            "vendor": self._get_vendor(client_mac),
            "bssid": bssid,
            "last_seen": datetime.now().isoformat()
        }
        
        with self._lock:
            if client_mac not in self.clients:
                self.clients[client_mac] = []
            self.clients[client_mac].append(client_info)
    
    def _detect_encryption(self, pkt) -> str:
        """Determine encryption type."""
        try:
            cap = pkt[Dot11].cap
            
            # Check for WPA3 (RSN + MFP required)
            has_rsn = False
            has_mfp = False
            
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48:  # RSN
                    has_rsn = True
                if elt.ID == 33:  # MFP
                    has_mfp = True
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
            
            if cap & 0x0010:  # Privacy
                if has_rsn and has_mfp:
                    return "WPA3"
                elif has_rsn:
                    return "WPA2"
                else:
                    return "WPA"
            else:
                return "OPEN"
        except:
            return "Unknown"
    
    def _get_vendor(self, mac: str) -> str:
        """Look up vendor from OUI database."""
        oui = mac.replace(":", "").upper()[:6]
        return self.OUI_DB.get(oui, "Unknown")

    
    def get_networks_sorted(self, sort_by: str = "signal") -> list:
        """Return networks sorted by specified field."""
        if sort_by == "signal":
            return sorted(self.scan_results.values(), 
                         key=lambda x: x.get("signal", -100), reverse=True)
        elif sort_by == "ssid":
            return sorted(self.scan_results.values(), 
                         key=lambda x: x.get("ssid", "").lower())
        elif sort_by == "channel":
            return sorted(self.scan_results.values(), 
                         key=lambda x: x.get("channel", 0))
        elif sort_by == "encryption":
            return sorted(self.scan_results.values(), 
                         key=lambda x: x.get("encryption", ""))
        else:
            return list(self.scan_results.values())
    
    def get_network(self, bssid: str) -> Optional[Dict]:
        """Get specific network by BSSID."""
        return self.scan_results.get(bssid)
    
    def get_networks_by_encryption(self, enc_type: str) -> list:
        """Filter networks by encryption type."""
        return [net for net in self.scan_results.values() 
                if net.get("encryption", "").upper() == enc_type.upper()]
    
    def get_open_networks(self) -> list:
        """Get all open (unencrypted) networks."""
        return self.get_networks_by_encryption("OPEN")
    
    def get_wpa_networks(self) -> list:
        """Get all WPA/WPA2/WPA3 networks."""
        return [net for net in self.scan_results.values() 
                if "WPA" in net.get("encryption", "")]
    
    def get_hidden_networks(self) -> list:
        """Get networks with hidden SSID."""
        return [net for net in self.scan_results.values() 
                if net.get("ssid") == "<Hidden>"]
    
    def get_networks_by_channel(self, channel: int) -> list:
        """Get networks on specific channel."""
        return [net for net in self.scan_results.values() 
                if net.get("channel") == channel]
    
    def get_networks_by_vendor(self, vendor: str) -> list:
        """Search networks by vendor name (partial match)."""
        return [net for net in self.scan_results.values() 
                if vendor.lower() in net.get("vendor", "").lower()]
    
    def get_strongest_network(self) -> Optional[Dict]:
        """Get network with strongest signal."""
        if not self.scan_results:
            return None
        return max(self.scan_results.values(), 
                  key=lambda x: x.get("signal", -100))
    
    def get_clients_for_network(self, bssid: str) -> list:
        """Get clients connected to a specific network."""
        return [client for client_list in self.clients.values() 
                for client in client_list if client.get("bssid") == bssid]
    
    def get_network_summary(self, bssid: str) -> Dict:
        """Get detailed summary of a network."""
        network = self.get_network(bssid)
        if not network:
            return {}
        
        clients = self.get_clients_for_network(bssid)
        
        return {
            **network,
            "clients_count": len(clients),
            "clients": clients[:10],  # First 10 clients
            "age_seconds": (datetime.now() - 
                           datetime.fromisoformat(network["first_seen"])).total_seconds()
            if network.get("first_seen") else 0
        }
    
    def get_statistics(self) -> Dict:
        """Get scan statistics."""
        total = len(self.scan_results)
        if total == 0:
            return {"total": 0}
        
        encryptions = defaultdict(int)
        channels = defaultdict(int)
        vendors = defaultdict(int)
        signals = []
        
        for net in self.scan_results.values():
            encryptions[net.get("encryption", "Unknown")] += 1
            channels[net.get("channel", 0)] += 1
            vendors[net.get("vendor", "Unknown")] += 1
            signals.append(net.get("signal", -100))
        
        return {
            "total": total,
            "encryption_distribution": dict(encryptions),
            "channel_distribution": dict(sorted(channels.items())),
            "top_vendors": dict(sorted(vendors.items(), 
                         key=lambda x: x[1], reverse=True)[:10]),
            "signal_range": {
                "min": min(signals) if signals else -100,
                "max": max(signals) if signals else -100,
                "avg": sum(signals) / len(signals) if signals else -100
            },
            "hidden_networks": len(self.get_hidden_networks()),
            "open_networks": len(self.get_open_networks()),
            "packets_processed": self._packet_count,
            "scan_duration": time.time() - self._start_time if self._start_time else 0
        }
    
    def export_json(self, filepath: str):
        """Export scan results to JSON file."""
        import json
        data = {
            "scan_time": datetime.now().isoformat(),
            "interface": self.interface,
            "statistics": self.get_statistics(),
            "networks": list(self.scan_results.values()),
            "clients": {mac: clients for mac, clients in self.clients.items()}
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        self.logger.info(f"Scan results exported to {filepath}")
    
    def export_csv(self, filepath: str):
        """Export scan results to CSV file."""
        import csv
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["SSID", "BSSID", "Channel", "Encryption", 
                           "Signal", "Max Signal", "Vendor", "First Seen", "Last Seen"])
            for net in self.scan_results.values():
                writer.writerow([
                    net.get("ssid", ""),
                    net.get("bssid", ""),
                    net.get("channel", ""),
                    net.get("encryption", ""),
                    net.get("signal", ""),
                    net.get("max_signal", ""),
                    net.get("vendor", ""),
                    net.get("first_seen", ""),
                    net.get("last_seen", "")
                ])
        self.logger.info(f"Scan results exported to {filepath}")
    
    def display_table(self, sort_by: str = "signal"):
        """Display scan results as formatted table."""
        networks = self.get_networks_sorted(sort_by)
        
        if not networks:
            print("\n[!] No networks found. Run scan first.\n")
            return
        
        print(f"\n{'='*90}")
        print(f"{'SSID':<25} {'BSSID':<20} {'Ch':>3} {'Enc':<7} {'Signal':>7} {'Vendor':<15}")
        print(f"{'='*90}")
        
        for net in networks:
            enc = net.get('encryption', '?')
            print(f"{net.get('ssid', '?')[:24]:<25} "
                  f"{net.get('bssid', '?'):<20} "
                  f"{net.get('channel', '?'):>3} "
                  f"{enc:<7} "
                  f"{net.get('signal', -100):>6}dBm "
                  f"{net.get('vendor', '?')[:14]:<15}")
        
        print(f"{'='*90}")
        print(f"Total: {len(networks)} networks\n")
    
    def display_statistics(self):
        """Display scan statistics."""
        stats = self.get_statistics()
        
        print(f"\n{'='*50}")
        print(f"  SCAN STATISTICS")
        print(f"{'='*50}")
        print(f"  Total Networks:    {stats.get('total', 0)}")
        print(f"  Hidden Networks:   {stats.get('hidden_networks', 0)}")
        print(f"  Open Networks:     {stats.get('open_networks', 0)}")
        print(f"  Packets Processed: {stats.get('packets_processed', 0)}")
        
        if stats.get('signal_range'):
            sig = stats['signal_range']
            print(f"\n  Signal Range:")
            print(f"    Min: {sig['min']}dBm")
            print(f"    Max: {sig['max']}dBm")
            print(f"    Avg: {sig['avg']:.1f}dBm")
        
        if stats.get('encryption_distribution'):
            print(f"\n  Encryption Distribution:")
            for enc, count in stats['encryption_distribution'].items():
                print(f"    {enc}: {count}")
        
        if stats.get('top_vendors'):
            print(f"\n  Top Vendors:")
            for vendor, count in list(stats['top_vendors'].items())[:5]:
                print(f"    {vendor}: {count}")
        
        print(f"{'='*50}\n")
    
    def stop(self):
        """Stop the scanner."""
        self.running = False
        self.logger.info("Scanner stopped")
    
    def is_running(self) -> bool:
        """Check if scanner is running."""
        return self.running
    
    def get_results(self) -> Dict:
        """Get current scan results."""
        return self.scan_results.copy()
    
    def clear_results(self):
        """Clear all scan results."""
        self.scan_results.clear()
        self.clients.clear()
        self._packet_count = 0
        self._network_count = 0
        self.logger.info("Scan results cleared")
