#!/usr/bin/env python3
"""
SUDOIT Evil Twin Detection Module
Detect rogue access points spoofing legitimate networks.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import defaultdict

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class EvilTwinDetector:
    """
    Evil Twin / Rogue AP Detector.
    
    Monitors WiFi traffic to identify multiple access points
    claiming the same SSID, which may indicate an evil twin attack.
    
    Features:
        - SSID monitoring
        - BSSID whitelist
        - Signal anomaly detection
        - Channel mismatch detection
        - OUI/vendor verification
        - Real-time alerts
        - Historical tracking
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._callback: Optional[Callable] = None
        self._alerts: List[Dict] = []
        self._ssid_map: Dict[str, List[Dict]] = defaultdict(list)
        self._whitelist: Dict[str, str] = {}  # SSID -> legitimate BSSID
        self._start_time = None
    
    def set_callback(self, callback: Callable):
        """Set callback for real-time alerts."""
        self._callback = callback
    
    def add_whitelist(self, ssid: str, bssid: str):
        """Add a known legitimate AP to whitelist."""
        self._whitelist[ssid.lower()] = bssid.lower()
        print(f"[*] Whitelisted: {ssid} -> {bssid}")
    
    def remove_whitelist(self, ssid: str):
        """Remove SSID from whitelist."""
        if ssid.lower() in self._whitelist:
            del self._whitelist[ssid.lower()]
    
    def detect(self, target_ssid: Optional[str] = None,
               target_bssid: Optional[str] = None,
               duration: int = 60,
               check_signal: bool = True,
               check_channel: bool = True,
               check_vendor: bool = True) -> List[Dict]:
        """
        Detect evil twin / rogue APs.
        
        Args:
            target_ssid: SSID to monitor (None = all)
            target_bssid: Expected legitimate BSSID
            duration: Monitoring duration in seconds
            check_signal: Check for signal anomalies
            check_channel: Check for channel mismatches
            check_vendor: Check vendor/OUI consistency
        
        Returns:
            List of detected rogue APs
        """
        self.logger.info(f"Evil twin detection started for '{target_ssid or 'ALL'}'")
        self.running = True
        self._start_time = time.time()
        self._alerts.clear()
        self._ssid_map.clear()
        
        # Auto-whitelist target
        if target_ssid and target_bssid:
            self.add_whitelist(target_ssid, target_bssid)
        
        print(f"\n[*] Evil Twin Detection Active")
        print(f"    Target SSID: {target_ssid or 'ALL'}")
        if target_bssid:
            print(f"    Legitimate:  {target_bssid}")
        print(f"    Duration:    {duration}s")
        print(f"    Press Ctrl+C to stop\n")
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    bssid = pkt[Dot11].addr2
                    if not bssid:
                        return
                    
                    # Extract SSID
                    ssid = ""
                    if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info:
                        try:
                            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                        except:
                            pass
                    
                    if not ssid:
                        return
                    
                    # Filter by target SSID
                    if target_ssid and ssid != target_ssid:
                        return
                    
                    # Extract channel
                    channel = None
                    try:
                        elt = pkt.getlayer(Dot11Elt)
                        while elt:
                            if elt.ID == 3:
                                channel = ord(elt.info)
                                break
                            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
                    except:
                        pass
                    
                    # Signal
                    signal = -100
                    if pkt.haslayer(RadioTap):
                        signal = pkt[RadioTap].dBm_AntSignal
                    
                    # Record this AP
                    ap_info = {
                        "bssid": bssid,
                        "ssid": ssid,
                        "channel": channel,
                        "signal": signal,
                        "last_seen": datetime.now().isoformat()
                    }
                    
                    key = ssid.lower()
                    existing = [ap for ap in self._ssid_map[key] if ap['bssid'].lower() == bssid.lower()]
                    
                    if not existing:
                        self._ssid_map[key].append(ap_info)
                        
                        # Check if this is rogue
                        is_rogue, reason = self._check_rogue(
                            ssid, bssid, channel, signal,
                            check_signal, check_channel, check_vendor
                        )
                        
                        if is_rogue:
                            alert = {
                                "type": "EVIL_TWIN",
                                "ssid": ssid,
                                "bssid": bssid,
                                "channel": channel,
                                "signal": signal,
                                "reason": reason,
                                "timestamp": datetime.now().isoformat()
                            }
                            
                            self._alerts.append(alert)
                            
                            print(f"  [!] EVIL TWIN DETECTED!")
                            print(f"      SSID:    {ssid}")
                            print(f"      BSSID:   {bssid}")
                            print(f"      Channel: {channel}")
                            print(f"      Signal:  {signal}dBm")
                            print(f"      Reason:  {reason}")
                            print()
                            
                            if self._callback:
                                self._callback(alert)
                    else:
                        existing[0].update(ap_info)
                        
            except Exception as e:
                self.logger.debug(f"Packet handler error: {e}")
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0,
                timeout=duration
            )
        except Exception as e:
            self.logger.error(f"Detection error: {e}")
        finally:
            self.running = False
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        print(f"\n[*] Detection complete: {len(self._alerts)} rogue APs in {elapsed:.1f}s")
        
        return self._alerts
    
    def _check_rogue(self, ssid: str, bssid: str, channel: Optional[int],
                     signal: int, check_signal: bool, check_channel: bool,
                     check_vendor: bool) -> Tuple[bool, str]:
        """Check if an AP is potentially rogue."""
        key = ssid.lower()
        reasons = []
        
        # Check whitelist
        if key in self._whitelist:
            if bssid.lower() != self._whitelist[key]:
                reasons.append("BSSID mismatch (not whitelisted)")
        
        # Multiple APs with same SSID
        known_bssids = [ap['bssid'].lower() for ap in self._ssid_map[key]]
        if len(known_bssids) > 1:
            reasons.append(f"Multiple APs ({len(known_bssids)}) for SSID")
        
        # Signal anomaly
        if check_signal and len(self._ssid_map[key]) > 1:
            avg_signal = sum(ap.get('signal', -100) for ap in self._ssid_map[key]) / len(self._ssid_map[key])
            if abs(signal - avg_signal) > 20:
                reasons.append(f"Signal anomaly ({signal}dBm vs avg {avg_signal:.0f}dBm)")
        
        # Channel mismatch
        if check_channel and len(self._ssid_map[key]) > 1:
            channels = [ap.get('channel') for ap in self._ssid_map[key] if ap.get('channel')]
            if channels and channel and channel not in channels:
                reasons.append(f"Channel mismatch ({channel} vs {channels})")
        
        # Vendor check
        if check_vendor:
            vendor = self._get_vendor(bssid)
            if vendor == "Unknown":
                reasons.append("Unknown vendor/OUI")
        
        return len(reasons) > 0, "; ".join(reasons) if reasons else ""
    
    def _get_vendor(self, mac: str) -> str:
        """Quick OUI vendor lookup."""
        OUI = {
            "FCA621": "Apple", "B827EB": "Raspberry Pi",
            "DC9FDB": "Ubiquiti", "080030": "NETGEAR",
            "001D7E": "TP-Link", "00A0C5": "D-Link",
            "ACF1DF": "Google", "E8DE27": "Microsoft"
        }
        oui = mac.replace(":", "").upper()[:6]
        return OUI.get(oui, "Unknown")
    
    def get_detected_aps(self, ssid: Optional[str] = None) -> Dict:
        """Get all detected APs, optionally filtered by SSID."""
        if ssid:
            key = ssid.lower()
            return {key: self._ssid_map.get(key, [])}
        return dict(self._ssid_map)
    
    def get_alerts(self) -> List[Dict]:
        """Get all generated alerts."""
        return self._alerts.copy()
    
    def export_report(self, filepath: str):
        """Export detection report to JSON."""
        import json
        report = {
            "timestamp": datetime.now().isoformat(),
            "duration": time.time() - self._start_time if self._start_time else 0,
            "monitored_ssids": list(self._ssid_map.keys()),
            "total_rogue_aps": len(self._alerts),
            "alerts": self._alerts,
            "all_aps": {k: v for k, v in self._ssid_map.items()}
        }
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[✓] Report exported: {filepath}")
        self.logger.info(f"Report exported: {filepath}")
    
    def clear_alerts(self):
        """Clear all alerts and AP data."""
        self._alerts.clear()
        self._ssid_map.clear()
        self.logger.info("Alerts cleared")
    
    def stop(self):
        """Stop detection."""
        self.running = False
        self.logger.info("Evil twin detection stopped")
    
    def is_running(self) -> bool:
        """Check if detector is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "running": self.running,
            "total_alerts": len(self._alerts),
            "monitored_ssids": len(self._ssid_map),
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
