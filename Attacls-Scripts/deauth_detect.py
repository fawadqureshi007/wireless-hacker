#!/usr/bin/env python3
"""
SUDOIT Deauth Detection Module
Monitor and detect deauthentication attacks in real-time.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import defaultdict

from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, RadioTap

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class DeauthDetector:
    """
    Real-time Deauthentication Attack Detector.
    
    Monitors WiFi traffic for excessive deauth/disassociation
    frames which may indicate an ongoing attack.
    
    Features:
        - Real-time deauth detection
        - Per-BSSID tracking
        - Configurable threshold
        - Attack source identification
        - Alert callback system
        - Attack logging
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._callback: Optional[Callable] = None
        self._alerts: List[Dict] = []
        self._deauth_stats: Dict[str, Dict] = {}
        self._start_time = None
        
    def set_callback(self, callback: Callable):
        """Set callback for real-time attack alerts."""
        self._callback = callback
    
    def monitor(self, threshold: int = 10, interval: int = 5,
                duration: int = 0, auto_stop: bool = False) -> List[Dict]:
        """
        Monitor for deauth attacks.
        
        Args:
            threshold: Packets per interval to trigger alert
            interval: Time window in seconds
            duration: Total monitor time (0 = continuous)
            auto_stop: Stop after first detection
        
        Returns:
            List of detected attacks
        """
        self.logger.info(f"Deauth detection started (threshold={threshold}/{interval}s)")
        self.running = True
        self._start_time = time.time()
        self._alerts.clear()
        
        print(f"\n[*] Deauth Detection Active")
        print(f"    Threshold: {threshold} packets/{interval}s")
        print(f"    Press Ctrl+C to stop\n")
        
        deauth_counter = defaultdict(int)
        disassoc_counter = defaultdict(int)
        last_reset = time.time()
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(Dot11Deauth):
                    attacker = pkt[Dot11].addr2
                    victim = pkt[Dot11].addr1
                    bssid = pkt[Dot11].addr3 if pkt[Dot11].addr3 else attacker
                    
                    deauth_counter[attacker] += 1
                    
                    # Get reason code
                    reason = "Unknown"
                    try:
                        reason = pkt[Dot11Deauth].reason
                    except:
                        pass
                    
                    # Check threshold
                    current_time = time.time()
                    if current_time - last_reset >= interval:
                        self._check_threshold(
                            deauth_counter, "DEAUTH", threshold, interval
                        )
                        deauth_counter.clear()
                        disassoc_counter.clear()
                        last_reset = current_time
                        
                elif pkt.haslayer(Dot11Disas):
                    attacker = pkt[Dot11].addr2
                    disassoc_counter[attacker] += 1
                    
            except Exception as e:
                self.logger.debug(f"Packet handler error: {e}")
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Deauth detection error: {e}")
        finally:
            self.running = False
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        print(f"\n[*] Detection complete: {len(self._alerts)} attacks in {elapsed:.1f}s")
        
        return self._alerts
    
    def _check_threshold(self, counter: Dict, attack_type: str,
                         threshold: int, interval: int):
        """Check if any source exceeds threshold."""
        for addr, count in counter.items():
            if count >= threshold:
                alert = {
                    "type": attack_type,
                    "attacker": addr,
                    "packet_count": count,
                    "interval": interval,
                    "timestamp": datetime.now().isoformat()
                }
                
                self._alerts.append(alert)
                
                print(f"  [!] {attack_type} ATTACK DETECTED!")
                print(f"      Attacker: {addr}")
                print(f"      Packets:  {count}/{interval}s")
                print()
                
                # Log it
                if addr not in self._deauth_stats:
                    self._deauth_stats[addr] = {
                        "first_seen": datetime.now().isoformat(),
                        "total_packets": 0,
                        "attacks": 0
                    }
                self._deauth_stats[addr]["total_packets"] += count
                self._deauth_stats[addr]["attacks"] += 1
                self._deauth_stats[addr]["last_seen"] = datetime.now().isoformat()
                
                # Callback
                if self._callback:
                    self._callback(alert)
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        return {
            "total_alerts": len(self._alerts),
            "attacker_stats": dict(self._deauth_stats),
            "monitor_duration": time.time() - self._start_time if self._start_time else 0,
            "recent_alerts": self._alerts[-10:]  # Last 10 alerts
        }
    
    def get_top_attackers(self, top_n: int = 5) -> List[Dict]:
        """Get top attacking MAC addresses."""
        sorted_stats = sorted(
            self._deauth_stats.items(),
            key=lambda x: x[1]['total_packets'],
            reverse=True
        )
        
        return [
            {"mac": mac, **stats}
            for mac, stats in sorted_stats[:top_n]
        ]
    
    def export_alerts(self, filepath: str):
        """Export alerts to JSON file."""
        import json
        data = {
            "export_time": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "alerts": self._alerts,
            "attackers": self.get_top_attackers(20)
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        self.logger.info(f"Alerts exported to {filepath}")
        print(f"[✓] Alerts exported: {filepath}")
    
    def clear_alerts(self):
        """Clear all detected alerts."""
        self._alerts.clear()
        self._deauth_stats.clear()
        self.logger.info("Alerts cleared")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        self.logger.info("Deauth detection stopped")
    
    def is_running(self) -> bool:
        """Check if detector is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current detection status."""
        return {
            "running": self.running,
            "total_alerts": len(self._alerts),
            "monitoring_time": time.time() - self._start_time if self._start_time else 0
        }
