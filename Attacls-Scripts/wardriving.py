#!/usr/bin/env python3
"""
SUDOIT Wardriving Module
GPS-enabled WiFi surveying and mapping.
"""

import os
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import threading

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)

try:
    import gps
    GPS_AVAILABLE = True
except ImportError:
    GPS_AVAILABLE = False


class Wardriving:
    """
    Wardriving Module with GPS Support.
    
    Features:
        - GPS coordinate logging
        - Network discovery with location
        - KML/GPX export for Google Earth
        - CSV export for WiGLE.net
        - Real-time position tracking
        - Signal heatmap data
        - WarKML generation
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.running = False
        self._networks: List[Dict] = []
        self._gps_data: Dict = {"lat": 0.0, "lon": 0.0, "alt": 0.0, "speed": 0.0}
        self._gps_available = False
        self._start_time = None
        self._scan_thread = None
        self._gps_thread = None
    
    def start(self, duration: int = 0, gps_device: str = "/dev/ttyUSB0",
              export_kml: bool = True, export_wigle: bool = True,
              output_dir: Optional[str] = None):
        """
        Start wardriving session.
        
        Args:
            duration: Session duration (0 = continuous)
            gps_device: GPS device path
            export_kml: Generate KML file
            export_wigle: Generate WiGLE CSV
            output_dir: Output directory
        """
        self.running = True
        self._start_time = time.time()
        self._networks.clear()
        
        if not output_dir:
            output_dir = f"/tmp/sudoit_wardrive_{datetime.now():%Y%m%d_%H%M%S}"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[*] Wardriving Session Started")
        print(f"    GPS Device:  {gps_device}")
        print(f"    Export KML:  {'Yes' if export_kml else 'No'}")
        print(f"    Export WiGLE:{'Yes' if export_wigle else 'No'}")
        print(f"    Output:      {self.output_dir}")
        print()
        
        # Initialize GPS
        if GPS_AVAILABLE:
            try:
                self._gps_thread = threading.Thread(
                    target=self._gps_tracker,
                    args=(gps_device,),
                    daemon=True
                )
                self._gps_thread.start()
                self._gps_available = True
                print("[✓] GPS tracking active")
            except Exception as e:
                print(f"[!] GPS not available: {e}")
                print("[*] Wardriving without GPS (signal only)")
        else:
            print("[!] GPS module not installed (pip install gps)")
            print("[*] Wardriving without GPS (signal only)")
        
        # Start scanning
        from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
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
                            if elt.ID == 3:
                                channel = ord(elt.info)
                                break
                            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
                    except:
                        pass
                    
                    # Signal
                    signal_strength = -100
                    if pkt.haslayer(RadioTap):
                        signal_strength = pkt[RadioTap].dBm_AntSignal
                    
                    # Check if already seen
                    existing = [n for n in self._networks if n['bssid'] == bssid]
                    
                    if not existing:
                        network = {
                            "bssid": bssid,
                            "ssid": ssid,
                            "channel": channel or 0,
                            "signal": signal_strength,
                            "max_signal": signal_strength,
                            "lat": self._gps_data["lat"],
                            "lon": self._gps_data["lon"],
                            "alt": self._gps_data["alt"],
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat()
                        }
                        self._networks.append(network)
                        print(f"  [{len(self._networks)}] {ssid:<20} {bssid}  "
                              f"{signal_strength:>4}dBm  "
                              f"({self._gps_data['lat']:.4f}, {self._gps_data['lon']:.4f})")
                    else:
                        existing[0]['last_seen'] = datetime.now().isoformat()
                        existing[0]['lat'] = self._gps_data['lat']
                        existing[0]['lon'] = self._gps_data['lon']
                        if signal_strength > existing[0]['max_signal']:
                            existing[0]['max_signal'] = signal_strength
                            
            except Exception as e:
                self.logger.debug(f"Packet error: {e}")
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
        finally:
            self.running = False
        
        # Generate exports
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        print(f"\n[*] Wardriving Complete")
        print(f"    Networks: {len(self._networks)}")
        print(f"    Duration: {elapsed:.1f}s")
        
        if export_kml:
            self._export_kml()
        if export_wigle:
            self._export_wigle()
        self._export_json()
    
    def _gps_tracker(self, device: str):
        """GPS tracking thread."""
        try:
            session = gps.gps(mode=gps.WATCH_ENABLE)
            
            while self.running:
                try:
                    report = session.next()
                    
                    if report['class'] == 'TPV':
                        if hasattr(report, 'lat'):
                            self._gps_data['lat'] = report.lat
                        if hasattr(report, 'lon'):
                            self._gps_data['lon'] = report.lon
                        if hasattr(report, 'alt'):
                            self._gps_data['alt'] = report.alt
                        if hasattr(report, 'speed'):
                            self._gps_data['speed'] = report.speed
                except StopIteration:
                    pass
                except Exception:
                    time.sleep(0.5)
        except Exception as e:
            self.logger.error(f"GPS error: {e}")
    
    def get_position(self) -> Dict:
        """Get current GPS position."""
        return self._gps_data.copy()
    
    def get_networks(self) -> List[Dict]:
        """Get all discovered networks."""
        return self._networks.copy()
    
    def get_statistics(self) -> Dict:
        """Get wardriving statistics."""
        if not self._networks:
            return {"total": 0}
        
        signals = [n['signal'] for n in self._networks]
        encrypted = sum(1 for n in self._networks if n.get('encryption', '') != 'OPEN')
        open_nets = len(self._networks) - encrypted
        
        return {
            "total": len(self._networks),
            "encrypted": encrypted,
            "open": open_nets,
            "avg_signal": sum(signals) / len(signals),
            "max_signal": max(signals),
            "min_signal": min(signals),
            "gps_points": len(set(f"{n['lat']},{n['lon']}" for n in self._networks if n['lat']))
        }
    
    def _export_kml(self):
        """Generate KML file for Google Earth."""
        kml_path = self.output_dir / f"wardrive_{datetime.now():%Y%m%d_%H%M%S}.kml"
        
        placemarks = ""
        for net in self._networks:
            if net['lat'] == 0.0 and net['lon'] == 0.0:
                continue
            
            placemarks += f"""
        <Placemark>
            <name>{net['ssid']}</name>
            <description>
                BSSID: {net['bssid']}
                Signal: {net['signal']} dBm
                Channel: {net['channel']}
                First Seen: {net['first_seen']}
            </description>
            <Point>
                <coordinates>{net['lon']},{net['lat']},{net['alt']}</coordinates>
            </Point>
        </Placemark>"""
        
        kml = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>SUDOIT Wardrive {datetime.now():%Y-%m-%d %H:%M}</name>
    <description>WiFi Networks discovered during wardriving</description>
    {placemarks}
  </Document>
</kml>"""
        
        kml_path.write_text(kml)
        print(f"[✓] KML exported: {kml_path}")
    
    def _export_wigle(self):
        """Generate WiGLE.net compatible CSV."""
        csv_path = self.output_dir / f"wigle_{datetime.now():%Y%m%d_%H%M%S}.csv"
        
        # WiGLE CSV header
        lines = ["WigleWifi-1.4,appRelease=SUDOIT,model=KaliLinux,release=1.0.0,device=PC,display=Laptop,board=PC,brand=Generic"]
        lines.append("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type")
        
        for net in self._networks:
            # Convert timestamp to WiGLE format
            try:
                dt = datetime.fromisoformat(net['first_seen'])
                first_seen = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                first_seen = net['first_seen']
            
            line = f"{net['bssid']},{net['ssid']},[WPA2],{first_seen},{net['channel']},{net['signal']},{net['lat']},{net['lon']},{net['alt']},10,WIFI"
            lines.append(line)
        
        csv_path.write_text('\n'.join(lines))
        print(f"[✓] WiGLE CSV exported: {csv_path}")
    
    def _export_json(self):
        """Export all data to JSON."""
        json_path = self.output_dir / f"wardrive_{datetime.now():%Y%m%d_%H%M%S}.json"
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "networks": self._networks,
            "gps_track": self._gps_data
        }
        
        json_path.write_text(json.dumps(data, indent=4))
        print(f"[✓] JSON exported: {json_path}")
    
    def stop(self):
        """Stop wardriving session."""
        self.running = False
        self.logger.info("Wardriving stopped")
    
    def is_running(self) -> bool:
        """Check if session is active."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current wardriving status."""
        return {
            "running": self.running,
            "networks_found": len(self._networks),
            "gps_available": self._gps_available,
            "position": self._gps_data,
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
