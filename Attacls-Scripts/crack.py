#!/usr/bin/env python3
"""
SUDOIT Cracking Engine Module
WPA/WPA2 handshake cracking with aircrack-ng and hashcat.
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


class CrackingEngine:
    """
    WPA/WPA2 Handshake Cracking Engine.
    
    Features:
        - aircrack-ng integration
        - hashcat integration
        - Wordlist management
        - Multiple attack modes
        - Progress tracking
        - Result management
        - Dictionary attack
        - Rule-based attack
    """
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger()
        self.running = False
        self._proc = None
        self._start_time = None
        self._results: List[Dict] = []
        self._default_wordlist = "/usr/share/wordlists/rockyou.txt"
    
    def crack_with_aircrack(self, capture_file: str,
                            wordlist: Optional[str] = None,
                            timeout: int = 300) -> Optional[str]:
        """
        Crack handshake using aircrack-ng.
        
        Args:
            capture_file: Path to .cap file
            wordlist: Path to wordlist
            timeout: Max cracking time in seconds
        
        Returns:
            Passphrase or None
        """
        if not os.path.isfile(capture_file):
            print(f"[✗] Capture file not found: {capture_file}")
            return None
        
        wl = wordlist or self._default_wordlist
        if not os.path.isfile(wl):
            print(f"[✗] Wordlist not found: {wl}")
            return None
        
        print(f"\n[*] Cracking with aircrack-ng...")
        print(f"    File:     {capture_file}")
        print(f"    Wordlist: {wl}")
        print(f"    Timeout:  {timeout}s\n")
        
        self.running = True
        self._start_time = time.time()
        
        cmd = ["aircrack-ng", "-w", wl, capture_file]
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            key_found = None
            start = time.time()
            
            while time.time() - start < timeout:
                if not self.running:
                    break
                
                line = self._proc.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                
                # Show progress
                if "KEY FOUND" in line:
                    # Extract key
                    parts = line.split(':')
                    if len(parts) >= 2:
                        key_found = parts[-1].strip().strip('"')
                        print(f"\n[✓] KEY FOUND: {key_found}")
                        
                        self._results.append({
                            "file": capture_file,
                            "key": key_found,
                            "method": "aircrack-ng",
                            "wordlist": wl,
                            "timestamp": datetime.now().isoformat(),
                            "duration": time.time() - self._start_time
                        })
                        break
                elif "tried" in line.lower():
                    print(f"  {line}")
            
            # Terminate
            self._proc.terminate()
            self._proc.wait(timeout=5)
            
            if key_found:
                elapsed = time.time() - self._start_time
                print(f"    Time: {elapsed:.1f}s")
                self.logger.info(f"Key cracked: {capture_file}")
                return key_found
            else:
                print(f"\n[✗] Key not found in wordlist")
                return None
                
        except FileNotFoundError:
            print(f"[✗] aircrack-ng not found! Install: apt install aircrack-ng")
            return None
        except Exception as e:
            self.logger.error(f"Cracking error: {e}")
            print(f"[✗] Error: {e}")
            return None
        finally:
            self.running = False
            self._cleanup()
    
    def crack_with_hashcat(self, capture_file: str,
                           wordlist: Optional[str] = None,
                           timeout: int = 300,
                           mode: int = 22000) -> Optional[str]:
        """
        Crack handshake using hashcat (mode 22000 for WPA/WPA2).
        
        Args:
            capture_file: Path to .cap or .22000 file
            wordlist: Path to wordlist
            timeout: Max time in seconds
            mode: Hashcat mode (22000=WPA/WPA2)
        
        Returns:
            Passphrase or None
        """
        if not os.path.isfile(capture_file):
            print(f"[✗] File not found: {capture_file}")
            return None
        
        wl = wordlist or self._default_wordlist
        if not os.path.isfile(wl):
            print(f"[✗] Wordlist not found: {wl}")
            return None
        
        print(f"\n[*] Cracking with hashcat...")
        print(f"    File:     {capture_file}")
        print(f"    Wordlist: {wl}")
        print(f"    Mode:     {mode}")
        print(f"    Timeout:  {timeout}s\n")
        
        self.running = True
        self._start_time = time.time()
        
        cmd = [
            "hashcat",
            "-m", str(mode),
            capture_file,
            wl,
            "--force",
            "--status",
            "--status-timer=5"
        ]
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            key_found = None
            start = time.time()
            
            while time.time() - start < timeout:
                if not self.running:
                    break
                
                line = self._proc.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                
                if "Cracked" in line or "Recovered" in line:
                    # Try to extract key
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            key_found = parts[-1].strip()
                            print(f"\n[✓] KEY FOUND: {key_found}")
                            break
                
                if "Status" in line or "Progress" in line:
                    print(f"  {line}")
            
            self._proc.terminate()
            self._proc.wait(timeout=5)
            
            if key_found:
                elapsed = time.time() - self._start_time
                print(f"    Time: {elapsed:.1f}s")
                
                self._results.append({
                    "file": capture_file,
                    "key": key_found,
                    "method": "hashcat",
                    "wordlist": wl,
                    "timestamp": datetime.now().isoformat(),
                    "duration": elapsed
                })
                
                self.logger.info(f"Key cracked with hashcat: {capture_file}")
                return key_found
            else:
                print(f"\n[✗] Key not found")
                return None
                
        except FileNotFoundError:
            print(f"[✗] hashcat not found! Install: apt install hashcat")
            return None
        except Exception as e:
            self.logger.error(f"Hashcat error: {e}")
            return None
        finally:
            self.running = False
            self._cleanup()
    
    def crack_auto(self, capture_file: str,
                   wordlist: Optional[str] = None,
                   timeout: int = 300) -> Optional[str]:
        """
        Auto-select best cracking method.
        Tries hashcat first, falls back to aircrack-ng.
        """
        # Try hashcat first
        result = self.crack_with_hashcat(capture_file, wordlist, timeout)
        if result:
            return result
        
        # Fallback to aircrack-ng
        print(f"\n[*] Falling back to aircrack-ng...")
        return self.crack_with_aircrack(capture_file, wordlist, timeout)
    
    def crack_multiple(self, capture_files: List[str],
                       wordlist: Optional[str] = None,
                       timeout_per_file: int = 300) -> Dict[str, Optional[str]]:
        """
        Crack multiple capture files.
        
        Returns:
            Dict mapping file -> passphrase or None
        """
        results = {}
        
        for i, cap_file in enumerate(capture_files):
            print(f"\n[*] File {i+1}/{len(capture_files)}: {cap_file}")
            key = self.crack_auto(cap_file, wordlist, timeout_per_file)
            results[cap_file] = key
        
        # Summary
        cracked = sum(1 for k in results.values() if k)
        print(f"\n[*] Summary: {cracked}/{len(capture_files)} cracked")
        
        return results
    
    def verify_key(self, capture_file: str, key: str) -> bool:
        """Verify a passphrase against a capture file."""
        # Create temp wordlist with single key
        import tempfile
        tmp_wl = tempfile.NamedTemporaryFile(mode='w', delete=False)
        tmp_wl.write(key + '\n')
        tmp_wl.close()
        
        result = self.crack_with_aircrack(capture_file, tmp_wl.name, timeout=10)
        
        os.unlink(tmp_wl.name)
        return result is not None
    
    def find_wordlists(self, search_path: str = "/usr/share/wordlists") -> List[str]:
        """Find available wordlist files."""
        wordlists = []
        
        if os.path.isdir(search_path):
            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if file.endswith(('.txt', '.lst', '.dict')):
                        filepath = os.path.join(root, file)
                        size_mb = os.path.getsize(filepath) / (1024 * 1024)
                        wordlists.append({
                            "path": filepath,
                            "name": file,
                            "size_mb": round(size_mb, 2)
                        })
        
        return sorted(wordlists, key=lambda x: x['size_mb'])
    
    def show_wordlists(self):
        """Display available wordlists."""
        wordlists = self.find_wordlists()
        
        print(f"\n[*] Available Wordlists:")
        print(f"{'='*60}")
        
        for wl in wordlists[:20]:
            print(f"  {wl['name']:<35} {wl['size_mb']:>8.1f} MB")
        
        print(f"{'='*60}")
        print(f"  Total: {len(wordlists)} wordlists")
    
    def get_results(self) -> List[Dict]:
        """Get all cracking results."""
        return self._results.copy()
    
    def export_results(self, filepath: str):
        """Export cracking results to JSON."""
        import json
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "results": self._results
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"[✓] Results exported: {filepath}")
    
    def _cleanup(self):
        """Clean up subprocess."""
        if self._proc:
            try:
                self._proc.terminate()
            except:
                pass
    
    def stop(self):
        """Stop cracking."""
        self.running = False
        self._cleanup()
        self.logger.info("Cracking stopped")
    
    def is_running(self) -> bool:
        """Check if cracking is running."""
        return self.running
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "running": self.running,
            "results_count": len(self._results),
            "elapsed": time.time() - self._start_time if self._start_time else 0
        }
