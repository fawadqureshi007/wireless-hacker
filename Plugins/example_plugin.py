#!/usr/bin/env python3
"""
SUDOIT Example Plugin
Template for creating custom plugins.

To create your own plugin:
1. Copy this file
2. Rename to your_plugin.py
3. Modify the Plugin class
4. Place in plugins/ directory
5. Restart SUDOIT

Your plugin will be auto-loaded on startup!
"""

from datetime import datetime
from typing import Dict, Any, Optional


class Plugin:
    """
    Example SUDOIT Plugin.
    
    All plugins must have:
    - name: Unique plugin name
    - version: Plugin version
    - author: Your name
    - description: What the plugin does
    - run(): Main plugin method
    """
    
    # Plugin metadata (REQUIRED)
    name = "Example Plugin"
    version = "1.0.0"
    author = "Your Name"
    description = "An example plugin for SUDOIT Framework"
    
    def __init__(self):
        self.results = []
        self.running = False
        self._start_time = None
    
    def run(self, framework: Any, **kwargs) -> Dict[str, Any]:
        """
        Main plugin method.
        
        Args:
            framework: SUDOIT framework instance (access all modules)
            **kwargs: Additional arguments
        
        Returns:
            Dict with results
        """
        self.running = True
        self._start_time = datetime.now()
        
        print(f"\n[*] Running {self.name} v{self.version}")
        print(f"    Author: {self.author}")
        print(f"    {self.description}")
        
        # Access framework features
        # Example: Run a quick scan
        if hasattr(framework, 'scan_networks'):
            print(f"[*] Running quick scan via framework...")
            results = framework.scan_networks(duration=10)
            
            # Process results
            for bssid, info in results.items():
                self.results.append({
                    "bssid": bssid,
                    "ssid": info.get("ssid", "?"),
                    "encryption": info.get("encryption", "?"),
                    "signal": info.get("signal", -100),
                    "timestamp": datetime.now().isoformat()
                })
        
        # Your custom logic here
        self._custom_logic(framework, **kwargs)
        
        self.running = False
        
        return {
            "plugin": self.name,
            "version": self.version,
            "results": self.results,
            "status": "completed"
        }
    
    def _custom_logic(self, framework: Any, **kwargs):
        """Your custom plugin logic goes here."""
        
        # Example: Log networks to a file
        import os
        log_dir = getattr(framework, 'output_dir', './output')
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"plugin_{self.name.lower().replace(' ', '_')}.log")
        
        with open(log_file, 'a') as f:
            f.write(f"\n[{datetime.now().isoformat()}] Plugin executed\n")
            for result in self.results:
                f.write(f"  {result['bssid']} - {result['ssid']}\n")
        
        print(f"[✓] Results logged to: {log_file}")
    
    def get_info(self) -> Dict[str, str]:
        """Return plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description
        }
    
    def stop(self):
        """Stop plugin execution."""
        self.running = False
        print(f"[*] {self.name} stopped")
    
    def is_running(self) -> bool:
        """Check if plugin is running."""
        return self.running


# ==================== PLUGIN REGISTRATION ====================
# This function is called by SUDOIT when loading plugins

def register(plugin_manager):
    """
    Register this plugin with SUDOIT framework.
    
    Args:
        plugin_manager: SUDOIT PluginManager instance
    """
    plugin_manager.register(Plugin())
    print(f"[✓] Plugin loaded: {Plugin.name} v{Plugin.version}")
