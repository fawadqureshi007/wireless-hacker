#!/usr/bin/env python3
"""Configuration management for SUDOIT framework."""

import json
import os
from typing import Dict, Any, Optional

DEFAULT_CONFIG = {
    "interface": "wlan0",
    "monitor_interface": "wlan0mon",
    "output_dir": "./output",
    "log_level": "INFO",
    "wordlist": "/usr/share/wordlists/rockyou.txt",
    "timeout": 60,
    "channel_hop_interval": 0.3,
    "deauth_count": 15,
    "wps_pixie_timeout": 120,
    "database_file": "sudoit_sessions.db",
    "web_port": 8080,
    "web_host": "127.0.0.1",
    "enable_web": False,
    "mac_randomization": False,
    "karma_enabled": False,
    "beacon_flood_threshold": 50,
    "session_auto_save": True,
    "plugin_dir": "./plugins",
    "auto_start_monitor": True,
    "cleanup_exit": True,
    "report_format": "html"
}

class ConfigManager:
    """Handle framework configuration with file and CLI override support."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = DEFAULT_CONFIG.copy()
        self.config_path = config_path or "config.json"
        
    def load_from_file(self, filepath: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        path = filepath or self.config_path
        if os.path.isfile(path):
            try:
                with open(path, 'r') as f:
                    file_config = json.load(f)
                    self.config.update(file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[!] Error loading config from {path}: {e}")
        return self.config
    
    def load_default(self) -> Dict[str, Any]:
        """Load default config, merge with file if exists."""
        self.load_from_file()
        return self.config
    
    def save_to_file(self, filepath: Optional[str] = None):
        """Save current configuration to JSON file."""
        path = filepath or self.config_path
        with open(path, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value with optional default."""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set a config value."""
        self.config[key] = value
    
    def update(self, updates: Dict[str, Any]):
        """Update multiple config values."""
        self.config.update(updates)
    
    def __getitem__(self, key: str) -> Any:
        return self.config[key]
    
    def __setitem__(self, key: str, value: Any):
        self.config[key] = value
    
    def __contains__(self, key: str) -> bool:
        return key in self.config
