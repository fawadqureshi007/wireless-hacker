#!/usr/bin/env python3
"""Database manager for SUDOIT framework - SQLite session persistence."""

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

class DatabaseManager:
    """Handle session persistence, scan results, and attack logging."""
    
    def __init__(self, db_path: str = "sudoit_sessions.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()
    
    def _init_tables(self):
        """Create all required tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT DEFAULT '',
                start_time TEXT NOT NULL,
                end_time TEXT,
                description TEXT DEFAULT '',
                status TEXT DEFAULT 'active'
            );
            
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                bssid TEXT NOT NULL,
                ssid TEXT DEFAULT '<Hidden>',
                channel INTEGER DEFAULT 0,
                encryption TEXT DEFAULT 'Unknown',
                signal INTEGER DEFAULT -100,
                vendor TEXT DEFAULT 'Unknown',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_target INTEGER DEFAULT 0,
                notes TEXT DEFAULT '',
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER NOT NULL,
                mac TEXT NOT NULL,
                vendor TEXT DEFAULT 'Unknown',
                signal INTEGER DEFAULT -100,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER NOT NULL,
                capture_file TEXT NOT NULL,
                captured_time TEXT NOT NULL,
                cracked INTEGER DEFAULT 0,
                passphrase TEXT DEFAULT '',
                FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                network_id INTEGER,
                attack_type TEXT NOT NULL,
                target_bssid TEXT DEFAULT '',
                status TEXT DEFAULT 'started',
                start_time TEXT NOT NULL,
                end_time TEXT,
                result TEXT DEFAULT '',
                output_file TEXT DEFAULT '',
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS plugins_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_name TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT DEFAULT ''
            );
        """)
        self.conn.commit()
    
    # ==================== SESSION METHODS ====================
    def create_session(self, name: str = "", description: str = "") -> int:
        """Create a new session and return its ID."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO sessions (name, start_time, description) VALUES (?, ?, ?)",
            (name, now, description)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def close_session(self, session_id: int):
        """Mark a session as completed."""
        now = datetime.now().isoformat()
        self.conn.execute(
            "UPDATE sessions SET end_time = ?, status = 'completed' WHERE id = ?",
            (now, session_id)
        )
        self.conn.commit()
    
    def get_session(self, session_id: int) -> Optional[Dict]:
        """Get session info by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_sessions(self) -> List[Dict]:
        """Get all sessions ordered by start time."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions ORDER BY start_time DESC")
        return [dict(row) for row in cursor.fetchall()]
    
    def get_active_session(self) -> Optional[Dict]:
        """Get the currently active session."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE status = 'active' ORDER BY start_time DESC LIMIT 1")
        row = cursor.fetchone()
        return dict(row) if row else None
    
    # ==================== NETWORK METHODS ====================
    def add_network(self, session_id: int, bssid: str, ssid: str = "<Hidden>",
                    channel: int = 0, encryption: str = "Unknown",
                    signal: int = -100, vendor: str = "Unknown") -> int:
        """Add a discovered network and return its ID."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO networks (session_id, bssid, ssid, channel, encryption, signal, vendor, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, bssid, ssid, channel, encryption, signal, vendor, now, now))
        self.conn.commit()
        return cursor.lastrowid
    
    def update_network_signal(self, bssid: str, signal: int):
        """Update the last seen time and signal strength of a network."""
        now = datetime.now().isoformat()
        self.conn.execute(
            "UPDATE networks SET signal = ?, last_seen = ? WHERE bssid = ?",
            (signal, now, bssid)
        )
        self.conn.commit()
    
    def get_network_by_bssid(self, bssid: str) -> Optional[Dict]:
        """Get network info by BSSID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM networks WHERE bssid = ?", (bssid,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_network_id_by_bssid(self, bssid: str) -> Optional[int]:
        """Get network database ID by BSSID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM networks WHERE bssid = ?", (bssid,))
        row = cursor.fetchone()
        return row["id"] if row else None
    
    def get_session_networks(self, session_id: int) -> List[Dict]:
        """Get all networks discovered in a session."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM networks WHERE session_id = ? ORDER BY signal DESC", (session_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    def get_targets(self, session_id: int) -> List[Dict]:
        """Get networks marked as targets."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM networks WHERE session_id = ? AND is_target = 1", (session_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    def mark_as_target(self, bssid: str, target: bool = True):
        """Mark or unmark a network as a target."""
        self.conn.execute(
            "UPDATE networks SET is_target = ? WHERE bssid = ?",
            (1 if target else 0, bssid)
        )
        self.conn.commit()
    
    def add_note(self, bssid: str, note: str):
        """Add a note to a network."""
        self.conn.execute(
            "UPDATE networks SET notes = ? WHERE bssid = ?",
            (note, bssid)
        )
        self.conn.commit()
    
    def get_network_count(self, session_id: int) -> int:
        """Get total number of networks in a session."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM networks WHERE session_id = ?", (session_id,))
        return cursor.fetchone()["count"]
    
    # ==================== CLIENT METHODS ====================
    def add_client(self, network_id: int, mac: str, vendor: str = "Unknown",
                   signal: int = -100) -> int:
        """Add a connected client and return its ID."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO clients (network_id, mac, vendor, signal, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (network_id, mac, vendor, signal, now, now))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_network_clients(self, network_id: int) -> List[Dict]:
        """Get all clients connected to a network."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM clients WHERE network_id = ?", (network_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== HANDSHAKE METHODS ====================
    def add_handshake(self, network_id: int, capture_file: str) -> int:
        """Record a captured handshake."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO handshakes (network_id, capture_file, captured_time) VALUES (?, ?, ?)",
            (network_id, capture_file, now)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def mark_cracked(self, handshake_id: int, passphrase: str):
        """Mark a handshake as cracked with the passphrase."""
        self.conn.execute(
            "UPDATE handshakes SET cracked = 1, passphrase = ? WHERE id = ?",
            (passphrase, handshake_id)
        )
        self.conn.commit()
    
    def get_handshakes(self, session_id: int) -> List[Dict]:
        """Get all handshakes for a session."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT h.*, n.ssid, n.bssid 
            FROM handshakes h 
            JOIN networks n ON h.network_id = n.id 
            WHERE n.session_id = ?
        """, (session_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== ATTACK METHODS ====================
    def start_attack(self, session_id: int, attack_type: str, 
                     target_bssid: str = "", network_id: int = None) -> int:
        """Log the start of an attack and return attack ID."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO attacks (session_id, network_id, attack_type, target_bssid, start_time) VALUES (?, ?, ?, ?, ?)",
            (session_id, network_id, attack_type, target_bssid, now)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def end_attack(self, attack_id: int, status: str = "completed", result: str = ""):
        """Log the end of an attack with result."""
        now = datetime.now().isoformat()
        self.conn.execute(
            "UPDATE attacks SET status = ?, end_time = ?, result = ? WHERE id = ?",
            (status, now, result, attack_id)
        )
        self.conn.commit()
    
    def get_attack_history(self, session_id: int) -> List[Dict]:
        """Get all attacks performed in a session."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM attacks WHERE session_id = ? ORDER BY start_time DESC", (session_id,))
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== PLUGIN METHODS ====================
    def log_plugin(self, plugin_name: str, action: str, data: str = ""):
        """Log a plugin action."""
        now = datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO plugins_log (plugin_name, action, timestamp, data) VALUES (?, ?, ?, ?)",
            (plugin_name, action, now, data)
        )
        self.conn.commit()
    
    # ==================== UTILITY METHODS ====================
    def get_statistics(self, session_id: int) -> Dict:
        """Get summary statistics for a session."""
        cursor = self.conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM networks WHERE session_id = ?", (session_id,))
        total_networks = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM handshakes h JOIN networks n ON h.network_id = n.id WHERE n.session_id = ?", (session_id,))
        total_handshakes = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM handshakes h JOIN networks n ON h.network_id = n.id WHERE n.session_id = ? AND h.cracked = 1", (session_id,))
        cracked = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM attacks WHERE session_id = ?", (session_id,))
        total_attacks = cursor.fetchone()["count"]
        
        return {
            "total_networks": total_networks,
            "total_handshakes": total_handshakes,
            "cracked_handshakes": cracked,
            "total_attacks": total_attacks
        }
    
    def cleanup_old_sessions(self, days: int = 30):
        """Delete sessions older than specified days."""
        cursor = self.conn.cursor()
        cutoff = datetime.now().isoformat()
        cursor.execute("DELETE FROM sessions WHERE start_time < date('now', ?)", (f'-{days} days',))
        self.conn.commit()
        return cursor.rowcount
    
    def export_session_json(self, session_id: int, filepath: str):
        """Export session data to JSON file."""
        import json
        data = {
            "session": self.get_session(session_id),
            "networks": self.get_session_networks(session_id),
            "handshakes": self.get_handshakes(session_id),
            "attacks": self.get_attack_history(session_id),
            "statistics": self.get_statistics(session_id)
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
