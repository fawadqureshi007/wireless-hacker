#!/usr/bin/env python3
"""
Wireless-Hacker - Professional WiFi Penetration Testing Framework
Main Entry Point
Usage: sudo python3 wireless-hacker.py [options]
"""

import sys
import os
import argparse
import textwrap

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import SUDOIT
from core.config import ConfigManager

__version__ = "1.0.0"
#!/usr/bin/env python3
"""
SUDOIT - Professional WiFi Penetration Testing Framework
Main Entry Point
Usage: sudo python3 sudoit.py [options]
"""

import sys
import os
import argparse
import textwrap

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import SUDOIT
from core.config import ConfigManager

__version__ = "1.0.0"

BANNER = f"""
██╗    ██╗██╗██████╗ ███████╗██╗     ███████╗███████╗███████╗
██║    ██║██║██╔══██╗██╔════╝██║     ██╔════╝██╔════╝██╔════╝
██║ █╗ ██║██║██████╔╝█████╗  ██║     █████╗  ███████╗███████╗
██║███╗██║██║██╔══██╗██╔══╝  ██║     ██╔══╝  ╚════██║╚════██║
╚███╔███╔╝██║██║  ██║███████╗███████╗███████║███████║███████║
╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝

██████╗  █████╗ ███╗   ██╗██████╗ ███████╗███████╗███████╗
██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔════╝██╔════╝
██████╔╝███████║██╔██╗ ██║██████╔╝█████╗  ███████╗███████╗
██╔══██╗██╔══██║██║╚██╗██║██╔══██╗██╔══╝  ╚════██║╚════██║
██████╔╝██║  ██║██║ ╚████║██████╔╝███████╗███████║███████║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚══════╝╚══════╝

╔══════════════════════════════════════════════════════════╗
║           wireless-hacker v{__version__}                ║
║      Ethical Use Only | Authorized Testing Only          ║
║      Kali Linux | Python 3.8+ | Professional Grade       ║
║             Developer: h4cker_fawad                      ║
╚══════════════════════════════════════════════════════════╝
"""

HELP_TEXT = """
SUDOIT - WiFi Penetration Testing Framework

MODULES:
  scan        Scan for WiFi networks
  handshake   Capture WPA/WPA2 handshake
  pmkid       PMKID attack
  deauth      Detect deauth attacks
  pixie       WPS Pixie Dust attack
  eviltwin    Detect evil twin APs
  karma       KARMA attack (probe monitoring)
  beacon      Detect beacon flood attacks
  macspoof    Spoof MAC address
  crack       Crack captured handshake
  report      Generate assessment report
  dashboard   Start web dashboard
  session     Session management
  status      Show framework status

EXAMPLES:
  sudo python3 wireless-hacker.py scan -d 60
  sudo python3 wireless-hacker.py handshake -b AA:BB:CC:DD:EE:FF -c 6
  sudo python3 wireless-hacker.py pmkid -b AA:BB:CC:DD:EE:FF
  sudo python3 wireless-hacker.py pixie -b AA:BB:CC:DD:EE:FF -c 6
  sudo python3 wireless-hacker.py eviltwin -s "MyWiFi"
  sudo python3 wireless-hacker.py crack -f capture.cap -w wordlist.txt
  sudo python3 wireless-hacker.py report -f html
  sudo python3 wireless-hacker.py dashboard
"""

def create_parser():
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description="SUDOIT - Professional WiFi Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_TEXT
    )
    
    parser.add_argument("-i", "--interface", default="wlan0",
                       help="Wireless interface (default: wlan0)")
    parser.add_argument("-c", "--config", help="JSON config file")
    parser.add_argument("-v", "--version", action="version",
                       version=f"SUDOIT v{__version__}")
    
    subparsers = parser.add_subparsers(dest="module", help="Module to run")
    
    # SCAN
    scan_parser = subparsers.add_parser("scan", help="Scan WiFi networks")
    scan_parser.add_argument("-d", "--duration", type=int, default=60,
                            help="Scan duration in seconds")
    scan_parser.add_argument("--no-hop", action="store_true",
                            help="Disable channel hopping")
    
    # HANDSHAKE
    hs_parser = subparsers.add_parser("handshake", help="Capture WPA handshake")
    hs_parser.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    hs_parser.add_argument("-c", "--channel", type=int, required=True, help="Channel")
    hs_parser.add_argument("--no-deauth", action="store_true", help="Disable deauth")
    hs_parser.add_argument("-o", "--output", help="Output prefix")
    
    # PMKID
    pmkid_parser = subparsers.add_parser("pmkid", help="PMKID attack")
    pmkid_parser.add_argument("-b", "--bssid", help="Target BSSID")
    pmkid_parser.add_argument("-t", "--timeout", type=int, default=120,
                             help="Timeout in seconds")
    
    # DEAUTH DETECT
    deauth_parser = subparsers.add_parser("deauth", help="Detect deauth attacks")
    deauth_parser.add_argument("-t", "--threshold", type=int, default=10,
                              help="Packets per interval")
    deauth_parser.add_argument("-d", "--duration", type=int, default=60,
                              help="Monitor duration")
    
    # PIXIE DUST
    pixie_parser = subparsers.add_parser("pixie", help="WPS Pixie Dust attack")
    pixie_parser.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    pixie_parser.add_argument("-c", "--channel", type=int, required=True, help="Channel")
    pixie_parser.add_argument("-t", "--timeout", type=int, default=120,
                             help="Timeout in seconds")
    
    # EVIL TWIN
    et_parser = subparsers.add_parser("eviltwin", help="Detect evil twin APs")
    et_parser.add_argument("-s", "--ssid", required=True, help="Legitimate SSID")
    et_parser.add_argument("-b", "--bssid", help="Legitimate BSSID")
    et_parser.add_argument("-d", "--duration", type=int, default=60,
                          help="Detection duration")
    
    # KARMA
    karma_parser = subparsers.add_parser("karma", help="KARMA attack")
    karma_parser.add_argument("-d", "--duration", type=int, default=120,
                             help="Attack duration")
    
    # BEACON FLOOD
    beacon_parser = subparsers.add_parser("beacon", help="Detect beacon flood")
    beacon_parser.add_argument("-t", "--threshold", type=int, default=50,
                              help="Beacon threshold")
    beacon_parser.add_argument("-d", "--duration", type=int, default=60,
                              help="Detection duration")
    
    # MAC SPOOF
    mac_parser = subparsers.add_parser("macspoof", help="Spoof MAC address")
    mac_parser.add_argument("-m", "--mac", help="New MAC address (random if empty)")
    mac_parser.add_argument("--vendor", help="Generate MAC for vendor")
    mac_parser.add_argument("--restore", action="store_true", help="Restore original MAC")
    
    # CRACK
    crack_parser = subparsers.add_parser("crack", help="Crack handshake")
    crack_parser.add_argument("-f", "--file", required=True, help="Capture file")
    crack_parser.add_argument("-w", "--wordlist", help="Wordlist path")
    crack_parser.add_argument("--hashcat", action="store_true", help="Use hashcat")
    crack_parser.add_argument("-t", "--timeout", type=int, default=300,
                             help="Timeout in seconds")
    
    # REPORT
    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument("-f", "--format", default="html",
                              choices=["json", "html", "csv", "pdf", "all"],
                              help="Report format")
    report_parser.add_argument("-o", "--output", help="Output directory")
    
    # DASHBOARD
    dash_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dash_parser.add_argument("--host", default="127.0.0.1", help="Host")
    dash_parser.add_argument("-p", "--port", type=int, default=8080, help="Port")
    
    # SESSION
    sess_parser = subparsers.add_parser("session", help="Session management")
    sess_parser.add_argument("action", choices=["new", "close", "list"],
                            help="Session action")
    sess_parser.add_argument("-n", "--name", default="", help="Session name")
    
    # STATUS
    subparsers.add_parser("status", help="Show framework status")
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show help if no module specified
    if not args.module:
        print(BANNER)
        print(HELP_TEXT)
        return
    
    # Load config
    config_manager = ConfigManager()
    config = config_manager.load_default()
    if args.config:
        config_manager.load_from_file(args.config)
    config["interface"] = args.interface
    
    # Initialize framework
    fw = SUDOIT(config)
    fw.check_root()
    fw.check_dependencies()
    fw.start_monitor_mode()
    fw.new_session("CLI Session")
    
    try:
        # Execute module
        if args.module == "scan":
            fw.scan_networks(duration=args.duration, channel_hop=not args.no_hop)
            fw.show_scan_results()
            
        elif args.module == "handshake":
            result = fw.capture_handshake(
                target_bssid=args.bssid,
                channel=args.channel,
                output_prefix=args.output,
                deauth=not args.no_deauth
            )
            if result:
                print(f"\n[✓] Handshake saved: {result}")
            
        elif args.module == "pmkid":
            fw.pmkid_attack(target_bssid=args.bssid, timeout=args.timeout)
            
        elif args.module == "deauth":
            fw.detect_deauth(threshold=args.threshold, duration=args.duration)
            
        elif args.module == "pixie":
            fw.wps_pixie_attack(args.bssid, args.channel)
            
        elif args.module == "eviltwin":
            fw.detect_evil_twin(args.ssid, args.bssid, args.duration)
            
        elif args.module == "karma":
            fw.karma_attack(duration=args.duration)
            
        elif args.module == "beacon":
            fw.detect_beacon_flood(threshold=args.threshold)
            
        elif args.module == "macspoof":
            if args.restore:
                # MAC restore handled inside
                pass
            else:
                fw.spoof_mac(args.mac)
            
        elif args.module == "crack":
            fw.crack_handshake(
                capture_file=args.file,
                wordlist=args.wordlist,
                use_hashcat=args.hashcat
            )
            
        elif args.module == "report":
            from modules.reporter import ReportGenerator
            reporter = ReportGenerator()
            reporter.set_data({"scan_results": fw.scan_results})
            
            if args.format == "all":
                out_dir = args.output or "./reports"
                reporter.generate_all(out_dir)
            elif args.format == "json":
                reporter.generate_json(args.output or "./report.json")
            elif args.format == "html":
                reporter.generate_html(args.output or "./report.html")
            elif args.format == "csv":
                reporter.generate_csv(args.output or "./report.csv")
            elif args.format == "pdf":
                reporter.generate_pdf(args.output or "./report.pdf")
            
        elif args.module == "dashboard":
            from modules.dashboard import WebDashboard
            dashboard = WebDashboard(host=args.host, port=args.port)
            
            def data_provider():
                nets = []
                for bssid, info in fw.scan_results.items():
                    nets.append({
                        "ssid": info.get("ssid", "?"),
                        "bssid": bssid,
                        "channel": info.get("channel", "?"),
                        "encryption": info.get("encryption", "?"),
                        "signal": info.get("signal", -100),
                        "vendor": info.get("vendor", "?")
                    })
                return {
                    "total_networks": len(fw.scan_results),
                    "open_networks": sum(1 for n in fw.scan_results.values() if n.get("encryption") == "OPEN"),
                    "handshakes": 0,
                    "attacks": 0,
                    "uptime": "active",
                    "networks": nets,
                    "logs": [{"time": datetime.now().strftime("%H:%M:%S"), "type": "info", "message": "Dashboard started"}]
                }
            
            from datetime import datetime
            dashboard.set_data_provider(data_provider)
            dashboard.start()
            
        elif args.module == "session":
            if args.action == "new":
                fw.new_session(args.name)
            elif args.action == "close":
                fw.close_session()
            elif args.action == "list":
                sessions = fw.db.get_all_sessions()
                print(f"\n[*] Sessions:")
                for s in sessions:
                    print(f"    ID:{s['id']} | {s['name']} | {s['start_time']} | {s['status']}")
                    
        elif args.module == "status":
            fw.show_status()
            
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user")
    finally:
        fw.cleanup_exit()


if __name__ == "__main__":
    main()
"""

print(banner)
HELP_TEXT = """
Wireless-Hacker - WiFi Penetration Testing Framework

MODULES:
  scan        Scan for WiFi networks
  handshake   Capture WPA/WPA2 handshake
  pmkid       PMKID attack
  deauth      Detect deauth attacks
  pixie       WPS Pixie Dust attack
  eviltwin    Detect evil twin APs
  karma       KARMA attack (probe monitoring)
  beacon      Detect beacon flood attacks
  macspoof    Spoof MAC address
  crack       Crack captured handshake
  report      Generate assessment report
  dashboard   Start web dashboard
  session     Session management
  status      Show framework status

EXAMPLES:
  sudo python3 wireless-hacker.py.py scan -d 60
  sudo python3 wireless-hacker.py handshake -b AA:BB:CC:DD:EE:FF -c 6
  sudo python3 wireless-hacker.py pmkid -b AA:BB:CC:DD:EE:FF
  sudo python3 wireless-hacker.py pixie -b AA:BB:CC:DD:EE:FF -c 6
  sudo python3 wireless-hacker.py eviltwin -s "MyWiFi"
  sudo python3 wireless-hacker.py crack -f capture.cap -w wordlist.txt
  sudo python3 wireless-hacker.py report -f html
  sudo python3 wireless-hacker.py dashboard
"""

def create_parser():
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description="SUDOIT - Professional WiFi Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_TEXT
    )
    
    parser.add_argument("-i", "--interface", default="wlan0",
                       help="Wireless interface (default: wlan0)")
    parser.add_argument("-c", "--config", help="JSON config file")
    parser.add_argument("-v", "--version", action="version",
                       version=f"SUDOIT v{__version__}")
    
    subparsers = parser.add_subparsers(dest="module", help="Module to run")
    
    # SCAN
    scan_parser = subparsers.add_parser("scan", help="Scan WiFi networks")
    scan_parser.add_argument("-d", "--duration", type=int, default=60,
                            help="Scan duration in seconds")
    scan_parser.add_argument("--no-hop", action="store_true",
                            help="Disable channel hopping")
    
    # HANDSHAKE
    hs_parser = subparsers.add_parser("handshake", help="Capture WPA handshake")
    hs_parser.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    hs_parser.add_argument("-c", "--channel", type=int, required=True, help="Channel")
    hs_parser.add_argument("--no-deauth", action="store_true", help="Disable deauth")
    hs_parser.add_argument("-o", "--output", help="Output prefix")
    
    # PMKID
    pmkid_parser = subparsers.add_parser("pmkid", help="PMKID attack")
    pmkid_parser.add_argument("-b", "--bssid", help="Target BSSID")
    pmkid_parser.add_argument("-t", "--timeout", type=int, default=120,
                             help="Timeout in seconds")
    
    # DEAUTH DETECT
    deauth_parser = subparsers.add_parser("deauth", help="Detect deauth attacks")
    deauth_parser.add_argument("-t", "--threshold", type=int, default=10,
                              help="Packets per interval")
    deauth_parser.add_argument("-d", "--duration", type=int, default=60,
                              help="Monitor duration")
    
    # PIXIE DUST
    pixie_parser = subparsers.add_parser("pixie", help="WPS Pixie Dust attack")
    pixie_parser.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    pixie_parser.add_argument("-c", "--channel", type=int, required=True, help="Channel")
    pixie_parser.add_argument("-t", "--timeout", type=int, default=120,
                             help="Timeout in seconds")
    
    # EVIL TWIN
    et_parser = subparsers.add_parser("eviltwin", help="Detect evil twin APs")
    et_parser.add_argument("-s", "--ssid", required=True, help="Legitimate SSID")
    et_parser.add_argument("-b", "--bssid", help="Legitimate BSSID")
    et_parser.add_argument("-d", "--duration", type=int, default=60,
                          help="Detection duration")
    
    # KARMA
    karma_parser = subparsers.add_parser("karma", help="KARMA attack")
    karma_parser.add_argument("-d", "--duration", type=int, default=120,
                             help="Attack duration")
    
    # BEACON FLOOD
    beacon_parser = subparsers.add_parser("beacon", help="Detect beacon flood")
    beacon_parser.add_argument("-t", "--threshold", type=int, default=50,
                              help="Beacon threshold")
    beacon_parser.add_argument("-d", "--duration", type=int, default=60,
                              help="Detection duration")
    
    # MAC SPOOF
    mac_parser = subparsers.add_parser("macspoof", help="Spoof MAC address")
    mac_parser.add_argument("-m", "--mac", help="New MAC address (random if empty)")
    mac_parser.add_argument("--vendor", help="Generate MAC for vendor")
    mac_parser.add_argument("--restore", action="store_true", help="Restore original MAC")
    
    # CRACK
    crack_parser = subparsers.add_parser("crack", help="Crack handshake")
    crack_parser.add_argument("-f", "--file", required=True, help="Capture file")
    crack_parser.add_argument("-w", "--wordlist", help="Wordlist path")
    crack_parser.add_argument("--hashcat", action="store_true", help="Use hashcat")
    crack_parser.add_argument("-t", "--timeout", type=int, default=300,
                             help="Timeout in seconds")
    
    # REPORT
    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument("-f", "--format", default="html",
                              choices=["json", "html", "csv", "pdf", "all"],
                              help="Report format")
    report_parser.add_argument("-o", "--output", help="Output directory")
    
    # DASHBOARD
    dash_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dash_parser.add_argument("--host", default="127.0.0.1", help="Host")
    dash_parser.add_argument("-p", "--port", type=int, default=8080, help="Port")
    
    # SESSION
    sess_parser = subparsers.add_parser("session", help="Session management")
    sess_parser.add_argument("action", choices=["new", "close", "list"],
                            help="Session action")
    sess_parser.add_argument("-n", "--name", default="", help="Session name")
    
    # STATUS
    subparsers.add_parser("status", help="Show framework status")
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Show help if no module specified
    if not args.module:
        print(BANNER)
        print(HELP_TEXT)
        return
    
    # Load config
    config_manager = ConfigManager()
    config = config_manager.load_default()
    if args.config:
        config_manager.load_from_file(args.config)
    config["interface"] = args.interface
    
    # Initialize framework
    fw = SUDOIT(config)
    fw.check_root()
    fw.check_dependencies()
    fw.start_monitor_mode()
    fw.new_session("CLI Session")
    
    try:
        # Execute module
        if args.module == "scan":
            fw.scan_networks(duration=args.duration, channel_hop=not args.no_hop)
            fw.show_scan_results()
            
        elif args.module == "handshake":
            result = fw.capture_handshake(
                target_bssid=args.bssid,
                channel=args.channel,
                output_prefix=args.output,
                deauth=not args.no_deauth
            )
            if result:
                print(f"\n[✓] Handshake saved: {result}")
            
        elif args.module == "pmkid":
            fw.pmkid_attack(target_bssid=args.bssid, timeout=args.timeout)
            
        elif args.module == "deauth":
            fw.detect_deauth(threshold=args.threshold, duration=args.duration)
            
        elif args.module == "pixie":
            fw.wps_pixie_attack(args.bssid, args.channel)
            
        elif args.module == "eviltwin":
            fw.detect_evil_twin(args.ssid, args.bssid, args.duration)
            
        elif args.module == "karma":
            fw.karma_attack(duration=args.duration)
            
        elif args.module == "beacon":
            fw.detect_beacon_flood(threshold=args.threshold)
            
        elif args.module == "macspoof":
            if args.restore:
                # MAC restore handled inside
                pass
            else:
                fw.spoof_mac(args.mac)
            
        elif args.module == "crack":
            fw.crack_handshake(
                capture_file=args.file,
                wordlist=args.wordlist,
                use_hashcat=args.hashcat
            )
            
        elif args.module == "report":
            from modules.reporter import ReportGenerator
            reporter = ReportGenerator()
            reporter.set_data({"scan_results": fw.scan_results})
            
            if args.format == "all":
                out_dir = args.output or "./reports"
                reporter.generate_all(out_dir)
            elif args.format == "json":
                reporter.generate_json(args.output or "./report.json")
            elif args.format == "html":
                reporter.generate_html(args.output or "./report.html")
            elif args.format == "csv":
                reporter.generate_csv(args.output or "./report.csv")
            elif args.format == "pdf":
                reporter.generate_pdf(args.output or "./report.pdf")
            
        elif args.module == "dashboard":
            from modules.dashboard import WebDashboard
            dashboard = WebDashboard(host=args.host, port=args.port)
            
            def data_provider():
                nets = []
                for bssid, info in fw.scan_results.items():
                    nets.append({
                        "ssid": info.get("ssid", "?"),
                        "bssid": bssid,
                        "channel": info.get("channel", "?"),
                        "encryption": info.get("encryption", "?"),
                        "signal": info.get("signal", -100),
                        "vendor": info.get("vendor", "?")
                    })
                return {
                    "total_networks": len(fw.scan_results),
                    "open_networks": sum(1 for n in fw.scan_results.values() if n.get("encryption") == "OPEN"),
                    "handshakes": 0,
                    "attacks": 0,
                    "uptime": "active",
                    "networks": nets,
                    "logs": [{"time": datetime.now().strftime("%H:%M:%S"), "type": "info", "message": "Dashboard started"}]
                }
            
            from datetime import datetime
            dashboard.set_data_provider(data_provider)
            dashboard.start()
            
        elif args.module == "session":
            if args.action == "new":
                fw.new_session(args.name)
            elif args.action == "close":
                fw.close_session()
            elif args.action == "list":
                sessions = fw.db.get_all_sessions()
                print(f"\n[*] Sessions:")
                for s in sessions:
                    print(f"    ID:{s['id']} | {s['name']} | {s['start_time']} | {s['status']}")
                    
        elif args.module == "status":
            fw.show_status()
            
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user")
    finally:
        fw.cleanup_exit()


if __name__ == "__main__":
    main()
