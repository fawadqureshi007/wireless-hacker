#!/bin/bash
# Wireless-Hacker Framework Installer
# Created by: h4cker_fawad

echo "========================================="
echo "  Wireless Hacker  Installer v1.0"
echo "  WiFi Penetration Testing Framework"
echo "========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root: sudo bash install.sh"
    exit 1
fi

echo "[*] Updating package list..."
apt update -y

echo "[*] Installing system dependencies..."
apt install -y \
    aircrack-ng \
    reaver \
    hcxtools \
    hashcat \
    hostapd \
    dnsmasq \
    iptables \
    xterm \
    tmux \
    macchanger \
    python3 \
    python3-pip

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages

echo "[*] Creating symlink..."
chmod +x sudoit.py
ln -sf $(pwd)/sudoit.py /usr/local/bin/sudoit 2>/dev/null

echo ""
echo "[✓] Installation complete!"
echo "    Run: sudo sudoit"
echo "    Or:  sudo python3 sudoit.py"
echo ""
