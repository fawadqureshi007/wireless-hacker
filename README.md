# ⚡ wireless-hacker

### Professional Wireless Security Assessment Framework

> **"With great power comes great responsibility."**

A modular wireless security assessment framework designed for **authorized Wi-Fi security testing**, **wireless assessments**, and **security research**.

---

# 👨‍💻 Developer

**Developed by:** **h4cker_fawad**

Wireless Security Researcher • Red Team Enthusiast • Offensive Security

---

# ⚠️ Disclaimer

> **This project is intended exclusively for educational purposes and authorized security assessments.**

Using this framework against networks or systems without explicit permission may violate applicable laws and regulations.

By using this software, you agree that you are solely responsible for your actions. The developer assumes no liability for misuse or damages resulting from unauthorized or illegal use.

Always obtain written authorization before conducting any security assessment.

---

# ✨ Highlights

* Professional command-line interface
* Modular architecture
* Session management
* SQLite database support
* Real-time dashboard
* Automated reporting
* Plugin-ready design
* Built for Kali Linux
* Python 3.8+

---

# 🔥 Features

* 📡 Advanced Wi-Fi Network Discovery
* 📶 2.4GHz & 5GHz Support
* 🛰 OUI Vendor Fingerprinting
* 🤝 WPA/WPA2 Handshake Capture
* 🔐 PMKID Capture
* 📍 WPS Security Assessment
* 🚨 Deauthentication Detection
* 👥 Evil Twin Detection
* 📡 Probe Request Monitoring
* 📢 Beacon Flood Detection
* 🎭 MAC Address Randomization
* 📊 HTML / JSON / CSV / PDF Reports
* 🌐 Live Web Dashboard
* 🔌 Plugin Framework
* 💾 Session Persistence

---

# 📦 Installation

```bash
git clone https://github.com/h4cker_fawad/wireless-hacker.git

cd wireless-hacker

sudo bash install.sh
```

---

# 🚀 Usage

```bash
sudo python3 wireless-hacker.py
```

### Scan Networks

```bash
sudo python3 wireless-hacker.py scan -d 60
```

### Capture a Handshake

```bash
sudo python3 wireless-hacker.py handshake -b AA:BB:CC:DD:EE:FF -c 6
```

### PMKID

```bash
sudo python3 wireless-hacker.py pmkid -b AA:BB:CC:DD:EE:FF
```

### Generate Reports

```bash
sudo python3 wireless-hacker.py report -f html
```

### Launch Dashboard

```bash
sudo python3 wireless-hacker.py dashboard
```

---

# 🛠 Requirements

* Kali Linux (Recommended)
* Python 3.8+
* aircrack-ng
* hcxdumptool
* hcxtools
* tshark
* Flask
* SQLite3
* hashcat (Optional)

---

# 📁 Project Structure

```
wireless-hacker/
├── core/
├── modules/
├── plugins/
├── reports/
├── sessions/
├── logs/
├── config/
└── wireless-hacker.py
```

---

# 🎯 Intended Audience

* Security Researchers
* Red Team Operators
* Penetration Testers
* Blue Team Professionals
* Students Learning Wireless Security

---

# 🤝 Contributing

Contributions, bug reports, feature requests, and security improvements are welcome.

Please open an issue or submit a pull request.

---

# 📄 License

This project is released for educational use and authorized security assessments.

Users are responsible for ensuring compliance with applicable laws and regulations.

---

# ⭐ Support

If this project helps you, consider giving it a ⭐ on GitHub.

---

## Developed by

# **h4cker_fawad**

**wireless-hacker v1.0.0**

Professional Wireless Security Assessment Framework
