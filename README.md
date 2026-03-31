# IoT Attack Surface Scanner

**Discover and fingerprint IoT devices on your local network in minutes.**

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)

---

## ⚠️ Disclaimer

This tool is designed **for authorized security testing, educational purposes, and defensive security assessments only**. Unauthorized network scanning or access to systems you don't own or have explicit permission to test is **illegal**.

- Only use this tool on networks you own or have explicit written permission to test
- Respect privacy and comply with all applicable laws
- The authors assume no liability for misuse

---

## 🛠️ Tools and Commands

Run commands interactively or via the `--command` flag:

| Command | Description |
|---------|-------------|
| `scan` | Run full network scan on the target subnet |
| `scan --passive` | Scan without active UPnP/SSDP probes |
| `scan --timeout=<sec>` | Scan with custom timeout (default: 2s) |
| `devices` | List all discovered devices from the database |
| `devices --json` | Export devices as JSON |
| `devices --filter <text>` | Filter devices by vendor or IP prefix |
| `ports <ip>` | Show open ports for a device (Stage 2 — coming soon) |
| `vuln <ip>` | Run vulnerability assessment (Stage 3 — coming soon) |
| `report` | Generate and export the scan report as JSON |
| `clear` | Clear the terminal screen |
| `help` | Show all available commands |
| `exit` / `quit` | Exit the scanner |

---

## 📦 Installation

**Complete setup in under 2 minutes:**

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/iot-attack-surface-scanner.git
cd iot-attack-surface-scanner

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux / Mac
.\venv\Scripts\activate.ps1       # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the scanner
python3 main.py 192.168.1.0/24
```

**That's it.** No `pip install -e .`, no system-wide installs, no confusion.

### Using `make` (Optional)

If you have `make` installed:

```bash
make setup        # Set up venv and install dependencies
make run          # Prompt for subnet and launch scanner
make run-example  # Launch with example subnet 192.168.1.0/24
```

---

## 🚀 Usage

### Interactive Mode (Default)

Launch the scanner and enter commands at the interactive prompt:

```bash
python3 main.py 192.168.1.0/24
```

```
██╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
[... banner ...]

Target: 192.168.1.0/24

[192.168.1.0/24] > scan
[scanning...]
[192.168.1.0/24] > devices
[device table]
[192.168.1.0/24] > exit
Goodbye!
```

### One-Shot Mode (--command)

Run a single command and exit:

```bash
# Long form
python3 main.py 192.168.1.0/24 --command scan

# Short form
python3 main.py 192.168.1.0/24 -c devices
```

### Examples

```bash
# Scan your home network
python3 main.py 192.168.1.0/24

# Export all discovered devices as JSON
python3 main.py 192.168.1.0/24 -c "devices --json" > devices.json

# Scan with custom timeout
python3 main.py 10.0.0.0/24 -c "scan --timeout=5"
```

---

## 📝 How It Works

**Stage 1: Device Discovery** (Current)
- ARP scanning to find active devices
- UPnP/SSDP probes to identify smart devices
- Hostname resolution
- MAC vendor lookup
- Service detection (HTTP, SSH, HTTPS, custom ports)

**Stage 2: Port Probing** (Coming Soon)
- Open port enumeration
- Service banners and versions
- Default credentials checking

**Stage 3: Vulnerability Assessment** (Coming Soon)
- CVE correlation
- Known vulnerability matching
- Risk scoring

---

## 📂 Data Storage

Device data is stored in SQLite:

```
~/.iotscanner/scanner.db
```

Reports are saved as JSON:

```
~/.iotscanner/report_YYYYMMDD_HHMMSS.json
```

---

## 🔧 Requirements

- **Python 3.11+**
- **Root/sudo** for ARP scanning (raw socket access)
- Linux or macOS (Windows requires WSL for best compatibility)

---

## 📚 Documentation

### Full Command Reference

```bash
# Help
python3 main.py 192.168.1.0/24 -c help

# Version
python3 main.py --version
```

### Environment Variables

Create a `.env` file in the project root:

```
# .env
IOTSCANNER_DB_PATH=~/.iotscanner/scanner.db
IOTSCANNER_TIMEOUT=2
```

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- [ ] Windows native support (without WSL)
- [ ] Additional service fingerprinting
- [ ] REST API / web dashboard
- [ ] Automated CVE correlation
- [ ] Custom plugin system

To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- Inspired by [Osintgram](https://github.com/Datalux/Osintgram) for UI/UX simplicity
- Built with [Scapy](https://scapy.net/), [Rich](https://rich.readthedocs.io/), and [Zeroconf](https://github.com/jstasiak/python-zeroconf)

---

**Questions?** Open an issue on GitHub.
