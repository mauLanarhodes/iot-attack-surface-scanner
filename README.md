# IoT Attack Surface Scanner

Discover and fingerprint IoT devices on your local network.

## Install

```bash
git clone https://github.com/yourusername/iot-attack-surface-scanner.git
cd iot-attack-surface-scanner
source .venv/bin/activate
pip install -e .
```

## Usage

### Scan your network

```bash
# ARP scanning requires root/sudo
sudo iotscanner scan --subnet 192.168.1.0/24

# Passive mode (skip UPnP/SSDP, ARP + mDNS only)
sudo iotscanner scan --subnet 192.168.1.0/24 --passive

# Save results to JSON
sudo iotscanner scan --subnet 192.168.1.0/24 --output results.json
```

### List known devices

```bash
iotscanner devices
iotscanner devices --json
iotscanner devices --filter "Raspberry"
```

### Version

```bash
iotscanner version
```

## Note

- **sudo required** for ARP scanning (raw socket access)
- Device data is stored in `~/.iotscanner/scanner.db` (SQLite)

## Roadmap

More stages coming: port probing, CVE correlation, ML anomaly detection, API dashboard, and reporting.
