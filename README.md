# 🔍 MoniPy

A powerful, real-time network monitoring tool that keeps track of all devices on your local network.

![Network Scanner Banner](https://img.shields.io/badge/Network-Scanner-blue?style=for-the-badge&logo=wifi&logoColor=white)

## ✨ Features

- **Real-time device detection** - Instantly identify new devices that connect to your network
- **Fast Scanning** - Uses both `arp-scan` (fast) and `nmap` (thorough) scanning methods
- **Beautiful Tables** - Clear, formatted display of connected and recently disconnected devices
- **Desktop Notifications** - Get alerts when devices connect or disconnect
- **Device Tracking** - Maintains history of all known devices
- **Vendor Identification** - Identifies device manufacturers from MAC addresses
- **Custom Naming** - Name your devices for easy identification

## 📸 Screenshots

```
Connected devices: 5

┌─────────────────┬─────────────────────┬──────────────────────────────────────────┬─────────────────┐
│ IP Address      │ MAC Address         │ Vendor                                   │ Name            │
├─────────────────┼─────────────────────┼──────────────────────────────────────────┼─────────────────┤
│ 192.168.3.1     │ 78:c5:f8:98:de:13   │ Huawei Device Co., Ltd.                  │ Router          │
│ 192.168.3.52    │ f8:ff:c2:89:05:be   │ Apple, Inc.                              │ iPhone          │
│ 192.168.3.74    │ f0:7d:f7:a6:30:6c   │ Unknown                                  │ Laptop          │
│ 192.168.3.200   │ 2e:67:af:3c:8e:2c   │ Unknown: locally administered            │ Smart TV        │
│ 192.168.3.235   │ b4:fb:e3:d6:de:9d   │ AltoBeam (China) Inc.                    │                 │
└─────────────────┴─────────────────────┴──────────────────────────────────────────┴─────────────────┘

Recently Disconnected Devices:
┌─────────────────┬─────────────────────┬──────────────────────────────────────────┬─────────────────┐
│ IP Address      │ MAC Address         │ Vendor                                   │ Name/Host       │
├─────────────────┼─────────────────────┼──────────────────────────────────────────┼─────────────────┤
│ 192.168.3.110   │ 5c:96:9d:65:fe:c2   │ Apple, Inc.                              │ iPad            │
└─────────────────┴─────────────────────┴──────────────────────────────────────────┴─────────────────┘
```

## 🚀 Installation

### Prerequisites

- Python 3.6+
- nmap (`sudo apt install nmap`)  
- arp-scan (`sudo apt install arp-scan`)

### Setup

1. Clone this repository:
```bash
git clone https://your-repo-url/network-scanner.git
cd network-scanner
```

2. Run the scanner:
```bash
python3 network_scanner.py
```

## 🎮 Usage

```
python3 network_scanner.py [options]

Options:
  -i, --interval SEC   Scan interval in seconds (default: 30)
  -n, --notify         Enable desktop notifications for device changes
  -q, --quiet          Don't show notifications for existing devices on first run
  -t, --tables-only    Print only tables without scan statistics and status messages
  -w, --waybar         Output JSON for Waybar with connected devices and tooltip
  --nmap-only          Use only nmap for scanning (slower but more detailed)
```

## 🔧 Configuration

The scanner creates a `known_network_devices.json` file that stores information about all devices it discovers. You can customize device names and other settings by editing this file.

### Sample device entry:

```json
"00:11:22:33:44:55": {
  "ip": "192.168.1.100",
  "hostname": "device-hostname",
  "mac": "00:11:22:33:44:55",
  "vendor": "Device Manufacturer",
  "name": "My Device",
  "first_seen": "2025-04-29 10:00:00",
  "last_seen": "2025-04-29 10:30:00",
  "status": "connected",
  "ignore": false
}
```

Set `"ignore": true` to disable notifications for specific devices.

## 📱 Notifications

Get desktop notifications when:
- New devices connect
- Known devices reconnect
- Devices disconnect

Notification format:
```
NAME: device-name
IP: 192.168.1.100
VENDOR: Device Manufacturer
MAC: 00:11:22:33:44:55
```

## 🛡️ Privacy & Security

This tool only scans your local network. All data is stored locally in the `known_network_devices.json` file.

## 📋 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- Uses `nmap` and `arp-scan` for device discovery
- Built with Python and love ❤️
