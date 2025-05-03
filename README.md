# NetMon - Advanced Network Monitoring Tool 🛡️🔍

A powerful, lightweight network scanning and monitoring utility designed for Linux systems. NetMon helps you track devices connecting to your network in real-time with detailed information and notifications.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features ✨

- **Network Discovery**: Automatically detect all devices on your local network
- **Device Tracking**: Monitor device connections and disconnections
- **Vendor Identification**: Identify device manufacturers using MAC address lookup
- **Real-time Notifications**: Get alerts when new devices connect to your network
- **Intensive Scanning**: Run detailed port scans on the entire network with live progress display
- **Persistent Storage**: Save device history between runs
- **Flexible Output**: View results in table format with uptime information
- **Scheduling**: Run scans at regular intervals

## Requirements 📋

- Python 3.6+
- Nmap
- Root/sudo privileges (required for proper network scanning)
- Linux/Unix environment (tested on Ubuntu/Debian)

## Installation 🚀

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/netmon.git
   cd netmon
   ```

2. Install required dependencies:
   ```bash
   sudo apt-get install nmap
   pip install requests
   ```

3. Make the scripts executable:
   ```bash
   chmod +x netmon.py notifier.py
   ```

## Usage 🖥️

### Basic Network Scan

```bash
sudo ./netmon.py
```

### View Connected Devices in Table Format

```bash
sudo ./netmon.py -T
```

### Continuous Monitoring (every 60 seconds)

```bash
sudo ./netmon.py -i 60 -T
```

### Intensive Network Scan with Progress Display

```bash
sudo ./netmon.py -I
```

### Update Device Vendor Information

```bash
sudo ./netmon.py -H
```

### Enable Real-time Notifications

In one terminal:
```bash
./notifier.py
```

In another terminal:
```bash
sudo ./netmon.py -N -i 30
```

## Command Line Options 🛠️

### NetMon Options

| Option | Description |
|--------|-------------|
| `-D`, `--debug` | Enable debug output |
| `-i SECONDS`, `--interval SECONDS` | Scan interval in seconds (default: run once) |
| `-T`, `--table` | Print a table of connected hosts |
| `-C`, `--clear` | Clear screen before each output |
| `-N`, `--notify` | Send notifications when devices connect/disconnect |
| `-S PATH`, `--socket PATH` | Path to notification socket (default: /tmp/netmon_socket) |
| `-H`, `--rescan-hosts` | Force rescan of MAC, hostname and vendor info for all devices |
| `-I`, `--intensive-scan` | Perform intensive nmap scan on the entire network |
| `-U`, `--update-vendors-only` | Update MAC vendor information only |

### Notifier Options

| Option | Description |
|--------|-------------|
| `-p PATH`, `--path PATH` | Unix socket path (default: /tmp/netmon_socket) |
| `-c CMD`, `--command CMD` | Command to execute on notification |

## Output Files 📁

- `network_devices.json`: Database of all discovered devices
- `oui.csv`: MAC vendor database
- `scans/`: Directory containing detailed scan results

## Examples 📝

### Monitoring for New Devices

```bash
# Start the notifier to receive alerts
./notifier.py &

# Run continuous monitoring with table display
sudo ./netmon.py -T -N -i 60
```

### Running Weekly Intensive Scans

Add to crontab:
```
0 2 * * 0 cd /path/to/netmon && sudo ./netmon.py -I > /var/log/netmon_scan.log 2>&1
```

## How It Works 🔧

1. NetMon uses nmap to discover devices on your local network
2. MAC addresses are looked up in the IEEE OUI database
3. Device information is stored in a JSON database
4. Connection status changes trigger notifications via Unix socket
5. The notifier process displays desktop notifications

## License 📄

MIT

## Contributing 🤝

Contributions are welcome! Feel free to submit issues and pull requests.

## Acknowledgements 🙏

- Uses the IEEE MAC vendors database
- Built with Python and Nmap