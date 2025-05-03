#!/usr/bin/env python3
# filepath: nmap_scanner.py
# A simple network scanner that uses nmap or arp-scan to find devices on your network

import os
import subprocess
import time
import json
from datetime import datetime, timedelta
subprocess.run(["notify-send", "starting network monitor"], check=True)

# File to store known devices (save in the same directory as the script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWN_DEVICES_FILE = os.path.join(SCRIPT_DIR, "known_network_devices.json")

def load_known_devices():
    """Load known devices from the JSON file"""
    if os.path.exists(KNOWN_DEVICES_FILE):
        with open(KNOWN_DEVICES_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_known_devices(devices):
    """Save known devices to the JSON file"""
    with open(KNOWN_DEVICES_FILE, 'w') as f:
        json.dump(devices, f, indent=2)

def get_mac_vendor(mac):
    """Try to get vendor name from MAC address"""
    if not mac or mac == "Unknown":
        return "Unknown vendor"
        
    # First 6 characters of MAC address (the OUI)
    oui = mac.replace(":", "")[:6].upper()
    
    try:
        # Try to get vendor information from the local file
        vendor_file = '/usr/share/nmap/nmap-mac-prefixes'
        if os.path.exists(vendor_file):
            with open(vendor_file, 'r', errors='ignore') as f:
                for line in f:
                    if line.startswith(oui):
                        return line.split(' ', 1)[1].strip()
    except Exception:
        pass
        
    return "Unknown vendor"

def get_network_range():
    """Get the network range (subnet) from the default route"""
    try:
        # Get default gateway and interface
        route_output = subprocess.check_output(["ip", "route"], text=True)
        for line in route_output.splitlines():
            if "default" in line:
                parts = line.split()
                dev_idx = parts.index("dev") + 1 if "dev" in parts else -1
                via_idx = parts.index("via") + 1 if "via" in parts else -1
                
                if via_idx > 0 and via_idx < len(parts):
                    gateway = parts[via_idx]
                    # Assume a /24 network from the gateway
                    network = ".".join(gateway.split(".")[0:3]) + ".0/24"
                    return network
    except Exception:
        pass
    
    # Fallback: try to get an IP address and guess the subnet
    try:
        ip_output = subprocess.check_output(["hostname", "-I"], text=True).strip()
        if ip_output:
            ip = ip_output.split()[0]  # Get first IP
            # Assume a /24 network
            network = ".".join(ip.split(".")[0:3]) + ".0/24"
            return network
    except Exception:
        pass
    
    # Default fallback
    return "192.168.1.0/24"

def clear_screen():
    """Clear the terminal screen"""
    os.system('clear')

def scan_with_arp():
    """Scan the network using arp-scan for faster results"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    discovered_devices = []
    scan_stats = ""
    
    try:
        # Run arp-scan for quick discovery
        arp_output = subprocess.check_output(
            ["arp-scan", "--localnet"],
            text=True, stderr=subprocess.DEVNULL
        )
        
        # Extract scan statistics for display later
        stats_lines = []
        stat_mode = False
        device_lines = []
        
        # First, separate device lines from header/footer
        for line in arp_output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Detect statistics section
            if "packets received" in line or "Ending arp-scan" in line:
                stat_mode = True
                
            if stat_mode:
                stats_lines.append(line)
            elif not line.startswith("Interface:") and not line.startswith("Starting"):
                # This is likely a device line
                if "." in line.split()[0]:  # Basic check for IP address
                    device_lines.append(line)
        
        # Store stats for later display
        scan_stats = "\n".join(stats_lines)
        
        # Process actual device lines
        for line in device_lines:
            parts = line.strip().split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1].lower()
                vendor = ' '.join(parts[2:]) if len(parts) > 2 else get_mac_vendor(mac)
                
                device_info = {
                    "ip": ip,
                    "hostname": "Unknown",  # arp-scan doesn't provide hostnames
                    "mac": mac,
                    "vendor": vendor,
                    "last_seen": timestamp,
                    "scan_stats": scan_stats  # Store stats to display later
                }
                discovered_devices.append(device_info)
                
    except Exception as e:
        print(f"Error with arp-scan: {e}")
        print("Falling back to nmap scan...")
    
    return discovered_devices

def scan_with_nmap(network_range):
    """Scan the network using nmap"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    discovered_devices = []
    
    try:
        # Run nmap ping scan
        nmap_output = subprocess.check_output(
            ["nmap", "-sn", network_range],
            text=True, stderr=subprocess.DEVNULL
        )
        
        # Process output to extract devices
        current_ip = None
        current_hostname = None
        current_mac = None
        
        for line in nmap_output.splitlines():
            line = line.strip()
            
            # IP address line
            if line.startswith("Nmap scan report for"):
                # Process previous device if we have one
                if current_ip:
                    device_info = {
                        "ip": current_ip,
                        "hostname": current_hostname or "Unknown",
                        "mac": current_mac or "Unknown",
                        "vendor": get_mac_vendor(current_mac),
                        "last_seen": timestamp
                    }
                    discovered_devices.append(device_info)
                
                # Start a new device
                parts = line.split("for ", 1)
                if len(parts) > 1:
                    addr_part = parts[1]
                    if "(" in addr_part and ")" in addr_part:
                        # Format: Nmap scan report for hostname.local (192.168.1.1)
                        current_hostname = addr_part.split(" (")[0]
                        current_ip = addr_part.split("(")[1].split(")")[0]
                    else:
                        # Format: Nmap scan report for 192.168.1.1
                        current_ip = addr_part
                        current_hostname = None
                    current_mac = None
            
            # MAC address line
            elif line.startswith("MAC Address:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    mac_parts = parts[1].strip().split(" ", 1)
                    current_mac = mac_parts[0].lower()
        
        # Process the last device
        if current_ip:
            device_info = {
                "ip": current_ip,
                "hostname": current_hostname or "Unknown",
                "mac": current_mac or "Unknown",
                "vendor": get_mac_vendor(current_mac),
                "last_seen": timestamp
            }
            discovered_devices.append(device_info)
        
    except Exception as e:
        print(f"Error scanning with nmap: {e}")
    
    return discovered_devices

def scan_network(network_range, use_nmap_only=False, tables_only=False):
    """Choose the appropriate scan method based on settings"""
    if use_nmap_only:
        if not tables_only:
            print("Using nmap scan mode...")
        return scan_with_nmap(network_range)
    else:
        if not tables_only:
            print("Using arp-scan (fast mode)...")
        devices = scan_with_arp()
        if not devices:
            if not tables_only:
                print("No devices found with arp-scan. Falling back to nmap...")
            devices = scan_with_nmap(network_range)
        return devices

def send_notification(title, message):
    """Send a desktop notification using notify-send"""
    try:
        subprocess.run(["notify-send", title, message], check=True)
    except Exception as e:
        print(f"Failed to send notification: {e}")

def update_known_devices(discovered_devices, known_devices, notify=False, args=None):
    """Update the known devices database with newly discovered devices"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now = datetime.now()
    debounce_time = 6  # seconds - debounce period for connect/disconnect
    new_devices = []
    disconnected_devices = []
    current_device_ids = set()

    # Process each discovered device
    for device in discovered_devices:
        device_id = device["mac"] if device["mac"] != "Unknown" else device["ip"]
        current_device_ids.add(device_id)

        if device_id not in known_devices:
            # This is an unknown device
            known_devices[device_id] = {
                "ip": device["ip"],
                "hostname": device["hostname"],
                "mac": device["mac"],
                "vendor": device["vendor"],
                "name": "",  # User can set this later
                "first_seen": timestamp,
                "last_seen": timestamp,
                "status": "connected",
                "ignore": False  # Default to not ignored
            }
            new_devices.append(device_id)

            # Notify about the unknown device if not ignored
            if not known_devices[device_id]["ignore"]:
                message = f"IP: {device['ip']}\nMAC: {device['mac']}\nVENDOR: {device['vendor']}\nLAST SEEN: {timestamp}"

                if not (args.tables_only or args.waybar):
                    print("\nUNKNOWN DEVICE CONNECTED")
                    print(message)
                if notify:
                    send_notification("UNKNOWN DEVICE CONNECTED", message)
        else:
            old_status = known_devices[device_id].get("status", "")
            # Update existing device
            known_devices[device_id]["last_seen"] = timestamp
            known_devices[device_id]["ip"] = device["ip"]
            
            # Only update the status if it's different, this prevents notifications for devices that remain connected
            if old_status != "connected":
                known_devices[device_id]["status"] = "connected"
            
            if device["hostname"] != "Unknown":
                known_devices[device_id]["hostname"] = device["hostname"]
            if device["mac"] != "Unknown":
                known_devices[device_id]["mac"] = device["mac"]
                known_devices[device_id]["vendor"] = device["vendor"]

            # Notify about the known device if not ignored and wasn't already connected
            if old_status != "connected" and not known_devices[device_id]["ignore"]:
                # Check if this device was recently disconnected (within debounce time)
                # If it was, don't notify about reconnection
                last_disconnect_time = known_devices[device_id].get("disconnect_time")
                if last_disconnect_time:
                    # Convert string timestamp to datetime object
                    try:
                        disconnect_datetime = datetime.strptime(last_disconnect_time, "%Y-%m-%d %H:%M:%S")
                        # If device disconnected within debounce window, skip notification
                        if (now - disconnect_datetime).total_seconds() < debounce_time:
                            # Still update status but skip notification
                            continue
                    except (ValueError, TypeError):
                        # If timestamp format is invalid, proceed with notification
                        pass
                
                device_name = known_devices[device_id].get("name", "")
                message = f"IP: {device['ip']}\nMAC: {device['mac']}\nVENDOR: {device['vendor']}\nLAST SEEN: {timestamp}"
                if not (args.tables_only or args.waybar):
                    print("\nKNOWN DEVICE CONNECTED")
                    if device_name:
                        print(f"NAME: {device_name}")
                    print(message)
                if notify:
                    if device_name:
                        message = f"NAME: {device_name}\n" + message
                    send_notification("KNOWN DEVICE CONNECTED", message)

    # Now check for disconnected devices - devices in database but not in current scan
    # Get all previously connected devices
    for device_id, info in known_devices.items():
        if info.get("status") == "connected" and device_id not in current_device_ids:
            # Mark as disconnected
            known_devices[device_id]["status"] = "disconnected"
            # Record when the device disconnected (for debounce)
            known_devices[device_id]["disconnect_time"] = timestamp
            disconnected_devices.append(device_id)

            # Notify about the disconnected device if not ignored
            if not info.get("ignore", False):
                device_name = info.get("name", "")
                message = f"IP: {info.get('ip', 'Unknown')}\nMAC: {info.get('mac', 'Unknown')}\nVENDOR: {info.get('vendor', 'Unknown')}\nLAST SEEN: {info.get('last_seen', 'Unknown')}"
                if not (args.tables_only or args.waybar):
                    print("\nKNOWN DEVICE DISCONNECTED")
                    if device_name:
                        print(f"NAME: {device_name}")
                    print(message)
                if notify:
                    if device_name:
                        message = f"NAME: {device_name}\n" + message
                    send_notification("KNOWN DEVICE DISCONNECTED", message)

    # Save the updated known devices
    save_known_devices(known_devices)

    return new_devices, disconnected_devices

def main():
    # Parse command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description="Simple Network Scanner")
    parser.add_argument("-i", "--interval", type=int, default=30, 
                        help="Scan interval in seconds (default: 30)")
    parser.add_argument("-n", "--notify", action="store_true",
                        help="Enable desktop notifications for device changes")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Don't show notifications for existing devices on first run")
    parser.add_argument("--nmap-only", action="store_true",
                        help="Use only nmap for scanning (slower but more detailed)")
    parser.add_argument("-t", "--tables-only", action="store_true",
                        help="Print only tables without scan statistics and status messages")
    parser.add_argument("-w", "--waybar", action="store_true",
                        help="Output JSON for Waybar with connected devices and tooltip")
    args = parser.parse_args()
     ##if waybar is set print text and tooltip starting in json
    if args.waybar:
        waybar_output = {
                                "text": "...",
                                "tooltip": "starting network monitor"
                            }
        print(json.dumps(waybar_output, ensure_ascii=False)) 
    
    # Get the network range to scan
    network_range = get_network_range()
    
    # Load known devices
    known_devices = load_known_devices()
    
    # On first run, set all devices as "unknown" status if quiet mode is enabled
    if args.quiet:
        for device_id in known_devices:
            known_devices[device_id]["status"] = "unknown"
    
    scan_interval = args.interval
    last_scan_time = 0
    first_run = True
    
    try:
        while True:
            current_time = time.time()
            if current_time - last_scan_time >= scan_interval:
                last_scan_time = current_time
                
                # Scan network first (don't clear screen yet)
                if not args.tables_only:
                    print(f"Scanning network {network_range}... (this may take a few seconds)")
                discovered_devices = scan_network(network_range, args.nmap_only, args.tables_only)

                # Update known devices database and get notifications
                new_devices, disconnected_devices = update_known_devices(
                    discovered_devices, known_devices, notify=args.notify, args=args
                )

                # Now clear the screen before displaying results
                if not args.notify:
                    clear_screen()

                # Get recent disconnected devices (those disconnected in the last 20 minutes)
                twenty_min_ago = (datetime.now() - timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S")
                recent_disconnected = [
                    (d_id, info) for d_id, info in known_devices.items() 
                    if info.get("status") == "disconnected" and
                    info.get("last_seen", "") >= twenty_min_ago
                ]

                if args.waybar:
                    # Prepare the connected devices table as a single string
                    connected_table_header = (
                        "┌─────────────────┬─────────────────────┬──────────────────────────────────────────┬─────────────────┐\n"
                        "│ IP Address      │ MAC Address         │ Vendor                                   │ Name            │\n"
                        "├─────────────────┼─────────────────────┼──────────────────────────────────────────┼─────────────────┤\n"
                    )
                    connected_table_rows = "\n".join([
                        f"│ {'#' + device['ip'] if known_devices.get(device['mac'] if device['mac'] != 'Unknown' else device['ip'], {}).get('ignore', False) else device['ip']:<15} │ {device['mac']:<19} │ {device['vendor']:<40} │ {known_devices.get(device['mac'] if device['mac'] != 'Unknown' else device['ip'], {}).get('name', 'Unknown'):<15} │"
                        for device in discovered_devices
                    ])
                    connected_table_footer = "\n└─────────────────┴─────────────────────┴──────────────────────────────────────────┴─────────────────┘"
                    connected_table = connected_table_header + connected_table_rows + connected_table_footer

                    # Prepare the disconnected devices table as a single string
                    disconnected_table_header = (
                        "\nRecently Disconnected Devices:\n"
                        "┌─────────────────┬─────────────────────┬──────────────────────────────────────────┬─────────────────┐\n"
                        "│ IP Address      │ MAC Address         │ Vendor                                   │ Name/Host       │\n"
                        "├─────────────────┼─────────────────────┼──────────────────────────────────────────┼─────────────────┤\n"
                    )
                    disconnected_table_rows = "\n".join([
                        f"│ {'#' + info.get('ip', 'Unknown') if info.get('ignore', False) else info.get('ip', 'Unknown'):<15} │ {info.get('mac', 'Unknown'):<19} │ {info.get('vendor', 'Unknown vendor'):<40} │ {info.get('name', 'Unknown') or info.get('hostname', 'Unknown'):<15} │"
                        for _, info in recent_disconnected
                    ])
                    disconnected_table_footer = "\n└─────────────────┴─────────────────────┴──────────────────────────────────────────┴─────────────────┘"
                    disconnected_table = disconnected_table_header + disconnected_table_rows + disconnected_table_footer

                    # Combine both tables
                    full_tooltip = connected_table + disconnected_table

                    # Prepare JSON output for Waybar
                    waybar_output = {
                        "text": str(len([device for device in discovered_devices if not known_devices.get(device['mac'] if device['mac'] != 'Unknown' else device['ip'], {}).get('ignore', False)])),
                        "tooltip": full_tooltip
                    }
                    print(json.dumps(waybar_output, ensure_ascii=False))
                    continue  # Skip the rest of the loop for Waybar output

                # Suppress console output for connected and disconnected devices
                if not args.waybar:
                    # Create a clean table format for displaying results
                    print(f"Connected devices: {len(discovered_devices)}")

                    # Count total known devices (connected & disconnected)
                    total_known = len([d for d in known_devices.values() 
                                      if d.get("last_seen", "") >= 
                                         (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")])

                    # Table headers (with wider vendor column)
                    print("\n┌─────────────────┬─────────────────────┬──────────────────────────────────────────┬─────────────────┐")
                    print("│ IP Address      │ MAC Address         │ Vendor                                   │ Name            │")
                    print("├─────────────────┼─────────────────────┼──────────────────────────────────────────┼─────────────────┤")

                    # Print connected devices in a table
                    for device in discovered_devices:
                        ip = device["ip"]
                        mac = device["mac"] if device["mac"] != "Unknown" else "Unknown MAC"
                        vendor = device["vendor"]
                        if len(vendor) > 38:
                            vendor = vendor[:35] + "..."

                        # Get custom name if set in known devices
                        device_id = device["mac"] if device["mac"] != "Unknown" else device["ip"]
                        name = known_devices.get(device_id, {}).get("name", "")

                        print(f"│ {ip:<15} │ {mac:<19} │ {vendor:<40} │ {name:<15} │")

                    # Table footer
                    print("└─────────────────┴─────────────────────┴──────────────────────────────────────────┴─────────────────┘")

                    # Display recently disconnected devices in a table
                    if recent_disconnected:
                        print("\nRecently Disconnected Devices:")
                        print("┌─────────────────┬─────────────────────┬──────────────────────────────────────────┬─────────────────┐")
                        print("│ IP Address      │ MAC Address         │ Vendor                                   │ Name/Host       │")
                        print("├─────────────────┼─────────────────────┼──────────────────────────────────────────┼─────────────────┤")

                        for device_id, info in recent_disconnected:
                            ip = info.get("ip", "Unknown")
                            mac = info.get("mac", "Unknown")
                            vendor = info.get("vendor", "Unknown vendor")
                            if len(vendor) > 38:
                                vendor = vendor[:35] + "..."

                            # Use name if available, otherwise hostname
                            device_name = info.get("name", "") or info.get("hostname", "")
                            if not device_name or device_name == "Unknown":
                                device_name = ""

                            print(f"│ {ip:<15} │ {mac:<19} │ {vendor:<40} │ {device_name:<15} │")

                        print("└─────────────────┴─────────────────────┴──────────────────────────────────────────┴─────────────────┘")

                # Display arp-scan statistics if available (from fast scan mode)
                if not args.tables_only and not args.nmap_only and discovered_devices and "scan_stats" in discovered_devices[0]:
                    print("\nScan Statistics:")
                    print(discovered_devices[0]["scan_stats"])

                # Print status summary footer
                print(f"\nStatus: {len(discovered_devices)} connected, {len(recent_disconnected)} recently disconnected")
                print(f"Auto-refresh every {scan_interval}s")

                first_run = False

            # Sleep to reduce CPU usage
            time.sleep(1)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
