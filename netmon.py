#!/usr/bin/env python3
# filepath: /home/gabriwar/scripts/netmon/netmon.py

import subprocess
import re
import socket
import os
import sys
import argparse
import json
from urllib.request import urlopen
from datetime import datetime
import time
import csv
import requests
from collections import defaultdict

# Global debug flag
DEBUG = False

# JSON file to store network scan results
SCAN_RESULTS_FILE = "network_devices.json"

def debug_print(message):
    """Print message only if debug mode is enabled"""
    if DEBUG:
        print(message)

# MAC address vendor database
MAC_VENDORS_URL = "https://standards-oui.ieee.org/oui/oui.csv"
MAC_VENDORS_FILE = "oui.csv"
MAC_VENDORS = {}

def load_mac_vendors():
    """Load MAC address vendor database"""
    global MAC_VENDORS
    
    debug_print("Loading MAC vendor database...")
    
    # Check if we have a local copy of the MAC vendors file
    if os.path.exists(MAC_VENDORS_FILE):
        try:
            debug_print(f"Loading MAC vendors from local file: {MAC_VENDORS_FILE}")
            with open(MAC_VENDORS_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                count = 0
                for row in reader:
                    if len(row) >= 2:
                        mac_prefix = row[1].strip().replace('-', '').upper()
                        vendor = row[2].strip()
                        MAC_VENDORS[mac_prefix] = vendor
                        count += 1
            debug_print(f"Loaded {count} MAC vendor entries from local file")
            return
        except Exception as e:
            debug_print(f"Error loading MAC vendors from local file: {e}")
            debug_print("Attempting to download MAC vendor database...")
    
    # If we don't have a local file or it failed to load, download it
    try:
        debug_print(f"Downloading MAC vendors from {MAC_VENDORS_URL}")
        response = requests.get(MAC_VENDORS_URL)
        with open(MAC_VENDORS_FILE, 'wb') as f:
            f.write(response.content)
        
        with open(MAC_VENDORS_FILE, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                if len(row) >= 2:
                    mac_prefix = row[1].strip().replace('-', '').upper()
                    vendor = row[2].strip()
                    MAC_VENDORS[mac_prefix] = vendor
                    count += 1
        debug_print(f"Loaded {count} MAC vendor entries from downloaded file")
    except Exception as e:
        debug_print(f"Error downloading MAC vendors: {e}")

def get_mac_vendor(mac_address):
    """Look up vendor for a MAC address"""
    if not mac_address:
        return "Unknown"
    
    # Try different prefix lengths
    for i in range(8, 0, -1):
        prefix = mac_address.upper().replace(':', '')[:i]
        if prefix in MAC_VENDORS:
            return MAC_VENDORS[prefix]
    
    return "Unknown"

def get_mac_address(ip_address):
    """Get MAC address for an IP using ARP"""
    debug_print(f"Getting MAC address for {ip_address}")
    try:
        # First ping the IP to ensure it's in the ARP table
        ping_cmd = ['ping', '-c', '1', '-W', '1', ip_address]
        subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Then query the ARP table
        arp_cmd = ['arp', '-n', ip_address]
        result = subprocess.run(arp_cmd, capture_output=True, text=True)
        
        # Extract MAC address using regex
        match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', result.stdout)
        if match:
            return match.group(1).lower()
        else:
            debug_print(f"No MAC address found for {ip_address}")
            return None
    except Exception as e:
        debug_print(f"Error getting MAC address: {e}")
        return None

def get_default_gateway():
    """Detect the default gateway IP address"""
    try:
        # Run the route command to get the default gateway
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                               capture_output=True, text=True, check=True)
        
        # Extract the gateway IP address using regex
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            gateway_ip = match.group(1)
            debug_print(f"Default gateway detected: {gateway_ip}")
            return gateway_ip
        else:
            debug_print("Could not find default gateway in route output")
            return None
    except subprocess.SubprocessError as e:
        debug_print(f"Error detecting default gateway: {e}")
        return None

def get_network_range(gateway_ip):
    """Determine the network range based on the gateway IP"""
    # Simple approach: replace the last octet with 0/24
    network = gateway_ip.rsplit('.', 1)[0] + '.0/24'
    return network

def scan_network(network_range, rescan_all=False):
    """Perform an nmap scan of the specified network range"""
    debug_print(f"Scanning network {network_range} for hosts...")
    
    # Load previous results to check which devices we already know
    previous_results = load_previous_scan_results()
    
    try:
        # Run nmap with -sn option (ping scan - no port scan)
        nmap_cmd = ['nmap', '-sn', network_range]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, check=True)
        
        # Extract hosts that are up
        hosts = re.findall(r'Nmap scan report for ([^\s]+)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?', result.stdout)
        
        # Process the results
        active_hosts = []
        for host in hosts:
            if host[1]:  # IP address in second group
                hostname = host[0]
                ip = host[1]
            else:  # IP address in first group
                hostname = ''
                ip = host[0]
            
            # Check if this IP is already in our database
            existing_device = None
            for mac, device in previous_results.items():
                if device.get('ip') == ip and not rescan_all:
                    existing_device = device
                    break
            
            if existing_device and not rescan_all:
                # Use existing information for this device
                active_hosts.append({
                    'ip': ip,
                    'hostname': existing_device.get('hostname', 'Unknown'),
                    'mac': existing_device.get('mac'),
                    'vendor': existing_device.get('vendor', 'Unknown')
                })
                debug_print(f"Using cached information for {ip}")
            else:
                # New device or rescan requested - get full information
                debug_print(f"Getting detailed information for {ip}" + 
                           (" (forced rescan)" if rescan_all else ""))
                
                # Try to resolve hostname if it's not provided by nmap
                if not hostname:
                    try:
                        hostname = socket.getfqdn(ip)
                        # If getfqdn just returns the IP, it didn't resolve
                        if hostname == ip:
                            # Try gethostbyaddr instead
                            try:
                                hostname = socket.gethostbyaddr(ip)[0]
                            except socket.herror:
                                hostname = "Unknown"
                    except Exception:
                        hostname = "Unknown"
                
                # Get MAC address and vendor
                mac_address = get_mac_address(ip)
                
                # If rescan_all is true, always lookup the vendor, even if it was known before
                if rescan_all and mac_address and existing_device is not None and 'mac' in existing_device and existing_device['mac'] == mac_address:
                    # Still the same MAC address, force a vendor lookup from the OUI database
                    vendor = get_mac_vendor(mac_address)
                    debug_print(f"Forced vendor lookup for {mac_address}: {vendor}")
                else:
                    vendor = get_mac_vendor(mac_address) if mac_address else "Unknown"
                
                active_hosts.append({
                    'ip': ip, 
                    'hostname': hostname,
                    'mac': mac_address,
                    'vendor': vendor
                })
            
        return active_hosts
    except subprocess.SubprocessError as e:
        debug_print(f"Error scanning network: {e}")
        return []

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Network monitoring tool')
    parser.add_argument('-D', '--debug', action='store_true', 
                        help='Enable debug output')
    parser.add_argument('-i', '--interval', type=int, default=0,
                        help='Scan interval in seconds (default: run once and exit)')
    parser.add_argument('-T', '--table', action='store_true',
                        help='Print a table of connected hosts')
    parser.add_argument('-C', '--clear', action='store_true',
                        help='Clear screen before each output')
    parser.add_argument('-N', '--notify', action='store_true',
                        help='Send notifications when devices connect/disconnect')
    parser.add_argument('-S', '--socket', default='/tmp/netmon_socket',
                        help='Path to the notification socket (default: /tmp/netmon_socket)')
    parser.add_argument('-H', '--rescan-hosts', action='store_true',
                        help='Force rescan of MAC, hostname and vendor information for all devices')
    parser.add_argument('-I', '--intensive-scan', action='store_true',
                        help='Perform intensive nmap scan on each connected device')
    parser.add_argument('-U', '--update-vendors-only', action='store_true',
                        help='Update MAC vendor information only, without scanning the network')
    return parser.parse_args()

def load_previous_scan_results():
    """Load previous scan results from JSON file"""
    try:
        if os.path.exists(SCAN_RESULTS_FILE):
            with open(SCAN_RESULTS_FILE, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        debug_print(f"Error loading previous scan results: {e}")
        return {}

def save_scan_results(active_hosts, notify=False, socket_path='/tmp/netmon_socket'):
    """Save scan results to JSON file"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Load previous results to preserve history data
    previous_results = load_previous_scan_results()
    
    # Track connected/disconnected devices
    connected_devices = []
    
    # Update the results with new scan data
    for host in active_hosts:
        if host['mac']:
            mac = host['mac']
            if mac in previous_results:
                # Check if device was previously disconnected
                if previous_results[mac]['status'] != "connected":
                    debug_print(f"Device connected: {host['ip']} ({host['mac']}) - {host['vendor']}")
                    connected_devices.append(mac)
                    # Update connection time for uptime calculation
                    previous_results[mac]['connection_time'] = current_time
                    
                    # Send notification if enabled
                    if notify and not previous_results[mac].get('ignore', False):
                        send_notification(socket_path, 'connected', previous_results[mac])
                
                # Update existing record
                previous_results[mac]['ip'] = host['ip']
                previous_results[mac]['hostname'] = host['hostname'] if host['hostname'] else "Unknown"
                previous_results[mac]['vendor'] = host['vendor']
                previous_results[mac]['last_seen'] = current_time
                previous_results[mac]['status'] = "connected"
            else:
                # New device found
                debug_print(f"New device found: {host['ip']} ({host['mac']}) - {host['vendor']}")
                connected_devices.append(mac)
                
                # Create new record
                previous_results[mac] = {
                    'ip': host['ip'],
                    'hostname': host['hostname'] if host['hostname'] else "Unknown",
                    'mac': mac,
                    'vendor': host['vendor'],
                    'name': "",
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'connection_time': current_time,
                    'status': "connected",
                    'ignore': False
                }
                
                # Send notification if enabled
                if notify:
                    send_notification(socket_path, 'new', previous_results[mac])
    
    # Check for devices that have disconnected
    for mac, device in previous_results.items():
        # If the device was connected but not in the current scan
        if device['status'] == "connected" and mac not in [h['mac'] for h in active_hosts if h['mac']]:
            previous_results[mac]['status'] = "disconnected"
            debug_print(f"Device disconnected: {device['ip']} ({mac}) - {device['vendor']}")
            
            # Send notification if enabled
            if notify and not device.get('ignore', False):
                send_notification(socket_path, 'disconnected', device)
    
    # Write updated results back to file
    try:
        with open(SCAN_RESULTS_FILE, 'w') as f:
            json.dump(previous_results, f, indent=2)
        
        # Set permissions to make the file readable and writable by everyone
        os.chmod(SCAN_RESULTS_FILE, 0o666)
        debug_print(f"Saved scan results to {SCAN_RESULTS_FILE}")
    except Exception as e:
        debug_print(f"Error saving scan results: {e}")

def print_hosts_table(hosts_data):
    """Print a formatted table of connected hosts"""
    # Only show this output even without debug mode
    if not hosts_data:
        print("No hosts found")
        return
    
    # Get current time for uptime calculation
    current_time = datetime.now()
    
    # Print header
    print("\nNETWORK HOSTS:")
    print("=" * 100)
    print(f"{'NAME':<20} {'IP':<16} {'MAC':<18} {'CONNECTED':<12} {'VENDOR':<20} {'HOSTNAME'}")
    print("-" * 100)
    
    # Sort hosts by IP address
    try:
        sorted_hosts = sorted(hosts_data.items(), key=lambda x: socket.inet_aton(x[1]['ip']))
    except:
        # Fallback sorting method if IP address sorting fails
        sorted_hosts = sorted(hosts_data.items(), key=lambda x: x[1]['ip'])
    
    # Print each host
    for mac, host in sorted_hosts:
        # Skip hosts that are not connected
        if host.get('status') != "connected":
            continue
            
        # Format name and handle ignored hosts
        name = host.get('name', '')
        if not name:
            name = ""  # Ensure empty string if no name is set
        if host.get('ignore', False):
            name = f"# {name}"
        
        # Calculate connection time in minutes
        conn_time = "Unknown"
        try:
            # Use connection_time if available, otherwise use first_seen or last_seen as fallback
            if 'connection_time' in host:
                time_field = host['connection_time']
            elif 'first_seen' in host:
                time_field = host['first_seen']
            elif 'last_seen' in host:
                time_field = host['last_seen']
            else:
                time_field = None
                
            if time_field:
                connection_time = datetime.strptime(time_field, "%Y-%m-%d %H:%M:%S")
                minutes_connected = int((current_time - connection_time).total_seconds() / 60)
                conn_time = f"{minutes_connected} min"
        except Exception as e:
            debug_print(f"Error calculating connection time: {e}")
            conn_time = "Error"
        
        # Format vendor and hostname
        vendor = host.get('vendor', 'Unknown')
        hostname = host.get('hostname', 'Unknown')
        
        # Print the row
        print(f"{name:<20} {host['ip']:<16} {host['mac']:<18} {conn_time:<12} {vendor:<20} {hostname}")
    
    # Print recently disconnected devices (within last 10 minutes)
    recent_disconnects = []
    
    for mac, host in sorted_hosts:
        # Only check disconnected devices
        if host.get('status') != "disconnected":
            continue
            
        # Calculate time since disconnect
        if 'last_seen' in host:
            try:
                last_seen = datetime.strptime(host['last_seen'], "%Y-%m-%d %H:%M:%S")
                time_since_disconnect = (current_time - last_seen).total_seconds() / 60
                
                # If disconnected within the last 10 minutes, add to the list
                if time_since_disconnect <= 10:
                    recent_disconnects.append((mac, host, time_since_disconnect))
            except Exception:
                pass
    
    # If we have recent disconnects, print them
    if recent_disconnects:
        print("\nRECENTLY DISCONNECTED DEVICES (Last 10 minutes):")
        print("=" * 100)
        print(f"{'NAME':<20} {'IP':<16} {'MAC':<18} {'DISCONNECTED':<20} {'VENDOR'}")
        print("-" * 100)
        
        # Sort by disconnect time (most recent first)
        recent_disconnects.sort(key=lambda x: x[2])
        
        for mac, host, minutes in recent_disconnects:
            # Format name
            name = host.get('name', '')
            if not name:
                name = ""
            if host.get('ignore', False):
                name = f"# {name}"
            
            # Format time since disconnect
            if minutes < 1:
                time_str = "< 1 min ago"
            else:
                time_str = f"{int(minutes)} min ago"
                
            # Format vendor
            vendor = host.get('vendor', 'Unknown')
            
            # Print the row
            print(f"{name:<20} {host['ip']:<16} {mac:<18} {time_str:<20} {vendor}")

def send_notification(socket_path, event_type, device):
    """Send notification about device connection/disconnection events"""
    if not device.get('mac'):
        return
    
    # Skip notification if device is marked as ignored
    if device.get('ignore', False):
        return
    
    try:
        # Create notification data
        notification = {
            'event': event_type,
            'ip': device.get('ip', ''),
            'mac': device.get('mac', ''),
            'name': device.get('name', ''),
            'vendor': device.get('vendor', 'Unknown'),
            'hostname': device.get('hostname', 'Unknown'),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Create Unix domain socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        
        # Connect to the socket
        try:
            sock.connect(socket_path)
            # Send the notification as JSON
            sock.sendall(json.dumps(notification).encode('utf-8'))
            debug_print(f"Notification sent: {event_type} - {device.get('ip')} ({device.get('mac')})")
        except socket.error as e:
            debug_print(f"Failed to connect to notification socket: {e}")
        finally:
            sock.close()
    except Exception as e:
        debug_print(f"Error sending notification: {e}")

def perform_intensive_scan(device):
    """Perform an intensive nmap scan on a specific device"""
    if not device.get('mac') or not device.get('ip'):
        debug_print(f"Cannot scan device: missing MAC or IP")
        return False
    
    mac = device['mac'].replace(':', '')
    ip = device['ip']
    
    # Create directory structure: ./scans/<datetime>/<mac>
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"./scans/{current_time}/{mac}"
    
    # Ensure the directory exists
    try:
        os.makedirs(scan_dir, exist_ok=True)
        debug_print(f"Created scan directory: {scan_dir}")
    except Exception as e:
        debug_print(f"Error creating scan directory: {e}")
        return False
    
    output_file = f"{scan_dir}/scan"
    
    debug_print(f"Performing intensive scan on {ip} ({device.get('hostname', 'Unknown')}, {device.get('vendor', 'Unknown')})")
    
    try:
        # Run intensive nmap scan
        nmap_cmd = ['nmap', '-p-', '-T4', '-A', '-v', '-Pn', '-oA', output_file, ip]
        debug_print(f"Running command: {' '.join(nmap_cmd)}")
        
        result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            debug_print(f"Scan completed successfully. Results saved to {output_file}.*")
            return True
        else:
            debug_print(f"Scan failed with error code {result.returncode}")
            debug_print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        debug_print(f"Error performing intensive scan: {e}")
        return False

def perform_network_intensive_scan(network_range):
    """Perform an intensive nmap scan on the entire network range with progress display"""
    if not network_range:
        debug_print(f"Cannot scan: missing network range")
        return False
    
    # Create directory structure: ./scans/<datetime>/network
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"./scans/{current_time}/network"
    
    # Ensure the directory exists
    try:
        os.makedirs(scan_dir, exist_ok=True)
        debug_print(f"Created scan directory: {scan_dir}")
    except Exception as e:
        debug_print(f"Error creating scan directory: {e}")
        return False
    
    output_file = f"{scan_dir}/network_scan"
    
    print(f"Performing intensive scan on entire network range: {network_range}")
    print(f"This may take a considerable amount of time depending on the network size")
    print(f"Scan results will be saved to {output_file}.*")
    
    try:
        # Run intensive nmap scan on the entire network with real-time output
        nmap_cmd = ['nmap', '-sT', '--top-ports', '300', '-T4', '-A', '-vv', '-oA',  output_file, network_range]
        print(f"\nRunning command: {' '.join(nmap_cmd)}")
        print("\n" + "=" * 80)
        print("SCAN PROGRESS (Live Output):")
        print("=" * 80)
        
        # Use Popen instead of run to get live output
        process = subprocess.Popen(
            nmap_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        scan_started = False
        
        # Process live output
        for line in iter(process.stdout.readline, ''):
            # Display informative lines about scan progress
            if any(x in line for x in [
                'Initiating', 'Scanning', 'Discovered', 'Completed', 
                '% done', 'seconds', 'finished', 'scanned'
            ]):
                print(line.rstrip())
            # Always show port findings
            elif 'open' in line and 'port' in line:
                print(line.rstrip())
                
            # Keep track of when the scan starts running
            if 'Starting Nmap' in line and not scan_started:
                scan_started = True
                start_time = datetime.now()
                print(f"Scan started at {start_time.strftime('%H:%M:%S')}")
        
        # Wait for the process to complete and get return code
        return_code = process.wait()
        
        if return_code == 0:
            end_time = datetime.now()
            duration = end_time - start_time
            print("\n" + "=" * 80)
            print(f"Network scan completed successfully in {duration.seconds//60} minutes, {duration.seconds%60} seconds")
            print(f"Results saved to {output_file}.*")
            return True
        else:
            print("\n" + "=" * 80)
            print(f"Network scan failed with error code {return_code}")
            return False
    except Exception as e:
        print(f"\nError performing network scan: {e}")
        return False

def main():
    # Parse arguments
    global DEBUG
    args = parse_arguments()
    DEBUG = args.debug
    
    # Check if script is run as root
    if os.geteuid() != 0:
        debug_print("This script requires root privileges to run nmap effectively.")
        debug_print("Please run with sudo.")
        sys.exit(1)
    
    # Load MAC vendor database
    load_mac_vendors()
    
    # If -H is specified, update all MAC vendors in the database regardless of online status
    if args.rescan_hosts:
        debug_print("Rescanning all MAC addresses in the database for vendor information...")
        devices_data = load_previous_scan_results()
        updated_count = 0
        scanned_count = 0
        
        for mac, device in devices_data.items():
            if mac and mac != "Unknown":
                scanned_count += 1
                old_vendor = device.get('vendor', "Unknown")
                
                # Always print which MAC is being looked up when debug is enabled
                if DEBUG:
                    print(f"Looking up vendor for MAC: {mac} (Current: {old_vendor})")
                
                new_vendor = get_mac_vendor(mac)
                if old_vendor != new_vendor:
                    if DEBUG:
                        print(f"✓ Updating vendor for {mac}: {old_vendor} -> {new_vendor}")
                    devices_data[mac]['vendor'] = new_vendor
                    updated_count += 1
                else:
                    if DEBUG:
                        print(f"- MAC lookup for {mac}: Vendor unchanged ({old_vendor})")
        
        if updated_count > 0:
            print(f"Updated vendor information for {updated_count} out of {scanned_count} devices")
            # Save the updated data
            try:
                with open(SCAN_RESULTS_FILE, 'w') as f:
                    json.dump(devices_data, f, indent=2)
                # Set permissions to make the file readable and writable by everyone
                os.chmod(SCAN_RESULTS_FILE, 0o666)
                debug_print(f"Saved updated vendor information to {SCAN_RESULTS_FILE}")
            except Exception as e:
                debug_print(f"Error saving updated vendor information: {e}")
        else:
            print(f"Scanned {scanned_count} devices, no vendor updates needed")
            
        # If we're only updating vendors with -H and not doing a network scan, exit
        if args.update_vendors_only:
            sys.exit(0)
    
    # Get the default gateway
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        debug_print("Failed to determine default gateway. Exiting.")
        sys.exit(1)
    
    # Get the network range
    network_range = get_network_range(gateway_ip)
    
    # Run scan once or periodically based on interval argument
    try:
        first_run = True
        while True:
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if not first_run:
                debug_print(f"\nRunning scan at {scan_time}")
            
            # Scan the network
            active_hosts = scan_network(network_range, args.rescan_hosts)
            
            # Save results to JSON file and check for changes
            save_scan_results(active_hosts, args.notify, args.socket)
            
            # Clear screen if -C option is used
            if args.clear:
                os.system('clear' if os.name == 'posix' else 'cls')
            
            # Display the results only in debug mode
            debug_print(f"Found {len(active_hosts)} active hosts on the network:")
            for host in active_hosts:
                output = f"IP: {host['ip']}"
                if host['hostname']:
                    output += f", Hostname: {host['hostname']}"
                if host['mac']:
                    output += f", MAC: {host['mac']}"
                if host['vendor'] != "Unknown":
                    output += f", Vendor: {host['vendor']}"
                debug_print(output)
            
            # Print the hosts table if the -T option is used
            if args.table:
                hosts_data = load_previous_scan_results()
                print_hosts_table(hosts_data)
            
            # Perform intensive scan if -I option is used
            if args.intensive_scan:
                # Only perform intensive scan on the entire network range
                print(f"\nPerforming intensive scan on the entire network range: {network_range}")
                if perform_network_intensive_scan(network_range):
                    print(f"Network-wide intensive scan completed successfully")
                else:
                    print(f"Network-wide intensive scan failed")
            
            # If interval is not set, exit after first scan
            if args.interval <= 0:
                break
                
            first_run = False
            debug_print(f"Waiting {args.interval} seconds until next scan...")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        debug_print("\nScan interrupted by user. Exiting.")
    except Exception as e:
        debug_print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()