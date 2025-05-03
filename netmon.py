#!/usr/bin/env python3
# filepath: /home/gabriwar/scripts/netmon/netmon.py

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import threading
import shutil
from datetime import datetime, timedelta
import requests
import ipaddress
import signal

# Constants
VERSION = "1.0.0"
DEFAULT_SOCKET_PATH = '/tmp/netmon_socket'
DEVICE_DB_FILE = 'network_devices.json'
OUI_FILE = 'oui.csv'
SCAN_DIR = 'scans'

class NetworkMonitor:
    def __init__(self, args):
        """Initialize the network monitor with command line arguments"""
        self.debug = args.debug
        self.interval = args.interval
        self.table_mode = args.table
        self.clear_screen = args.clear
        self.notify = args.notify
        self.socket_path = args.socket
        self.rescan_hosts = args.rescan_hosts
        self.intensive_scan = args.intensive_scan
        self.update_vendors_only = args.update_vendors_only
        
        # Ensure scan directory exists
        if not os.path.exists(SCAN_DIR):
            os.makedirs(SCAN_DIR)
        
        # Load device database
        self.devices = self.load_devices()
        
        # Get network interface and IP information
        self.network_info = self.get_network_info()
        
        # Check for root privileges
        if os.geteuid() != 0 and not self.update_vendors_only:
            print("⚠️  Warning: NetMon requires root privileges for full functionality.")
            print("    Some features may not work correctly when run without sudo.")
            
        # Load or update OUI database if necessary
        if not os.path.exists(OUI_FILE) or self.update_vendors_only:
            self.update_oui_database()
            if self.update_vendors_only:
                sys.exit(0)
    
    def log(self, message, level="INFO"):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if level == "DEBUG" and not self.debug:
            return
        
        level_prefix = {
            "INFO": "ℹ️",
            "DEBUG": "🔍",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "SUCCESS": "✅"
        }.get(level, "")
        
        print(f"[{timestamp}] {level_prefix} {message}")
    
    def load_devices(self):
        """Load device information from JSON file"""
        if os.path.exists(DEVICE_DB_FILE):
            try:
                with open(DEVICE_DB_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, PermissionError) as e:
                self.log(f"Error loading device database: {e}", "ERROR")
                return {}
        else:
            return {}
    
    def save_devices(self):
        """Save device information to JSON file"""
        try:
            with open(DEVICE_DB_FILE, 'w') as f:
                json.dump(self.devices, f, indent=2)
        except PermissionError as e:
            self.log(f"Error saving device database: {e}", "ERROR")
    
    def get_network_info(self):
        """Get network interface and IP information"""
        try:
            # Get default route interface
            route_cmd = subprocess.run(['ip', 'route', 'show', 'default'], 
                                       capture_output=True, text=True)
            interface_match = re.search(r'dev\s+(\w+)', route_cmd.stdout)
            
            if not interface_match:
                self.log("Could not determine default network interface", "ERROR")
                return None
            
            interface = interface_match.group(1)
            
            # Get IP address and network CIDR
            ip_cmd = subprocess.run(['ip', '-f', 'inet', 'addr', 'show', interface], 
                                   capture_output=True, text=True)
            ip_match = re.search(r'inet\s+([0-9.]+)/(\d+)', ip_cmd.stdout)
            
            if not ip_match:
                self.log(f"Could not determine IP address for interface {interface}", "ERROR")
                return None
            
            ip_address = ip_match.group(1)
            cidr = ip_match.group(2)
            network = str(ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False))
            
            self.log(f"Network information: Interface={interface}, IP={ip_address}, Network={network}", "DEBUG")
            
            return {
                "interface": interface,
                "ip_address": ip_address,
                "network": network
            }
            
        except (subprocess.SubprocessError, OSError) as e:
            self.log(f"Error determining network information: {e}", "ERROR")
            return None
    
    def update_oui_database(self):
        """Update MAC vendor database from IEEE"""
        self.log("Updating MAC vendor database...", "INFO")
        
        try:
            # Download the OUI database from IEEE
            response = requests.get('http://standards-oui.ieee.org/oui/oui.csv')
            response.raise_for_status()
            
            # Save the database
            with open(OUI_FILE, 'w', encoding='utf-8') as f:
                f.write(response.text)
                
            self.log("MAC vendor database updated successfully", "SUCCESS")
            
        except (requests.RequestException, IOError) as e:
            self.log(f"Error updating MAC vendor database: {e}", "ERROR")
    
    def lookup_vendor(self, mac):
        """Look up vendor from MAC address using OUI database"""
        if not mac or not os.path.exists(OUI_FILE):
            return "Unknown"
        
        # Format MAC prefix for lookup
        mac_prefix = mac.replace(':', '').upper()[0:6]
        
        try:
            with open(OUI_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if mac_prefix in line:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            return parts[2].strip('"')
        except IOError as e:
            self.log(f"Error reading OUI database: {e}", "ERROR")
            
        return "Unknown"
    
    def scan_network(self, intensive=False):
        """Scan the network for connected devices"""
        if not self.network_info:
            self.log("Cannot scan network: network information not available", "ERROR")
            return {}
        
        network = self.network_info["network"]
        self.log(f"Scanning network: {network}...", "INFO")
        
        current_time = datetime.now()
        connected_devices = {}
        
        try:
            if intensive:
                # Perform intensive scan with nmap
                self.log("Starting intensive network scan (this may take several minutes)...", "INFO")
                
                # Generate output filename with timestamp
                timestamp = current_time.strftime("%Y%m%d_%H%M%S")
                output_file = f"{SCAN_DIR}/scan_{timestamp}"
                
                # Run nmap with XML output
                nmap_cmd = [
                    'nmap', '-sS', '-sV', '-O', '--osscan-guess', 
                    '-T4', network, '-oX', f"{output_file}.xml"
                ]
                
                # Execute nmap scan with progress monitoring
                process = subprocess.Popen(
                    nmap_cmd, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                # Show progress
                for line in iter(process.stdout.readline, ''):
                    if "Nmap scan report for" in line:
                        ip = line.split("for ")[1].strip()
                        self.log(f"Scanning: {ip}", "INFO")
                    elif "% done" in line:
                        print(f"\r{line.strip()}", end='')
                    
                process.stdout.close()
                return_code = process.wait()
                
                if return_code != 0:
                    self.log(f"Nmap scan failed with return code {return_code}", "ERROR")
                else:
                    self.log(f"Intensive scan complete! Results saved to {output_file}.xml", "SUCCESS")
                
                # Parse XML output to get device information
                try:
                    # Simple XML parsing to extract basic information
                    with open(f"{output_file}.xml", 'r') as f:
                        xml_content = f.read()
                        
                    # Extract hosts with IP and MAC
                    host_blocks = re.findall(r'<host[^>]*>(.*?)</host>', xml_content, re.DOTALL)
                    
                    for host in host_blocks:
                        # Extract IP address
                        ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', host)
                        if not ip_match:
                            continue
                            
                        ip = ip_match.group(1)
                        
                        # Extract MAC address
                        mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"', host)
                        mac = mac_match.group(1) if mac_match else None
                        
                        # Extract hostname if available
                        hostname_match = re.search(r'<hostname name="([^"]+)"', host)
                        hostname = hostname_match.group(1) if hostname_match else ""
                        
                        # Create device entry
                        device = {
                            "ip": ip,
                            "connected": True,
                            "last_seen": current_time.isoformat(),
                            "first_seen": current_time.isoformat()
                        }
                        
                        if mac:
                            device["mac"] = mac
                            vendor = self.lookup_vendor(mac)
                            device["vendor"] = vendor
                            
                        if hostname:
                            device["name"] = hostname
                            
                        connected_devices[ip] = device
                        
                except Exception as e:
                    self.log(f"Error parsing nmap XML output: {e}", "ERROR")
            
            else:
                # Perform standard scan with ping sweep
                ping_cmd = ['nmap', '-sn', network]
                ping_result = subprocess.run(ping_cmd, capture_output=True, text=True)
                
                # Extract IP addresses from nmap output
                ip_matches = re.finditer(r'Nmap scan report for (?:([^\s]+) )?\(([0-9.]+)\)', ping_result.stdout)
                
                for match in ip_matches:
                    hostname = match.group(1)
                    ip = match.group(2)
                    
                    # Skip local IP
                    if ip == self.network_info["ip_address"]:
                        continue
                        
                    # Try to get MAC address for this IP
                    mac = self.get_mac_address(ip)
                    
                    # Create device entry
                    device = {
                        "ip": ip,
                        "connected": True,
                        "last_seen": current_time.isoformat(),
                        "first_seen": current_time.isoformat()
                    }
                    
                    if mac:
                        device["mac"] = mac
                        vendor = self.lookup_vendor(mac)
                        device["vendor"] = vendor
                        
                    if hostname:
                        device["name"] = hostname
                        
                    connected_devices[ip] = device
            
            self.log(f"Found {len(connected_devices)} active devices on the network", "INFO")
            return connected_devices
            
        except (subprocess.SubprocessError, OSError) as e:
            self.log(f"Error scanning network: {e}", "ERROR")
            return {}
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP using arp"""
        try:
            arp_cmd = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            mac_match = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', arp_cmd.stdout, re.IGNORECASE)
            
            if mac_match:
                return mac_match.group(1).lower()
            else:
                # Try to ping the device to update ARP cache and try again
                subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                arp_cmd = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                mac_match = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', arp_cmd.stdout, re.IGNORECASE)
                
                if mac_match:
                    return mac_match.group(1).lower()
                    
                return None
                
        except (subprocess.SubprocessError, OSError) as e:
            self.log(f"Error getting MAC address for {ip}: {e}", "DEBUG")
            return None
    
    def update_device_status(self, scan_results):
        """Update device status based on scan results"""
        current_time = datetime.now()
        notifications = []
        
        # Check for new or reconnected devices
        for ip, device in scan_results.items():
            if ip in self.devices:
                existing_device = self.devices[ip]
                
                # Update device information
                existing_device["last_seen"] = current_time.isoformat()
                existing_device["ip"] = ip  # Ensure IP is updated
                
                # Update MAC address if it's missing but we found it now
                if "mac" not in existing_device and "mac" in device:
                    existing_device["mac"] = device["mac"]
                    existing_device["vendor"] = device["vendor"]
                
                # Update hostname if it's missing but we found it now
                if "name" not in existing_device and "name" in device:
                    existing_device["name"] = device["name"]
                
                # Force rescan if requested
                if self.rescan_hosts:
                    if "mac" in device:
                        existing_device["mac"] = device["mac"]
                        existing_device["vendor"] = device["vendor"]
                    if "name" in device:
                        existing_device["name"] = device["name"]
                
                # Check if it was previously disconnected
                if not existing_device.get("connected", True):
                    existing_device["connected"] = True
                    
                    # Create notification for reconnected device
                    if self.notify:
                        notifications.append({
                            "event": "connected",
                            "ip": ip,
                            "mac": existing_device.get("mac", ""),
                            "name": existing_device.get("name", ""),
                            "vendor": existing_device.get("vendor", "Unknown")
                        })
                        
                    self.log(f"Device reconnected: {ip} {existing_device.get('name', '')}", "INFO")
            else:
                # New device discovered
                new_device = device.copy()
                new_device["first_seen"] = current_time.isoformat()
                new_device["last_seen"] = current_time.isoformat()
                new_device["connected"] = True
                
                self.devices[ip] = new_device
                
                # Create notification for new device
                if self.notify:
                    notifications.append({
                        "event": "new",
                        "ip": ip,
                        "mac": new_device.get("mac", ""),
                        "name": new_device.get("name", ""),
                        "vendor": new_device.get("vendor", "Unknown")
                    })
                    
                self.log(f"New device discovered: {ip} {new_device.get('name', '')} {new_device.get('vendor', '')}", "INFO")
        
        # Check for disconnected devices
        for ip, device in self.devices.items():
            if ip not in scan_results and device.get("connected", False):
                device["connected"] = False
                
                # Create notification for disconnected device
                if self.notify:
                    notifications.append({
                        "event": "disconnected",
                        "ip": ip,
                        "mac": device.get("mac", ""),
                        "name": device.get("name", ""),
                        "vendor": device.get("vendor", "Unknown")
                    })
                    
                self.log(f"Device disconnected: {ip} {device.get('name', '')}", "INFO")
        
        # Send notifications
        for notification in notifications:
            self.send_notification(notification)
        
        return len(notifications) > 0
    
    def send_notification(self, event_data):
        """Send notification through Unix socket"""
        if not self.notify:
            return
            
        try:
            # Create client socket
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            
            # Try to connect to the socket
            try:
                client.connect(self.socket_path)
            except socket.error:
                self.log(f"Could not connect to notification socket at {self.socket_path}", "WARNING")
                self.log("Make sure the notifier script is running", "WARNING")
                return
                
            # Send JSON event data
            message = json.dumps(event_data)
            client.sendall(message.encode('utf-8'))
            client.close()
            
        except Exception as e:
            self.log(f"Error sending notification: {e}", "ERROR")
    
    def print_table(self):
        """Print a formatted table of connected devices"""
        # Clear screen if requested
        if self.clear_screen:
            os.system('clear')
            
        # Print table header
        current_time = datetime.now()
        print(f"\n🌐 NETWORK DEVICES - {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Network: {self.network_info['network']} (Interface: {self.network_info['interface']})")
        print("-" * 110)
        print(f"{'STATUS':<10} {'IP ADDRESS':<15} {'MAC ADDRESS':<18} {'VENDOR':<25} {'NAME':<20} {'UPTIME':<20}")
        print("-" * 110)
        
        # Sort devices by IP address
        sorted_ips = sorted(self.devices.keys(), 
                           key=lambda ip: [int(octet) for octet in ip.split('.')])
        
        # Print device information
        for ip in sorted_ips:
            device = self.devices[ip]
            
            # Get status
            if device.get("connected", False):
                status = "🟢 ONLINE"
                
                # Calculate uptime
                if "first_seen" in device:
                    first_seen = datetime.fromisoformat(device["first_seen"])
                    uptime = current_time - first_seen
                    uptime_str = self.format_uptime(uptime)
                else:
                    uptime_str = "Unknown"
            else:
                status = "🔴 OFFLINE"
                uptime_str = ""
                
                # Skip offline devices unless in debug mode
                if not self.debug:
                    continue
            
            # Print device row
            print(f"{status:<10} {ip:<15} {device.get('mac', ''):<18} {device.get('vendor', 'Unknown'):<25} "
                  f"{device.get('name', ''):<20} {uptime_str:<20}")
            
        print("-" * 110)
        print(f"Total devices: {len(self.devices)} ({sum(1 for d in self.devices.values() if d.get('connected', False))} online)")
    
    def format_uptime(self, delta):
        """Format timedelta as readable uptime string"""
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        else:
            return f"{minutes}m {seconds}s"
    
    def run(self):
        """Run the network monitor"""
        try:
            # If intensive scan requested, run it once and exit
            if self.intensive_scan:
                self.log("Starting intensive network scan...", "INFO")
                scan_results = self.scan_network(intensive=True)
                self.update_device_status(scan_results)
                self.save_devices()
                self.log("Intensive scan completed", "SUCCESS")
                return
                
            # Initial scan
            self.log("Starting network monitor...", "INFO")
            scan_results = self.scan_network()
            self.update_device_status(scan_results)
            self.save_devices()
            
            # Print initial table if requested
            if self.table_mode:
                self.print_table()
                
            # If no interval specified, exit after first scan
            if not self.interval:
                return
                
            # Setup signal handler for graceful exit
            def signal_handler(sig, frame):
                self.log("\nExiting network monitor...", "INFO")
                self.save_devices()
                sys.exit(0)
                
            signal.signal(signal.SIGINT, signal_handler)
            
            # Continuous scanning
            self.log(f"Monitoring network every {self.interval} seconds. Press Ctrl+C to stop.", "INFO")
            
            while True:
                # Wait for the next scan
                time.sleep(self.interval)
                
                # Perform scan
                scan_results = self.scan_network()
                changes = self.update_device_status(scan_results)
                self.save_devices()
                
                # Print table if in table mode or if changes detected
                if self.table_mode or changes:
                    self.print_table()
                    
        except KeyboardInterrupt:
            self.log("\nExiting network monitor...", "INFO")
            self.save_devices()
        except Exception as e:
            self.log(f"Error in network monitor: {e}", "ERROR")
            self.save_devices()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='NetMon - Network Device Monitor')
    
    parser.add_argument('-D', '--debug', action='store_true',
                        help='Enable debug output')
    parser.add_argument('-i', '--interval', type=int, 
                        help='Scan interval in seconds (default: run once)')
    parser.add_argument('-T', '--table', action='store_true',
                        help='Print a table of connected hosts')
    parser.add_argument('-C', '--clear', action='store_true',
                        help='Clear screen before each output')
    parser.add_argument('-N', '--notify', action='store_true',
                        help='Send notifications when devices connect/disconnect')
    parser.add_argument('-S', '--socket', default=DEFAULT_SOCKET_PATH,
                        help=f'Path to notification socket (default: {DEFAULT_SOCKET_PATH})')
    parser.add_argument('-H', '--rescan-hosts', action='store_true',
                        help='Force rescan of MAC, hostname and vendor info for all devices')
    parser.add_argument('-I', '--intensive-scan', action='store_true',
                        help='Perform intensive nmap scan on the entire network')
    parser.add_argument('-U', '--update-vendors-only', action='store_true',
                        help='Update MAC vendor information only')
    parser.add_argument('-v', '--version', action='version',
                        version=f'NetMon v{VERSION}')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    monitor = NetworkMonitor(args)
    monitor.run()

if __name__ == "__main__":
    main()