#!/usr/bin/env python3
# filepath: /home/gabriwar/scripts/netmon/notifier.py

import socket
import json
import os
import sys
import time
import argparse
from datetime import datetime

# Default socket configurations
SOCKET_PATH = '/tmp/netmon_socket'
BUFFER_SIZE = 4096

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Network device notification listener')
    parser.add_argument('-p', '--path', default=SOCKET_PATH,
                        help=f'Unix socket path (default: {SOCKET_PATH})')
    parser.add_argument('-c', '--command', 
                        help='Command to execute on notification (event details available as $EVENT, $IP, $MAC, $NAME, $VENDOR)',
                        default='notify-send')
    return parser.parse_args()

def setup_socket(socket_path):
    """Set up the Unix domain socket server"""
    # Remove socket file if it already exists
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    
    # Create Unix domain socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(5)
    print(f"Listening for network events on {socket_path}")
    return server

def run_command(command, event_data):
    """Execute a command with event data as environment variables"""
    if not command:
        return
    
    # Create a copy of the environment
    env = os.environ.copy()
    
    # Add event data as environment variables
    event_type = event_data.get('event', '')
    ip = event_data.get('ip', '')
    mac = event_data.get('mac', '')
    name = event_data.get('name', '')
    vendor = event_data.get('vendor', 'Unknown')
    
    # Format message based on event type
    if command == 'notify-send':
        if event_type == 'new':
            title = "⚠️ NEW DEVICE CONNECTED ⚠️"
            message = f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}"
        elif event_type == 'connected':
            if name:
                title = f"{name} connected"
            else:
                title = f"Device connected"
            message = f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}"
        elif event_type == 'disconnected':
            if name:
                title = f"{name} disconnected"
            else:
                title = f"Device disconnected"
            message = f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}"
        else:
            title = f"Network Event: {event_type}"
            message = f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}"
            
        # Execute the notify-send command
        os.system(f'DISPLAY=:0 notify-send "{title}" "{message}"')
    else:
        # For custom commands, set environment variables
        env['EVENT'] = event_type
        env['IP'] = ip
        env['MAC'] = mac
        env['NAME'] = name
        env['VENDOR'] = vendor
        
        # Execute the custom command
        os.system(f'DISPLAY=:0 {command}')

def handle_connection(connection, command=None):
    """Handle incoming connection and process the notification"""
    try:
        # Receive data
        data = connection.recv(BUFFER_SIZE)
        if data:
            # Try to parse as JSON
            try:
                event_data = json.loads(data.decode('utf-8'))
                event_type = event_data.get('event')
                device_name = event_data.get('name', '')
                if not device_name:
                    device_name = event_data.get('mac', 'Unknown device')
                
                # Print notification
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if event_type == 'connected':
                    print(f"[{timestamp}] 🟢 Device connected: {device_name} ({event_data.get('ip')}) - {event_data.get('vendor')}")
                elif event_type == 'disconnected':
                    print(f"[{timestamp}] 🔴 Device disconnected: {device_name} ({event_data.get('ip')}) - {event_data.get('vendor')}")
                elif event_type == 'new':
                    print(f"[{timestamp}] 🆕 New device found: {device_name} ({event_data.get('ip')}) - {event_data.get('vendor')}")
                
                # Run command if specified
                if command:
                    run_command(command, event_data)
                
            except json.JSONDecodeError:
                print(f"Received non-JSON data: {data.decode('utf-8')}")
    finally:
        connection.close()

def main():
    """Main function"""
    args = parse_arguments()
    socket_path = args.path
    command = args.command
    
    try:
        server = setup_socket(socket_path)
        
        while True:
            # Wait for connection
            print("Waiting for notifications...")
            connection, client_address = server.accept()
            handle_connection(connection, command)
            
    except KeyboardInterrupt:
        print("\nShutting down notifier")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'server' in locals():
            server.close()
        # Clean up socket file
        if os.path.exists(socket_path):
            os.unlink(socket_path)

if __name__ == "__main__":
    main()