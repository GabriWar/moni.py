#!/usr/bin/env python3
# filepath: wifi_notifier.py
# This script runs as a regular user and displays notifications from the root wifi_monitor.py script

import os
import json
import subprocess
import sys
import signal
import time

FIFO_PATH = '/tmp/wifi_monitor_pipe'

def create_fifo():
    """Create the FIFO pipe if it doesn't exist"""
    # Wait for up to 5 seconds for pipe to be created by monitor
    timeout = 5
    while timeout > 0 and not os.path.exists(FIFO_PATH):
        print(f"Waiting for pipe to be created... ({timeout}s left)")
        time.sleep(1)
        timeout -= 1
        
    if not os.path.exists(FIFO_PATH):
        try:
            os.mkfifo(FIFO_PATH)
            print(f"Created notification pipe at {FIFO_PATH}")
        except Exception as e:
            print(f"Error creating pipe: {e}")
            print("Try running the wifi_monitor.py script as root first")
            sys.exit(1)
    
    # Try to make sure the pipe is readable and writable by everyone
    try:
        os.chmod(FIFO_PATH, 0o666)
    except Exception as e:
        print(f"Warning: Could not set pipe permissions: {e}")
        print("If the wifi_monitor.py script is running as root, it will set the permissions.")
    
    print("Notification pipe is ready")

def send_notification(title, message):
    """Send a desktop notification using notify-send"""
    try:
        # Use os.system to call notify-send directly
        os.system(f'notify-send "{title}" "{message}"')
    except Exception as e:
        print(f"Notification error: {e}")
    print(f"{title}: {message}")

def read_notifications():
    """Read and process notifications from the pipe"""
    print("Waiting for notifications from WiFi monitor...")
    print("Press Ctrl+C to exit")
    
    try:
        while True:
            # Open the pipe for reading (this blocks until there's data)
            with open(FIFO_PATH, 'r') as pipe:
                for line in pipe:
                    try:
                        data = json.loads(line.strip())
                        title = data.get('title', 'WiFi Monitor')
                        message = data.get('message', 'New device detected')
                        send_notification(title, message)
                    except json.JSONDecodeError:
                        print(f"Error parsing notification: {line}")
    except KeyboardInterrupt:
        print("\nExiting notifier")
    finally:
        # Clean up is optional since the pipe is persistent
        pass

def cleanup(signum=None, frame=None):
    """Clean up before exit"""
    if os.path.exists(FIFO_PATH):
        os.unlink(FIFO_PATH)
    sys.exit(0)

if __name__ == "__main__":
    # Handle signals for clean exit
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    
    # Create the FIFO pipe
    create_fifo()
    
    try:
        # Start the notification monitor
        read_notifications()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cleanup()
