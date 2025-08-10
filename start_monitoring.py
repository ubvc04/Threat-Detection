#!/usr/bin/env python3
"""
Quick Start Script for Threat Detection System
Starts both the Django web interface and system monitoring
"""

import subprocess
import sys
import time
import threading
from pathlib import Path

def start_django_server():
    """Start Django development server"""
    print("🌐 Starting Django web server...")
    try:
        subprocess.run([sys.executable, "manage.py", "runserver"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Django server error: {e}")
    except KeyboardInterrupt:
        print("\n🛑 Django server stopped")

def start_system_monitor():
    """Start system monitoring service"""
    print("🔧 Starting system monitoring...")
    try:
        subprocess.run([sys.executable, "system_monitor_service.py", "start"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ System monitor error: {e}")
    except KeyboardInterrupt:
        print("\n🛑 System monitor stopped")

def main():
    """Main function"""
    print("🚀 Starting Threat Detection System...")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("manage.py").exists():
        print("❌ Error: manage.py not found. Please run this script from the project root directory.")
        return
    
    print("📋 Starting services:")
    print("  1. Django Web Interface (http://127.0.0.1:8000/)")
    print("  2. System Monitoring Service")
    print("  3. Network Traffic Analysis")
    print("  4. Process Monitoring")
    print("  5. File System Monitoring")
    print("  6. USB Device Monitoring")
    print()
    
    # Start Django server in a separate thread
    django_thread = threading.Thread(target=start_django_server, daemon=True)
    django_thread.start()
    
    # Wait a moment for Django to start
    time.sleep(3)
    
    # Start system monitoring
    start_system_monitor()

if __name__ == "__main__":
    main() 