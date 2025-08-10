#!/usr/bin/env python3
"""
System Monitor Service
Actively monitors system network, processes, and activities
Integrates with Django dashboard for real-time threat detection
"""

import os
import sys
import time
import threading
import django
from pathlib import Path
import psutil
import json
from datetime import datetime

# Add the project directory to Python path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
django.setup()

from detection_core.network_sniffer import NetworkSniffer
from detection_core.process_monitor import ProcessMonitor
from detection_core.file_scanner import FileScanner
from detection_core.usb_monitor import USBMonitor
from detection_core.sysmon_monitor import SysmonMonitor
from dashboard.models import Alert, SystemInfo, ProcessLog

class SystemMonitorService:
    def __init__(self):
        self.running = False
        self.monitors = {}
        self.monitor_threads = {}
        
        # Initialize monitoring components
        self.network_sniffer = NetworkSniffer()
        self.process_monitor = ProcessMonitor()
        self.file_scanner = FileScanner()
        self.usb_monitor = USBMonitor()
        self.sysmon_monitor = SysmonMonitor()
        
        print("🔧 System Monitor Service initialized")
    
    def start_monitoring(self):
        """Start all monitoring services"""
        if self.running:
            print("⚠️  Monitoring is already running")
            return
        
        print("🚀 Starting System Monitoring...")
        self.running = True
        
        # Start network monitoring
        self.start_network_monitoring()
        
        # Start process monitoring
        self.start_process_monitoring()
        
        # Start file system monitoring
        self.start_file_monitoring()
        
        # Start USB monitoring
        self.start_usb_monitoring()
        
        # Start system info collection
        self.start_system_info_collection()
        
        print("✅ All monitoring services started successfully!")
        print("📊 Dashboard available at: http://127.0.0.1:8000/")
    
    def start_network_monitoring(self):
        """Start network traffic monitoring"""
        def network_monitor():
            try:
                print("🌐 Starting network monitoring...")
                interfaces = self.network_sniffer.get_network_interfaces()
                if interfaces:
                    # Start sniffing on the first available interface
                    self.network_sniffer.start_sniffing(interface=interfaces[0])
                else:
                    print("⚠️  No network interfaces found")
            except Exception as e:
                print(f"❌ Network monitoring error: {e}")
        
        thread = threading.Thread(target=network_monitor, daemon=True)
        thread.start()
        self.monitor_threads['network'] = thread
    
    def start_process_monitoring(self):
        """Start process monitoring"""
        def process_monitor():
            try:
                print("⚙️  Starting process monitoring...")
                self.process_monitor.start_monitoring()
            except Exception as e:
                print(f"❌ Process monitoring error: {e}")
        
        thread = threading.Thread(target=process_monitor, daemon=True)
        thread.start()
        self.monitor_threads['process'] = thread
    
    def start_file_monitoring(self):
        """Start file system monitoring"""
        def file_monitor():
            try:
                print("📁 Starting file system monitoring...")
                # Monitor common directories for suspicious files
                watch_dirs = [
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    os.path.expanduser("~/Documents"),
                    "C:/Windows/Temp",
                    "C:/Temp"
                ]
                
                for directory in watch_dirs:
                    if os.path.exists(directory):
                        self.file_scanner.watch_directory(directory)
            except Exception as e:
                print(f"❌ File monitoring error: {e}")
        
        thread = threading.Thread(target=file_monitor, daemon=True)
        thread.start()
        self.monitor_threads['file'] = thread
    
    def start_usb_monitoring(self):
        """Start USB device monitoring"""
        def usb_monitor():
            try:
                print("💾 Starting USB monitoring...")
                self.usb_monitor.start_monitoring()
            except Exception as e:
                print(f"❌ USB monitoring error: {e}")
        
        thread = threading.Thread(target=usb_monitor, daemon=True)
        thread.start()
        self.monitor_threads['usb'] = thread
    
    def start_system_info_collection(self):
        """Start collecting system information"""
        def system_info_collector():
            try:
                print("📊 Starting system info collection...")
                while self.running:
                    try:
                        # Collect system statistics
                        cpu_percent = psutil.cpu_percent(interval=1)
                        memory = psutil.virtual_memory()
                        disk = psutil.disk_usage('/')
                        
                        # Get network connections
                        connections = len(psutil.net_connections())
                        
                        # Get active processes
                        active_processes = len(psutil.pids())
                        
                        # Save to database
                        SystemInfo.objects.create(
                            cpu_percent=cpu_percent,
                            memory_percent=memory.percent,
                            disk_usage=disk.percent,
                            network_connections=connections,
                            active_processes=active_processes
                        )
                        
                        # Log suspicious processes
                        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                            try:
                                if proc.info['cpu_percent'] > 50 or proc.info['memory_percent'] > 10:
                                    ProcessLog.objects.create(
                                        process_name=proc.info['name'],
                                        process_id=proc.info['pid'],
                                        cpu_percent=proc.info['cpu_percent'],
                                        memory_percent=proc.info['memory_percent'],
                                        suspicious=proc.info['cpu_percent'] > 80
                                    )
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                        
                        time.sleep(30)  # Collect every 30 seconds
                        
                    except Exception as e:
                        print(f"⚠️  System info collection error: {e}")
                        time.sleep(60)  # Wait longer on error
                        
            except Exception as e:
                print(f"❌ System info collection error: {e}")
        
        thread = threading.Thread(target=system_info_collector, daemon=True)
        thread.start()
        self.monitor_threads['system_info'] = thread
    
    def create_alert(self, alert_type, message, severity='MEDIUM', source='System Monitor', details=None):
        """Create an alert in the database"""
        try:
            Alert.objects.create(
                alert_type=alert_type,
                severity=severity,
                message=message,
                source=source,
                details=details or {}
            )
            print(f"🚨 Alert created: {alert_type} - {message}")
        except Exception as e:
            print(f"❌ Error creating alert: {e}")
    
    def stop_monitoring(self):
        """Stop all monitoring services"""
        if not self.running:
            print("⚠️  Monitoring is not running")
            return
        
        print("🛑 Stopping System Monitoring...")
        self.running = False
        
        # Stop network monitoring
        if hasattr(self.network_sniffer, 'stop_sniffing'):
            self.network_sniffer.stop_sniffing()
        
        # Stop process monitoring
        if hasattr(self.process_monitor, 'stop_monitoring'):
            self.process_monitor.stop_monitoring()
        
        # Stop USB monitoring
        if hasattr(self.usb_monitor, 'stop_monitoring'):
            self.usb_monitor.stop_monitoring()
        
        # Wait for threads to finish
        for thread_name, thread in self.monitor_threads.items():
            if thread.is_alive():
                thread.join(timeout=5)
        
        print("✅ All monitoring services stopped")
    
    def get_status(self):
        """Get monitoring status"""
        status = {
            'running': self.running,
            'monitors': {}
        }
        
        for monitor_name, thread in self.monitor_threads.items():
            status['monitors'][monitor_name] = {
                'active': thread.is_alive(),
                'name': monitor_name
            }
        
        return status
    
    def run_demo(self):
        """Run a demo with sample alerts"""
        print("🎭 Running System Monitor Demo...")
        
        # Create sample alerts
        sample_alerts = [
            ('NETWORK', 'Suspicious connection detected to 192.168.1.100', 'HIGH'),
            ('PROCESS', 'High CPU usage detected in chrome.exe (85%)', 'MEDIUM'),
            ('USB', 'New USB device connected: Kingston DataTraveler', 'LOW'),
            ('SYSTEM', 'System memory usage at 78%', 'MEDIUM'),
            ('MALWARE', 'Suspicious file detected: suspicious_file.exe', 'CRITICAL'),
        ]
        
        for alert_type, message, severity in sample_alerts:
            self.create_alert(alert_type, message, severity)
            time.sleep(2)
        
        print("✅ Demo completed!")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='System Monitor Service')
    parser.add_argument('action', choices=['start', 'stop', 'status', 'demo'], 
                       help='Action to perform')
    
    args = parser.parse_args()
    
    service = SystemMonitorService()
    
    if args.action == 'start':
        service.start_monitoring()
        try:
            # Keep the service running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Received interrupt signal")
            service.stop_monitoring()
    
    elif args.action == 'stop':
        service.stop_monitoring()
    
    elif args.action == 'status':
        status = service.get_status()
        print("📊 System Monitor Status:")
        print(f"  Running: {status['running']}")
        print("  Monitors:")
        for monitor_name, monitor_info in status['monitors'].items():
            status_icon = "✅" if monitor_info['active'] else "❌"
            print(f"    {status_icon} {monitor_name}: {'Active' if monitor_info['active'] else 'Inactive'}")
    
    elif args.action == 'demo':
        service.run_demo()

if __name__ == '__main__':
    main() 