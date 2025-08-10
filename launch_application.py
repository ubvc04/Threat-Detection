#!/usr/bin/env python3
"""
Advanced Threat Detection System - Application Launcher
Professional launcher for all system components
"""

import os
import sys
import time
import threading
import subprocess
import signal
import psutil
from datetime import datetime
from pathlib import Path

class ThreatDetectionLauncher:
    def __init__(self):
        self.project_dir = Path(__file__).resolve().parent
        self.processes = {}
        self.running = False
        
        # Service configurations
        self.services = {
            'django': {
                'name': 'Django Web Server',
                'command': ['python', 'manage.py', 'runserver'],
                'port': 8000,
                'required': True,
                'description': 'Web dashboard and API server'
            },
            'kernel_monitoring': {
                'name': 'Kernel-Level Monitoring',
                'command': ['python', 'advanced_kernel_monitoring.py', 'start'],
                'required': False,
                'description': 'Advanced kernel-level threat detection'
            },
            'system_monitor': {
                'name': 'System Monitor Service',
                'command': ['python', 'system_monitor_service.py', 'start'],
                'required': False,
                'description': 'System resource monitoring service'
            }
        }
        
        print("🛡️ Advanced Threat Detection System - Application Launcher")
        print("=" * 60)
    
    def check_prerequisites(self):
        """Check if all prerequisites are met"""
        print("🔍 Checking prerequisites...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8+ required")
            return False
        
        # Check Django
        try:
            import django
            print(f"✅ Django {django.get_version()} found")
        except ImportError:
            print("❌ Django not found. Please install requirements.")
            return False
        
        # Check required packages
        required_packages = ['psutil', 'scapy', 'yara']
        for package in required_packages:
            try:
                __import__(package)
                print(f"✅ {package} found")
            except ImportError:
                print(f"⚠️ {package} not found (some features may be limited)")
        
        # Check database
        if not os.path.exists('db.sqlite3'):
            print("⚠️ Database not found. Will be created on first run.")
        
        print("✅ Prerequisites check completed")
        return True
    
    def setup_database(self):
        """Setup Django database"""
        print("🗄️ Setting up database...")
        try:
            # Run migrations
            subprocess.run(['python', 'manage.py', 'makemigrations'], 
                         capture_output=True, text=True)
            subprocess.run(['python', 'manage.py', 'migrate'], 
                         capture_output=True, text=True)
            print("✅ Database setup completed")
            return True
        except Exception as e:
            print(f"❌ Database setup failed: {e}")
            return False
    
    def start_service(self, service_name, service_config):
        """Start a specific service"""
        try:
            print(f"🚀 Starting {service_config['name']}...")
            
            # Start the process
            process = subprocess.Popen(
                service_config['command'],
                cwd=self.project_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.processes[service_name] = {
                'process': process,
                'config': service_config,
                'start_time': datetime.now()
            }
            
            # Wait a moment to check if it started successfully
            time.sleep(2)
            
            if process.poll() is None:
                print(f"✅ {service_config['name']} started successfully")
                return True
            else:
                print(f"❌ {service_config['name']} failed to start")
                return False
                
        except Exception as e:
            print(f"❌ Error starting {service_config['name']}: {e}")
            return False
    
    def stop_service(self, service_name):
        """Stop a specific service"""
        if service_name in self.processes:
            process_info = self.processes[service_name]
            process = process_info['process']
            
            print(f"🛑 Stopping {process_info['config']['name']}...")
            
            try:
                # Try graceful shutdown
                process.terminate()
                process.wait(timeout=5)
                print(f"✅ {process_info['config']['name']} stopped gracefully")
            except subprocess.TimeoutExpired:
                # Force kill if needed
                process.kill()
                print(f"⚠️ {process_info['config']['name']} force stopped")
            
            del self.processes[service_name]
    
    def start_all_services(self):
        """Start all configured services"""
        print("🚀 Starting all services...")
        
        # Start required services first
        for service_name, service_config in self.services.items():
            if service_config['required']:
                if not self.start_service(service_name, service_config):
                    print(f"❌ Failed to start required service: {service_config['name']}")
                    return False
        
        # Start optional services
        for service_name, service_config in self.services.items():
            if not service_config['required']:
                self.start_service(service_name, service_config)
        
        self.running = True
        print("✅ All services started successfully")
        return True
    
    def stop_all_services(self):
        """Stop all running services"""
        print("🛑 Stopping all services...")
        
        for service_name in list(self.processes.keys()):
            self.stop_service(service_name)
        
        self.running = False
        print("✅ All services stopped")
    
    def show_status(self):
        """Show status of all services"""
        print("\n📊 Service Status:")
        print("-" * 50)
        
        for service_name, service_config in self.services.items():
            status = "🟢 Running" if service_name in self.processes else "🔴 Stopped"
            print(f"{service_config['name']:<25} {status}")
            print(f"{'':25} {service_config['description']}")
            print()
    
    def show_menu(self):
        """Show main menu"""
        print("\n🎛️ Application Control Menu:")
        print("=" * 40)
        print("1. Start All Services")
        print("2. Stop All Services")
        print("3. Show Service Status")
        print("4. Open Web Dashboard")
        print("5. View Logs")
        print("6. System Information")
        print("7. Exit")
        print("=" * 40)
    
    def open_web_dashboard(self):
        """Open web dashboard in default browser"""
        import webbrowser
        
        urls = [
            "http://127.0.0.1:8000/dashboard/",
            "http://127.0.0.1:8000/dashboard/kernel-monitoring/",
            "http://127.0.0.1:8000/dashboard/alerts/"
        ]
        
        print("🌐 Opening web dashboard...")
        for url in urls:
            try:
                webbrowser.open(url)
                time.sleep(1)
            except Exception as e:
                print(f"⚠️ Could not open {url}: {e}")
    
    def view_logs(self):
        """View system logs"""
        log_files = [
            'logs/threat_detection.log',
            'logs/system_monitor.log',
            'logs/kernel_monitor.log'
        ]
        
        print("📋 Available Log Files:")
        for log_file in log_files:
            if os.path.exists(log_file):
                size = os.path.getsize(log_file)
                print(f"📄 {log_file} ({size} bytes)")
            else:
                print(f"📄 {log_file} (not found)")
    
    def show_system_info(self):
        """Show system information"""
        print("\n💻 System Information:")
        print("-" * 30)
        
        # CPU info
        cpu_percent = psutil.cpu_percent(interval=1)
        print(f"CPU Usage: {cpu_percent}%")
        
        # Memory info
        memory = psutil.virtual_memory()
        print(f"Memory Usage: {memory.percent}% ({memory.used // (1024**3)}GB / {memory.total // (1024**3)}GB)")
        
        # Disk info
        disk = psutil.disk_usage('/')
        print(f"Disk Usage: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)")
        
        # Network info
        network = psutil.net_io_counters()
        print(f"Network: {network.bytes_sent // (1024**2)}MB sent, {network.bytes_recv // (1024**2)}MB received")
    
    def run_interactive(self):
        """Run interactive mode"""
        while True:
            self.show_menu()
            
            try:
                choice = input("Enter your choice (1-7): ").strip()
                
                if choice == '1':
                    if not self.running:
                        if self.start_all_services():
                            print("🎉 All services started successfully!")
                            print("🌐 Access your dashboard at: http://127.0.0.1:8000/dashboard/")
                    else:
                        print("⚠️ Services are already running")
                
                elif choice == '2':
                    if self.running:
                        self.stop_all_services()
                    else:
                        print("⚠️ No services are running")
                
                elif choice == '3':
                    self.show_status()
                
                elif choice == '4':
                    if self.running:
                        self.open_web_dashboard()
                    else:
                        print("⚠️ Please start services first")
                
                elif choice == '5':
                    self.view_logs()
                
                elif choice == '6':
                    self.show_system_info()
                
                elif choice == '7':
                    if self.running:
                        print("🛑 Stopping all services before exit...")
                        self.stop_all_services()
                    print("👋 Goodbye!")
                    break
                
                else:
                    print("❌ Invalid choice. Please try again.")
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n🛑 Interrupted by user")
                if self.running:
                    self.stop_all_services()
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def run_auto(self):
        """Run automatic mode - start all services and keep running"""
        print("🤖 Running in automatic mode...")
        
        if not self.check_prerequisites():
            print("❌ Prerequisites check failed")
            return False
        
        if not self.setup_database():
            print("❌ Database setup failed")
            return False
        
        if not self.start_all_services():
            print("❌ Failed to start services")
            return False
        
        print("🎉 All services started successfully!")
        print("🌐 Access your dashboard at: http://127.0.0.1:8000/dashboard/")
        print("🔄 Press Ctrl+C to stop all services")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
            self.stop_all_services()
            print("✅ Shutdown complete")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Threat Detection System Launcher')
    parser.add_argument('--auto', action='store_true', 
                       help='Run in automatic mode (start all services)')
    parser.add_argument('--check', action='store_true',
                       help='Check prerequisites only')
    
    args = parser.parse_args()
    
    launcher = ThreatDetectionLauncher()
    
    if args.check:
        launcher.check_prerequisites()
    elif args.auto:
        launcher.run_auto()
    else:
        launcher.run_interactive()

if __name__ == '__main__':
    main() 