"""
Threat Detection System - Main Integration Module
Coordinates all detection modules and provides the main entry point
"""

import os
import sys
import time
import threading
import django
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
django.setup()

from detection_core.phishing_detector import phishing_detector
from detection_core.spam_detector import spam_detector
from detection_core.file_scanner import file_scanner
from detection_core.usb_monitor import usb_monitor
from detection_core.network_sniffer import network_sniffer
from detection_core.process_monitor import process_monitor
from detection_core.sysmon_monitor import sysmon_monitor
from dashboard.models import Alert

class ThreatDetectionSystem:
    def __init__(self):
        self.running = False
        self.modules = {
            'phishing_detector': phishing_detector,
            'spam_detector': spam_detector,
            'file_scanner': file_scanner,
            'usb_monitor': usb_monitor,
            'network_sniffer': network_sniffer,
            'process_monitor': process_monitor,
            'sysmon_monitor': sysmon_monitor
        }
        self.module_threads = {}
        
    def start_all_modules(self):
        """Start all detection modules"""
        print("Starting Threat Detection System...")
        
        try:
            # Start USB monitoring
            print("Starting USB monitoring...")
            usb_monitor.start_monitoring()
            
            # Start process monitoring
            print("Starting process monitoring...")
            process_monitor.start_monitoring()
            
            # Start Sysmon monitoring
            print("Starting Sysmon monitoring...")
            sysmon_monitor.start_monitoring()
            
            # Start network sniffing (requires admin privileges)
            try:
                print("Starting network sniffing...")
                network_sniffer.start_sniffing()
            except Exception as e:
                print(f"Warning: Could not start network sniffing (requires admin privileges): {e}")
            
            # Log system startup
            Alert.objects.create(
                alert_type='SYSTEM',
                severity='LOW',
                message='Threat Detection System started successfully',
                source='system_integration',
                details={'status': 'started', 'modules': list(self.modules.keys())}
            )
            
            self.running = True
            print("Threat Detection System started successfully!")
            
        except Exception as e:
            print(f"Error starting Threat Detection System: {e}")
            self.running = False
    
    def stop_all_modules(self):
        """Stop all detection modules"""
        print("Stopping Threat Detection System...")
        
        try:
            # Stop all monitoring modules
            usb_monitor.stop_monitoring()
            process_monitor.stop_monitoring()
            sysmon_monitor.stop_monitoring()
            network_sniffer.stop_sniffing()
            
            # Log system shutdown
            Alert.objects.create(
                alert_type='SYSTEM',
                severity='LOW',
                message='Threat Detection System stopped',
                source='system_integration',
                details={'status': 'stopped'}
            )
            
            self.running = False
            print("Threat Detection System stopped successfully!")
            
        except Exception as e:
            print(f"Error stopping Threat Detection System: {e}")
    
    def get_system_status(self):
        """Get status of all modules"""
        status = {
            'system_running': self.running,
            'modules': {}
        }
        
        for name, module in self.modules.items():
            if hasattr(module, 'monitoring'):
                status['modules'][name] = {
                    'running': module.monitoring,
                    'name': name
                }
            else:
                status['modules'][name] = {
                    'running': True,  # Static modules are always available
                    'name': name
                }
        
        return status
    
    def test_phishing_detection(self, url):
        """Test phishing detection with a URL"""
        try:
            result = phishing_detector.detect_phishing(url, source="test")
            if result:
                print(f"Phishing detected: {url}")
            else:
                print(f"No phishing detected: {url}")
            return result
        except Exception as e:
            print(f"Error testing phishing detection: {e}")
            return False
    
    def test_spam_detection(self, text):
        """Test spam detection with text"""
        try:
            result = spam_detector.detect_spam(text, source="test")
            if result:
                print(f"Spam detected: {text[:50]}...")
            else:
                print(f"No spam detected: {text[:50]}...")
            return result
        except Exception as e:
            print(f"Error testing spam detection: {e}")
            return False
    
    def test_file_scanning(self, file_path):
        """Test file scanning with a file path"""
        try:
            result = file_scanner.detect_malware(file_path, source="test")
            if result:
                print(f"Malware detected: {file_path}")
            else:
                print(f"No malware detected: {file_path}")
            return result
        except Exception as e:
            print(f"Error testing file scanning: {e}")
            return False
    
    def scan_usb_drives(self):
        """Scan all currently connected USB drives"""
        try:
            count = usb_monitor.scan_all_drives()
            print(f"Scanned {count} USB drives")
            return count
        except Exception as e:
            print(f"Error scanning USB drives: {e}")
            return 0
    
    def get_network_stats(self):
        """Get network monitoring statistics"""
        try:
            return network_sniffer.get_connection_stats()
        except Exception as e:
            print(f"Error getting network stats: {e}")
            return {}
    
    def get_process_stats(self):
        """Get process monitoring statistics"""
        try:
            return process_monitor.get_process_stats()
        except Exception as e:
            print(f"Error getting process stats: {e}")
            return {}
    
    def get_sysmon_stats(self):
        """Get Sysmon monitoring statistics"""
        try:
            return sysmon_monitor.get_sysmon_stats()
        except Exception as e:
            print(f"Error getting Sysmon stats: {e}")
            return {}
    
    def run_demo(self):
        """Run a demonstration of the system"""
        print("Running Threat Detection System Demo...")
        
        # Test phishing detection
        print("\n1. Testing Phishing Detection:")
        test_urls = [
            "https://www.google.com",  # Legitimate
            "http://login-bank-secure.verify-account.com",  # Suspicious
            "https://www.microsoft.com",  # Legitimate
        ]
        
        for url in test_urls:
            self.test_phishing_detection(url)
        
        # Test spam detection
        print("\n2. Testing Spam Detection:")
        test_messages = [
            "Hello, how are you?",  # Legitimate
            "URGENT: You've won $1,000,000! Click here now!",  # Spam
            "Meeting reminder for tomorrow at 2 PM",  # Legitimate
        ]
        
        for message in test_messages:
            self.test_spam_detection(message)
        
        # Test USB scanning
        print("\n3. Testing USB Drive Scanning:")
        self.scan_usb_drives()
        
        # Show system statistics
        print("\n4. System Statistics:")
        print(f"Network Stats: {self.get_network_stats()}")
        print(f"Process Stats: {self.get_process_stats()}")
        print(f"Sysmon Stats: {self.get_sysmon_stats()}")
        
        print("\nDemo completed!")

# Global instance
threat_system = ThreatDetectionSystem()

def main():
    """Main entry point"""
    print("=" * 60)
    print("Threat Detection System")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'start':
            threat_system.start_all_modules()
            
            # Keep the system running
            try:
                while threat_system.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down...")
                threat_system.stop_all_modules()
        
        elif command == 'stop':
            threat_system.stop_all_modules()
        
        elif command == 'status':
            status = threat_system.get_system_status()
            print("System Status:")
            for module_name, module_status in status['modules'].items():
                print(f"  {module_name}: {'Running' if module_status['running'] else 'Stopped'}")
        
        elif command == 'demo':
            threat_system.run_demo()
        
        elif command == 'test-phishing':
            if len(sys.argv) > 2:
                url = sys.argv[2]
                threat_system.test_phishing_detection(url)
            else:
                print("Usage: python threat_detection_system.py test-phishing <url>")
        
        elif command == 'test-spam':
            if len(sys.argv) > 2:
                text = sys.argv[2]
                threat_system.test_spam_detection(text)
            else:
                print("Usage: python threat_detection_system.py test-spam <text>")
        
        elif command == 'test-file':
            if len(sys.argv) > 2:
                file_path = sys.argv[2]
                threat_system.test_file_scanning(file_path)
            else:
                print("Usage: python threat_detection_system.py test-file <file_path>")
        
        elif command == 'scan-usb':
            threat_system.scan_usb_drives()
        
        else:
            print("Unknown command. Available commands:")
            print("  start       - Start the threat detection system")
            print("  stop        - Stop the threat detection system")
            print("  status      - Show system status")
            print("  demo        - Run a demonstration")
            print("  test-phishing <url> - Test phishing detection")
            print("  test-spam <text> - Test spam detection")
            print("  test-file <path> - Test file scanning")
            print("  scan-usb    - Scan USB drives")
    
    else:
        print("Usage: python threat_detection_system.py <command>")
        print("Run 'python threat_detection_system.py' for help")

if __name__ == '__main__':
    main() 