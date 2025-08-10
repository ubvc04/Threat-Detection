#!/usr/bin/env python3
"""
Optimized Windows Advanced Threat Detection System
Reduces false positives and focuses on real security threats
"""

import os
import sys
import time
import threading
import json
import requests
import hashlib
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    print("⚠️  YARA not available - malware detection will be limited")
    YARA_AVAILABLE = False

try:
    import virustotal_python
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    print("⚠️  VirusTotal not available - cloud malware scanning disabled")
    VIRUSTOTAL_AVAILABLE = False

from pathlib import Path
from datetime import datetime, timedelta
import psutil
import socket
import subprocess
import winreg
import win32api
import win32process
import win32security
import win32con
import win32file

# Add project path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
import django
django.setup()

from dashboard.models import Alert, SystemInfo, ProcessLog

class OptimizedWindowsThreatDetection:
    def __init__(self):
        self.running = False
        self.vt_api_key = None
        self.suspicious_hashes = set()
        self.known_malware_patterns = []
        self.network_baseline = {}
        self.process_baseline = {}
        self.alert_history = {}  # Track recent alerts to avoid spam
        
        # Whitelist of normal Windows processes
        self.whitelisted_processes = {
            'explorer.exe', 'svchost.exe', 'RuntimeBroker.exe', 'conhost.exe',
            'msedgewebview2.exe', 'chrome.exe', 'python.exe', 'powershell.exe',
            'TextInputHost.exe', 'SearchHost.exe', 'ShellHost.exe', 'Cursor.exe',
            'WhatsApp.exe', 'SecurityHealthSystray.exe', 'ApplicationFrameHost.exe',
            'SystemSettings.exe', 'backgroundTaskHost.exe', 'UserOOBEBroker.exe',
            'Widgets.exe', 'AMDRSServ.exe', 'AMDRSSrcExt.exe', 'RadeonSoftware.exe',
            'CrossDeviceService.exe', 'CrossDeviceResume.exe', 'PhoneExperienceHost.exe',
            'WidgetService.exe', 'StartMenuExperienceHost.exe', 'ShellExperienceHost.exe',
            'crashpad_handler.exe', 'unsecapp.exe', 'RtkAudUService64.exe',
            'WavesSvc64.exe', 'cncmd.exe', 'CrossDeviceResume.exe'
        }
        
        # Load YARA rules for malware detection
        self.load_yara_rules()
        
        print("🔧 Optimized Windows Advanced Threat Detection initialized")
    
    def load_yara_rules(self):
        """Load YARA rules for malware detection"""
        if not YARA_AVAILABLE:
            self.yara_rules = None
            return
            
        try:
            # Create more specific YARA rules for real threats
            basic_rules = r"""
            rule suspicious_behavior {
                strings:
                    $cmd_shell = "cmd.exe" nocase
                    $powershell = "powershell" nocase
                    $download = "download" nocase
                    $execute = "execute" nocase
                    $registry = "registry" nocase
                    $system32 = "system32" nocase
                    $encrypted = "base64" nocase
                    $hex_pattern = "0x" nocase
                
                condition:
                    any of them
            }
            
            rule potential_malware {
                strings:
                    $encrypted_string = "encrypted" nocase
                    $hex_string = "hex" nocase
                    $url_pattern = "http://" nocase
                    $suspicious_cmd = "powershell" nocase
                    $base64_decode = "base64" nocase
                
                condition:
                    any of them
            }
            """
            
            # Compile YARA rules
            self.yara_rules = yara.compile(source=basic_rules)
            print("✅ YARA rules loaded successfully")
            
        except Exception as e:
            print(f"⚠️  YARA rules loading failed: {e}")
            self.yara_rules = None
    
    def setup_virustotal(self, api_key):
        """Setup VirusTotal integration"""
        if not VIRUSTOTAL_AVAILABLE:
            print("⚠️  VirusTotal not available")
            return
            
        self.vt_api_key = api_key
        print("✅ VirusTotal integration configured")
    
    def should_create_alert(self, alert_type, message, severity):
        """Check if we should create an alert (avoid spam)"""
        alert_key = f"{alert_type}:{message[:50]}"
        current_time = time.time()
        
        # Clean old entries (older than 5 minutes)
        self.alert_history = {k: v for k, v in self.alert_history.items() 
                             if current_time - v < 300}
        
        # Check if we've seen this alert recently
        if alert_key in self.alert_history:
            return False
        
        # Store this alert
        self.alert_history[alert_key] = current_time
        return True
    
    def analyze_network_anomalies(self):
        """Analyze network traffic for real anomalies"""
        try:
            connections = psutil.net_connections()
            
            # Analyze connection patterns
            connection_stats = {}
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr.ip if conn.raddr else None
                    if remote_ip and remote_ip != '127.0.0.1':
                        if remote_ip not in connection_stats:
                            connection_stats[remote_ip] = {
                                'count': 0,
                                'ports': set(),
                                'processes': set()
                            }
                        
                        connection_stats[remote_ip]['count'] += 1
                        connection_stats[remote_ip]['ports'].add(conn.raddr.port)
                        
                        try:
                            process = psutil.Process(conn.pid)
                            connection_stats[remote_ip]['processes'].add(process.name())
                        except:
                            pass
            
            # Detect real anomalies
            for ip, stats in connection_stats.items():
                # Multiple connections to same external IP (more than 20)
                if stats['count'] > 20:
                    message = f'High number of connections to external IP {ip} ({stats["count"]} connections)'
                    if self.should_create_alert('NETWORK', message, 'HIGH'):
                        self.create_alert('NETWORK', message, 'HIGH', 'Network Analyzer',
                                        {'ip': ip, 'connections': stats['count']})
                
                # Multiple ports to same IP (more than 10)
                if len(stats['ports']) > 10:
                    message = f'Multiple ports accessed on external IP {ip} ({len(stats["ports"])} ports)'
                    if self.should_create_alert('NETWORK', message, 'MEDIUM'):
                        self.create_alert('NETWORK', message, 'MEDIUM', 'Network Analyzer',
                                        {'ip': ip, 'ports': list(stats['ports'])})
                
                # Suspicious process making external connections
                suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
                for proc in stats['processes']:
                    if proc.lower() in suspicious_processes:
                        message = f'Suspicious process {proc} making external connections to {ip}'
                        if self.should_create_alert('NETWORK', message, 'HIGH'):
                            self.create_alert('NETWORK', message, 'HIGH', 'Network Analyzer',
                                            {'ip': ip, 'process': proc})
                        
        except Exception as e:
            print(f"⚠️  Network analysis error: {e}")
    
    def analyze_process_anomalies(self):
        """Analyze process behavior for real anomalies"""
        try:
            processes = psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline'])
            
            for proc in processes:
                try:
                    info = proc.info
                    process_name = info['name'].lower()
                    
                    # Skip whitelisted processes
                    if process_name in self.whitelisted_processes:
                        continue
                    
                    # High CPU usage (more than 90%)
                    if info['cpu_percent'] > 90:
                        message = f'Very high CPU usage detected in {info["name"]} ({info["cpu_percent"]:.1f}%)'
                        if self.should_create_alert('PROCESS', message, 'MEDIUM'):
                            self.create_alert('PROCESS', message, 'MEDIUM', 'Process Analyzer',
                                            {'process': info['name'], 'cpu': info['cpu_percent']})
                    
                    # High memory usage (more than 50%)
                    if info['memory_percent'] > 50:
                        message = f'Very high memory usage detected in {info["name"]} ({info["memory_percent"]:.1f}%)'
                        if self.should_create_alert('PROCESS', message, 'MEDIUM'):
                            self.create_alert('PROCESS', message, 'MEDIUM', 'Process Analyzer',
                                            {'process': info['name'], 'memory': info['memory_percent']})
                    
                    # Suspicious command line patterns
                    if info['cmdline']:
                        cmdline = ' '.join(info['cmdline']).lower()
                        suspicious_patterns = [
                            'powershell -enc', 'powershell -e ', 'cmd /c powershell',
                            'http://', 'https://', 'ftp://', 'download',
                            'execute', 'run', 'registry', 'regedit',
                            'base64', 'decode', 'encrypt', 'decrypt'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern in cmdline:
                                message = f'Suspicious command line in {info["name"]}: {cmdline[:100]}...'
                                if self.should_create_alert('PROCESS', message, 'HIGH'):
                                    self.create_alert('PROCESS', message, 'HIGH', 'Process Analyzer',
                                                    {'process': info['name'], 'cmdline': cmdline})
                                break
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"⚠️  Process analysis error: {e}")
    
    def monitor_file_system(self):
        """Monitor file system for suspicious activities"""
        try:
            # Monitor common directories
            watch_dirs = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                "C:/Windows/Temp",
                "C:/Temp"
            ]
            
            for directory in watch_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Check for suspicious file extensions
                            if file.lower().endswith(('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                                # Scan with YARA
                                yara_result = self.scan_file_with_yara(file_path)
                                if yara_result and yara_result.get('suspicious'):
                                    message = f'Suspicious file detected: {file}'
                                    if self.should_create_alert('MALWARE', message, 'HIGH'):
                                        self.create_alert('MALWARE', message, 'HIGH', 'File Scanner',
                                                        {'file': file, 'path': file_path, 'yara_result': yara_result})
                                
                                # Scan with VirusTotal (if configured)
                                if self.vt_api_key:
                                    vt_result = self.scan_file_with_virustotal(file_path)
                                    if vt_result and vt_result.get('suspicious'):
                                        message = f'Malware detected by VirusTotal: {file}'
                                        if self.should_create_alert('MALWARE', message, 'CRITICAL'):
                                            self.create_alert('MALWARE', message, 'CRITICAL', 'VirusTotal Scanner',
                                                            {'file': file, 'path': file_path, 'vt_result': vt_result})
                                        
        except Exception as e:
            print(f"⚠️  File system monitoring error: {e}")
    
    def check_windows_security(self):
        """Check Windows-specific security settings"""
        try:
            # Check Windows Defender status using PowerShell
            try:
                result = subprocess.run(['powershell', 'Get-MpComputerStatus'], 
                                      capture_output=True, text=True)
                if 'RealTimeProtectionEnabled : False' in result.stdout:
                    message = 'Windows Defender real-time protection is disabled'
                    if self.should_create_alert('SYSTEM', message, 'HIGH'):
                        self.create_alert('SYSTEM', message, 'HIGH', 'Windows Security Scanner',
                                        {'vulnerability': 'defender_disabled'})
            except:
                pass
            
            # Check for open ports (only critical ones)
            critical_ports = [21, 22, 23, 3389]  # FTP, SSH, Telnet, RDP
            for port in critical_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', port))
                    sock.close()
                    
                    if result == 0:
                        message = f'Critical open port detected: {port} ({self.get_service_name(port)})'
                        if self.should_create_alert('SYSTEM', message, 'HIGH'):
                            self.create_alert('SYSTEM', message, 'HIGH', 'Windows Security Scanner',
                                            {'port': port, 'service': self.get_service_name(port)})
                except:
                    continue
            
            # Check Windows Firewall status
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                      capture_output=True, text=True)
                if 'State                                 OFF' in result.stdout:
                    message = 'Windows Firewall is disabled'
                    if self.should_create_alert('SYSTEM', message, 'HIGH'):
                        self.create_alert('SYSTEM', message, 'HIGH', 'Windows Security Scanner',
                                        {'vulnerability': 'firewall_disabled'})
            except:
                pass
                    
        except Exception as e:
            print(f"⚠️  Windows security check error: {e}")
    
    def check_registry_anomalies(self):
        """Check Windows registry for suspicious entries"""
        try:
            # Check for suspicious registry keys
            suspicious_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            ]
            
            for key_path in suspicious_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(key, i)
                            # Check for highly suspicious values
                            if any(susp in value.lower() for susp in ['http://', 'https://', 'ftp://', 'download', 'powershell -enc']):
                                message = f'Suspicious registry entry found: {name} = {value[:100]}...'
                                if self.should_create_alert('REGISTRY', message, 'HIGH'):
                                    self.create_alert('REGISTRY', message, 'HIGH', 'Registry Scanner',
                                                    {'key': key_path, 'name': name, 'value': value})
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except:
                    continue
                    
        except Exception as e:
            print(f"⚠️  Registry analysis error: {e}")
    
    def scan_file_with_virustotal(self, file_path):
        """Scan file with VirusTotal"""
        if not self.vt_api_key or not VIRUSTOTAL_AVAILABLE:
            return None
        
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Check if already scanned
            if file_hash in self.suspicious_hashes:
                return {"suspicious": True, "reason": "Previously detected"}
            
            # Query VirusTotal
            with virustotal_python.Virustotal(self.vt_api_key) as vt:
                result = vt.file_info([file_hash])
                
                if result.get('positives', 0) > 0:
                    self.suspicious_hashes.add(file_hash)
                    return {
                        "suspicious": True,
                        "positives": result.get('positives', 0),
                        "total": result.get('total', 0),
                        "hash": file_hash
                    }
                
                return {"suspicious": False}
                
        except Exception as e:
            print(f"⚠️  VirusTotal scan error: {e}")
            return None
    
    def scan_file_with_yara(self, file_path):
        """Scan file with YARA rules"""
        if not self.yara_rules or not YARA_AVAILABLE:
            return None
        
        try:
            with open(file_path, 'rb') as f:
                matches = self.yara_rules.match(data=f.read())
                
                if matches:
                    return {
                        "suspicious": True,
                        "rules_matched": [match.rule for match in matches],
                        "strings_found": [str(match.strings) for match in matches]
                    }
                
                return {"suspicious": False}
                
        except Exception as e:
            print(f"⚠️  YARA scan error: {e}")
            return None
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB',
            3389: 'RDP'
        }
        return services.get(port, 'Unknown')
    
    def create_alert(self, alert_type, message, severity, source, details=None):
        """Create an alert in the database"""
        try:
            Alert.objects.create(
                alert_type=alert_type,
                severity=severity,
                message=message,
                source=source,
                details=details or {}
            )
            print(f"🚨 Optimized Alert: {alert_type} - {message}")
        except Exception as e:
            print(f"❌ Error creating alert: {e}")
    
    def start_advanced_monitoring(self):
        """Start advanced monitoring services"""
        if self.running:
            print("⚠️  Advanced monitoring is already running")
            return
        
        print("🚀 Starting Optimized Windows Advanced Threat Detection...")
        self.running = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.network_monitor_loop, daemon=True),
            threading.Thread(target=self.process_monitor_loop, daemon=True),
            threading.Thread(target=self.file_monitor_loop, daemon=True),
            threading.Thread(target=self.windows_security_loop, daemon=True),
            threading.Thread(target=self.registry_monitor_loop, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("✅ Optimized Windows advanced monitoring services started")
    
    def network_monitor_loop(self):
        """Network monitoring loop"""
        while self.running:
            try:
                self.analyze_network_anomalies()
                time.sleep(120)  # Check every 2 minutes
            except Exception as e:
                print(f"⚠️  Network monitoring error: {e}")
                time.sleep(240)
    
    def process_monitor_loop(self):
        """Process monitoring loop"""
        while self.running:
            try:
                self.analyze_process_anomalies()
                time.sleep(60)  # Check every minute
            except Exception as e:
                print(f"⚠️  Process monitoring error: {e}")
                time.sleep(120)
    
    def file_monitor_loop(self):
        """File system monitoring loop"""
        while self.running:
            try:
                self.monitor_file_system()
                time.sleep(600)  # Check every 10 minutes
            except Exception as e:
                print(f"⚠️  File monitoring error: {e}")
                time.sleep(1200)
    
    def windows_security_loop(self):
        """Windows security monitoring loop"""
        while self.running:
            try:
                self.check_windows_security()
                time.sleep(3600)  # Check every hour
            except Exception as e:
                print(f"⚠️  Windows security monitoring error: {e}")
                time.sleep(7200)
    
    def registry_monitor_loop(self):
        """Registry monitoring loop"""
        while self.running:
            try:
                self.check_registry_anomalies()
                time.sleep(1800)  # Check every 30 minutes
            except Exception as e:
                print(f"⚠️  Registry monitoring error: {e}")
                time.sleep(3600)
    
    def stop_advanced_monitoring(self):
        """Stop advanced monitoring services"""
        if not self.running:
            print("⚠️  Advanced monitoring is not running")
            return
        
        print("🛑 Stopping Optimized Windows Advanced Threat Detection...")
        self.running = False
        print("✅ Optimized Windows advanced monitoring services stopped")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Optimized Windows Advanced Threat Detection')
    parser.add_argument('action', choices=['start', 'stop', 'demo'], 
                       help='Action to perform')
    parser.add_argument('--vt-api-key', help='VirusTotal API key')
    
    args = parser.parse_args()
    
    advanced_detection = OptimizedWindowsThreatDetection()
    
    if args.vt_api_key:
        advanced_detection.setup_virustotal(args.vt_api_key)
    
    if args.action == 'start':
        advanced_detection.start_advanced_monitoring()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Received interrupt signal")
            advanced_detection.stop_advanced_monitoring()
    
    elif args.action == 'stop':
        advanced_detection.stop_advanced_monitoring()
    
    elif args.action == 'demo':
        print("🎭 Running Optimized Windows Advanced Detection Demo...")
        
        # Create sample advanced alerts
        sample_alerts = [
            ('NETWORK', 'High number of connections to external IP 192.168.1.100 (25 connections)', 'HIGH'),
            ('PROCESS', 'Suspicious command line in unknown.exe: powershell -enc', 'HIGH'),
            ('MALWARE', 'YARA rule matched: suspicious_behavior in suspicious_file.exe', 'CRITICAL'),
            ('SYSTEM', 'Windows Defender real-time protection is disabled', 'HIGH'),
            ('REGISTRY', 'Suspicious registry entry found in Run key', 'MEDIUM'),
            ('SYSTEM', 'Critical open port detected: 3389 (RDP)', 'HIGH'),
        ]
        
        for alert_type, message, severity in sample_alerts:
            advanced_detection.create_alert(alert_type, message, severity, 'Optimized Demo')
            time.sleep(2)
        
        print("✅ Optimized Windows advanced demo completed!")

if __name__ == '__main__':
    main() 