#!/usr/bin/env python3
"""
Advanced Kernel-Level Monitoring System
Captures network packets, application behavior, and Windows system activities
"""

import os
import sys
import time
import threading
import json
import hashlib
import subprocess
import socket
import struct
from datetime import datetime, timedelta
from pathlib import Path

# Add project path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
import django
django.setup()

from dashboard.models import Alert, SystemInfo, ProcessLog

try:
    import psutil
    import win32api
    import win32process
    import win32security
    import win32con
    import win32file
    import win32event
    import win32service
    import win32serviceutil
    import winreg
    import wmi
    from scapy.all import *
    import pefile
    import yara
    WINDOWS_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Windows-specific modules not available: {e}")
    WINDOWS_AVAILABLE = False

class AdvancedKernelMonitor:
    def __init__(self):
        self.running = False
        self.packet_capture_running = False
        self.process_monitoring_running = False
        self.registry_monitoring_running = False
        self.service_monitoring_running = False
        self.file_system_monitoring_running = False
        
        # Data storage
        self.captured_packets = []
        self.process_behavior = {}
        self.network_connections = {}
        self.suspicious_activities = []
        self.kernel_events = []
        
        # YARA rules for malware detection
        self.load_yara_rules()
        
        # WMI connections
        self.wmi_connection = None
        if WINDOWS_AVAILABLE:
            try:
                self.wmi_connection = wmi.WMI()
                print("✅ WMI connection established")
            except Exception as e:
                print(f"⚠️  WMI connection failed: {e}")
        
        print("🔧 Advanced Kernel-Level Monitoring System initialized")
    
    def load_yara_rules(self):
        """Load advanced YARA rules for kernel-level detection"""
        try:
            # Advanced YARA rules for kernel-level threats
            advanced_rules = r"""
            rule kernel_level_threats {
                strings:
                    $kernel_injection = "CreateRemoteThread" nocase
                    $driver_loading = "LoadDriver" nocase
                    $registry_persistence = "HKEY_LOCAL_MACHINE" nocase
                    $service_creation = "CreateService" nocase
                    $process_hollowing = "NtUnmapViewOfSection" nocase
                    $code_injection = "VirtualAllocEx" nocase
                    $privilege_escalation = "SeDebugPrivilege" nocase
                    $memory_manipulation = "NtProtectVirtualMemory" nocase
                
                condition:
                    any of them
            }
            
            rule network_anomalies {
                strings:
                    $dns_tunneling = "nslookup" nocase
                    $encrypted_traffic = "https://" nocase
                    $command_control = "cmd.exe" nocase
                    $data_exfiltration = "ftp://" nocase
                    $reverse_shell = "bash" nocase
                    $port_scanning = "nmap" nocase
                
                condition:
                    any of them
            }
            
            rule process_anomalies {
                strings:
                    $process_injection = "CreateRemoteThread" nocase
                    $dll_injection = "LoadLibrary" nocase
                    $process_creation = "CreateProcess" nocase
                    $thread_creation = "CreateThread" nocase
                    $memory_allocation = "VirtualAlloc" nocase
                    $code_execution = "VirtualProtect" nocase
                
                condition:
                    any of them
            }
            """
            
            self.yara_rules = yara.compile(source=advanced_rules)
            print("✅ Advanced YARA rules loaded")
            
        except Exception as e:
            print(f"⚠️  YARA rules loading failed: {e}")
            self.yara_rules = None
    
    def start_kernel_monitoring(self):
        """Start all kernel-level monitoring services"""
        if self.running:
            print("⚠️  Kernel monitoring is already running")
            return
        
        print("🚀 Starting Advanced Kernel-Level Monitoring...")
        self.running = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.network_packet_capture, daemon=True),
            threading.Thread(target=self.process_behavior_monitoring, daemon=True),
            threading.Thread(target=self.registry_monitoring, daemon=True),
            threading.Thread(target=self.service_monitoring, daemon=True),
            threading.Thread(target=self.file_system_monitoring, daemon=True),
            threading.Thread(target=self.kernel_event_monitoring, daemon=True),
            threading.Thread(target=self.memory_analysis, daemon=True),
            threading.Thread(target=self.network_behavior_analysis, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("✅ Advanced kernel-level monitoring services started")
    
    def network_packet_capture(self):
        """Capture and analyze network packets at kernel level"""
        if not WINDOWS_AVAILABLE:
            return
        
        self.packet_capture_running = True
        print("📡 Starting network packet capture...")
        
        try:
            # Use Scapy for packet capture
            def packet_handler(packet):
                try:
                    # Analyze packet for suspicious patterns
                    packet_info = {
                        'timestamp': datetime.now(),
                        'src_ip': packet[IP].src if IP in packet else None,
                        'dst_ip': packet[IP].dst if IP in packet else None,
                        'src_port': packet[TCP].sport if TCP in packet else None,
                        'dst_port': packet[TCP].dport if TCP in packet else None,
                        'protocol': packet.proto if hasattr(packet, 'proto') else None,
                        'payload': str(packet.payload) if hasattr(packet, 'payload') else None
                    }
                    
                    # Check for suspicious patterns
                    if self.analyze_packet_suspicious(packet_info):
                        self.create_alert('NETWORK', f'Suspicious network activity detected: {packet_info["src_ip"]} -> {packet_info["dst_ip"]}:{packet_info["dst_port"]}', 'HIGH', 'Packet Analyzer', packet_info)
                    
                    # Store packet for analysis
                    self.captured_packets.append(packet_info)
                    
                    # Keep only last 1000 packets
                    if len(self.captured_packets) > 1000:
                        self.captured_packets.pop(0)
                        
                except Exception as e:
                    pass
            
            # Start packet capture
            sniff(prn=packet_handler, store=0, timeout=60)
            
        except Exception as e:
            print(f"⚠️  Packet capture error: {e}")
        
        self.packet_capture_running = False
    
    def analyze_packet_suspicious(self, packet_info):
        """Analyze packet for suspicious patterns"""
        if not packet_info.get('payload'):
            return False
        
        payload = packet_info['payload'].lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'cmd.exe', 'powershell', 'wget', 'curl', 'download',
            'http://', 'https://', 'ftp://', 'tcp://',
            'base64', 'encode', 'decode', 'encrypt',
            'reverse', 'shell', 'backdoor', 'trojan'
        ]
        
        return any(pattern in payload for pattern in suspicious_patterns)
    
    def process_behavior_monitoring(self):
        """Monitor process behavior at kernel level"""
        if not WINDOWS_AVAILABLE:
            return
        
        self.process_monitoring_running = True
        print("🔍 Starting process behavior monitoring...")
        
        try:
            # Monitor process creation and behavior
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections', 'open_files']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Analyze process behavior
                    behavior_analysis = self.analyze_process_behavior(proc_info)
                    
                    if behavior_analysis['suspicious']:
                        self.create_alert('PROCESS', f'Suspicious process behavior detected: {proc_info["name"]} (PID: {pid})', 'HIGH', 'Process Behavior Analyzer', behavior_analysis)
                    
                    # Store process behavior data
                    self.process_behavior[pid] = {
                        'name': proc_info['name'],
                        'cmdline': proc_info.get('cmdline', []),
                        'connections': len(proc_info.get('connections', [])),
                        'open_files': len(proc_info.get('open_files', [])),
                        'suspicious_score': behavior_analysis['suspicious_score'],
                        'timestamp': datetime.now()
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"⚠️  Process behavior monitoring error: {e}")
        
        self.process_monitoring_running = False
    
    def analyze_process_behavior(self, proc_info):
        """Analyze individual process behavior"""
        suspicious_score = 0
        suspicious_indicators = []
        
        # Check command line
        if proc_info.get('cmdline'):
            cmdline = ' '.join(proc_info['cmdline']).lower()
            
            # Suspicious command line patterns
            suspicious_patterns = [
                'powershell -enc', 'cmd /c', 'wget', 'curl',
                'download', 'execute', 'run', 'install',
                'registry', 'service', 'driver', 'kernel'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in cmdline:
                    suspicious_score += 10
                    suspicious_indicators.append(f'Command line pattern: {pattern}')
        
        # Check network connections
        if proc_info.get('connections'):
            connections = proc_info['connections']
            if len(connections) > 10:
                suspicious_score += 5
                suspicious_indicators.append('High number of network connections')
            
            # Check for suspicious connections
            for conn in connections:
                if conn.raddr and conn.raddr.port in [22, 23, 3389, 445]:
                    suspicious_score += 3
                    suspicious_indicators.append(f'Suspicious port connection: {conn.raddr.port}')
        
        # Check file operations
        if proc_info.get('open_files'):
            open_files = proc_info['open_files']
            if len(open_files) > 50:
                suspicious_score += 3
                suspicious_indicators.append('High number of open files')
        
        return {
            'suspicious': suspicious_score > 15,
            'suspicious_score': suspicious_score,
            'indicators': suspicious_indicators
        }
    
    def registry_monitoring(self):
        """Monitor Windows registry changes at kernel level"""
        if not WINDOWS_AVAILABLE:
            return
        
        self.registry_monitoring_running = True
        print("🔧 Starting registry monitoring...")
        
        try:
            # Monitor critical registry keys
            critical_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                r"SYSTEM\CurrentControlSet\Services",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
            ]
            
            for key_path in critical_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(key, i)
                            
                            # Analyze registry value
                            if self.analyze_registry_value(value):
                                self.create_alert('REGISTRY', f'Suspicious registry entry: {name} in {key_path}', 'HIGH', 'Registry Monitor', {
                                    'key': key_path,
                                    'name': name,
                                    'value': value,
                                    'type': type
                                })
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"⚠️  Registry monitoring error: {e}")
        
        self.registry_monitoring_running = False
    
    def analyze_registry_value(self, value):
        """Analyze registry value for suspicious content"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        
        # Suspicious registry patterns
        suspicious_patterns = [
            'http://', 'https://', 'ftp://', 'download',
            'powershell', 'cmd.exe', 'wscript', 'cscript',
            'rundll32', 'regsvr32', 'mshta', 'javascript'
        ]
        
        return any(pattern in value_lower for pattern in suspicious_patterns)
    
    def service_monitoring(self):
        """Monitor Windows services at kernel level"""
        if not WINDOWS_AVAILABLE:
            return
        
        self.service_monitoring_running = True
        print("⚙️  Starting service monitoring...")
        
        try:
            # Get all services
            services = self.wmi_connection.Win32_Service()
            
            for service in services:
                try:
                    # Analyze service for suspicious characteristics
                    if self.analyze_service_suspicious(service):
                        self.create_alert('SYSTEM', f'Suspicious service detected: {service.Name}', 'MEDIUM', 'Service Monitor', {
                            'name': service.Name,
                            'display_name': service.DisplayName,
                            'path': service.PathName,
                            'start_mode': service.StartMode,
                            'state': service.State
                        })
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"⚠️  Service monitoring error: {e}")
        
        self.service_monitoring_running = False
    
    def analyze_service_suspicious(self, service):
        """Analyze service for suspicious characteristics"""
        suspicious_score = 0
        
        # Check service path
        if service.PathName:
            path_lower = service.PathName.lower()
            
            # Suspicious service paths
            suspicious_paths = [
                'temp', 'downloads', 'desktop', 'appdata',
                'users', 'public', 'programdata'
            ]
            
            if any(path in path_lower for path in suspicious_paths):
                suspicious_score += 5
        
        # Check service name
        if service.Name:
            name_lower = service.Name.lower()
            
            # Suspicious service names
            suspicious_names = [
                'update', 'security', 'system', 'windows',
                'microsoft', 'service', 'svc', 'driver'
            ]
            
            if any(name in name_lower for name in suspicious_names):
                suspicious_score += 3
        
        return suspicious_score > 5
    
    def file_system_monitoring(self):
        """Monitor file system changes at kernel level"""
        if not WINDOWS_AVAILABLE:
            return
        
        self.file_system_monitoring_running = True
        print("📁 Starting file system monitoring...")
        
        try:
            # Monitor critical directories
            critical_dirs = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                "C:/Windows/Temp",
                "C:/Temp",
                "C:/Windows/System32"
            ]
            
            for directory in critical_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Check for suspicious files
                            if self.analyze_file_suspicious(file_path):
                                self.create_alert('FILE', f'Suspicious file detected: {file}', 'HIGH', 'File System Monitor', {
                                    'file': file,
                                    'path': file_path,
                                    'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
                                })
                                
        except Exception as e:
            print(f"⚠️  File system monitoring error: {e}")
        
        self.file_system_monitoring_running = False
    
    def analyze_file_suspicious(self, file_path):
        """Analyze file for suspicious characteristics"""
        try:
            # Check file extension
            if file_path.lower().endswith(('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                # Check file size (suspicious if very small or very large)
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    if size < 1024 or size > 100 * 1024 * 1024:  # < 1KB or > 100MB
                        return True
                
                # Check file name
                filename = os.path.basename(file_path).lower()
                suspicious_names = [
                    'update', 'security', 'system', 'windows',
                    'microsoft', 'service', 'driver', 'install'
                ]
                
                if any(name in filename for name in suspicious_names):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def kernel_event_monitoring(self):
        """Monitor kernel-level events"""
        if not WINDOWS_AVAILABLE:
            return
        
        print("⚡ Starting kernel event monitoring...")
        
        try:
            # Monitor system events using WMI
            watcher = self.wmi_connection.Win32_Process.watch_for("creation")
            
            while self.running:
                try:
                    process = watcher(timeout_ms=1000)
                    if process:
                        # Analyze new process
                        if self.analyze_new_process(process):
                            self.create_alert('PROCESS', f'Suspicious new process: {process.Caption}', 'HIGH', 'Kernel Event Monitor', {
                                'name': process.Caption,
                                'pid': process.ProcessId,
                                'command_line': process.CommandLine,
                                'parent_pid': process.ParentProcessId
                            })
                            
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    print(f"⚠️  Kernel event monitoring error: {e}")
                    break
                    
        except Exception as e:
            print(f"⚠️  Kernel event monitoring setup error: {e}")
    
    def analyze_new_process(self, process):
        """Analyze newly created process"""
        suspicious_score = 0
        
        # Check process name
        if process.Caption:
            name_lower = process.Caption.lower()
            suspicious_names = [
                'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                'rundll32.exe', 'regsvr32.exe', 'mshta.exe'
            ]
            
            if name_lower in suspicious_names:
                suspicious_score += 10
        
        # Check command line
        if process.CommandLine:
            cmdline_lower = process.CommandLine.lower()
            suspicious_patterns = [
                'powershell -enc', 'cmd /c', 'wget', 'curl',
                'download', 'execute', 'run', 'install'
            ]
            
            if any(pattern in cmdline_lower for pattern in suspicious_patterns):
                suspicious_score += 15
        
        return suspicious_score > 10
    
    def memory_analysis(self):
        """Analyze process memory for suspicious patterns"""
        if not WINDOWS_AVAILABLE:
            return
        
        print("🧠 Starting memory analysis...")
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Analyze process memory
                    if self.analyze_process_memory(pid):
                        self.create_alert('MEMORY', f'Suspicious memory pattern in process: {proc_info["name"]} (PID: {pid})', 'HIGH', 'Memory Analyzer', {
                            'process': proc_info['name'],
                            'pid': pid
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"⚠️  Memory analysis error: {e}")
    
    def analyze_process_memory(self, pid):
        """Analyze individual process memory"""
        try:
            # This is a simplified analysis - in a real implementation,
            # you would use Windows API to read process memory
            process = psutil.Process(pid)
            
            # Check memory usage patterns
            memory_info = process.memory_info()
            
            # Suspicious if process uses a lot of memory but is small
            if memory_info.rss > 100 * 1024 * 1024:  # > 100MB
                return True
                
        except Exception:
            pass
        
        return False
    
    def network_behavior_analysis(self):
        """Analyze network behavior patterns"""
        print("🌐 Starting network behavior analysis...")
        
        try:
            # Analyze network connections
            connections = psutil.net_connections()
            
            # Group connections by remote IP
            ip_connections = {}
            for conn in connections:
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    if remote_ip not in ip_connections:
                        ip_connections[remote_ip] = []
                    ip_connections[remote_ip].append(conn)
            
            # Analyze each IP for suspicious behavior
            for ip, conns in ip_connections.items():
                if self.analyze_ip_behavior(ip, conns):
                    self.create_alert('NETWORK', f'Suspicious network behavior from IP: {ip}', 'HIGH', 'Network Behavior Analyzer', {
                        'ip': ip,
                        'connections': len(conns),
                        'ports': [conn.raddr.port for conn in conns if conn.raddr]
                    })
                    
        except Exception as e:
            print(f"⚠️  Network behavior analysis error: {e}")
    
    def analyze_ip_behavior(self, ip, connections):
        """Analyze behavior of a specific IP address"""
        # Check for port scanning behavior
        if len(connections) > 20:
            return True
        
        # Check for connections to suspicious ports
        suspicious_ports = [22, 23, 3389, 445, 135, 139]
        suspicious_conns = [conn for conn in connections if conn.raddr and conn.raddr.port in suspicious_ports]
        
        if len(suspicious_conns) > 5:
            return True
        
        return False
    
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
            print(f"🚨 Kernel Alert: {alert_type} - {message}")
        except Exception as e:
            print(f"❌ Error creating alert: {e}")
    
    def stop_kernel_monitoring(self):
        """Stop all kernel-level monitoring services"""
        if not self.running:
            print("⚠️  Kernel monitoring is not running")
            return
        
        print("🛑 Stopping Advanced Kernel-Level Monitoring...")
        self.running = False
        self.packet_capture_running = False
        self.process_monitoring_running = False
        self.registry_monitoring_running = False
        self.service_monitoring_running = False
        self.file_system_monitoring_running = False
        print("✅ Advanced kernel-level monitoring services stopped")
    
    def get_monitoring_stats(self):
        """Get current monitoring statistics"""
        return {
            'packet_capture_running': self.packet_capture_running,
            'process_monitoring_running': self.process_monitoring_running,
            'registry_monitoring_running': self.registry_monitoring_running,
            'service_monitoring_running': self.service_monitoring_running,
            'file_system_monitoring_running': self.file_system_monitoring_running,
            'captured_packets': len(self.captured_packets),
            'monitored_processes': len(self.process_behavior),
            'suspicious_activities': len(self.suspicious_activities),
            'kernel_events': len(self.kernel_events)
        }

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Kernel-Level Monitoring System')
    parser.add_argument('action', choices=['start', 'stop', 'demo'], 
                       help='Action to perform')
    
    args = parser.parse_args()
    
    kernel_monitor = AdvancedKernelMonitor()
    
    if args.action == 'start':
        kernel_monitor.start_kernel_monitoring()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Received interrupt signal")
            kernel_monitor.stop_kernel_monitoring()
    
    elif args.action == 'stop':
        kernel_monitor.stop_kernel_monitoring()
    
    elif args.action == 'demo':
        print("🎭 Running Advanced Kernel-Level Monitoring Demo...")
        
        # Create sample kernel-level alerts
        sample_alerts = [
            ('NETWORK', 'Suspicious network packet detected: DNS tunneling attempt', 'HIGH'),
            ('PROCESS', 'Suspicious process behavior: Code injection detected', 'CRITICAL'),
            ('REGISTRY', 'Suspicious registry modification: Persistence mechanism', 'HIGH'),
            ('SYSTEM', 'Suspicious service detected: Unauthorized kernel driver', 'CRITICAL'),
            ('FILE', 'Suspicious file activity: Kernel-level file modification', 'HIGH'),
            ('MEMORY', 'Suspicious memory pattern: Process hollowing detected', 'CRITICAL'),
        ]
        
        for alert_type, message, severity in sample_alerts:
            kernel_monitor.create_alert(alert_type, message, severity, 'Kernel Demo')
            time.sleep(2)
        
        print("✅ Advanced kernel-level monitoring demo completed!")

if __name__ == '__main__':
    main() 