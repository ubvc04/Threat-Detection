"""
Credential Theft Detection Module
Monitors for LSASS access, suspicious credential dumping tools, and memory dumps
"""

import psutil
import win32process
import win32api
import win32con
import win32security
import win32gui
import win32event
import win32file
import win32service
import win32com.client
import time
import threading
import logging
import os
import re
from datetime import datetime
from typing import List, Dict, Any

class CredentialTheftDetector:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.suspicious_tools = [
            'mimikatz.exe', 'procdump.exe', 'wce.exe', 'pwdump.exe',
            'fgdump.exe', 'gsecdump.exe', 'wdigest.exe', 'sekurlsa.exe',
            'lsadump.exe', 'kerberos.exe', 'cachedump.exe', 'hashdump.exe',
            'quarks-pwdump.exe', 'ophcrack.exe', 'john.exe', 'hashcat.exe',
            'cain.exe', 'l0phtcrack.exe', 'rainbowcrack.exe', 'ophcrack.exe'
        ]
        self.lsass_process = None
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
        
    def start_monitoring(self):
        """Start credential theft monitoring"""
        self.monitoring = True
        self.logger.info("🔐 Starting Credential Theft Detection...")
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_lsass_access, daemon=True).start()
        threading.Thread(target=self._monitor_suspicious_tools, daemon=True).start()
        threading.Thread(target=self._monitor_memory_dumps, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop credential theft monitoring"""
        self.monitoring = False
        self.logger.info("🔐 Stopping Credential Theft Detection...")
        
    def _monitor_lsass_access(self):
        """Monitor LSASS process access"""
        while self.monitoring:
            try:
                # Find lsass.exe process
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if proc.info['name'] and proc.info['name'].lower() == 'lsass.exe':
                        self.lsass_process = proc
                        break
                
                if self.lsass_process:
                    # Check for processes accessing lsass
                    for proc in psutil.process_iter(['pid', 'name', 'exe', 'connections']):
                        try:
                            if proc.info['pid'] != self.lsass_process.pid:
                                # Check if process has handles to lsass
                                if self._check_lsass_handles(proc.info['pid']):
                                    self._create_alert(
                                        "CRITICAL",
                                        f"Process {proc.info['name']} (PID: {proc.info['pid']}) accessing LSASS",
                                        f"Potential credential theft attempt detected. Process {proc.info['name']} is accessing the LSASS process.",
                                        "credential_theft"
                                    )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
            except Exception as e:
                self.logger.error(f"Error monitoring LSASS access: {e}")
                
            time.sleep(5)  # Check every 5 seconds
            
    def _check_lsass_handles(self, pid: int) -> bool:
        """Check if process has handles to LSASS"""
        try:
            # Use Windows API to check process handles
            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            if process_handle:
                # Check for specific handle types that might indicate LSASS access
                # This is a simplified check - in production you'd use more sophisticated methods
                return False  # Placeholder - implement actual handle checking
        except:
            pass
        return False
        
    def _monitor_suspicious_tools(self):
        """Monitor for suspicious credential dumping tools"""
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    try:
                        proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                        
                        # Check for suspicious tools
                        for tool in self.suspicious_tools:
                            if tool in proc_name:
                                cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                                
                                self._create_alert(
                                    "HIGH",
                                    f"Suspicious credential tool detected: {proc_name}",
                                    f"Process {proc_name} (PID: {proc.info['pid']}) is running. Command line: {cmdline}",
                                    "credential_theft"
                                )
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except Exception as e:
                self.logger.error(f"Error monitoring suspicious tools: {e}")
                
            time.sleep(10)  # Check every 10 seconds
            
    def _monitor_memory_dumps(self):
        """Monitor for memory dump files that might contain credentials"""
        while self.monitoring:
            try:
                # Check common locations for memory dumps
                dump_locations = [
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Downloads"),
                    "C:\\temp",
                    "C:\\windows\\temp"
                ]
                
                for location in dump_locations:
                    if os.path.exists(location):
                        for file in os.listdir(location):
                            if file.lower().endswith(('.dmp', '.mem', '.raw')):
                                file_path = os.path.join(location, file)
                                file_size = os.path.getsize(file_path)
                                
                                # Alert on large memory dump files
                                if file_size > 100 * 1024 * 1024:  # 100MB
                                    self._create_alert(
                                        "MEDIUM",
                                        f"Large memory dump file detected: {file}",
                                        f"Large memory dump file found: {file_path} ({file_size / (1024*1024):.1f}MB)",
                                        "credential_theft"
                                    )
                                    
            except Exception as e:
                self.logger.error(f"Error monitoring memory dumps: {e}")
                
            time.sleep(30)  # Check every 30 seconds
            
    def _create_alert(self, severity: str, title: str, description: str, alert_type: str):
        """Create alert using the existing alert system"""
        if self.alert_callback:
            alert_data = {
                'severity': severity,
                'title': title,
                'description': description,
                'alert_type': alert_type,
                'timestamp': datetime.now(),
                'source': 'credential_theft_detector'
            }
            self.alert_callback(alert_data)
            
        self.logger.warning(f"🔐 {severity} Alert: {title} - {description}")
        
    def get_status(self) -> Dict[str, Any]:
        """Get current status of credential theft detection"""
        return {
            'monitoring': self.monitoring,
            'lsass_found': self.lsass_process is not None,
            'lsass_pid': self.lsass_process.pid if self.lsass_process else None,
            'suspicious_tools_count': len(self.suspicious_tools)
        } 