"""
USB Monitor Module
Detects USB device insertions and scans for autorun.inf files
"""

import os
import time
import threading
import win32file
import win32con
import win32api
import win32gui
import win32event
from pathlib import Path
import shutil

class USBMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.known_devices = set()
        self.suspicious_files = [
            'autorun.inf',
            'desktop.ini',
            'thumbs.db',
            '.DS_Store',
            'autorun.exe',
            'autorun.bat',
            'autorun.cmd',
            'autorun.ps1',
        ]
        
    def get_drive_letters(self):
        """Get all available drive letters"""
        drives = []
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                drives.append(drive)
        return drives
    
    def scan_drive_for_suspicious_files(self, drive_path):
        """Scan a drive for suspicious files"""
        try:
            suspicious_found = []
            
            for root, dirs, files in os.walk(drive_path):
                for file in files:
                    if file.lower() in [f.lower() for f in self.suspicious_files]:
                        file_path = os.path.join(root, file)
                        suspicious_found.append({
                            'file_name': file,
                            'file_path': file_path,
                            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
                        })
            
            return suspicious_found
            
        except Exception as e:
            print(f"Error scanning drive {drive_path}: {e}")
            return []
    
    def analyze_autorun_inf(self, file_path):
        """Analyze autorun.inf file for suspicious content"""
        try:
            if not os.path.exists(file_path):
                return None
            
            analysis = {
                'file_path': file_path,
                'suspicious_commands': [],
                'suspicious_sections': [],
                'content': ''
            }
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                analysis['content'] = content
            
            # Check for suspicious commands
            suspicious_commands = [
                'open=',
                'shell\\open\\command=',
                'shell\\explore\\command=',
                'shell\\find\\command=',
                'shell\\print\\command=',
                'shell\\printto\\command=',
                'shell\\printto\\command=',
            ]
            
            lines = content.split('\n')
            for line in lines:
                line = line.strip().lower()
                for command in suspicious_commands:
                    if line.startswith(command):
                        analysis['suspicious_commands'].append(line)
            
            # Check for suspicious sections
            suspicious_sections = [
                '[autorun]',
                '[autorun.alpha]',
                '[autorun.mips]',
                '[autorun.ppc]',
                '[autorun.x86]',
            ]
            
            for section in suspicious_sections:
                if section.lower() in content.lower():
                    analysis['suspicious_sections'].append(section)
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing autorun.inf: {e}")
            return None
    
    def get_device_info(self, drive_path):
        """Get information about a USB device"""
        try:
            volume_name = win32file.GetVolumeInformation(drive_path)[0]
            file_system = win32file.GetVolumeInformation(drive_path)[4]
            
            # Get drive size
            free_bytes, total_bytes, free_clusters, total_clusters = win32file.GetDiskFreeSpace(drive_path)
            total_size = total_bytes * total_clusters
            free_size = free_bytes * free_clusters
            
            return {
                'drive_letter': drive_path,
                'volume_name': volume_name,
                'file_system': file_system,
                'total_size': total_size,
                'free_size': free_size,
                'used_size': total_size - free_size
            }
            
        except Exception as e:
            print(f"Error getting device info for {drive_path}: {e}")
            return None
    
    def monitor_usb_devices(self):
        """Monitor for USB device insertions and removals"""
        try:
            # Get initial drives
            current_drives = set(self.get_drive_letters())
            self.known_devices = current_drives.copy()
            
            while self.monitoring:
                try:
                    # Check for new drives
                    current_drives = set(self.get_drive_letters())
                    new_drives = current_drives - self.known_devices
                    removed_drives = self.known_devices - current_drives
                    
                    # Handle new drives
                    for drive in new_drives:
                        self.handle_device_insertion(drive)
                    
                    # Handle removed drives
                    for drive in removed_drives:
                        self.handle_device_removal(drive)
                    
                    # Update known devices
                    self.known_devices = current_drives
                    
                    # Sleep for a short time
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"Error in USB monitoring loop: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            print(f"Error in USB monitoring: {e}")
    
    def handle_device_insertion(self, drive_path):
        """Handle USB device insertion"""
        try:
            print(f"USB device inserted: {drive_path}")
            
            # Get device info
            device_info = self.get_device_info(drive_path)
            if not device_info:
                return
            
            # Scan for suspicious files
            suspicious_files = self.scan_drive_for_suspicious_files(drive_path)
            
            # Check for autorun.inf
            autorun_path = os.path.join(drive_path, 'autorun.inf')
            autorun_analysis = None
            if os.path.exists(autorun_path):
                autorun_analysis = self.analyze_autorun_inf(autorun_path)
            
            # Log alert if suspicious files found
            if suspicious_files or autorun_analysis:
                self.log_usb_alert(drive_path, device_info, suspicious_files, autorun_analysis)
            
        except Exception as e:
            print(f"Error handling device insertion: {e}")
    
    def handle_device_removal(self, drive_path):
        """Handle USB device removal"""
        try:
            print(f"USB device removed: {drive_path}")
            
            # Log device removal
            from dashboard.models import Alert
            
            Alert.objects.create(
                alert_type='USB',
                severity='LOW',
                message=f"USB device removed: {drive_path}",
                source='usb_monitor',
                details={
                    'event_type': 'device_removal',
                    'drive_letter': drive_path
                }
            )
            
        except Exception as e:
            print(f"Error handling device removal: {e}")
    
    def log_usb_alert(self, drive_path, device_info, suspicious_files, autorun_analysis):
        """Log USB alert to Django"""
        try:
            from dashboard.models import Alert
            
            # Determine severity
            severity = 'LOW'
            if autorun_analysis and autorun_analysis['suspicious_commands']:
                severity = 'HIGH'
            elif suspicious_files:
                severity = 'MEDIUM'
            
            # Create alert message
            message = f"USB device detected: {drive_path}"
            if suspicious_files:
                message += f" - Found {len(suspicious_files)} suspicious files"
            if autorun_analysis:
                message += " - Autorun.inf detected"
            
            Alert.objects.create(
                alert_type='USB',
                severity=severity,
                message=message,
                source='usb_monitor',
                details={
                    'device_info': device_info,
                    'suspicious_files': suspicious_files,
                    'autorun_analysis': autorun_analysis,
                    'drive_letter': drive_path
                }
            )
            
        except Exception as e:
            print(f"Error logging USB alert: {e}")
    
    def start_monitoring(self):
        """Start USB monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_usb_devices, daemon=True)
        self.monitor_thread.start()
        print("USB monitoring started")
    
    def stop_monitoring(self):
        """Stop USB monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("USB monitoring stopped")
    
    def scan_all_drives(self):
        """Scan all currently connected USB drives"""
        try:
            drives = self.get_drive_letters()
            for drive in drives:
                self.handle_device_insertion(drive)
            
            return len(drives)
            
        except Exception as e:
            print(f"Error scanning all drives: {e}")
            return 0

# Global instance
usb_monitor = USBMonitor() 