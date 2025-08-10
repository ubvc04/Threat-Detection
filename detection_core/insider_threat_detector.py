"""
Insider Threat Monitoring Module
Detects abnormal file transfers, unauthorized remote access tools, and behavioral anomalies
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
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
from collections import defaultdict

class InsiderThreatDetector:
    def __init__(self, alert_callback=None, ai_model_callback=None):
        self.alert_callback = alert_callback
        self.ai_model_callback = ai_model_callback
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
        
        # Remote access tools to monitor
        self.remote_access_tools = {
            'anydesk': ['anydesk.exe', 'anydesk.exe'],
            'teamviewer': ['teamviewer.exe', 'teamviewer_service.exe'],
            'vnc': ['vncviewer.exe', 'vncserver.exe', 'tightvnc.exe', 'ultravnc.exe'],
            'rdp': ['mstsc.exe', 'rdpclip.exe'],
            'logmein': ['logmein.exe', 'logmeinrescue.exe'],
            'gotomeeting': ['g2mcomm.exe', 'g2mlauncher.exe'],
            'join.me': ['join.me.exe'],
            'supremo': ['supremo.exe'],
            'ammyy': ['ammyy.exe'],
            'aero': ['aero.exe'],
            'chrome_remote': ['chrome.exe'],  # Chrome remote desktop
            'microsoft_rdp': ['mstsc.exe'],
        }
        
        # Cloud sync folders to monitor
        self.cloud_sync_folders = [
            os.path.expanduser("~\\OneDrive"),
            os.path.expanduser("~\\Google Drive"),
            os.path.expanduser("~\\Dropbox"),
            os.path.expanduser("~\\Box"),
            os.path.expanduser("~\\iCloud Drive"),
            os.path.expanduser("~\\Documents\\OneDrive"),
            os.path.expanduser("~\\Desktop\\OneDrive"),
        ]
        
        # External device patterns
        self.external_device_patterns = [
            r'[A-Z]:\\',  # Any drive letter
            r'\\\\[^\\]+\\',  # Network shares
        ]
        
        # Suspicious file transfer patterns
        self.suspicious_transfer_patterns = [
            r'.*\.(doc|docx|xls|xlsx|ppt|pptx|pdf|txt|csv|db|sql|bak|zip|rar|7z)$',  # Documents and databases
            r'.*password.*\.(txt|doc|docx)$',  # Password files
            r'.*config.*\.(ini|cfg|conf|json|xml)$',  # Configuration files
            r'.*backup.*\.(bak|zip|tar|gz)$',  # Backup files
        ]
        
        # Behavioral thresholds
        self.behavioral_thresholds = {
            'large_file_transfer_mb': 100,  # Alert on transfers > 100MB
            'multiple_file_transfers': 10,  # Alert on > 10 files in short time
            'after_hours_activity': True,  # Monitor after-hours activity
            'weekend_activity': True,  # Monitor weekend activity
            'unusual_time_threshold': 3,  # Hours outside normal business hours
        }
        
        # Track file transfer activity
        self.file_transfers = defaultdict(list)
        self.process_activity = defaultdict(list)
        self.user_activity = defaultdict(list)
        
        # Load behavioral baseline (if exists)
        self.behavioral_baseline = self._load_behavioral_baseline()
        
    def start_monitoring(self):
        """Start insider threat monitoring"""
        self.monitoring = True
        self.logger.info("👤 Starting Insider Threat Detection...")
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_remote_access_tools, daemon=True).start()
        threading.Thread(target=self._monitor_file_transfers, daemon=True).start()
        threading.Thread(target=self._monitor_cloud_sync, daemon=True).start()
        threading.Thread(target=self._monitor_external_devices, daemon=True).start()
        threading.Thread(target=self._monitor_behavioral_anomalies, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop insider threat monitoring"""
        self.monitoring = False
        self.logger.info("👤 Stopping Insider Threat Detection...")
        
    def _monitor_remote_access_tools(self):
        """Monitor for unauthorized remote access tools"""
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    try:
                        proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                        
                        # Check for remote access tools
                        for tool_category, tool_names in self.remote_access_tools.items():
                            for tool_name in tool_names:
                                if tool_name.lower() in proc_name:
                                    cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                                    
                                    # Check if this is authorized usage
                                    if not self._is_authorized_remote_access(tool_category, proc.info['exe']):
                                        self._create_alert(
                                            "HIGH",
                                            f"Unauthorized Remote Access Tool: {tool_category}",
                                            f"Process {proc_name} (PID: {proc.info['pid']}) is running. "
                                            f"Command line: {cmdline}",
                                            "insider_threat"
                                        )
                                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except Exception as e:
                self.logger.error(f"Error monitoring remote access tools: {e}")
                
            time.sleep(30)  # Check every 30 seconds
            
    def _monitor_file_transfers(self):
        """Monitor file transfer activities"""
        while self.monitoring:
            try:
                # Monitor file system activity
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'open_files']):
                    try:
                        if proc.info['open_files']:
                            for file_info in proc.info['open_files']:
                                file_path = file_info.path
                                if self._is_suspicious_file_transfer(file_path):
                                    self._record_file_transfer(proc.info['name'], file_path)
                                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except Exception as e:
                self.logger.error(f"Error monitoring file transfers: {e}")
                
            time.sleep(10)  # Check every 10 seconds
            
    def _monitor_cloud_sync(self):
        """Monitor cloud sync folder activities"""
        while self.monitoring:
            try:
                for cloud_folder in self.cloud_sync_folders:
                    if os.path.exists(cloud_folder):
                        # Check for recent file modifications
                        for root, dirs, files in os.walk(cloud_folder):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    stat = os.stat(file_path)
                                    file_age = time.time() - stat.st_mtime
                                    
                                    # Alert on recent modifications to cloud sync
                                    if file_age < 300:  # 5 minutes
                                        file_size = stat.st_size
                                        if file_size > self.behavioral_thresholds['large_file_transfer_mb'] * 1024 * 1024:
                                            self._create_alert(
                                                "MEDIUM",
                                                f"Large File Uploaded to Cloud: {os.path.basename(file_path)}",
                                                f"Large file ({file_size / (1024*1024):.1f}MB) recently uploaded to cloud sync: {file_path}",
                                                "insider_threat"
                                            )
                                            
                                except (OSError, PermissionError):
                                    continue
                                    
            except Exception as e:
                self.logger.error(f"Error monitoring cloud sync: {e}")
                
            time.sleep(60)  # Check every minute
            
    def _monitor_external_devices(self):
        """Monitor external device connections and file transfers"""
        while self.monitoring:
            try:
                # Check for external drives
                for drive in win32api.GetLogicalDriveStrings().split('\000')[:-1]:
                    drive_type = win32file.GetDriveType(drive)
                    
                    # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3, DRIVE_REMOTE = 4
                    if drive_type == 2:  # Removable drive
                        self._monitor_external_drive(drive)
                        
            except Exception as e:
                self.logger.error(f"Error monitoring external devices: {e}")
                
            time.sleep(30)  # Check every 30 seconds
            
    def _monitor_external_drive(self, drive_path: str):
        """Monitor specific external drive for file transfers"""
        try:
            for root, dirs, files in os.walk(drive_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        file_age = time.time() - stat.st_mtime
                        
                        # Alert on recent files on external drive
                        if file_age < 600:  # 10 minutes
                            file_size = stat.st_size
                            if file_size > 10 * 1024 * 1024:  # 10MB
                                self._create_alert(
                                    "MEDIUM",
                                    f"Large File on External Device: {os.path.basename(file_path)}",
                                    f"Large file ({file_size / (1024*1024):.1f}MB) recently transferred to external device: {file_path}",
                                    "insider_threat"
                                )
                                
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error monitoring external drive {drive_path}: {e}")
            
    def _monitor_behavioral_anomalies(self):
        """Monitor for behavioral anomalies using AI model if available"""
        while self.monitoring:
            try:
                current_time = datetime.now()
                
                # Check for after-hours activity
                if self.behavioral_thresholds['after_hours_activity']:
                    if self._is_after_hours(current_time):
                        self._check_after_hours_activity()
                        
                # Check for weekend activity
                if self.behavioral_thresholds['weekend_activity']:
                    if current_time.weekday() >= 5:  # Saturday = 5, Sunday = 6
                        self._check_weekend_activity()
                        
                # Analyze file transfer patterns
                self._analyze_file_transfer_patterns()
                
                # Use AI model for behavioral analysis if available
                if self.ai_model_callback:
                    self._analyze_behavior_with_ai()
                    
            except Exception as e:
                self.logger.error(f"Error monitoring behavioral anomalies: {e}")
                
            time.sleep(300)  # Check every 5 minutes
            
    def _is_authorized_remote_access(self, tool_category: str, exe_path: str) -> bool:
        """Check if remote access tool usage is authorized"""
        # This would typically check against a whitelist or policy
        # For now, we'll consider all remote access tools as potentially unauthorized
        return False
        
    def _is_suspicious_file_transfer(self, file_path: str) -> bool:
        """Check if file transfer is suspicious"""
        if not file_path:
            return False
            
        file_path_lower = file_path.lower()
        
        # Check against suspicious patterns
        for pattern in self.suspicious_transfer_patterns:
            if re.match(pattern, file_path_lower):
                return True
                
        # Check file size
        try:
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                if file_size > self.behavioral_thresholds['large_file_transfer_mb'] * 1024 * 1024:
                    return True
        except:
            pass
            
        return False
        
    def _record_file_transfer(self, process_name: str, file_path: str):
        """Record file transfer activity"""
        transfer_record = {
            'timestamp': datetime.now(),
            'process_name': process_name,
            'file_path': file_path,
            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        }
        
        self.file_transfers[process_name].append(transfer_record)
        
        # Keep only recent transfers (last hour)
        cutoff_time = datetime.now() - timedelta(hours=1)
        self.file_transfers[process_name] = [
            transfer for transfer in self.file_transfers[process_name]
            if transfer['timestamp'] > cutoff_time
        ]
        
    def _analyze_file_transfer_patterns(self):
        """Analyze file transfer patterns for anomalies"""
        for process_name, transfers in self.file_transfers.items():
            if len(transfers) > self.behavioral_thresholds['multiple_file_transfers']:
                total_size = sum(transfer['file_size'] for transfer in transfers)
                
                self._create_alert(
                    "MEDIUM",
                    f"Multiple File Transfers: {process_name}",
                    f"Process {process_name} has transferred {len(transfers)} files "
                    f"({total_size / (1024*1024):.1f}MB total) in the last hour",
                    "insider_threat"
                )
                
    def _is_after_hours(self, current_time: datetime) -> bool:
        """Check if current time is after business hours"""
        hour = current_time.hour
        return hour < 6 or hour > 18  # Before 6 AM or after 6 PM
        
    def _check_after_hours_activity(self):
        """Check for suspicious after-hours activity"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    
                    # Check for suspicious processes during after-hours
                    suspicious_after_hours = [
                        'cmd.exe', 'powershell.exe', 'explorer.exe',
                        'notepad.exe', 'wordpad.exe', 'calc.exe'
                    ]
                    
                    if proc_name in suspicious_after_hours:
                        self._create_alert(
                            "LOW",
                            f"After-Hours Activity: {proc_name}",
                            f"Process {proc_name} (PID: {proc.info['pid']}) running during after-hours",
                            "insider_threat"
                        )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error checking after-hours activity: {e}")
            
    def _check_weekend_activity(self):
        """Check for suspicious weekend activity"""
        try:
            # Similar to after-hours check but for weekends
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    
                    # Check for work-related processes during weekends
                    work_processes = [
                        'outlook.exe', 'excel.exe', 'winword.exe', 'powerpnt.exe',
                        'chrome.exe', 'firefox.exe', 'edge.exe'
                    ]
                    
                    if proc_name in work_processes:
                        self._create_alert(
                            "LOW",
                            f"Weekend Activity: {proc_name}",
                            f"Work-related process {proc_name} (PID: {proc.info['pid']}) running during weekend",
                            "insider_threat"
                        )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error checking weekend activity: {e}")
            
    def _analyze_behavior_with_ai(self):
        """Use AI model to analyze behavioral patterns"""
        try:
            # Collect current behavioral data
            behavioral_data = {
                'file_transfers_count': sum(len(transfers) for transfers in self.file_transfers.values()),
                'active_processes': len(list(psutil.process_iter())),
                'timestamp': datetime.now().isoformat()
            }
            
            # Call AI model for analysis
            if self.ai_model_callback:
                anomaly_score = self.ai_model_callback(behavioral_data)
                if anomaly_score > 0.7:  # High anomaly score
                    self._create_alert(
                        "HIGH",
                        "AI Detected Behavioral Anomaly",
                        f"AI model detected unusual behavior pattern with score: {anomaly_score:.2f}",
                        "insider_threat"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error analyzing behavior with AI: {e}")
            
    def _load_behavioral_baseline(self) -> Dict[str, Any]:
        """Load behavioral baseline from file"""
        try:
            baseline_file = "behavioral_baseline.json"
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading behavioral baseline: {e}")
        return {}
        
    def _save_behavioral_baseline(self):
        """Save behavioral baseline to file"""
        try:
            baseline_data = {
                'file_transfer_patterns': dict(self.file_transfers),
                'process_activity': dict(self.process_activity),
                'user_activity': dict(self.user_activity),
                'timestamp': datetime.now().isoformat()
            }
            
            with open("behavioral_baseline.json", 'w') as f:
                json.dump(baseline_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving behavioral baseline: {e}")
            
    def _create_alert(self, severity: str, title: str, description: str, alert_type: str):
        """Create alert using the existing alert system"""
        if self.alert_callback:
            alert_data = {
                'severity': severity,
                'title': title,
                'description': description,
                'alert_type': alert_type,
                'timestamp': datetime.now(),
                'source': 'insider_threat_detector'
            }
            self.alert_callback(alert_data)
            
        self.logger.warning(f"👤 {severity} Alert: {title} - {description}")
        
    def get_status(self) -> Dict[str, Any]:
        """Get current status of insider threat detection"""
        return {
            'monitoring': self.monitoring,
            'remote_access_tools_count': len(self.remote_access_tools),
            'cloud_sync_folders_count': len(self.cloud_sync_folders),
            'file_transfers_count': sum(len(transfers) for transfers in self.file_transfers.values()),
            'behavioral_thresholds': self.behavioral_thresholds,
            'ai_model_available': self.ai_model_callback is not None
        }
        
    def add_authorized_remote_access(self, tool_name: str, exe_path: str):
        """Add authorized remote access tool"""
        if tool_name not in self.remote_access_tools:
            self.remote_access_tools[tool_name] = [exe_path]
        else:
            self.remote_access_tools[tool_name].append(exe_path)
            
    def update_behavioral_thresholds(self, thresholds: Dict[str, Any]):
        """Update behavioral detection thresholds"""
        self.behavioral_thresholds.update(thresholds) 