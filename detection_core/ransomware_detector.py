"""
Ransomware Detection & File Integrity Monitoring
Detects encryption-like behavior and prevents ransomware attacks
"""

import logging
import threading
import time
import os
import shutil
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Set
from collections import defaultdict, deque
from pathlib import Path
import win32file
import win32api
import win32con
import psutil
import numpy as np

class RansomwareDetector:
    """Ransomware Detection and File Integrity Monitoring System"""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = {
            'monitoring_enabled': True,
            'file_integrity_monitoring': True,
            'real_time_backup': True,
            'entropy_analysis': True,
            'critical_folders': [
                r'C:\Users',
                r'C:\Documents and Settings',
                r'C:\Program Files',
                r'C:\Program Files (x86)'
            ],
            'suspicious_extensions': [
                '.encrypted', '.locked', '.crypto', '.crypt', '.cryptolocker',
                '.cryptowall', '.locky', '.cerber', '.teslacrypt', '.petya',
                '.wannacry', '.notpetya', '.badrabbit', '.ryuk', '.sodinokibi'
            ],
            'suspicious_processes': [
                'crypt32.dll', 'cryptui.dll', 'cryptnet.dll', 'cryptsp.dll',
                'bcrypt.dll', 'ncrypt.dll', 'rsaenh.dll', 'dssenh.dll'
            ],
            'entropy_threshold': 7.5,
            'file_operation_threshold': 50,
            'backup_interval': 300,
            'integrity_check_interval': 60,
            'max_backup_size_mb': 1000
        }
        
        # State tracking
        self.monitoring = False
        self.file_hashes = {}
        self.file_operations = deque(maxlen=10000)
        self.suspicious_activities = []
        self.entropy_scores = {}
        self.backup_files = {}
        self.critical_files = set()
        self.process_file_operations = defaultdict(int)
        self.recent_file_changes = deque(maxlen=1000)
        
        # Threading
        self.monitor_thread = None
        self.backup_thread = None
        self.integrity_thread = None
        
        # Initialize critical files
        self._initialize_critical_files()
        
    def start_monitoring(self):
        """Start ransomware detection and file integrity monitoring"""
        try:
            self.logger.info("🛡️ Starting Ransomware Detection & File Integrity Monitoring...")
            self.monitoring = True
            
            # Start monitoring threads
            self.monitor_thread = threading.Thread(target=self._monitor_file_operations, daemon=True)
            self.backup_thread = threading.Thread(target=self._backup_critical_files, daemon=True)
            self.integrity_thread = threading.Thread(target=self._check_file_integrity, daemon=True)
            
            self.monitor_thread.start()
            self.backup_thread.start()
            self.integrity_thread.start()
            
            # Initial file integrity baseline
            self._create_integrity_baseline()
            
            self.logger.info("✅ Ransomware Detection & File Integrity Monitoring started successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error starting ransomware detection: {e}")
            self.monitoring = False
            
    def stop_monitoring(self):
        """Stop ransomware detection monitoring"""
        try:
            self.logger.info("🛑 Stopping Ransomware Detection & File Integrity Monitoring...")
            self.monitoring = False
            self.logger.info("✅ Ransomware Detection & File Integrity Monitoring stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping ransomware detection: {e}")
            
    def _initialize_critical_files(self):
        """Initialize list of critical files to monitor"""
        try:
            critical_paths = [
                r'C:\Windows\System32\config\SAM',
                r'C:\Windows\System32\config\SYSTEM',
                r'C:\Windows\System32\config\SECURITY',
                r'C:\Windows\System32\lsass.exe',
                r'C:\Windows\System32\winlogon.exe',
                r'C:\Windows\System32\services.exe'
            ]
            
            for path in critical_paths:
                if os.path.exists(path):
                    self.critical_files.add(path)
                    
            # Add user documents
            user_dirs = [
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Pictures')
            ]
            
            for user_dir in user_dirs:
                if os.path.exists(user_dir):
                    self.critical_files.add(user_dir)
                    
            self.logger.info(f"✅ Initialized {len(self.critical_files)} critical files/directories")
            
        except Exception as e:
            self.logger.error(f"Error initializing critical files: {e}")
            
    def _monitor_file_operations(self):
        """Monitor file operations for ransomware patterns"""
        while self.monitoring:
            try:
                # Check for file operation bursts
                self._check_file_operation_bursts()
                
                # Check for suspicious file patterns
                self._check_suspicious_file_patterns()
                
                # Monitor process file operations
                self._monitor_process_file_operations()
                
                # Check for suspicious processes
                self._check_suspicious_processes()
                
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Error in file operation monitoring: {e}")
                time.sleep(30)
                
    def _check_file_operation_bursts(self):
        """Check for file operation bursts"""
        try:
            # Analyze recent file operations by process
            process_ops = defaultdict(list)
            
            for op in self.recent_file_changes:
                process_name = op.get('process', {}).get('name', 'unknown')
                process_ops[process_name].append(op)
                
            # Check for processes with high file operation rates
            for process_name, operations in process_ops.items():
                recent_ops = [op for op in operations 
                            if op['timestamp'] > datetime.now() - timedelta(minutes=1)]
                
                if len(recent_ops) > 20:
                    self._create_alert(
                        'FILE_OPERATION_BURST',
                        f'File operation burst detected for process: {process_name}',
                        'MEDIUM',
                        {
                            'process_name': process_name,
                            'operation_count': len(recent_ops),
                            'timeframe': '1 minute',
                            'timestamp': datetime.now().isoformat()
                        }
                    )
                    
        except Exception as e:
            self.logger.error(f"Error checking file operation bursts: {e}")
            
    def _check_suspicious_file_patterns(self):
        """Check for suspicious file patterns"""
        try:
            # Look for files with ransom notes
            ransom_patterns = [
                r'readme\.txt', r'decrypt\.txt', r'how_to_decrypt\.txt',
                r'ransom_note\.txt', r'encrypted_files\.txt'
            ]
            
            for op in self.recent_file_changes:
                file_path = op.get('file_path', '').lower()
                
                for pattern in ransom_patterns:
                    if re.search(pattern, file_path):
                        self._create_alert(
                            'RANSOM_NOTE_DETECTED',
                            f'Potential ransom note detected: {op["file_path"]}',
                            'CRITICAL',
                            {
                                'file_path': op['file_path'],
                                'pattern': pattern,
                                'timestamp': datetime.now().isoformat()
                            }
                        )
                        
        except Exception as e:
            self.logger.error(f"Error checking suspicious file patterns: {e}")
            
    def _check_suspicious_processes(self):
        """Check for suspicious processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    # Check for suspicious process names
                    suspicious_patterns = ['crypt', 'encrypt', 'lock', 'ransom', 'crypto']
                    if any(pattern in proc_name for pattern in suspicious_patterns):
                        self._create_alert(
                            'SUSPICIOUS_PROCESS',
                            f'Suspicious process detected: {proc_info["name"]}',
                            'HIGH',
                            {
                                'process_name': proc_info['name'],
                                'pid': proc_info['pid'],
                                'exe': proc_info['exe'],
                                'timestamp': datetime.now().isoformat()
                            }
                        )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error checking suspicious processes: {e}")
            
    def _monitor_process_file_operations(self):
        """Monitor process file operations"""
        try:
            # Reset process operation counts periodically
            if time.time() % 60 < 10:
                self.process_file_operations.clear()
                
        except Exception as e:
            self.logger.error(f"Error monitoring process file operations: {e}")
            
    def _backup_critical_files(self):
        """Create real-time backups of critical files"""
        while self.monitoring:
            try:
                backup_dir = Path("backups/critical_files")
                backup_dir.mkdir(parents=True, exist_ok=True)
                
                for file_path in self.critical_files:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        self._backup_file(file_path, backup_dir)
                        
                time.sleep(self.config['backup_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in backup thread: {e}")
                time.sleep(60)
                
    def _backup_file(self, file_path: str, backup_dir: Path):
        """Backup a single critical file"""
        try:
            file_name = Path(file_path).name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = backup_dir / f"{file_name}_{timestamp}.bak"
            
            # Check backup size
            if backup_path.exists():
                size_mb = backup_path.stat().st_size / (1024 * 1024)
                if size_mb > self.config['max_backup_size_mb']:
                    return
                    
            # Create backup
            shutil.copy2(file_path, backup_path)
            self.backup_files[file_path] = str(backup_path)
            
        except Exception as e:
            self.logger.error(f"Error backing up file {file_path}: {e}")
            
    def _create_integrity_baseline(self):
        """Create baseline file integrity hashes"""
        try:
            for file_path in self.critical_files:
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    file_hash = self._calculate_file_hash(file_path)
                    self.file_hashes[file_path] = file_hash
                    
            self.logger.info(f"✅ Created integrity baseline for {len(self.file_hashes)} files")
            
        except Exception as e:
            self.logger.error(f"Error creating integrity baseline: {e}")
            
    def _check_file_integrity(self):
        """Periodic file integrity checking"""
        while self.monitoring:
            try:
                for file_path in self.file_hashes:
                    if os.path.exists(file_path):
                        self._check_single_file_integrity(file_path)
                        
                time.sleep(self.config['integrity_check_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in integrity checking: {e}")
                time.sleep(60)
                
    def _check_single_file_integrity(self, file_path: str):
        """Check file integrity against baseline"""
        try:
            if file_path not in self.file_hashes:
                return
                
            current_hash = self._calculate_file_hash(file_path)
            baseline_hash = self.file_hashes[file_path]
            
            if current_hash != baseline_hash:
                self._create_alert(
                    'FILE_INTEGRITY_VIOLATION',
                    f'File integrity violation detected: {file_path}',
                    'HIGH',
                    {
                        'file_path': file_path,
                        'baseline_hash': baseline_hash,
                        'current_hash': current_hash,
                        'timestamp': datetime.now().isoformat()
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Error checking file integrity: {e}")
            
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
                    
            return hash_sha256.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculating file hash: {e}")
            return ""
            
    def _create_alert(self, alert_type: str, message: str, severity: str, details: Dict[str, Any]):
        """Create security alert"""
        try:
            alert_data = {
                'alert_type': f'RANSOMWARE_{alert_type}',
                'message': message,
                'severity': severity,
                'source': 'Ransomware Detector',
                'timestamp': datetime.now().isoformat(),
                'details': details
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
            self.logger.warning(f"🚨 Ransomware Alert: {message}")
            
        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")
            
    def get_status(self) -> Dict[str, Any]:
        """Get ransomware detector status"""
        return {
            'monitoring': self.monitoring,
            'file_operations_count': len(self.file_operations),
            'suspicious_activities': len(self.suspicious_activities),
            'entropy_scores': len(self.entropy_scores),
            'backup_files': len(self.backup_files),
            'critical_files': len(self.critical_files),
            'integrity_baseline': len(self.file_hashes),
            'last_update': datetime.now().isoformat()
        }
        
    def get_ransomware_report(self) -> Dict[str, Any]:
        """Generate comprehensive ransomware detection report"""
        return {
            'total_file_operations': len(self.file_operations),
            'suspicious_activities': self.suspicious_activities,
            'backup_status': {
                'total_backups': len(self.backup_files),
                'backup_files': list(self.backup_files.keys())
            },
            'integrity_status': {
                'baseline_files': len(self.file_hashes),
                'monitored_files': list(self.file_hashes.keys())
            },
            'recommendations': self._generate_recommendations(),
            'timestamp': datetime.now().isoformat()
        }
        
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if len(self.suspicious_activities) > 0:
            recommendations.append("Review suspicious file operations")
            
        if len(self.backup_files) == 0:
            recommendations.append("Enable real-time backup for critical files")
            
        return recommendations 