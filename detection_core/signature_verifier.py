"""
Software Signature / Hash Verification Module
Verifies digital signatures of executable files and computes SHA-256 hashes
"""

import pefile
import hashlib
import win32api
import win32security
import win32crypt
import win32con
import win32file
import os
import time
import threading
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

class SignatureVerifier:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
        
        # Trusted hash database (in production, this would be a proper database)
        self.trusted_hashes = {}
        self.suspicious_hashes = set()
        
        # File extensions to monitor
        self.monitored_extensions = {'.exe', '.dll', '.sys', '.drv', '.scr'}
        
        # Directories to monitor
        self.monitored_directories = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\AppData\\Local\\Temp"),
            "C:\\temp",
            "C:\\windows\\temp"
        ]
        
        # Load trusted hashes from file if exists
        self._load_trusted_hashes()
        
    def start_monitoring(self):
        """Start signature verification monitoring"""
        self.monitoring = True
        self.logger.info("🔍 Starting Signature Verification...")
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_directories, daemon=True).start()
        threading.Thread(target=self._scan_system_files, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop signature verification monitoring"""
        self.monitoring = False
        self.logger.info("🔍 Stopping Signature Verification...")
        
    def _load_trusted_hashes(self):
        """Load trusted hashes from file"""
        try:
            hash_file = "trusted_hashes.json"
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    self.trusted_hashes = json.load(f)
                self.logger.info(f"Loaded {len(self.trusted_hashes)} trusted hashes")
        except Exception as e:
            self.logger.error(f"Error loading trusted hashes: {e}")
            
    def _save_trusted_hashes(self):
        """Save trusted hashes to file"""
        try:
            with open("trusted_hashes.json", 'w') as f:
                json.dump(self.trusted_hashes, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving trusted hashes: {e}")
            
    def _monitor_directories(self):
        """Monitor directories for new executable files"""
        while self.monitoring:
            try:
                for directory in self.monitored_directories:
                    if os.path.exists(directory):
                        for file in os.listdir(directory):
                            file_path = os.path.join(directory, file)
                            if os.path.isfile(file_path):
                                file_ext = Path(file).suffix.lower()
                                if file_ext in self.monitored_extensions:
                                    self._verify_file_signature(file_path)
                                    
            except Exception as e:
                self.logger.error(f"Error monitoring directories: {e}")
                
            time.sleep(60)  # Check every minute
            
    def _scan_system_files(self):
        """Scan system files for signature verification"""
        while self.monitoring:
            try:
                # Scan Windows system directories
                system_dirs = [
                    "C:\\Windows\\System32",
                    "C:\\Windows\\SysWOW64"
                ]
                
                for system_dir in system_dirs:
                    if os.path.exists(system_dir):
                        for root, dirs, files in os.walk(system_dir):
                            for file in files:
                                if Path(file).suffix.lower() in self.monitored_extensions:
                                    file_path = os.path.join(root, file)
                                    self._verify_file_signature(file_path)
                                    
            except Exception as e:
                self.logger.error(f"Error scanning system files: {e}")
                
            time.sleep(3600)  # Scan system files every hour
            
    def _verify_file_signature(self, file_path: str):
        """Verify digital signature and hash of a file"""
        try:
            if not os.path.exists(file_path):
                return
                
            # Get file hash
            file_hash = self._compute_file_hash(file_path)
            
            # Check if hash is already known
            if file_hash in self.trusted_hashes:
                return  # File is already trusted
                
            if file_hash in self.suspicious_hashes:
                self._create_alert(
                    "HIGH",
                    f"Suspicious file detected: {os.path.basename(file_path)}",
                    f"File with known suspicious hash detected: {file_path}",
                    "signature_verification"
                )
                return
                
            # Verify digital signature
            signature_valid, signature_info = self._verify_digital_signature(file_path)
            
            # Check file properties
            file_info = self._get_file_info(file_path)
            
            # Determine if file is suspicious
            is_suspicious = self._is_file_suspicious(file_path, signature_valid, file_info)
            
            if is_suspicious:
                self._create_alert(
                    "MEDIUM",
                    f"Potentially suspicious file: {os.path.basename(file_path)}",
                    f"File {file_path} has suspicious characteristics. "
                    f"Signature valid: {signature_valid}, "
                    f"File info: {file_info}",
                    "signature_verification"
                )
                
                # Add to suspicious hashes
                self.suspicious_hashes.add(file_hash)
            else:
                # Add to trusted hashes
                self.trusted_hashes[file_hash] = {
                    'file_path': file_path,
                    'signature_valid': signature_valid,
                    'file_info': file_info,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error verifying file signature {file_path}: {e}")
            
    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error computing hash for {file_path}: {e}")
            return ""
            
    def _verify_digital_signature(self, file_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Verify digital signature of file"""
        try:
            # Use pefile to check signature
            pe = pefile.PE(file_path)
            
            # Check if file has digital signature
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                # File has security directory (digital signature)
                signature_info = {
                    'has_signature': True,
                    'signature_type': 'PE Digital Signature'
                }
                
                # Additional signature verification could be implemented here
                # For now, we'll consider files with security directory as signed
                return True, signature_info
            else:
                return False, {'has_signature': False, 'signature_type': 'None'}
                
        except Exception as e:
            self.logger.error(f"Error verifying digital signature for {file_path}: {e}")
            return False, {'has_signature': False, 'error': str(e)}
            
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get file information"""
        try:
            stat = os.stat(file_path)
            file_info = {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'filename': os.path.basename(file_path),
                'directory': os.path.dirname(file_path)
            }
            
            # Get file version info if available
            try:
                version_info = win32api.GetFileVersionInfo(file_path, "\\")
                if version_info:
                    file_info['version_info'] = {
                        'file_version': win32api.GetFileVersionInfo(file_path, "FileVersion"),
                        'product_version': win32api.GetFileVersionInfo(file_path, "ProductVersion"),
                        'company_name': win32api.GetFileVersionInfo(file_path, "CompanyName"),
                        'file_description': win32api.GetFileVersionInfo(file_path, "FileDescription")
                    }
            except:
                pass
                
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error getting file info for {file_path}: {e}")
            return {}
            
    def _is_file_suspicious(self, file_path: str, signature_valid: bool, file_info: Dict[str, Any]) -> bool:
        """Determine if file is suspicious based on various factors"""
        suspicious_factors = []
        
        # Check if file is unsigned
        if not signature_valid:
            suspicious_factors.append("No digital signature")
            
        # Check file size (very small or very large executables)
        if 'size' in file_info:
            size = file_info['size']
            if size < 1024 or size > 100 * 1024 * 1024:  # < 1KB or > 100MB
                suspicious_factors.append(f"Unusual file size: {size} bytes")
                
        # Check file location
        filename = os.path.basename(file_path).lower()
        directory = os.path.dirname(file_path).lower()
        
        # Suspicious locations
        suspicious_locations = ['temp', 'downloads', 'desktop']
        if any(loc in directory for loc in suspicious_locations):
            suspicious_factors.append(f"Suspicious location: {directory}")
            
        # Suspicious filenames
        suspicious_names = [
            'keygen', 'crack', 'patch', 'hack', 'exploit', 'backdoor',
            'trojan', 'virus', 'malware', 'stealer', 'logger', 'spy'
        ]
        if any(name in filename for name in suspicious_names):
            suspicious_factors.append(f"Suspicious filename: {filename}")
            
        # Check if file is recently created
        if 'created' in file_info:
            age_hours = (datetime.now() - file_info['created']).total_seconds() / 3600
            if age_hours < 24:  # Less than 24 hours old
                suspicious_factors.append(f"Recently created: {age_hours:.1f} hours ago")
                
        # Return True if multiple suspicious factors
        return len(suspicious_factors) >= 2
        
    def add_trusted_hash(self, file_hash: str, file_path: str):
        """Add a file hash to trusted database"""
        self.trusted_hashes[file_hash] = {
            'file_path': file_path,
            'signature_valid': True,
            'file_info': self._get_file_info(file_path),
            'timestamp': datetime.now().isoformat(),
            'manually_added': True
        }
        self._save_trusted_hashes()
        
    def add_suspicious_hash(self, file_hash: str):
        """Add a file hash to suspicious database"""
        self.suspicious_hashes.add(file_hash)
        
    def _create_alert(self, severity: str, title: str, description: str, alert_type: str):
        """Create alert using the existing alert system"""
        if self.alert_callback:
            alert_data = {
                'severity': severity,
                'title': title,
                'description': description,
                'alert_type': alert_type,
                'timestamp': datetime.now(),
                'source': 'signature_verifier'
            }
            self.alert_callback(alert_data)
            
        self.logger.warning(f"🔍 {severity} Alert: {title} - {description}")
        
    def get_status(self) -> Dict[str, Any]:
        """Get current status of signature verification"""
        return {
            'monitoring': self.monitoring,
            'trusted_hashes_count': len(self.trusted_hashes),
            'suspicious_hashes_count': len(self.suspicious_hashes),
            'monitored_extensions': list(self.monitored_extensions),
            'monitored_directories': self.monitored_directories
        }
        
    def verify_specific_file(self, file_path: str) -> Dict[str, Any]:
        """Verify a specific file and return results"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
            
        file_hash = self._compute_file_hash(file_path)
        signature_valid, signature_info = self._verify_digital_signature(file_path)
        file_info = self._get_file_info(file_path)
        is_suspicious = self._is_file_suspicious(file_path, signature_valid, file_info)
        
        return {
            'file_path': file_path,
            'file_hash': file_hash,
            'signature_valid': signature_valid,
            'signature_info': signature_info,
            'file_info': file_info,
            'is_suspicious': is_suspicious,
            'is_trusted': file_hash in self.trusted_hashes,
            'is_known_suspicious': file_hash in self.suspicious_hashes
        } 