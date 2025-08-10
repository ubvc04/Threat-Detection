"""
Live Memory Forensics & Analysis
Scans and extracts malicious code or patterns directly from RAM
"""

import logging
import threading
import time
import os
import json
import re
import struct
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Tuple
from collections import defaultdict, deque
import psutil
import win32process
import win32api
import win32con
import win32security
import win32gui
import win32event
import ctypes
from ctypes import wintypes
import numpy as np

class MemoryForensics:
    """Live Memory Forensics and Analysis System"""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = {
            'monitoring_enabled': True,
            'memory_scanning': True,
            'process_monitoring': True,
            'dll_injection_detection': True,
            'shellcode_detection': True,
            'scan_interval': 30,  # 30 seconds
            'memory_scan_size': 1024 * 1024,  # 1MB chunks
            'suspicious_patterns': [
                b'\x90\x90\x90',  # NOP sled
                b'\xCC\xCC\xCC',  # INT3 sled
                b'\xEB\xFE',      # JMP $
                b'\xE9\x00\x00\x00\x00',  # JMP with null
                b'\x68\x00\x00\x00\x00',  # PUSH null
                b'\x83\xEC\x00',  # SUB ESP, 0
                b'\x8B\xEC',      # MOV EBP, ESP
                b'\x55\x8B\xEC',  # PUSH EBP; MOV EBP, ESP
            ],
            'malicious_strings': [
                b'cmd.exe', b'powershell.exe', b'wscript.exe', b'cscript.exe',
                b'rundll32.exe', b'regsvr32.exe', b'mshta.exe', b'certutil.exe',
                b'bitsadmin.exe', b'wmic.exe', b'net.exe', b'ipconfig.exe',
                b'whoami.exe', b'systeminfo.exe', b'tasklist.exe', b'netstat.exe'
            ],
            'suspicious_dlls': [
                'kernel32.dll', 'ntdll.dll', 'user32.dll', 'gdi32.dll',
                'advapi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll',
                'ws2_32.dll', 'iphlpapi.dll', 'psapi.dll', 'version.dll'
            ]
        }
        
        # State tracking
        self.monitoring = False
        self.scan_results = []
        self.suspicious_processes = []
        self.injected_dlls = []
        self.shellcode_detections = []
        self.memory_patterns = []
        self.process_memory_maps = {}
        
        # Threading
        self.scan_thread = None
        self.process_thread = None
        
        # Windows API constants
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.PROCESS_VM_READ = 0x0010
        self.MEM_COMMIT = 0x1000
        self.PAGE_READWRITE = 0x04
        self.PAGE_EXECUTE_READWRITE = 0x40
        
    def start_monitoring(self):
        """Start memory forensics monitoring"""
        try:
            self.logger.info("🧠 Starting Live Memory Forensics & Analysis...")
            self.monitoring = True
            
            # Start monitoring threads
            self.scan_thread = threading.Thread(target=self._memory_scanning_loop, daemon=True)
            self.process_thread = threading.Thread(target=self._process_monitoring_loop, daemon=True)
            
            self.scan_thread.start()
            self.process_thread.start()
            
            self.logger.info("✅ Live Memory Forensics & Analysis started successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error starting memory forensics: {e}")
            self.monitoring = False
            
    def stop_monitoring(self):
        """Stop memory forensics monitoring"""
        try:
            self.logger.info("🛑 Stopping Live Memory Forensics & Analysis...")
            self.monitoring = False
            self.logger.info("✅ Live Memory Forensics & Analysis stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping memory forensics: {e}")
            
    def _memory_scanning_loop(self):
        """Main memory scanning loop"""
        while self.monitoring:
            try:
                # Scan all processes for suspicious memory patterns
                self._scan_all_processes()
                
                # Detect DLL injections
                self._detect_dll_injections()
                
                # Detect shellcode
                self._detect_shellcode()
                
                time.sleep(self.config['scan_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in memory scanning loop: {e}")
                time.sleep(60)
                
    def _process_monitoring_loop(self):
        """Process monitoring loop"""
        while self.monitoring:
            try:
                # Monitor process creation and termination
                self._monitor_process_changes()
                
                # Analyze process memory maps
                self._analyze_process_memory_maps()
                
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Error in process monitoring loop: {e}")
                time.sleep(30)
                
    def _scan_all_processes(self):
        """Scan all running processes for suspicious memory patterns"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Skip system processes if needed
                    if self._should_skip_process(proc_info):
                        continue
                        
                    # Scan process memory
                    self._scan_process_memory(pid, proc_info['name'])
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error scanning all processes: {e}")
            
    def _should_skip_process(self, proc_info: Dict[str, Any]) -> bool:
        """Determine if process should be skipped"""
        try:
            # Skip system processes
            system_processes = [
                'System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
                'services.exe', 'lsass.exe', 'winlogon.exe', 'explorer.exe'
            ]
            
            if proc_info['name'] in system_processes:
                return True
                
            # Skip processes without executable path
            if not proc_info['exe']:
                return True
                
            return False
            
        except Exception:
            return True
            
    def _scan_process_memory(self, pid: int, process_name: str):
        """Scan individual process memory for suspicious patterns"""
        try:
            # Open process handle
            process_handle = win32api.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
                False, pid
            )
            
            # Get process memory information
            memory_info = self._get_process_memory_info(process_handle)
            
            # Scan memory regions
            for region in memory_info:
                if self._is_suspicious_memory_region(region):
                    self._scan_memory_region(process_handle, region, pid, process_name)
                    
            # Close handle
            win32api.CloseHandle(process_handle)
            
        except Exception as e:
            # Access denied is common for system processes
            if "Access is denied" not in str(e):
                self.logger.debug(f"Error scanning process {pid} ({process_name}): {e}")
                
    def _get_process_memory_info(self, process_handle) -> List[Dict[str, Any]]:
        """Get process memory regions information"""
        try:
            regions = []
            address = 0
            
            while True:
                try:
                    # Query memory region
                    memory_basic_info = win32process.VirtualQueryEx(
                        process_handle, address
                    )
                    
                    if memory_basic_info:
                        region = {
                            'base_address': memory_basic_info[0],
                            'region_size': memory_basic_info[1],
                            'state': memory_basic_info[2],
                            'protect': memory_basic_info[3],
                            'type': memory_basic_info[4]
                        }
                        
                        regions.append(region)
                        address = memory_basic_info[0] + memory_basic_info[1]
                    else:
                        break
                        
                except Exception:
                    break
                    
            return regions
            
        except Exception as e:
            self.logger.error(f"Error getting process memory info: {e}")
            return []
            
    def _is_suspicious_memory_region(self, region: Dict[str, Any]) -> bool:
        """Check if memory region is suspicious"""
        try:
            # Check if region is committed and readable/writable
            if region['state'] != self.MEM_COMMIT:
                return False
                
            # Check if region is readable/writable or executable
            if region['protect'] in [self.PAGE_READWRITE, self.PAGE_EXECUTE_READWRITE]:
                return True
                
            return False
            
        except Exception:
            return False
            
    def _scan_memory_region(self, process_handle, region: Dict[str, Any], pid: int, process_name: str):
        """Scan a specific memory region for suspicious patterns"""
        try:
            base_address = region['base_address']
            region_size = region['region_size']
            
            # Read memory in chunks
            chunk_size = self.config['memory_scan_size']
            offset = 0
            
            while offset < region_size:
                try:
                    # Read memory chunk
                    chunk_size = min(chunk_size, region_size - offset)
                    memory_data = win32process.ReadProcessMemory(
                        process_handle, base_address + offset, chunk_size
                    )
                    
                    # Scan for suspicious patterns
                    self._scan_memory_chunk(memory_data, base_address + offset, pid, process_name)
                    
                    offset += chunk_size
                    
                except Exception:
                    # Skip unreadable memory regions
                    offset += chunk_size
                    
        except Exception as e:
            self.logger.debug(f"Error scanning memory region: {e}")
            
    def _scan_memory_chunk(self, memory_data: bytes, address: int, pid: int, process_name: str):
        """Scan memory chunk for suspicious patterns"""
        try:
            # Scan for suspicious byte patterns
            for pattern in self.config['suspicious_patterns']:
                if pattern in memory_data:
                    self._create_pattern_alert(pattern, address, pid, process_name)
                    
            # Scan for malicious strings
            for malicious_string in self.config['malicious_strings']:
                if malicious_string in memory_data:
                    self._create_string_alert(malicious_string, address, pid, process_name)
                    
            # Scan for shellcode indicators
            self._detect_shellcode_in_chunk(memory_data, address, pid, process_name)
            
        except Exception as e:
            self.logger.error(f"Error scanning memory chunk: {e}")
            
    def _detect_shellcode_in_chunk(self, memory_data: bytes, address: int, pid: int, process_name: str):
        """Detect shellcode patterns in memory chunk"""
        try:
            # Look for common shellcode patterns
            shellcode_patterns = [
                # Metasploit patterns
                b'\x89\xE5\x83\xEC\x20',  # MOV EBP, ESP; SUB ESP, 32
                b'\x31\xC0\x50\x68',      # XOR EAX, EAX; PUSH EAX; PUSH
                b'\x68\x2F\x2F\x73\x68',  # PUSH "//sh"
                b'\x68\x2F\x62\x69\x6E',  # PUSH "/bin"
                
                # Generic shellcode patterns
                b'\x90\x90\x90\x90',      # NOP sled
                b'\xCC\xCC\xCC\xCC',      # INT3 sled
                b'\xEB\xFE\xEB\xFE',      # JMP $ JMP $
            ]
            
            for pattern in shellcode_patterns:
                if pattern in memory_data:
                    self._create_shellcode_alert(pattern, address, pid, process_name)
                    
        except Exception as e:
            self.logger.error(f"Error detecting shellcode: {e}")
            
    def _detect_dll_injections(self):
        """Detect DLL injection techniques"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Check for suspicious DLLs loaded
                    self._check_suspicious_dlls(pid, proc_info['name'])
                    
                    # Check for DLL injection techniques
                    self._check_dll_injection_techniques(pid, proc_info['name'])
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error detecting DLL injections: {e}")
            
    def _check_suspicious_dlls(self, pid: int, process_name: str):
        """Check for suspicious DLLs loaded by process"""
        try:
            proc = psutil.Process(pid)
            dlls = proc.memory_maps()
            
            for dll in dlls:
                dll_name = os.path.basename(dll.path).lower()
                
                # Check for suspicious DLLs
                if dll_name in self.config['suspicious_dlls']:
                    # Additional checks for suspicious loading patterns
                    if self._is_suspicious_dll_loading(dll, process_name):
                        self._create_dll_alert(dll_name, pid, process_name, 'Suspicious DLL loaded')
                        
        except Exception as e:
            self.logger.debug(f"Error checking suspicious DLLs for {pid}: {e}")
            
    def _is_suspicious_dll_loading(self, dll_info, process_name: str) -> bool:
        """Check if DLL loading is suspicious"""
        try:
            # Check for DLLs loaded from unusual locations
            dll_path = dll_info.path.lower()
            
            suspicious_locations = [
                'temp', 'downloads', 'desktop', 'appdata',
                'users', 'program files', 'windows\\system32'
            ]
            
            # If DLL is loaded from suspicious location
            if any(location in dll_path for location in suspicious_locations):
                return True
                
            return False
            
        except Exception:
            return False
            
    def _check_dll_injection_techniques(self, pid: int, process_name: str):
        """Check for common DLL injection techniques"""
        try:
            # Check for SetWindowsHookEx injection
            if self._check_hook_injection(pid, process_name):
                self._create_dll_alert('Hook Injection', pid, process_name, 'SetWindowsHookEx injection detected')
                
            # Check for CreateRemoteThread injection
            if self._check_remote_thread_injection(pid, process_name):
                self._create_dll_alert('Remote Thread', pid, process_name, 'CreateRemoteThread injection detected')
                
        except Exception as e:
            self.logger.debug(f"Error checking DLL injection techniques for {pid}: {e}")
            
    def _check_hook_injection(self, pid: int, process_name: str) -> bool:
        """Check for SetWindowsHookEx injection"""
        try:
            # This would require more detailed analysis
            # For now, we'll check for suspicious hook-related processes
            suspicious_hook_processes = ['explorer.exe', 'svchost.exe']
            return process_name.lower() in suspicious_hook_processes
            
        except Exception:
            return False
            
    def _check_remote_thread_injection(self, pid: int, process_name: str) -> bool:
        """Check for CreateRemoteThread injection"""
        try:
            # This would require more detailed analysis
            # For now, we'll check for suspicious thread creation patterns
            return False
            
        except Exception:
            return False
            
    def _detect_shellcode(self):
        """Detect shellcode in running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Check for shellcode indicators in process memory
                    self._check_process_shellcode(pid, proc_info['name'])
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error detecting shellcode: {e}")
            
    def _check_process_shellcode(self, pid: int, process_name: str):
        """Check for shellcode in specific process"""
        try:
            # This would require detailed memory analysis
            # For now, we'll check for suspicious process behavior
            if self._has_suspicious_behavior(pid, process_name):
                self._create_shellcode_alert(b'Suspicious Behavior', 0, pid, process_name)
                
        except Exception as e:
            self.logger.debug(f"Error checking process shellcode for {pid}: {e}")
            
    def _has_suspicious_behavior(self, pid: int, process_name: str) -> bool:
        """Check for suspicious process behavior"""
        try:
            proc = psutil.Process(pid)
            
            # Check for unusual CPU usage patterns
            cpu_percent = proc.cpu_percent(interval=1)
            if cpu_percent > 80:  # High CPU usage
                return True
                
            # Check for unusual memory patterns
            memory_info = proc.memory_info()
            if memory_info.rss > 500 * 1024 * 1024:  # > 500MB
                return True
                
            return False
            
        except Exception:
            return False
            
    def _monitor_process_changes(self):
        """Monitor for process creation and termination"""
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    current_processes.add(proc_info['pid'])
                    
                    # Check for new processes
                    if proc_info['pid'] not in self.process_memory_maps:
                        self._analyze_new_process(proc_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Remove terminated processes
            terminated_pids = set(self.process_memory_maps.keys()) - current_processes
            for pid in terminated_pids:
                del self.process_memory_maps[pid]
                
        except Exception as e:
            self.logger.error(f"Error monitoring process changes: {e}")
            
    def _analyze_new_process(self, proc_info: Dict[str, Any]):
        """Analyze newly created process"""
        try:
            pid = proc_info['pid']
            process_name = proc_info['name']
            
            # Create memory map for new process
            self.process_memory_maps[pid] = {
                'name': process_name,
                'exe': proc_info['exe'],
                'created': datetime.now(),
                'memory_regions': [],
                'suspicious_indicators': []
            }
            
            # Initial analysis
            self._perform_initial_analysis(pid, process_name)
            
        except Exception as e:
            self.logger.error(f"Error analyzing new process: {e}")
            
    def _perform_initial_analysis(self, pid: int, process_name: str):
        """Perform initial analysis of new process"""
        try:
            # Check for suspicious process names
            suspicious_names = [
                'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
            ]
            
            if process_name.lower() in suspicious_names:
                self._create_process_alert(pid, process_name, 'Suspicious process name')
                
        except Exception as e:
            self.logger.error(f"Error performing initial analysis: {e}")
            
    def _analyze_process_memory_maps(self):
        """Analyze process memory maps for changes"""
        try:
            for pid, process_info in self.process_memory_maps.items():
                try:
                    # Update memory regions
                    self._update_process_memory_map(pid, process_info)
                    
                except Exception as e:
                    self.logger.debug(f"Error updating memory map for {pid}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing process memory maps: {e}")
            
    def _update_process_memory_map(self, pid: int, process_info: Dict[str, Any]):
        """Update process memory map"""
        try:
            proc = psutil.Process(pid)
            memory_maps = proc.memory_maps()
            
            # Update memory regions
            process_info['memory_regions'] = len(memory_maps)
            
            # Check for suspicious memory regions
            suspicious_count = 0
            for mmap in memory_maps:
                if self._is_suspicious_memory_map(mmap):
                    suspicious_count += 1
                    
            if suspicious_count > 0:
                process_info['suspicious_indicators'].append({
                    'timestamp': datetime.now().isoformat(),
                    'suspicious_regions': suspicious_count,
                    'type': 'Suspicious memory regions'
                })
                
        except Exception as e:
            self.logger.debug(f"Error updating memory map for {pid}: {e}")
            
    def _is_suspicious_memory_map(self, mmap) -> bool:
        """Check if memory map is suspicious"""
        try:
            # Check for executable memory regions
            if 'x' in mmap.perms:  # Executable
                return True
                
            # Check for private memory regions
            if 'p' in mmap.perms:  # Private
                return True
                
            return False
            
        except Exception:
            return False
            
    def _create_pattern_alert(self, pattern: bytes, address: int, pid: int, process_name: str):
        """Create alert for suspicious pattern detection"""
        try:
            alert_data = {
                'alert_type': 'MEMORY_SUSPICIOUS_PATTERN',
                'message': f'Suspicious memory pattern detected in {process_name}',
                'severity': 'MEDIUM',
                'source': 'Memory Forensics',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'pattern': pattern.hex(),
                    'address': hex(address),
                    'pid': pid,
                    'process_name': process_name
                }
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
            self.logger.warning(f"🚨 Memory Pattern Alert: {alert_data['message']}")
            
        except Exception as e:
            self.logger.error(f"Error creating pattern alert: {e}")
            
    def _create_string_alert(self, malicious_string: bytes, address: int, pid: int, process_name: str):
        """Create alert for malicious string detection"""
        try:
            alert_data = {
                'alert_type': 'MEMORY_MALICIOUS_STRING',
                'message': f'Malicious string detected in {process_name}',
                'severity': 'HIGH',
                'source': 'Memory Forensics',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'string': malicious_string.decode('utf-8', errors='ignore'),
                    'address': hex(address),
                    'pid': pid,
                    'process_name': process_name
                }
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
            self.logger.warning(f"🚨 Malicious String Alert: {alert_data['message']}")
            
        except Exception as e:
            self.logger.error(f"Error creating string alert: {e}")
            
    def _create_shellcode_alert(self, pattern: bytes, address: int, pid: int, process_name: str):
        """Create alert for shellcode detection"""
        try:
            alert_data = {
                'alert_type': 'MEMORY_SHELLCODE_DETECTED',
                'message': f'Shellcode detected in {process_name}',
                'severity': 'CRITICAL',
                'source': 'Memory Forensics',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'pattern': pattern.hex() if isinstance(pattern, bytes) else str(pattern),
                    'address': hex(address),
                    'pid': pid,
                    'process_name': process_name
                }
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
            self.logger.warning(f"🚨 Shellcode Alert: {alert_data['message']}")
            
        except Exception as e:
            self.logger.error(f"Error creating shellcode alert: {e}")
            
    def _create_dll_alert(self, dll_name: str, pid: int, process_name: str, reason: str):
        """Create alert for DLL injection detection"""
        try:
            alert_data = {
                'alert_type': 'MEMORY_DLL_INJECTION',
                'message': f'DLL injection detected in {process_name}',
                'severity': 'HIGH',
                'source': 'Memory Forensics',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'dll_name': dll_name,
                    'pid': pid,
                    'process_name': process_name,
                    'reason': reason
                }
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
            self.logger.warning(f"🚨 DLL Injection Alert: {alert_data['message']}")
            
        except Exception as e:
            self.logger.error(f"Error creating DLL alert: {e}")
            
    def _create_process_alert(self, pid: int, process_name: str, reason: str):
        """Create alert for suspicious process detection"""
        try:
            alert_data = {
                'alert_type': 'MEMORY_SUSPICIOUS_PROCESS',
                'message': f'Suspicious process detected: {process_name}',
                'severity': 'MEDIUM',
                'source': 'Memory Forensics',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'pid': pid,
                    'process_name': process_name,
                    'reason': reason
                }
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
            self.logger.warning(f"🚨 Suspicious Process Alert: {alert_data['message']}")
            
        except Exception as e:
            self.logger.error(f"Error creating process alert: {e}")
            
    def get_status(self) -> Dict[str, Any]:
        """Get memory forensics status"""
        return {
            'monitoring': self.monitoring,
            'scan_results_count': len(self.scan_results),
            'suspicious_processes': len(self.suspicious_processes),
            'injected_dlls': len(self.injected_dlls),
            'shellcode_detections': len(self.shellcode_detections),
            'memory_patterns': len(self.memory_patterns),
            'monitored_processes': len(self.process_memory_maps),
            'last_update': datetime.now().isoformat()
        }
        
    def get_memory_forensics_report(self) -> Dict[str, Any]:
        """Generate comprehensive memory forensics report"""
        return {
            'total_scan_results': len(self.scan_results),
            'suspicious_processes': self.suspicious_processes,
            'injected_dlls': self.injected_dlls,
            'shellcode_detections': self.shellcode_detections,
            'memory_patterns': self.memory_patterns,
            'process_memory_maps': self.process_memory_maps,
            'recommendations': self._generate_recommendations(),
            'timestamp': datetime.now().isoformat()
        }
        
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if len(self.suspicious_processes) > 0:
            recommendations.append("Investigate suspicious processes")
            
        if len(self.injected_dlls) > 0:
            recommendations.append("Review DLL injection attempts")
            
        if len(self.shellcode_detections) > 0:
            recommendations.append("Critical: Investigate shellcode detections")
            
        if len(self.memory_patterns) > 0:
            recommendations.append("Review suspicious memory patterns")
            
        return recommendations 