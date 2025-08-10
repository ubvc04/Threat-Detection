"""
Process Monitor Module
Detects CPU/memory spikes and suspicious process behavior
"""

import os
import time
import threading
import psutil
import win32process
import win32api
import win32con
import win32gui
import win32security
from collections import defaultdict, deque
import json

class ProcessMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.process_history = defaultdict(deque)
        self.suspicious_processes = deque(maxlen=1000)
        self.baseline_cpu = 0
        self.baseline_memory = 0
        
        # Suspicious process patterns
        self.suspicious_process_names = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe',
            'certutil.exe', 'bitsadmin.exe', 'netcat.exe', 'nc.exe',
            'nmap.exe', 'wireshark.exe', 'tcpdump.exe', 'netstat.exe',
            'tasklist.exe', 'taskkill.exe', 'sc.exe', 'schtasks.exe',
        ]
        
        self.suspicious_command_patterns = [
            r'(http|https|ftp)://',
            r'(download|upload|execute|run)',
            r'(registry|regedit)',
            r'(system32|windows)',
            r'(admin|administrator)',
            r'(password|credential)',
            r'(keylog|hook)',
            r'(inject|dll)',
            r'(encrypt|decrypt)',
            r'(backdoor|trojan|virus|malware)',
            r'(powershell|cmd|batch)',
            r'(netcat|nc|nmap)',
        ]
        
        # Thresholds for alerts
        self.cpu_threshold = 80.0  # CPU usage percentage
        self.memory_threshold = 80.0  # Memory usage percentage
        self.process_count_threshold = 200  # Number of processes
        self.suspicious_score_threshold = 20  # Suspicious behavior score
    
    def get_process_info(self, pid):
        """Get detailed information about a process"""
        try:
            process = psutil.Process(pid)
            
            # Basic process info
            info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'memory_info': process.memory_info()._asdict(),
                'create_time': process.create_time(),
                'status': process.status(),
                'num_threads': process.num_threads(),
                'num_handles': process.num_handles(),
                'username': process.username(),
                'ppid': process.ppid(),
                'suspicious_score': 0,
                'suspicious_reasons': []
            }
            
            # Check for suspicious process name
            if info['name'].lower() in [p.lower() for p in self.suspicious_process_names]:
                info['suspicious_score'] += 20
                info['suspicious_reasons'].append(f'Suspicious process name: {info["name"]}')
            
            # Check command line for suspicious patterns
            import re
            for pattern in self.suspicious_command_patterns:
                if re.search(pattern, info['cmdline'], re.IGNORECASE):
                    info['suspicious_score'] += 15
                    info['suspicious_reasons'].append(f'Suspicious command pattern: {pattern}')
            
            # Check for high CPU usage
            if info['cpu_percent'] > self.cpu_threshold:
                info['suspicious_score'] += 10
                info['suspicious_reasons'].append(f'High CPU usage: {info["cpu_percent"]:.1f}%')
            
            # Check for high memory usage
            if info['memory_percent'] > self.memory_threshold:
                info['suspicious_score'] += 10
                info['suspicious_reasons'].append(f'High memory usage: {info["memory_percent"]:.1f}%')
            
            # Check for unusual number of threads
            if info['num_threads'] > 100:
                info['suspicious_score'] += 15
                info['suspicious_reasons'].append(f'Unusual number of threads: {info["num_threads"]}')
            
            # Check for unusual number of handles
            if info['num_handles'] > 1000:
                info['suspicious_score'] += 10
                info['suspicious_reasons'].append(f'Unusual number of handles: {info["num_handles"]}')
            
            # Check process tree for suspicious parent processes
            try:
                parent = psutil.Process(info['ppid'])
                if parent.name().lower() in [p.lower() for p in self.suspicious_process_names]:
                    info['suspicious_score'] += 15
                    info['suspicious_reasons'].append(f'Suspicious parent process: {parent.name()}')
            except:
                pass
            
            # Check for processes running from suspicious locations
            suspicious_paths = [
                'temp', 'tmp', 'downloads', 'desktop',
                'appdata', 'local', 'roaming'
            ]
            
            if info['exe']:
                exe_lower = info['exe'].lower()
                for path in suspicious_paths:
                    if path in exe_lower:
                        info['suspicious_score'] += 10
                        info['suspicious_reasons'].append(f'Process running from suspicious location: {path}')
                        break
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            print(f"Error getting process info for PID {pid}: {e}")
            return None
    
    def get_system_stats(self):
        """Get overall system statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get process count
            process_count = len(psutil.pids())
            
            # Get network connections
            connections = psutil.net_connections()
            established_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_total': memory.total,
                'disk_percent': disk.percent,
                'disk_used': disk.used,
                'disk_total': disk.total,
                'process_count': process_count,
                'established_connections': established_connections,
                'timestamp': time.time()
            }
            
        except Exception as e:
            print(f"Error getting system stats: {e}")
            return None
    
    def analyze_process_behavior(self, process_info):
        """Analyze process behavior for suspicious patterns"""
        try:
            analysis = {
                'pid': process_info['pid'],
                'name': process_info['name'],
                'suspicious_score': process_info['suspicious_score'],
                'suspicious_reasons': process_info['suspicious_reasons'],
                'is_suspicious': process_info['suspicious_score'] >= self.suspicious_score_threshold
            }
            
            # Check for process injection patterns
            if process_info['num_threads'] > 50 and process_info['memory_percent'] > 10:
                analysis['suspicious_score'] += 20
                analysis['suspicious_reasons'].append('Potential process injection (high threads + memory)')
            
            # Check for command line obfuscation
            cmdline = process_info['cmdline'].lower()
            if len(cmdline) > 200 and ('powershell' in cmdline or 'cmd' in cmdline):
                analysis['suspicious_score'] += 15
                analysis['suspicious_reasons'].append('Potential command line obfuscation')
            
            # Check for processes with no parent (orphaned processes)
            try:
                parent = psutil.Process(process_info['ppid'])
                if parent.name() == 'System' and process_info['name'] not in ['svchost.exe', 'lsass.exe', 'winlogon.exe']:
                    analysis['suspicious_score'] += 10
                    analysis['suspicious_reasons'].append('Orphaned process (parent is System)')
            except:
                pass
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing process behavior: {e}")
            return None
    
    def monitor_processes(self):
        """Main process monitoring loop"""
        try:
            while self.monitoring:
                try:
                    # Get system stats
                    system_stats = self.get_system_stats()
                    if system_stats:
                        # Log system stats to Django
                        from dashboard.models import SystemInfo
                        
                        SystemInfo.objects.create(
                            cpu_percent=system_stats['cpu_percent'],
                            memory_percent=system_stats['memory_percent'],
                            disk_usage=system_stats['disk_percent'],
                            network_connections=system_stats['established_connections'],
                            active_processes=system_stats['process_count']
                        )
                        
                        # Check for system-wide anomalies
                        if system_stats['cpu_percent'] > self.cpu_threshold:
                            self.log_system_alert('HIGH_CPU', system_stats)
                        
                        if system_stats['memory_percent'] > self.memory_threshold:
                            self.log_system_alert('HIGH_MEMORY', system_stats)
                        
                        if system_stats['process_count'] > self.process_count_threshold:
                            self.log_system_alert('HIGH_PROCESS_COUNT', system_stats)
                    
                    # Monitor individual processes
                    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                        try:
                            process_info = self.get_process_info(proc.info['pid'])
                            if process_info:
                                # Store in history
                                self.process_history[proc.info['pid']].append(process_info)
                                
                                # Keep only recent history
                                if len(self.process_history[proc.info['pid']]) > 10:
                                    self.process_history[proc.info['pid']].popleft()
                                
                                # Analyze behavior
                                analysis = self.analyze_process_behavior(process_info)
                                if analysis and analysis['is_suspicious']:
                                    self.suspicious_processes.append(analysis)
                                    self.log_process_alert(process_info, analysis)
                                
                                # Log process info to Django
                                from dashboard.models import ProcessLog
                                
                                ProcessLog.objects.create(
                                    process_name=process_info['name'],
                                    process_id=process_info['pid'],
                                    cpu_percent=process_info['cpu_percent'],
                                    memory_percent=process_info['memory_percent'],
                                    command_line=process_info['cmdline'],
                                    suspicious=analysis['is_suspicious'] if analysis else False
                                )
                                
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                        except Exception as e:
                            print(f"Error monitoring process {proc.info['pid']}: {e}")
                    
                    # Sleep between monitoring cycles
                    time.sleep(5)
                    
                except Exception as e:
                    print(f"Error in process monitoring loop: {e}")
                    time.sleep(10)
                    
        except Exception as e:
            print(f"Error in process monitoring: {e}")
    
    def log_process_alert(self, process_info, analysis):
        """Log process alert to Django"""
        try:
            from dashboard.models import Alert
            
            # Determine severity
            if analysis['suspicious_score'] >= 50:
                severity = 'HIGH'
            elif analysis['suspicious_score'] >= 30:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Create alert message
            message = f"Suspicious process detected: {process_info['name']} (PID: {process_info['pid']})"
            if analysis['suspicious_reasons']:
                message += f" - {', '.join(analysis['suspicious_reasons'][:3])}"
            
            Alert.objects.create(
                alert_type='PROCESS',
                severity=severity,
                message=message,
                source='process_monitor',
                details={
                    'pid': process_info['pid'],
                    'name': process_info['name'],
                    'exe': process_info['exe'],
                    'cmdline': process_info['cmdline'],
                    'cpu_percent': process_info['cpu_percent'],
                    'memory_percent': process_info['memory_percent'],
                    'suspicious_score': analysis['suspicious_score'],
                    'suspicious_reasons': analysis['suspicious_reasons']
                }
            )
            
        except Exception as e:
            print(f"Error logging process alert: {e}")
    
    def log_system_alert(self, alert_type, system_stats):
        """Log system-wide alert to Django"""
        try:
            from dashboard.models import Alert
            
            if alert_type == 'HIGH_CPU':
                message = f"High CPU usage detected: {system_stats['cpu_percent']:.1f}%"
                severity = 'MEDIUM'
            elif alert_type == 'HIGH_MEMORY':
                message = f"High memory usage detected: {system_stats['memory_percent']:.1f}%"
                severity = 'MEDIUM'
            elif alert_type == 'HIGH_PROCESS_COUNT':
                message = f"High process count detected: {system_stats['process_count']}"
                severity = 'LOW'
            else:
                return
            
            Alert.objects.create(
                alert_type='SYSTEM',
                severity=severity,
                message=message,
                source='process_monitor',
                details=system_stats
            )
            
        except Exception as e:
            print(f"Error logging system alert: {e}")
    
    def start_monitoring(self):
        """Start process monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        self.monitor_thread.start()
        print("Process monitoring started")
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("Process monitoring stopped")
    
    def get_process_stats(self):
        """Get statistics about monitored processes"""
        return {
            'total_processes': len(self.process_history),
            'suspicious_processes': len(self.suspicious_processes),
            'recent_suspicious': list(self.suspicious_processes)[-10:] if self.suspicious_processes else [],
            'process_history_keys': list(self.process_history.keys())
        }
    
    def kill_suspicious_process(self, pid):
        """Kill a suspicious process"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait for termination
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
            
            return True
            
        except Exception as e:
            print(f"Error killing process {pid}: {e}")
            return False

# Global instance
process_monitor = ProcessMonitor() 