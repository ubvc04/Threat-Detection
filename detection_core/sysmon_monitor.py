"""
Sysmon Monitor Module
Parses Windows Event Logs from Sysmon to detect suspicious system events
"""

import os
import time
import threading
import win32evtlog
import win32evtlogutil
import win32con
import win32api
import win32security
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict, deque

class SysmonMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.last_event_id = 0
        self.event_counts = defaultdict(int)
        self.suspicious_events = deque(maxlen=1000)
        
        # Sysmon event IDs and their descriptions
        self.event_types = {
            1: 'Process Create',
            2: 'File Creation Time Changed',
            3: 'Network Connection',
            4: 'Sysmon Service State Changed',
            5: 'Process Terminated',
            6: 'Driver Loaded',
            7: 'Image Loaded',
            8: 'CreateRemoteThread',
            9: 'RawAccessRead',
            10: 'ProcessAccess',
            11: 'FileCreate',
            12: 'RegistryEvent (Create/Delete)',
            13: 'RegistryEvent (Value Set)',
            14: 'RegistryEvent (Key and Value Rename)',
            15: 'FileCreateStreamHash',
            16: 'Sysmon Configuration Change',
            17: 'Pipe Created',
            18: 'Pipe Connected',
            19: 'WmiEventFilter',
            20: 'WmiEventConsumer',
            21: 'WmiEventConsumerToFilter',
            22: 'DNS Query',
            23: 'File Delete',
            24: 'Clipboard Changed',
            25: 'Process Tampering',
            26: 'FileDeleteDetected',
            27: 'FileBlockExecutable',
            28: 'FileBlockShredding',
            29: 'FileExecutableDetected',
            255: 'Error'
        }
        
        # Suspicious event patterns
        self.suspicious_process_names = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe',
            'certutil.exe', 'bitsadmin.exe', 'netcat.exe', 'nc.exe',
            'nmap.exe', 'wireshark.exe', 'tcpdump.exe', 'netstat.exe',
            'tasklist.exe', 'taskkill.exe', 'sc.exe', 'schtasks.exe',
        ]
        
        self.suspicious_file_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.hta', '.scr', '.com', '.pif', '.reg', '.msi', '.msp'
        ]
        
        self.suspicious_registry_keys = [
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
            r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            r'SYSTEM\\CurrentControlSet\\Services',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects',
        ]
    
    def get_sysmon_events(self, start_time=None, event_types=None):
        """Get Sysmon events from Windows Event Log"""
        try:
            # Open the Windows Event Log
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            
            if not hand:
                print("Could not open Sysmon event log. Make sure Sysmon is installed and running.")
                return []
            
            # Set up event log reading
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = []
            total_events = win32evtlog.GetNumberOfEventLogRecords(hand)
            
            # Read events
            while True:
                events_raw = win32evtlog.ReadEventLog(hand, flags, 0)
                
                if not events_raw:
                    break
                
                for event in events_raw:
                    try:
                        # Parse event data
                        event_data = self.parse_sysmon_event(event)
                        if event_data:
                            # Filter by start time if specified
                            if start_time and event_data['timestamp'] < start_time:
                                continue
                            
                            # Filter by event types if specified
                            if event_types and event_data['event_id'] not in event_types:
                                continue
                            
                            events.append(event_data)
                            
                            # Update event counts
                            self.event_counts[event_data['event_id']] += 1
                            
                    except Exception as e:
                        print(f"Error parsing event: {e}")
                        continue
            
            win32evtlog.CloseEventLog(hand)
            return events
            
        except Exception as e:
            print(f"Error reading Sysmon events: {e}")
            return []
    
    def parse_sysmon_event(self, event):
        """Parse a single Sysmon event"""
        try:
            # Get basic event information
            event_id = win32evtlogutil.SafeFormatMessage(event, "Microsoft-Windows-Sysmon/Operational")
            
            # Extract event ID from the message
            event_id_num = None
            for line in event_id.split('\n'):
                if 'Event ID:' in line:
                    try:
                        event_id_num = int(line.split(':')[1].strip())
                        break
                    except:
                        continue
            
            if not event_id_num:
                return None
            
            # Parse event data based on event type
            event_data = {
                'event_id': event_id_num,
                'event_type': self.event_types.get(event_id_num, 'Unknown'),
                'timestamp': datetime.fromtimestamp(event.TimeGenerated),
                'source': 'sysmon',
                'raw_data': event_id,
                'suspicious_score': 0,
                'suspicious_reasons': []
            }
            
            # Parse specific event types
            if event_id_num == 1:  # Process Create
                event_data.update(self.parse_process_create(event_id))
            elif event_id_num == 3:  # Network Connection
                event_data.update(self.parse_network_connection(event_id))
            elif event_id_num == 6:  # Driver Loaded
                event_data.update(self.parse_driver_loaded(event_id))
            elif event_id_num == 7:  # Image Loaded
                event_data.update(self.parse_image_loaded(event_id))
            elif event_id_num == 8:  # CreateRemoteThread
                event_data.update(self.parse_create_remote_thread(event_id))
            elif event_id_num == 11:  # FileCreate
                event_data.update(self.parse_file_create(event_id))
            elif event_id_num == 12:  # RegistryEvent
                event_data.update(self.parse_registry_event(event_id))
            elif event_id_num == 22:  # DNS Query
                event_data.update(self.parse_dns_query(event_id))
            
            return event_data
            
        except Exception as e:
            print(f"Error parsing Sysmon event: {e}")
            return None
    
    def parse_process_create(self, event_data):
        """Parse Process Create event (Event ID 1)"""
        try:
            parsed = {}
            
            # Extract process information
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'Image':
                        parsed['process_name'] = value
                        # Check for suspicious process names
                        if value.lower() in [p.lower() for p in self.suspicious_process_names]:
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 30
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious process: {value}')
                    
                    elif key == 'CommandLine':
                        parsed['command_line'] = value
                        # Check for suspicious command line patterns
                        if any(pattern in value.lower() for pattern in ['powershell', 'cmd', 'http://', 'https://']):
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 20
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious command line: {value[:100]}...')
                    
                    elif key == 'ParentImage':
                        parsed['parent_process'] = value
                        # Check for suspicious parent processes
                        if value.lower() in [p.lower() for p in self.suspicious_process_names]:
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 15
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious parent process: {value}')
                    
                    elif key == 'User':
                        parsed['user'] = value
                    
                    elif key == 'ProcessGuid':
                        parsed['process_guid'] = value
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing process create event: {e}")
            return {}
    
    def parse_network_connection(self, event_data):
        """Parse Network Connection event (Event ID 3)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'Image':
                        parsed['process_name'] = value
                    
                    elif key == 'DestinationIp':
                        parsed['destination_ip'] = value
                        # Check for suspicious IPs
                        if value in ['127.0.0.1', '0.0.0.0', '255.255.255.255']:
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 10
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious destination IP: {value}')
                    
                    elif key == 'DestinationPort':
                        parsed['destination_port'] = value
                        # Check for suspicious ports
                        suspicious_ports = ['22', '23', '25', '3389', '1433', '5432', '5900']
                        if value in suspicious_ports:
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 15
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious destination port: {value}')
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing network connection event: {e}")
            return {}
    
    def parse_file_create(self, event_data):
        """Parse File Create event (Event ID 11)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'Image':
                        parsed['process_name'] = value
                    
                    elif key == 'TargetFilename':
                        parsed['target_filename'] = value
                        # Check for suspicious file extensions
                        if any(ext in value.lower() for ext in self.suspicious_file_extensions):
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 20
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious file created: {value}')
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing file create event: {e}")
            return {}
    
    def parse_registry_event(self, event_data):
        """Parse Registry Event (Event ID 12)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'Image':
                        parsed['process_name'] = value
                    
                    elif key == 'TargetObject':
                        parsed['registry_key'] = value
                        # Check for suspicious registry keys
                        for suspicious_key in self.suspicious_registry_keys:
                            if suspicious_key.lower() in value.lower():
                                parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 25
                                parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                                parsed['suspicious_reasons'].append(f'Suspicious registry key: {value}')
                                break
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing registry event: {e}")
            return {}
    
    def parse_dns_query(self, event_data):
        """Parse DNS Query event (Event ID 22)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'Image':
                        parsed['process_name'] = value
                    
                    elif key == 'QueryName':
                        parsed['query_name'] = value
                        # Check for suspicious domains
                        suspicious_domains = ['malware', 'phishing', 'botnet', 'c2', 'command']
                        if any(domain in value.lower() for domain in suspicious_domains):
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 30
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious DNS query: {value}')
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing DNS query event: {e}")
            return {}
    
    def parse_driver_loaded(self, event_data):
        """Parse Driver Loaded event (Event ID 6)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'ImageLoaded':
                        parsed['driver_path'] = value
                        # Check for suspicious driver locations
                        if 'temp' in value.lower() or 'downloads' in value.lower():
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 25
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious driver location: {value}')
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing driver loaded event: {e}")
            return {}
    
    def parse_image_loaded(self, event_data):
        """Parse Image Loaded event (Event ID 7)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'ImageLoaded':
                        parsed['image_path'] = value
                        # Check for suspicious image locations
                        if 'temp' in value.lower() or 'downloads' in value.lower():
                            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 20
                            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
                            parsed['suspicious_reasons'].append(f'Suspicious image location: {value}')
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing image loaded event: {e}")
            return {}
    
    def parse_create_remote_thread(self, event_data):
        """Parse CreateRemoteThread event (Event ID 8)"""
        try:
            parsed = {}
            
            lines = event_data.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'SourceImage':
                        parsed['source_process'] = value
                    
                    elif key == 'TargetImage':
                        parsed['target_process'] = value
            
            # CreateRemoteThread is inherently suspicious
            parsed['suspicious_score'] = parsed.get('suspicious_score', 0) + 40
            parsed['suspicious_reasons'] = parsed.get('suspicious_reasons', [])
            parsed['suspicious_reasons'].append('CreateRemoteThread detected (potential code injection)')
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing create remote thread event: {e}")
            return {}
    
    def monitor_sysmon_events(self):
        """Monitor Sysmon events in real-time"""
        try:
            while self.monitoring:
                try:
                    # Get events from the last minute
                    start_time = datetime.now() - timedelta(minutes=1)
                    events = self.get_sysmon_events(start_time=start_time)
                    
                    for event in events:
                        # Check if event is suspicious
                        if event.get('suspicious_score', 0) > 0:
                            self.suspicious_events.append(event)
                            self.log_sysmon_alert(event)
                    
                    # Sleep between checks
                    time.sleep(30)
                    
                except Exception as e:
                    print(f"Error in Sysmon monitoring loop: {e}")
                    time.sleep(60)
                    
        except Exception as e:
            print(f"Error in Sysmon monitoring: {e}")
    
    def log_sysmon_alert(self, event):
        """Log Sysmon alert to Django"""
        try:
            from dashboard.models import Alert
            
            # Determine severity
            suspicious_score = event.get('suspicious_score', 0)
            if suspicious_score >= 40:
                severity = 'HIGH'
            elif suspicious_score >= 20:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Create alert message
            message = f"Sysmon Event: {event['event_type']} (ID: {event['event_id']})"
            if event.get('suspicious_reasons'):
                message += f" - {', '.join(event['suspicious_reasons'][:3])}"
            
            Alert.objects.create(
                alert_type='SYSMON',
                severity=severity,
                message=message,
                source='sysmon_monitor',
                details={
                    'event_id': event['event_id'],
                    'event_type': event['event_type'],
                    'timestamp': event['timestamp'].isoformat(),
                    'suspicious_score': suspicious_score,
                    'suspicious_reasons': event.get('suspicious_reasons', []),
                    'process_name': event.get('process_name'),
                    'command_line': event.get('command_line'),
                    'parent_process': event.get('parent_process'),
                    'user': event.get('user')
                }
            )
            
        except Exception as e:
            print(f"Error logging Sysmon alert: {e}")
    
    def start_monitoring(self):
        """Start Sysmon monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_sysmon_events, daemon=True)
        self.monitor_thread.start()
        print("Sysmon monitoring started")
    
    def stop_monitoring(self):
        """Stop Sysmon monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("Sysmon monitoring stopped")
    
    def get_sysmon_stats(self):
        """Get statistics about Sysmon events"""
        return {
            'total_events': sum(self.event_counts.values()),
            'event_counts': dict(self.event_counts),
            'suspicious_events': len(self.suspicious_events),
            'recent_suspicious': list(self.suspicious_events)[-10:] if self.suspicious_events else []
        }
    
    def scan_recent_events(self, hours=24):
        """Scan recent Sysmon events for suspicious activity"""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            events = self.get_sysmon_events(start_time=start_time)
            
            suspicious_count = 0
            for event in events:
                if event.get('suspicious_score', 0) > 0:
                    suspicious_count += 1
                    self.log_sysmon_alert(event)
            
            return {
                'total_events': len(events),
                'suspicious_events': suspicious_count,
                'scan_period_hours': hours
            }
            
        except Exception as e:
            print(f"Error scanning recent events: {e}")
            return None

# Global instance
sysmon_monitor = SysmonMonitor() 