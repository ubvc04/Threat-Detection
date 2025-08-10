"""
Brute Force / Failed Login Detection Module
Monitors Windows Security Event Logs for failed login attempts and brute force attacks
"""

import win32evtlog
import win32evtlogutil
import win32con
import win32security
import win32api
import win32com.client
import time
import threading
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict

class BruteForceDetector:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
        
        # Event IDs to monitor for failed logins
        self.failed_login_events = {
            4625: "Failed logon",  # Account logon failure
            4648: "Explicit logon",  # Explicit credential logon
            4771: "Kerberos pre-authentication failure",  # Kerberos auth failure
            4776: "Credential validation failure",  # Credential validation
            4624: "Successful logon",  # Successful logon (for comparison)
        }
        
        # Brute force detection thresholds
        self.thresholds = {
            'failed_attempts_threshold': 5,  # Alert after 5 failed attempts
            'time_window_minutes': 10,  # Within 10 minutes
            'lockout_threshold': 10,  # Account lockout threshold
        }
        
        # Track failed attempts per user/IP
        self.failed_attempts = defaultdict(list)
        self.successful_logins = defaultdict(list)
        
    def start_monitoring(self):
        """Start brute force detection monitoring"""
        self.monitoring = True
        self.logger.info("🔒 Starting Brute Force Detection...")
        
        # Start monitoring thread
        threading.Thread(target=self._monitor_security_logs, daemon=True).start()
        threading.Thread(target=self._cleanup_old_attempts, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop brute force detection monitoring"""
        self.monitoring = False
        self.logger.info("🔒 Stopping Brute Force Detection...")
        
    def _monitor_security_logs(self):
        """Monitor Windows Security Event Logs"""
        while self.monitoring:
            try:
                # Open Security Event Log
                hand = win32evtlog.OpenEventLog(None, "Security")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                # Read recent events
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    if event.EventID in self.failed_login_events:
                        self._process_login_event(event)
                        
                win32evtlog.CloseEventLog(hand)
                
            except Exception as e:
                self.logger.error(f"Error monitoring security logs: {e}")
                
            time.sleep(30)  # Check every 30 seconds
            
    def _process_login_event(self, event):
        """Process login event and check for brute force patterns"""
        try:
            event_data = win32evtlogutil.SafeFormatMessage(event, "Security")
            event_id = event.EventID
            timestamp = datetime.fromtimestamp(event.TimeGenerated)
            
            # Extract user and IP information from event data
            user_info = self._extract_user_info(event_data, event_id)
            
            if not user_info:
                return
                
            username = user_info.get('username', 'Unknown')
            ip_address = user_info.get('ip_address', 'Unknown')
            workstation = user_info.get('workstation', 'Unknown')
            
            # Create unique key for tracking
            user_key = f"{username}@{ip_address}"
            
            if event_id in [4625, 4648, 4771, 4776]:  # Failed login events
                self._handle_failed_login(user_key, username, ip_address, workstation, timestamp, event_data)
            elif event_id == 4624:  # Successful login
                self._handle_successful_login(user_key, username, ip_address, workstation, timestamp)
                
        except Exception as e:
            self.logger.error(f"Error processing login event: {e}")
            
    def _extract_user_info(self, event_data: str, event_id: int) -> Optional[Dict[str, str]]:
        """Extract user information from event data"""
        try:
            # Parse event data to extract username, IP, workstation
            # This is a simplified parser - in production you'd use more sophisticated parsing
            
            lines = event_data.split('\n')
            username = 'Unknown'
            ip_address = 'Unknown'
            workstation = 'Unknown'
            
            for line in lines:
                line = line.strip()
                if 'Account Name:' in line:
                    username = line.split('Account Name:')[-1].strip()
                elif 'Source Network Address:' in line:
                    ip_address = line.split('Source Network Address:')[-1].strip()
                elif 'Workstation Name:' in line:
                    workstation = line.split('Workstation Name:')[-1].strip()
                    
            return {
                'username': username,
                'ip_address': ip_address,
                'workstation': workstation
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting user info: {e}")
            return None
            
    def _handle_failed_login(self, user_key: str, username: str, ip_address: str, 
                           workstation: str, timestamp: datetime, event_data: str):
        """Handle failed login attempt"""
        # Add to failed attempts list
        self.failed_attempts[user_key].append({
            'timestamp': timestamp,
            'username': username,
            'ip_address': ip_address,
            'workstation': workstation,
            'event_data': event_data
        })
        
        # Check for brute force patterns
        self._check_brute_force_patterns(user_key, username, ip_address)
        
    def _handle_successful_login(self, user_key: str, username: str, ip_address: str, 
                               workstation: str, timestamp: datetime):
        """Handle successful login"""
        # Add to successful logins list
        self.successful_logins[user_key].append({
            'timestamp': timestamp,
            'username': username,
            'ip_address': ip_address,
            'workstation': workstation
        })
        
        # Clear failed attempts if successful login occurs
        if user_key in self.failed_attempts:
            del self.failed_attempts[user_key]
            
    def _check_brute_force_patterns(self, user_key: str, username: str, ip_address: str):
        """Check for brute force attack patterns"""
        if user_key not in self.failed_attempts:
            return
            
        failed_attempts = self.failed_attempts[user_key]
        time_window = timedelta(minutes=self.thresholds['time_window_minutes'])
        current_time = datetime.now()
        
        # Count recent failed attempts
        recent_failures = [
            attempt for attempt in failed_attempts
            if current_time - attempt['timestamp'] <= time_window
        ]
        
        if len(recent_failures) >= self.thresholds['failed_attempts_threshold']:
            # Potential brute force attack detected
            self._create_brute_force_alert(username, ip_address, recent_failures)
            
        if len(recent_failures) >= self.thresholds['lockout_threshold']:
            # Account lockout threshold reached
            self._create_lockout_alert(username, ip_address, recent_failures)
            
    def _create_brute_force_alert(self, username: str, ip_address: str, failures: List[Dict]):
        """Create brute force attack alert"""
        failure_count = len(failures)
        time_span = failures[-1]['timestamp'] - failures[0]['timestamp']
        
        self._create_alert(
            "HIGH",
            f"Potential Brute Force Attack: {username}",
            f"Multiple failed login attempts detected for user '{username}' from IP {ip_address}. "
            f"{failure_count} failures in {time_span.total_seconds():.0f} seconds.",
            "brute_force"
        )
        
    def _create_lockout_alert(self, username: str, ip_address: str, failures: List[Dict]):
        """Create account lockout alert"""
        self._create_alert(
            "CRITICAL",
            f"Account Lockout Threshold Reached: {username}",
            f"Account lockout threshold reached for user '{username}' from IP {ip_address}. "
            f"Consider implementing account lockout policy.",
            "brute_force"
        )
        
    def _cleanup_old_attempts(self):
        """Clean up old failed attempts to prevent memory buildup"""
        while self.monitoring:
            try:
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(hours=1)  # Keep 1 hour of data
                
                # Clean up failed attempts
                for user_key in list(self.failed_attempts.keys()):
                    self.failed_attempts[user_key] = [
                        attempt for attempt in self.failed_attempts[user_key]
                        if attempt['timestamp'] > cutoff_time
                    ]
                    if not self.failed_attempts[user_key]:
                        del self.failed_attempts[user_key]
                        
                # Clean up successful logins
                for user_key in list(self.successful_logins.keys()):
                    self.successful_logins[user_key] = [
                        login for login in self.successful_logins[user_key]
                        if login['timestamp'] > cutoff_time
                    ]
                    if not self.successful_logins[user_key]:
                        del self.successful_logins[user_key]
                        
            except Exception as e:
                self.logger.error(f"Error cleaning up old attempts: {e}")
                
            time.sleep(300)  # Clean up every 5 minutes
            
    def _create_alert(self, severity: str, title: str, description: str, alert_type: str):
        """Create alert using the existing alert system"""
        if self.alert_callback:
            alert_data = {
                'severity': severity,
                'title': title,
                'description': description,
                'alert_type': alert_type,
                'timestamp': datetime.now(),
                'source': 'brute_force_detector'
            }
            self.alert_callback(alert_data)
            
        self.logger.warning(f"🔒 {severity} Alert: {title} - {description}")
        
    def get_status(self) -> Dict[str, Any]:
        """Get current status of brute force detection"""
        return {
            'monitoring': self.monitoring,
            'failed_attempts_count': len(self.failed_attempts),
            'successful_logins_count': len(self.successful_logins),
            'thresholds': self.thresholds,
            'monitored_events': list(self.failed_login_events.keys())
        }
        
    def get_failed_attempts_summary(self) -> Dict[str, Any]:
        """Get summary of current failed attempts"""
        summary = {}
        for user_key, attempts in self.failed_attempts.items():
            summary[user_key] = {
                'count': len(attempts),
                'last_attempt': max(attempt['timestamp'] for attempt in attempts),
                'first_attempt': min(attempt['timestamp'] for attempt in attempts)
            }
        return summary 