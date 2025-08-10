"""
Clipboard Monitoring Module
Monitors clipboard contents for passwords, crypto wallet addresses, and suspicious patterns
"""

import win32clipboard
import win32con
import win32gui
import win32api
import time
import threading
import logging
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

class ClipboardMonitor:
    def __init__(self, alert_callback=None, user_consent=True):
        self.alert_callback = alert_callback
        self.user_consent = user_consent
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
        self.last_clipboard_content = ""
        
        # Patterns to detect
        self.password_patterns = [
            r'password[:\s]*([^\s]+)',  # password: xyz
            r'pass[:\s]*([^\s]+)',      # pass: xyz
            r'pwd[:\s]*([^\s]+)',       # pwd: xyz
            r'secret[:\s]*([^\s]+)',    # secret: xyz
            r'key[:\s]*([^\s]+)',       # key: xyz
        ]
        
        # Crypto wallet address patterns
        self.crypto_patterns = {
            'bitcoin': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Bitcoin address
            'ethereum': r'0x[a-fA-F0-9]{40}',  # Ethereum address
            'litecoin': r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}',  # Litecoin address
            'ripple': r'r[a-zA-Z0-9]{24,34}',  # Ripple address
            'monero': r'[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}',  # Monero address
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'admin[:\s]*([^\s]+)',     # admin credentials
            r'root[:\s]*([^\s]+)',      # root credentials
            r'administrator[:\s]*([^\s]+)',  # administrator credentials
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # email addresses
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP addresses
            r'ftp://[^\s]+',            # FTP URLs
            r'http://[^\s]+',           # HTTP URLs
            r'https://[^\s]+',          # HTTPS URLs
            r'ssh://[^\s]+',            # SSH URLs
            r'telnet://[^\s]+',         # Telnet URLs
        ]
        
        # Credit card patterns (basic)
        self.credit_card_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 16-digit cards
            r'\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b',  # 15-digit cards (Amex)
        ]
        
        # Sensitive file paths
        self.sensitive_paths = [
            r'C:\\Users\\.*\\Documents\\.*\.txt',
            r'C:\\Users\\.*\\Desktop\\.*\.txt',
            r'C:\\Users\\.*\\Downloads\\.*\.txt',
            r'.*\\config\.ini',
            r'.*\\settings\.json',
            r'.*\\credentials\.txt',
            r'.*\\passwords\.txt',
        ]
        
    def start_monitoring(self):
        """Start clipboard monitoring"""
        if not self.user_consent:
            self.logger.warning("Clipboard monitoring disabled - user consent required")
            return
            
        self.monitoring = True
        self.logger.info("📋 Starting Clipboard Monitoring...")
        
        # Start monitoring thread
        threading.Thread(target=self._monitor_clipboard, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop clipboard monitoring"""
        self.monitoring = False
        self.logger.info("📋 Stopping Clipboard Monitoring...")
        
    def set_user_consent(self, consent: bool):
        """Set user consent for clipboard monitoring"""
        self.user_consent = consent
        if consent and not self.monitoring:
            self.start_monitoring()
        elif not consent and self.monitoring:
            self.stop_monitoring()
            
    def _monitor_clipboard(self):
        """Monitor clipboard for changes"""
        while self.monitoring:
            try:
                # Get current clipboard content
                win32clipboard.OpenClipboard()
                try:
                    clipboard_content = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                except:
                    clipboard_content = ""
                win32clipboard.CloseClipboard()
                
                # Check if content changed
                if clipboard_content != self.last_clipboard_content:
                    self._analyze_clipboard_content(clipboard_content)
                    self.last_clipboard_content = clipboard_content
                    
            except Exception as e:
                self.logger.error(f"Error monitoring clipboard: {e}")
                
            time.sleep(1)  # Check every second
            
    def _analyze_clipboard_content(self, content: str):
        """Analyze clipboard content for sensitive information"""
        if not content or len(content.strip()) == 0:
            return
            
        content = content.strip()
        detected_items = []
        
        # Check for passwords
        password_matches = self._check_password_patterns(content)
        if password_matches:
            detected_items.extend(password_matches)
            
        # Check for crypto addresses
        crypto_matches = self._check_crypto_patterns(content)
        if crypto_matches:
            detected_items.extend(crypto_matches)
            
        # Check for suspicious patterns
        suspicious_matches = self._check_suspicious_patterns(content)
        if suspicious_matches:
            detected_items.extend(suspicious_matches)
            
        # Check for credit card numbers
        credit_card_matches = self._check_credit_card_patterns(content)
        if credit_card_matches:
            detected_items.extend(credit_card_matches)
            
        # Check for sensitive file paths
        path_matches = self._check_sensitive_paths(content)
        if path_matches:
            detected_items.extend(path_matches)
            
        # Create alert if sensitive content detected
        if detected_items:
            self._create_clipboard_alert(content, detected_items)
            
    def _check_password_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Check for password patterns in clipboard content"""
        matches = []
        
        for pattern in self.password_patterns:
            matches_found = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches_found:
                matches.append({
                    'type': 'password',
                    'pattern': pattern,
                    'value': match.group(1) if match.groups() else match.group(0),
                    'severity': 'HIGH'
                })
                
        return matches
        
    def _check_crypto_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Check for cryptocurrency wallet addresses"""
        matches = []
        
        for crypto_type, pattern in self.crypto_patterns.items():
            matches_found = re.finditer(pattern, content)
            for match in matches_found:
                matches.append({
                    'type': 'crypto_address',
                    'crypto_type': crypto_type,
                    'value': match.group(0),
                    'severity': 'MEDIUM'
                })
                
        return matches
        
    def _check_suspicious_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Check for suspicious patterns"""
        matches = []
        
        for pattern in self.suspicious_patterns:
            matches_found = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches_found:
                pattern_type = self._get_pattern_type(pattern)
                matches.append({
                    'type': pattern_type,
                    'pattern': pattern,
                    'value': match.group(0),
                    'severity': 'MEDIUM'
                })
                
        return matches
        
    def _check_credit_card_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Check for credit card numbers"""
        matches = []
        
        for pattern in self.credit_card_patterns:
            matches_found = re.finditer(pattern, content)
            for match in matches_found:
                # Basic Luhn algorithm check for credit card validation
                card_number = re.sub(r'[-\s]', '', match.group(0))
                if self._is_valid_credit_card(card_number):
                    matches.append({
                        'type': 'credit_card',
                        'pattern': pattern,
                        'value': match.group(0),
                        'severity': 'HIGH'
                    })
                    
        return matches
        
    def _check_sensitive_paths(self, content: str) -> List[Dict[str, Any]]:
        """Check for sensitive file paths"""
        matches = []
        
        for pattern in self.sensitive_paths:
            matches_found = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches_found:
                matches.append({
                    'type': 'sensitive_path',
                    'pattern': pattern,
                    'value': match.group(0),
                    'severity': 'LOW'
                })
                
        return matches
        
    def _get_pattern_type(self, pattern: str) -> str:
        """Get human-readable pattern type"""
        if 'admin' in pattern:
            return 'admin_credentials'
        elif 'root' in pattern:
            return 'root_credentials'
        elif 'email' in pattern or '@' in pattern:
            return 'email_address'
        elif 'ip' in pattern or '\d{1,3}\.' in pattern:
            return 'ip_address'
        elif 'ftp://' in pattern:
            return 'ftp_url'
        elif 'http://' in pattern:
            return 'http_url'
        elif 'https://' in pattern:
            return 'https_url'
        elif 'ssh://' in pattern:
            return 'ssh_url'
        elif 'telnet://' in pattern:
            return 'telnet_url'
        else:
            return 'suspicious_pattern'
            
    def _is_valid_credit_card(self, card_number: str) -> bool:
        """Basic Luhn algorithm for credit card validation"""
        if not card_number.isdigit():
            return False
            
        # Luhn algorithm
        digits = [int(d) for d in card_number]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(divmod(d * 2, 10))
            
        return checksum % 10 == 0
        
    def _create_clipboard_alert(self, content: str, detected_items: List[Dict[str, Any]]):
        """Create alert for clipboard content"""
        # Determine highest severity
        severities = [item['severity'] for item in detected_items]
        highest_severity = 'LOW'
        if 'HIGH' in severities:
            highest_severity = 'HIGH'
        elif 'MEDIUM' in severities:
            highest_severity = 'MEDIUM'
            
        # Create alert description
        item_types = [item['type'] for item in detected_items]
        unique_types = list(set(item_types))
        
        description = f"Clipboard contains sensitive information: {', '.join(unique_types)}. "
        description += f"Content preview: {content[:100]}{'...' if len(content) > 100 else ''}"
        
        self._create_alert(
            highest_severity,
            f"Sensitive Clipboard Content Detected",
            description,
            "clipboard_monitoring"
        )
        
    def _create_alert(self, severity: str, title: str, description: str, alert_type: str):
        """Create alert using the existing alert system"""
        if self.alert_callback:
            alert_data = {
                'severity': severity,
                'title': title,
                'description': description,
                'alert_type': alert_type,
                'timestamp': datetime.now(),
                'source': 'clipboard_monitor'
            }
            self.alert_callback(alert_data)
            
        self.logger.warning(f"📋 {severity} Alert: {title} - {description}")
        
    def get_status(self) -> Dict[str, Any]:
        """Get current status of clipboard monitoring"""
        return {
            'monitoring': self.monitoring,
            'user_consent': self.user_consent,
            'password_patterns_count': len(self.password_patterns),
            'crypto_patterns_count': len(self.crypto_patterns),
            'suspicious_patterns_count': len(self.suspicious_patterns),
            'credit_card_patterns_count': len(self.credit_card_patterns),
            'sensitive_paths_count': len(self.sensitive_paths)
        }
        
    def add_custom_pattern(self, pattern_type: str, pattern: str, severity: str = 'MEDIUM'):
        """Add custom pattern for monitoring"""
        if pattern_type == 'password':
            self.password_patterns.append(pattern)
        elif pattern_type == 'crypto':
            self.crypto_patterns[f'custom_{len(self.crypto_patterns)}'] = pattern
        elif pattern_type == 'suspicious':
            self.suspicious_patterns.append(pattern)
        elif pattern_type == 'credit_card':
            self.credit_card_patterns.append(pattern)
        elif pattern_type == 'sensitive_path':
            self.sensitive_paths.append(pattern)
            
        self.logger.info(f"Added custom {pattern_type} pattern: {pattern}")
        
    def test_pattern(self, content: str) -> List[Dict[str, Any]]:
        """Test content against all patterns (for testing purposes)"""
        return self._analyze_clipboard_content(content) 