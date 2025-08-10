"""
Advanced Security Manager
Integrates all new security features: credential theft, brute force, signature verification, 
clipboard monitoring, and insider threat detection
"""

import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .credential_theft_detector import CredentialTheftDetector
from .brute_force_detector import BruteForceDetector
from .signature_verifier import SignatureVerifier
from .clipboard_monitor import ClipboardMonitor
from .insider_threat_detector import InsiderThreatDetector
from .zero_trust_monitor import ZeroTrustMonitor

class AdvancedSecurityManager:
    def __init__(self, alert_callback: Optional[Callable] = None, ai_model_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.ai_model_callback = ai_model_callback
        self.logger = logging.getLogger(__name__)
        
        # Initialize all security modules
        self.credential_detector = CredentialTheftDetector(alert_callback=self._create_alert)
        self.brute_force_detector = BruteForceDetector(alert_callback=self._create_alert)
        self.signature_verifier = SignatureVerifier(alert_callback=self._create_alert)
        self.clipboard_monitor = ClipboardMonitor(alert_callback=self._create_alert, user_consent=True)
        self.insider_threat_detector = InsiderThreatDetector(
            alert_callback=self._create_alert, 
            ai_model_callback=self.ai_model_callback
        )
        self.zero_trust_monitor = ZeroTrustMonitor(alert_callback=self._create_alert)
        
        # Status tracking
        self.modules_status = {}
        self.monitoring = False
        
    def start_all_monitoring(self):
        """Start all advanced security monitoring modules"""
        try:
            self.logger.info("🚀 Starting Advanced Security Manager...")
            self.monitoring = True
            
            # Start all modules
            self.credential_detector.start_monitoring()
            self.brute_force_detector.start_monitoring()
            self.signature_verifier.start_monitoring()
            self.clipboard_monitor.start_monitoring()
            self.insider_threat_detector.start_monitoring()
            self.zero_trust_monitor.start_monitoring()
            
            # Start status monitoring thread
            threading.Thread(target=self._monitor_modules_status, daemon=True).start()
            
            self.logger.info("✅ All advanced security modules started successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error starting advanced security modules: {e}")
            self.monitoring = False
            
    def stop_all_monitoring(self):
        """Stop all advanced security monitoring modules"""
        try:
            self.logger.info("🛑 Stopping Advanced Security Manager...")
            self.monitoring = False
            
            # Stop all modules
            self.credential_detector.stop_monitoring()
            self.brute_force_detector.stop_monitoring()
            self.signature_verifier.stop_monitoring()
            self.clipboard_monitor.stop_monitoring()
            self.insider_threat_detector.stop_monitoring()
            self.zero_trust_monitor.stop_monitoring()
            
            self.logger.info("✅ All advanced security modules stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping advanced security modules: {e}")
            
    def _monitor_modules_status(self):
        """Monitor the status of all modules"""
        while self.monitoring:
            try:
                self.modules_status = {
                    'credential_theft': self.credential_detector.get_status(),
                    'brute_force': self.brute_force_detector.get_status(),
                    'signature_verification': self.signature_verifier.get_status(),
                    'clipboard_monitoring': self.clipboard_monitor.get_status(),
                    'insider_threat': self.insider_threat_detector.get_status(),
                    'zero_trust': self.zero_trust_monitor.get_status(),
                    'overall_status': 'active' if self.monitoring else 'inactive',
                    'last_update': datetime.now().isoformat()
                }
                
            except Exception as e:
                self.logger.error(f"Error monitoring modules status: {e}")
                
            time.sleep(30)  # Update status every 30 seconds
            
    def _create_alert(self, alert_data: Dict[str, Any]):
        """Create alert and forward to main alert system"""
        if self.alert_callback:
            # Add advanced security source information
            alert_data['advanced_security'] = True
            alert_data['module_timestamp'] = datetime.now().isoformat()
            
            self.alert_callback(alert_data)
            
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all advanced security modules"""
        return {
            'manager_status': {
                'monitoring': self.monitoring,
                'modules_count': 5,
                'active_modules': sum(1 for status in self.modules_status.values() 
                                    if isinstance(status, dict) and status.get('monitoring', False))
            },
            'modules': self.modules_status,
            'features_summary': {
                'credential_theft_detection': 'Active - Monitors LSASS access and suspicious tools',
                'brute_force_detection': 'Active - Monitors Windows Security Event Logs',
                'signature_verification': 'Active - Verifies file signatures and hashes',
                'clipboard_monitoring': 'Active - Detects sensitive clipboard content',
                'insider_threat_detection': 'Active - Monitors file transfers and behavioral anomalies'
            }
        }
        
    def configure_module(self, module_name: str, config: Dict[str, Any]):
        """Configure specific module settings"""
        try:
            if module_name == 'credential_theft':
                # Configure credential theft detector
                if 'suspicious_tools' in config:
                    self.credential_detector.suspicious_tools.extend(config['suspicious_tools'])
                    
            elif module_name == 'brute_force':
                # Configure brute force detector
                if 'thresholds' in config:
                    self.brute_force_detector.thresholds.update(config['thresholds'])
                    
            elif module_name == 'signature_verification':
                # Configure signature verifier
                if 'trusted_hashes' in config:
                    for hash_value, file_path in config['trusted_hashes'].items():
                        self.signature_verifier.add_trusted_hash(hash_value, file_path)
                        
            elif module_name == 'clipboard_monitoring':
                # Configure clipboard monitor
                if 'user_consent' in config:
                    self.clipboard_monitor.set_user_consent(config['user_consent'])
                if 'custom_patterns' in config:
                    for pattern in config['custom_patterns']:
                        self.clipboard_monitor.add_custom_pattern(
                            pattern['type'], 
                            pattern['pattern'], 
                            pattern.get('severity', 'MEDIUM')
                        )
                        
            elif module_name == 'insider_threat':
                # Configure insider threat detector
                if 'authorized_remote_access' in config:
                    for tool in config['authorized_remote_access']:
                        self.insider_threat_detector.add_authorized_remote_access(
                            tool['name'], 
                            tool['exe_path']
                        )
                if 'behavioral_thresholds' in config:
                    self.insider_threat_detector.update_behavioral_thresholds(config['behavioral_thresholds'])
                    
            self.logger.info(f"✅ Configured {module_name} module")
            
        except Exception as e:
            self.logger.error(f"❌ Error configuring {module_name} module: {e}")
            
    def get_module_status(self, module_name: str) -> Dict[str, Any]:
        """Get status of specific module"""
        module_map = {
            'credential_theft': self.credential_detector,
            'brute_force': self.brute_force_detector,
            'signature_verification': self.signature_verifier,
            'clipboard_monitoring': self.clipboard_monitor,
            'insider_threat': self.insider_threat_detector
        }
        
        if module_name in module_map:
            return module_map[module_name].get_status()
        else:
            return {'error': f'Module {module_name} not found'}
            
    def test_module(self, module_name: str, test_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test specific module functionality"""
        try:
            if module_name == 'signature_verification':
                if 'file_path' in test_data:
                    return self.signature_verifier.verify_specific_file(test_data['file_path'])
                    
            elif module_name == 'clipboard_monitoring':
                if 'content' in test_data:
                    return self.clipboard_monitor.test_pattern(test_data['content'])
                    
            elif module_name == 'brute_force':
                if 'failed_attempts' in test_data:
                    return self.brute_force_detector.get_failed_attempts_summary()
                    
            return {'error': f'No test method available for {module_name}'}
            
        except Exception as e:
            return {'error': f'Test failed for {module_name}: {str(e)}'}
            
    def get_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'active' if self.monitoring else 'inactive',
                'modules_summary': {},
                'recommendations': []
            }
            
            # Collect module summaries
            for module_name, status in self.modules_status.items():
                if isinstance(status, dict):
                    report['modules_summary'][module_name] = {
                        'status': 'active' if status.get('monitoring', False) else 'inactive',
                        'details': status
                    }
                    
            # Generate recommendations
            recommendations = []
            
            # Check credential theft detection
            cred_status = self.modules_status.get('credential_theft', {})
            if cred_status.get('lsass_found', False):
                recommendations.append("LSASS process detected - ensure proper access controls")
                
            # Check brute force detection
            bf_status = self.modules_status.get('brute_force', {})
            if bf_status.get('failed_attempts_count', 0) > 0:
                recommendations.append("Failed login attempts detected - review authentication logs")
                
            # Check signature verification
            sig_status = self.modules_status.get('signature_verification', {})
            if sig_status.get('suspicious_hashes_count', 0) > 0:
                recommendations.append("Suspicious files detected - review file integrity")
                
            # Check clipboard monitoring
            clip_status = self.modules_status.get('clipboard_monitoring', {})
            if not clip_status.get('user_consent', False):
                recommendations.append("Clipboard monitoring disabled - consider enabling for enhanced security")
                
            # Check insider threat detection
            insider_status = self.modules_status.get('insider_threat', {})
            if insider_status.get('file_transfers_count', 0) > 10:
                recommendations.append("High file transfer activity detected - review data access patterns")
                
            report['recommendations'] = recommendations
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating security report: {e}")
            return {'error': f'Failed to generate report: {str(e)}'}
            
    def emergency_stop(self):
        """Emergency stop all monitoring"""
        self.logger.warning("🚨 EMERGENCY STOP - Stopping all advanced security modules")
        self.stop_all_monitoring()
        
    def restart_module(self, module_name: str):
        """Restart specific module"""
        try:
            module_map = {
                'credential_theft': self.credential_detector,
                'brute_force': self.brute_force_detector,
                'signature_verification': self.signature_verifier,
                'clipboard_monitoring': self.clipboard_monitor,
                'insider_threat': self.insider_threat_detector
            }
            
            if module_name in module_map:
                module = module_map[module_name]
                module.stop_monitoring()
                time.sleep(2)  # Brief pause
                module.start_monitoring()
                self.logger.info(f"✅ Restarted {module_name} module")
            else:
                self.logger.error(f"❌ Module {module_name} not found")
                
        except Exception as e:
            self.logger.error(f"❌ Error restarting {module_name} module: {e}") 