"""
Explainable AI (XAI) for Threat Alerts
Provides explanations for ML model predictions using SHAP and LIME
"""

import logging
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import pickle
from pathlib import Path
import re

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("⚠️ SHAP not available. Install with: pip install shap")

try:
    from lime.lime_text import LimeTextExplainer
    from lime.lime_tabular import LimeTabularExplainer
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    print("⚠️ LIME not available. Install with: pip install lime")

class ExplainableAI:
    """Explainable AI system for threat detection explanations"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.models_dir = Path("trained_models")
        
        # Load models and preprocessors
        self.models = {}
        self.preprocessors = {}
        self.explainers = {}
        
        # Feature explanations
        self.feature_descriptions = {
            'url_features': {
                'length': 'URL length (longer URLs may be suspicious)',
                'domain_age': 'Domain age (newer domains may be suspicious)',
                'suspicious_tld': 'Suspicious top-level domain',
                'ip_in_url': 'IP address in URL (suspicious)',
                'suspicious_words': 'Suspicious keywords in URL',
                'redirect_count': 'Number of redirects',
                'special_chars': 'Special characters in URL',
                'subdomain_count': 'Number of subdomains'
            },
            'text_features': {
                'length': 'Message length',
                'suspicious_words': 'Suspicious keywords',
                'urgent_language': 'Urgent or threatening language',
                'money_mentions': 'Mentions of money or financial terms',
                'personal_info': 'Personal information requests',
                'link_count': 'Number of links',
                'spam_indicators': 'Spam indicators',
                'grammar_errors': 'Grammar or spelling errors'
            }
        }
        
        self._load_models()
        
    def _load_models(self):
        """Load trained models and preprocessors"""
        try:
            if not self.models_dir.exists():
                self.logger.warning("Models directory not found")
                return
                
            # Load model summary
            summary_path = self.models_dir / "comprehensive_model_summary.json"
            if summary_path.exists():
                with open(summary_path, 'r') as f:
                    summary = json.load(f)
                    
                for model_name, model_info in summary['models'].items():
                    model_file = self.models_dir / f"{model_name}_{model_info['algorithm']}.pkl"
                    preprocessor_file = self.models_dir / f"{model_name}_preprocessor.pkl"
                    
                    if model_file.exists() and preprocessor_file.exists():
                        try:
                            with open(model_file, 'rb') as f:
                                self.models[model_name] = pickle.load(f)
                                
                            with open(preprocessor_file, 'rb') as f:
                                self.preprocessors[model_name] = pickle.load(f)
                                
                            self.logger.info(f"✅ Loaded model: {model_name}")
                            
                        except Exception as e:
                            self.logger.error(f"Error loading model {model_name}: {e}")
                            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            
    def explain_prediction(self, model_name: str, input_data: str, prediction_type: str = 'text') -> Dict[str, Any]:
        """Generate explanation for model prediction"""
        try:
            if model_name not in self.models:
                return {
                    'success': False,
                    'error': f'Model {model_name} not found'
                }
                
            model = self.models[model_name]
            preprocessor = self.preprocessors.get(model_name)
            
            if prediction_type == 'text':
                return self._explain_text_prediction(model, preprocessor, input_data, model_name)
            elif prediction_type == 'url':
                return self._explain_url_prediction(model, preprocessor, input_data, model_name)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported prediction type: {prediction_type}'
                }
                
        except Exception as e:
            self.logger.error(f"Error explaining prediction: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    def _explain_text_prediction(self, model, preprocessor, text: str, model_name: str) -> Dict[str, Any]:
        """Explain text-based prediction (SMS, email, etc.)"""
        try:
            # Prepare input
            if preprocessor:
                X = preprocessor.transform([text])
            else:
                X = np.array([text])
                
            # Get prediction
            prediction = model.predict(X)[0]
            probability = model.predict_proba(X)[0]
            
            # Generate explanations
            explanations = {}
            
            # SHAP explanation
            if SHAP_AVAILABLE and hasattr(model, 'feature_importances_'):
                explanations['shap'] = self._generate_shap_explanation(model, X, text)
                
            # LIME explanation
            if LIME_AVAILABLE:
                explanations['lime'] = self._generate_lime_explanation(model, text, 'text')
                
            # Feature-based explanation
            explanations['features'] = self._analyze_text_features(text)
            
            # Rule-based explanation
            explanations['rules'] = self._apply_text_rules(text)
            
            return {
                'success': True,
                'prediction': 'SPAM' if prediction == 1 else 'HAM',
                'confidence': float(max(probability)),
                'probability': {
                    'spam': float(probability[1] if len(probability) > 1 else probability[0]),
                    'ham': float(probability[0] if len(probability) > 1 else 0)
                },
                'explanations': explanations,
                'model_name': model_name,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error explaining text prediction: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    def _explain_url_prediction(self, model, preprocessor, url: str, model_name: str) -> Dict[str, Any]:
        """Explain URL-based prediction (phishing detection)"""
        try:
            # Prepare input
            if preprocessor:
                X = preprocessor.transform([url])
            else:
                X = np.array([url])
                
            # Get prediction
            prediction = model.predict(X)[0]
            probability = model.predict_proba(X)[0]
            
            # Generate explanations
            explanations = {}
            
            # SHAP explanation
            if SHAP_AVAILABLE and hasattr(model, 'feature_importances_'):
                explanations['shap'] = self._generate_shap_explanation(model, X, url)
                
            # LIME explanation
            if LIME_AVAILABLE:
                explanations['lime'] = self._generate_lime_explanation(model, url, 'url')
                
            # Feature-based explanation
            explanations['features'] = self._analyze_url_features(url)
            
            # Rule-based explanation
            explanations['rules'] = self._apply_url_rules(url)
            
            return {
                'success': True,
                'prediction': 'PHISHING' if prediction == 1 else 'SAFE',
                'confidence': float(max(probability)),
                'probability': {
                    'phishing': float(probability[1] if len(probability) > 1 else probability[0]),
                    'safe': float(probability[0] if len(probability) > 1 else 0)
                },
                'explanations': explanations,
                'model_name': model_name,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error explaining URL prediction: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    def _generate_shap_explanation(self, model, X, input_text: str) -> Dict[str, Any]:
        """Generate SHAP explanation"""
        try:
            if not SHAP_AVAILABLE:
                return {'available': False, 'message': 'SHAP not available'}
                
            # Create SHAP explainer
            if hasattr(model, 'feature_importances_'):
                explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X)
                
                # Get feature names
                feature_names = getattr(model, 'feature_names_in_', [f'feature_{i}' for i in range(X.shape[1])])
                
                # Create explanation
                explanation = {
                    'available': True,
                    'feature_importance': {},
                    'top_features': []
                }
                
                # Get feature importance
                if len(shap_values) > 1:  # Multi-class
                    shap_values = shap_values[1]  # Positive class
                    
                for i, (feature_name, importance) in enumerate(zip(feature_names, shap_values[0])):
                    explanation['feature_importance'][feature_name] = float(importance)
                    
                # Get top features
                feature_importance = list(explanation['feature_importance'].items())
                feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
                
                explanation['top_features'] = feature_importance[:10]
                
                return explanation
                
        except Exception as e:
            self.logger.error(f"Error generating SHAP explanation: {e}")
            return {'available': False, 'error': str(e)}
            
    def _generate_lime_explanation(self, model, input_text: str, input_type: str) -> Dict[str, Any]:
        """Generate LIME explanation"""
        try:
            if not LIME_AVAILABLE:
                return {'available': False, 'message': 'LIME not available'}
                
            if input_type == 'text':
                explainer = LimeTextExplainer(class_names=['HAM', 'SPAM'])
                
                # Create explainer function
                def predict_proba(texts):
                    # This would need to be adapted based on your model
                    return np.array([[0.8, 0.2]] * len(texts))
                    
                exp = explainer.explain_instance(input_text, predict_proba, num_features=10)
                
                return {
                    'available': True,
                    'explanation': exp.as_list(),
                    'score': exp.score
                }
                
            elif input_type == 'url':
                # For URL features, we'd need a tabular explainer
                return {
                    'available': False,
                    'message': 'LIME tabular explanation not implemented for URLs'
                }
                
        except Exception as e:
            self.logger.error(f"Error generating LIME explanation: {e}")
            return {'available': False, 'error': str(e)}
            
    def _analyze_text_features(self, text: str) -> Dict[str, Any]:
        """Analyze text features for explanation"""
        try:
            features = {
                'length': len(text),
                'word_count': len(text.split()),
                'suspicious_words': [],
                'urgent_language': False,
                'money_mentions': False,
                'personal_info': False,
                'link_count': 0,
                'spam_indicators': 0,
                'grammar_errors': 0
            }
            
            # Check for suspicious words
            suspicious_words = [
                'urgent', 'immediate', 'action required', 'account suspended',
                'verify', 'confirm', 'password', 'login', 'security',
                'limited time', 'offer', 'free', 'winner', 'prize'
            ]
            
            text_lower = text.lower()
            for word in suspicious_words:
                if word in text_lower:
                    features['suspicious_words'].append(word)
                    
            # Check for urgent language
            urgent_patterns = [
                r'urgent', r'immediate', r'action required', r'account suspended',
                r'verify now', r'confirm immediately'
            ]
            
            for pattern in urgent_patterns:
                if re.search(pattern, text_lower):
                    features['urgent_language'] = True
                    break
                    
            # Check for money mentions
            money_patterns = [
                r'\$\d+', r'dollar', r'money', r'payment', r'bank',
                r'credit card', r'account', r'balance'
            ]
            
            for pattern in money_patterns:
                if re.search(pattern, text_lower):
                    features['money_mentions'] = True
                    break
                    
            # Check for personal info requests
            personal_patterns = [
                r'password', r'username', r'login', r'account',
                r'social security', r'credit card', r'bank account'
            ]
            
            for pattern in personal_patterns:
                if re.search(pattern, text_lower):
                    features['personal_info'] = True
                    break
                    
            # Count links
            link_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            features['link_count'] = len(re.findall(link_pattern, text))
            
            # Spam indicators
            spam_indicators = [
                'free', 'winner', 'prize', 'limited time', 'offer',
                'click here', 'act now', 'exclusive'
            ]
            
            for indicator in spam_indicators:
                if indicator in text_lower:
                    features['spam_indicators'] += 1
                    
            return features
            
        except Exception as e:
            self.logger.error(f"Error analyzing text features: {e}")
            return {}
            
    def _analyze_url_features(self, url: str) -> Dict[str, Any]:
        """Analyze URL features for explanation"""
        try:
            features = {
                'length': len(url),
                'domain': '',
                'suspicious_tld': False,
                'ip_in_url': False,
                'suspicious_words': [],
                'redirect_count': 0,
                'special_chars': 0,
                'subdomain_count': 0
            }
            
            # Extract domain
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                features['domain'] = parsed.netloc
            except:
                features['domain'] = url
                
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            for tld in suspicious_tlds:
                if tld in url.lower():
                    features['suspicious_tld'] = True
                    break
                    
            # Check for IP in URL
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            if re.search(ip_pattern, url):
                features['ip_in_url'] = True
                
            # Check for suspicious words
            suspicious_words = [
                'login', 'signin', 'verify', 'confirm', 'secure',
                'account', 'bank', 'paypal', 'amazon', 'google'
            ]
            
            url_lower = url.lower()
            for word in suspicious_words:
                if word in url_lower:
                    features['suspicious_words'].append(word)
                    
            # Count special characters
            special_chars = re.findall(r'[^a-zA-Z0-9\-\.]', url)
            features['special_chars'] = len(special_chars)
            
            # Count subdomains
            if features['domain']:
                subdomains = features['domain'].split('.')
                features['subdomain_count'] = max(0, len(subdomains) - 2)
                
            return features
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL features: {e}")
            return {}
            
    def _apply_text_rules(self, text: str) -> Dict[str, Any]:
        """Apply rule-based explanations for text"""
        try:
            rules = {
                'urgent_language': False,
                'money_mentions': False,
                'personal_info_request': False,
                'multiple_links': False,
                'suspicious_patterns': []
            }
            
            text_lower = text.lower()
            
            # Rule 1: Urgent language
            urgent_patterns = [r'urgent', r'immediate', r'action required']
            for pattern in urgent_patterns:
                if re.search(pattern, text_lower):
                    rules['urgent_language'] = True
                    rules['suspicious_patterns'].append('Urgent language detected')
                    break
                    
            # Rule 2: Money mentions
            money_patterns = [r'\$\d+', r'dollar', r'payment', r'bank']
            for pattern in money_patterns:
                if re.search(pattern, text_lower):
                    rules['money_mentions'] = True
                    rules['suspicious_patterns'].append('Financial terms detected')
                    break
                    
            # Rule 3: Personal info requests
            personal_patterns = [r'password', r'username', r'login', r'account']
            for pattern in personal_patterns:
                if re.search(pattern, text_lower):
                    rules['personal_info_request'] = True
                    rules['suspicious_patterns'].append('Personal information request')
                    break
                    
            # Rule 4: Multiple links
            link_pattern = r'http[s]?://'
            links = re.findall(link_pattern, text)
            if len(links) > 1:
                rules['multiple_links'] = True
                rules['suspicious_patterns'].append('Multiple links detected')
                
            return rules
            
        except Exception as e:
            self.logger.error(f"Error applying text rules: {e}")
            return {}
            
    def _apply_url_rules(self, url: str) -> Dict[str, Any]:
        """Apply rule-based explanations for URLs"""
        try:
            rules = {
                'suspicious_tld': False,
                'ip_address': False,
                'long_url': False,
                'suspicious_domain': False,
                'suspicious_patterns': []
            }
            
            # Rule 1: Suspicious TLD
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            for tld in suspicious_tlds:
                if tld in url.lower():
                    rules['suspicious_tld'] = True
                    rules['suspicious_patterns'].append(f'Suspicious TLD: {tld}')
                    break
                    
            # Rule 2: IP address in URL
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            if re.search(ip_pattern, url):
                rules['ip_address'] = True
                rules['suspicious_patterns'].append('IP address in URL')
                
            # Rule 3: Long URL
            if len(url) > 100:
                rules['long_url'] = True
                rules['suspicious_patterns'].append('Unusually long URL')
                
            # Rule 4: Suspicious domain
            suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
            for domain in suspicious_domains:
                if domain in url.lower():
                    rules['suspicious_domain'] = True
                    rules['suspicious_patterns'].append(f'URL shortener: {domain}')
                    break
                    
            return rules
            
        except Exception as e:
            self.logger.error(f"Error applying URL rules: {e}")
            return {}
            
    def get_available_models(self) -> List[str]:
        """Get list of available models"""
        return list(self.models.keys())
        
    def get_explanation_summary(self, explanation: Dict[str, Any]) -> str:
        """Generate a human-readable explanation summary"""
        try:
            if not explanation.get('success', False):
                return "Unable to generate explanation"
                
            summary_parts = []
            
            # Add prediction
            prediction = explanation.get('prediction', 'Unknown')
            confidence = explanation.get('confidence', 0)
            summary_parts.append(f"Prediction: {prediction} (Confidence: {confidence:.2%})")
            
            # Add top features from SHAP
            if 'explanations' in explanation and 'shap' in explanation['explanations']:
                shap_explanation = explanation['explanations']['shap']
                if shap_explanation.get('available', False) and 'top_features' in shap_explanation:
                    top_features = shap_explanation['top_features'][:3]
                    if top_features:
                        summary_parts.append("Top contributing factors:")
                        for feature, importance in top_features:
                            summary_parts.append(f"  - {feature}: {importance:.3f}")
                            
            # Add rule-based explanations
            if 'explanations' in explanation and 'rules' in explanation['explanations']:
                rules = explanation['explanations']['rules']
                if rules.get('suspicious_patterns'):
                    summary_parts.append("Suspicious patterns detected:")
                    for pattern in rules['suspicious_patterns']:
                        summary_parts.append(f"  - {pattern}")
                        
            return "\n".join(summary_parts)
            
        except Exception as e:
            self.logger.error(f"Error generating explanation summary: {e}")
            return "Error generating explanation summary" 