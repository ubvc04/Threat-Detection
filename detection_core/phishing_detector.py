"""
Phishing URL Detection Module
Uses machine learning to detect phishing URLs based on various features
"""

import os
import re
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.model_path = 'models/phishing_detector.pkl'
        self.vectorizer_path = 'models/phishing_vectorizer.pkl'
        
    def extract_features(self, url):
        """Extract features from URL for phishing detection"""
        features = {}
        
        # Basic URL features
        parsed = urlparse(url)
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        
        # Suspicious patterns
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
        features['has_suspicious_words'] = 1 if re.search(r'(login|signin|bank|secure|account|update|verify)', url.lower()) else 0
        features['has_redirect'] = 1 if re.search(r'(redirect|goto|url=|link=)', url.lower()) else 0
        features['has_shortener'] = 1 if any(shortener in url.lower() for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else 0
        
        # Domain features
        features['subdomain_count'] = len(parsed.netloc.split('.')) - 1
        features['has_hyphen'] = 1 if '-' in parsed.netloc else 0
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # SSL/TLS features
        features['uses_https'] = 1 if parsed.scheme == 'https' else 0
        
        # Query parameters
        query_params = parse_qs(parsed.query)
        features['param_count'] = len(query_params)
        features['has_suspicious_params'] = 1 if any(param.lower() in ['login', 'password', 'user', 'id'] for param in query_params.keys()) else 0
        
        return features
    
    def preprocess_dataset(self, dataset_path):
        """Preprocess the phishing dataset"""
        try:
            # Expected CSV format: url,label (where label is 1 for phishing, 0 for legitimate)
            df = pd.read_csv(dataset_path)
            
            # Ensure required columns exist
            if 'url' not in df.columns or 'label' not in df.columns:
                raise ValueError("Dataset must contain 'url' and 'label' columns")
            
            # Extract features
            features_list = []
            for url in df['url']:
                features_list.append(self.extract_features(url))
            
            features_df = pd.DataFrame(features_list)
            
            # Combine features with labels
            X = features_df
            y = df['label']
            
            return X, y
            
        except Exception as e:
            print(f"Error preprocessing dataset: {e}")
            return None, None
    
    def train_model(self, dataset_path):
        """Train the phishing detection model"""
        print("Training phishing detection model...")
        
        X, y = self.preprocess_dataset(dataset_path)
        if X is None or y is None:
            return False
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train Random Forest classifier
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model accuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred))
        
        # Save the model
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, self.model_path)
        
        print(f"Model saved to {self.model_path}")
        return True
    
    def load_model(self):
        """Load the trained model"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                return True
            else:
                print("No trained model found. Please train the model first.")
                return False
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict(self, url):
        """Predict if a URL is phishing or legitimate"""
        if self.model is None:
            if not self.load_model():
                return None
        
        # Extract features
        features = self.extract_features(url)
        features_df = pd.DataFrame([features])
        
        # Make prediction
        prediction = self.model.predict(features_df)[0]
        probability = self.model.predict_proba(features_df)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(max(probability)),
            'features': features
        }
    
    def detect_phishing(self, url, source="manual_check"):
        """Detect phishing and log alert if detected"""
        try:
            result = self.predict(url)
            if result is None:
                return False
            
            if result['is_phishing']:
                # Log alert to Django
                from dashboard.models import Alert
                
                severity = 'HIGH' if result['confidence'] > 0.8 else 'MEDIUM'
                
                Alert.objects.create(
                    alert_type='PHISHING',
                    severity=severity,
                    message=f"Phishing URL detected: {url}",
                    source=source,
                    details={
                        'confidence': result['confidence'],
                        'features': result['features']
                    }
                )
                
                return True
            
            return False
            
        except Exception as e:
            print(f"Error in phishing detection: {e}")
            return False

# Global instance
phishing_detector = PhishingDetector() 