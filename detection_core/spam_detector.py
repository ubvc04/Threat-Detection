"""
Spam Detection Module
Uses machine learning to detect spam/ham messages
"""

import os
import re
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

class SpamDetector:
    def __init__(self):
        self.model = None
        self.pipeline = None
        self.model_path = 'models/spam_detector.pkl'
        
    def preprocess_text(self, text):
        """Preprocess text for spam detection"""
        if not isinstance(text, str):
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def preprocess_dataset(self, dataset_path):
        """Preprocess the spam dataset"""
        try:
            # Expected CSV format: text,label (where label is 'spam' or 'ham')
            df = pd.read_csv(dataset_path)
            
            # Ensure required columns exist
            if 'text' not in df.columns or 'label' not in df.columns:
                raise ValueError("Dataset must contain 'text' and 'label' columns")
            
            # Preprocess text
            df['processed_text'] = df['text'].apply(self.preprocess_text)
            
            # Convert labels to binary (spam=1, ham=0)
            df['label_binary'] = (df['label'] == 'spam').astype(int)
            
            # Remove empty texts
            df = df[df['processed_text'].str.len() > 0]
            
            X = df['processed_text']
            y = df['label_binary']
            
            return X, y
            
        except Exception as e:
            print(f"Error preprocessing dataset: {e}")
            return None, None
    
    def train_model(self, dataset_path):
        """Train the spam detection model"""
        print("Training spam detection model...")
        
        X, y = self.preprocess_dataset(dataset_path)
        if X is None or y is None:
            return False
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Create pipeline with TF-IDF vectorizer and Naive Bayes
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english')),
            ('classifier', MultinomialNB())
        ])
        
        # Train the pipeline
        self.pipeline.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model accuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred, target_names=['ham', 'spam']))
        
        # Save the model
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.pipeline, self.model_path)
        
        print(f"Model saved to {self.model_path}")
        return True
    
    def load_model(self):
        """Load the trained model"""
        try:
            if os.path.exists(self.model_path):
                self.pipeline = joblib.load(self.model_path)
                return True
            else:
                print("No trained model found. Please train the model first.")
                return False
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict(self, text):
        """Predict if a message is spam or ham"""
        if self.pipeline is None:
            if not self.load_model():
                return None
        
        # Preprocess text
        processed_text = self.preprocess_text(text)
        
        if not processed_text:
            return {
                'is_spam': False,
                'confidence': 0.0,
                'processed_text': ''
            }
        
        # Make prediction
        prediction = self.pipeline.predict([processed_text])[0]
        probability = self.pipeline.predict_proba([processed_text])[0]
        
        return {
            'is_spam': bool(prediction),
            'confidence': float(max(probability)),
            'processed_text': processed_text
        }
    
    def detect_spam(self, text, source="manual_check"):
        """Detect spam and log alert if detected"""
        try:
            result = self.predict(text)
            if result is None:
                return False
            
            if result['is_spam']:
                # Log alert to Django
                from dashboard.models import Alert
                
                severity = 'HIGH' if result['confidence'] > 0.9 else 'MEDIUM'
                
                # Truncate text for display
                display_text = text[:100] + "..." if len(text) > 100 else text
                
                Alert.objects.create(
                    alert_type='SPAM',
                    severity=severity,
                    message=f"Spam message detected: {display_text}",
                    source=source,
                    details={
                        'confidence': result['confidence'],
                        'text_length': len(text),
                        'processed_text': result['processed_text']
                    }
                )
                
                return True
            
            return False
            
        except Exception as e:
            print(f"Error in spam detection: {e}")
            return False
    
    def extract_spam_features(self, text):
        """Extract features that indicate spam"""
        features = {}
        
        # Convert to lowercase for analysis
        text_lower = text.lower()
        
        # Common spam indicators
        features['has_urgent_words'] = 1 if re.search(r'(urgent|immediate|act now|limited time|offer expires)', text_lower) else 0
        features['has_money_words'] = 1 if re.search(r'(money|cash|dollars|free|winner|prize|lottery)', text_lower) else 0
        features['has_suspicious_links'] = 1 if re.search(r'(http|www|\.com|\.net|\.org)', text_lower) else 0
        features['has_numbers'] = 1 if re.search(r'\d+', text) else 0
        features['has_caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        features['has_exclamation_marks'] = text.count('!')
        features['has_question_marks'] = text.count('?')
        features['text_length'] = len(text)
        
        return features

# Global instance
spam_detector = SpamDetector() 