#!/usr/bin/env python3
"""
Test Trained ML Models
Test the models trained from your datasets
"""

import os
import sys
import pickle
import json
from pathlib import Path
import pandas as pd
import numpy as np

# Add project path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

class ModelTester:
    def __init__(self):
        self.models_dir = Path("trained_models")
        self.models = {}
        self.vectorizers = {}
        
        print("🧪 Model Tester initialized")
    
    def load_models(self):
        """Load all trained models"""
        if not self.models_dir.exists():
            print("⚠️  No trained models found. Run train_models_from_datasets.py first.")
            return False
        
        # Load model summary
        summary_path = self.models_dir / "model_summary.json"
        if summary_path.exists():
            with open(summary_path, 'r') as f:
                summary = json.load(f)
            
            print(f"📊 Found {summary['total_models']} trained models:")
            for model_name, info in summary['models'].items():
                print(f"   {model_name}: {info['algorithm']} ({info['accuracy']:.4f} accuracy)")
        
        # Load individual models
        for model_file in self.models_dir.glob("*.pkl"):
            if "vectorizer" in model_file.name:
                continue
            
            model_name = model_file.stem
            try:
                with open(model_file, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
                print(f"✅ Loaded model: {model_name}")
            except Exception as e:
                print(f"❌ Error loading {model_name}: {e}")
        
        # Load vectorizers
        for vectorizer_file in self.models_dir.glob("*_vectorizer.pkl"):
            model_name = vectorizer_file.stem.replace("_vectorizer", "")
            try:
                with open(vectorizer_file, 'rb') as f:
                    self.vectorizers[model_name] = pickle.load(f)
                print(f"✅ Loaded vectorizer: {model_name}")
            except Exception as e:
                print(f"❌ Error loading vectorizer {model_name}: {e}")
        
        return len(self.models) > 0
    
    def test_sms_spam_model(self):
        """Test SMS spam detection model"""
        if 'sms_spam' not in self.models:
            print("⚠️  SMS spam model not found")
            return
        
        print("\n📱 Testing SMS Spam Detection Model:")
        
        # Test messages
        test_messages = [
            "URGENT: You have won a $1000 gift card! Click here to claim now!",
            "Hi, can you pick up some milk on your way home?",
            "FREE VIAGRA NOW!!! LIMITED TIME OFFER!!!",
            "Meeting tomorrow at 3 PM in conference room A",
            "CONGRATULATIONS! You've been selected for a special offer!",
            "The weather is nice today, want to go for a walk?",
            "URGENT: Your account has been suspended. Call immediately!",
            "Thanks for the birthday wishes everyone!"
        ]
        
        model = self.models['sms_spam']
        vectorizer = self.vectorizers.get('sms_spam')
        
        if vectorizer:
            # Vectorize test messages
            X_test = vectorizer.transform(test_messages)
            predictions = model.predict(X_test)
            probabilities = model.predict_proba(X_test)
            
            for i, message in enumerate(test_messages):
                pred = "SPAM" if predictions[i] == 1 else "HAM"
                prob = probabilities[i][1] if predictions[i] == 1 else probabilities[i][0]
                print(f"   '{message[:50]}...' -> {pred} ({prob:.3f})")
        else:
            print("⚠️  Vectorizer not found for SMS model")
    
    def test_phishing_model(self):
        """Test phishing website detection model"""
        if 'phishing_websites' not in self.models:
            print("⚠️  Phishing websites model not found")
            return
        
        print("\n🌐 Testing Phishing Website Detection Model:")
        
        # Create sample feature vectors (you would need to extract real features)
        # This is a simplified test with random data
        model = self.models['phishing_websites']
        
        # Get feature count from model
        if hasattr(model, 'n_features_in_'):
            n_features = model.n_features_in_
        else:
            n_features = 10  # Default fallback
        
        # Create test samples
        test_samples = np.random.rand(5, n_features)
        
        predictions = model.predict(test_samples)
        probabilities = model.predict_proba(test_samples)
        
        for i in range(len(test_samples)):
            pred = "PHISHING" if predictions[i] == 1 else "LEGITIMATE"
            prob = probabilities[i][1] if predictions[i] == 1 else probabilities[i][0]
            print(f"   Sample {i+1}: {pred} ({prob:.3f})")
    
    def run_all_tests(self):
        """Run all model tests"""
        print("🚀 Starting Model Tests...")
        
        if not self.load_models():
            return
        
        self.test_sms_spam_model()
        self.test_phishing_model()
        
        print("\n✅ All model tests completed!")

def main():
    """Main function"""
    tester = ModelTester()
    tester.run_all_tests()

if __name__ == '__main__':
    main() 