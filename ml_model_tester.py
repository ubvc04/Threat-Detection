#!/usr/bin/env python3
"""
ML Model Tester - User Interface
Test your links and messages with trained ML models
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

class MLModelTester:
    def __init__(self):
        self.models_dir = Path("trained_models")
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        
        print("🧪 ML Model Tester - User Interface")
        print("=" * 50)
        
    def load_models(self):
        """Load all trained models"""
        if not self.models_dir.exists():
            print("❌ No trained models found. Run training scripts first.")
            return False
        
        # Load comprehensive summary
        summary_path = self.models_dir / "comprehensive_model_summary.json"
        if summary_path.exists():
            with open(summary_path, 'r') as f:
                summary = json.load(f)
            
            print(f"📊 Found {summary['total_models']} trained models:")
            for model_name, info in summary['models'].items():
                print(f"   ✅ {model_name}: {info['type']} - {info['algorithm']} ({info['accuracy']:.4f} accuracy)")
        
        # Load individual models
        for model_file in self.models_dir.glob("*.pkl"):
            if "preprocessor" in model_file.name:
                continue
            
            model_name = model_file.stem
            try:
                with open(model_file, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
            except Exception as e:
                print(f"❌ Error loading {model_name}: {e}")
        
        # Load preprocessors
        for preprocessor_file in self.models_dir.glob("*_preprocessor.pkl"):
            model_name = preprocessor_file.stem.replace("_preprocessor", "")
            try:
                with open(preprocessor_file, 'rb') as f:
                    preprocessor = pickle.load(f)
                
                if hasattr(preprocessor, 'transform') and hasattr(preprocessor, 'get_feature_names_out'):
                    self.vectorizers[model_name] = preprocessor
                else:
                    self.scalers[model_name] = preprocessor
            except Exception as e:
                print(f"❌ Error loading preprocessor {model_name}: {e}")
        
        return len(self.models) > 0
    
    def test_sms_message(self, message):
        """Test SMS message for spam"""
        if 'text_spam_dataset' not in self.models:
            print("❌ SMS spam model not found")
            return None
        
        model = self.models['text_spam_dataset']
        vectorizer = self.vectorizers.get('text_spam_dataset')
        
        if not vectorizer:
            print("❌ SMS vectorizer not found")
            return None
        
        # Vectorize message
        X_test = vectorizer.transform([message])
        prediction = model.predict(X_test)[0]
        probability = model.predict_proba(X_test)[0]
        
        result = {
            'message': message,
            'prediction': 'SPAM' if prediction == 1 else 'HAM',
            'confidence': max(probability),
            'spam_probability': probability[1] if len(probability) > 1 else probability[0],
            'ham_probability': probability[0] if len(probability) > 1 else 0
        }
        
        return result
    
    def test_url(self, url):
        """Test URL for phishing"""
        if 'text_spam_dataset' not in self.models:
            print("❌ Phishing model not found")
            return None
        
        model = self.models['text_spam_dataset']
        vectorizer = self.vectorizers.get('text_spam_dataset')
        
        if not vectorizer:
            print("❌ URL vectorizer not found")
            return None
        
        # Vectorize URL
        X_test = vectorizer.transform([url])
        prediction = model.predict(X_test)[0]
        probability = model.predict_proba(X_test)[0]
        
        result = {
            'url': url,
            'prediction': 'PHISHING' if prediction == 1 else 'SAFE',
            'confidence': max(probability),
            'phishing_probability': probability[1] if len(probability) > 1 else probability[0],
            'safe_probability': probability[0] if len(probability) > 1 else 0
        }
        
        return result
    
    def interactive_menu(self):
        """Interactive menu for testing"""
        while True:
            print("\n" + "="*50)
            print("🎯 ML Model Testing Menu")
            print("="*50)
            print("1. Test SMS Message for Spam")
            print("2. Test URL for Phishing")
            print("3. Test Multiple Messages")
            print("4. Show Available Models")
            print("5. Exit")
            print("="*50)
            
            choice = input("Enter your choice (1-5): ").strip()
            
            if choice == '1':
                self.test_sms_interactive()
            elif choice == '2':
                self.test_url_interactive()
            elif choice == '3':
                self.test_multiple_interactive()
            elif choice == '4':
                self.show_models()
            elif choice == '5':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please try again.")
    
    def test_sms_interactive(self):
        """Interactive SMS testing"""
        print("\n📱 SMS Spam Detection")
        print("-" * 30)
        
        message = input("Enter your SMS message: ").strip()
        if not message:
            print("❌ Message cannot be empty")
            return
        
        print(f"\n🔍 Analyzing message: '{message[:50]}{'...' if len(message) > 50 else ''}'")
        
        result = self.test_sms_message(message)
        if result:
            print(f"\n📊 Results:")
            print(f"   Prediction: {result['prediction']}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Spam Probability: {result['spam_probability']:.1%}")
            print(f"   Ham Probability: {result['ham_probability']:.1%}")
            
            if result['prediction'] == 'SPAM':
                print("   ⚠️  This message appears to be SPAM!")
            else:
                print("   ✅ This message appears to be legitimate.")
    
    def test_url_interactive(self):
        """Interactive URL testing"""
        print("\n🌐 URL Phishing Detection")
        print("-" * 30)
        
        url = input("Enter URL to test: ").strip()
        if not url:
            print("❌ URL cannot be empty")
            return
        
        print(f"\n🔍 Analyzing URL: {url}")
        
        result = self.test_url(url)
        if result:
            print(f"\n📊 Results:")
            print(f"   Prediction: {result['prediction']}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Phishing Probability: {result['phishing_probability']:.1%}")
            print(f"   Safe Probability: {result['safe_probability']:.1%}")
            
            if result['prediction'] == 'PHISHING':
                print("   ⚠️  This URL appears to be PHISHING!")
            else:
                print("   ✅ This URL appears to be safe.")
    
    def test_multiple_interactive(self):
        """Test multiple items"""
        print("\n📋 Multiple Item Testing")
        print("-" * 30)
        print("Enter multiple items (one per line). Press Enter twice to finish:")
        
        items = []
        while True:
            item = input().strip()
            if not item:
                break
            items.append(item)
        
        if not items:
            print("❌ No items entered")
            return
        
        print(f"\n🔍 Testing {len(items)} items...")
        
        for i, item in enumerate(items, 1):
            print(f"\n--- Item {i} ---")
            
            # Try to determine if it's a URL or message
            if item.startswith(('http://', 'https://', 'www.')):
                result = self.test_url(item)
                if result:
                    print(f"URL: {result['prediction']} ({result['confidence']:.1%})")
            else:
                result = self.test_sms_message(item)
                if result:
                    print(f"SMS: {result['prediction']} ({result['confidence']:.1%})")
    
    def show_models(self):
        """Show available models"""
        print("\n📊 Available Models:")
        print("-" * 30)
        
        if not self.models:
            print("❌ No models loaded")
            return
        
        for model_name in self.models:
            model_type = "Text" if model_name in self.vectorizers else "Tabular"
            print(f"   ✅ {model_name} ({model_type})")
    
    def run_demo(self):
        """Run demo tests"""
        print("\n🎭 Running Demo Tests...")
        
        # Demo SMS messages
        demo_messages = [
            "Hi, can you pick up some milk on your way home?",
            "URGENT: You have won a $1000 gift card! Click here to claim now!",
            "Meeting tomorrow at 3 PM in conference room A",
            "FREE VIAGRA NOW!!! LIMITED TIME OFFER!!!",
            "Thanks for the birthday wishes everyone!"
        ]
        
        print("\n📱 SMS Spam Detection Demo:")
        for message in demo_messages:
            result = self.test_sms_message(message)
            if result:
                status = "⚠️ SPAM" if result['prediction'] == 'SPAM' else "✅ HAM"
                print(f"   '{message[:40]}...' -> {status} ({result['confidence']:.1%})")
        
        # Demo URLs
        demo_urls = [
            "https://www.google.com",
            "http://www.phishtank.com/phish_detail.php?phish_id=8508535",
            "https://www.microsoft.com",
            "http://free-gift-card-claim-now.com",
            "https://www.github.com"
        ]
        
        print("\n🌐 URL Phishing Detection Demo:")
        for url in demo_urls:
            result = self.test_url(url)
            if result:
                status = "⚠️ PHISHING" if result['prediction'] == 'PHISHING' else "✅ SAFE"
                print(f"   {url} -> {status} ({result['confidence']:.1%})")

def main():
    """Main function"""
    tester = MLModelTester()
    
    if not tester.load_models():
        print("❌ Failed to load models. Please run training scripts first.")
        return
    
    # Run demo first
    tester.run_demo()
    
    # Start interactive menu
    tester.interactive_menu()

if __name__ == "__main__":
    main() 