#!/usr/bin/env python3
"""
Test All Trained ML Models
Test all models trained from your datasets
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

class AllModelTester:
    def __init__(self):
        self.models_dir = Path("trained_models")
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        
        print("🧪 All Model Tester initialized")
    
    def load_all_models(self):
        """Load all trained models"""
        if not self.models_dir.exists():
            print("⚠️  No trained models found. Run train_all_datasets.py first.")
            return False
        
        # Load comprehensive summary
        summary_path = self.models_dir / "comprehensive_model_summary.json"
        if summary_path.exists():
            with open(summary_path, 'r') as f:
                summary = json.load(f)
            
            print(f"📊 Found {summary['total_models']} trained models:")
            for model_name, info in summary['models'].items():
                print(f"   {model_name}: {info['type']} - {info['algorithm']} ({info['accuracy']:.4f} accuracy)")
        
        # Load individual models
        for model_file in self.models_dir.glob("*.pkl"):
            if "preprocessor" in model_file.name:
                continue
            
            model_name = model_file.stem
            try:
                with open(model_file, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
                print(f"✅ Loaded model: {model_name}")
            except Exception as e:
                print(f"❌ Error loading {model_name}: {e}")
        
        # Load preprocessors
        for preprocessor_file in self.models_dir.glob("*_preprocessor.pkl"):
            model_name = preprocessor_file.stem.replace("_preprocessor", "")
            try:
                with open(preprocessor_file, 'rb') as f:
                    preprocessor = pickle.load(f)
                
                # Determine if it's a vectorizer or scaler
                if hasattr(preprocessor, 'transform') and hasattr(preprocessor, 'get_feature_names_out'):
                    self.vectorizers[model_name] = preprocessor
                    print(f"✅ Loaded vectorizer: {model_name}")
                else:
                    self.scalers[model_name] = preprocessor
                    print(f"✅ Loaded scaler: {model_name}")
            except Exception as e:
                print(f"❌ Error loading preprocessor {model_name}: {e}")
        
        return len(self.models) > 0
    
    def test_text_model(self, model_name):
        """Test text-based model"""
        if model_name not in self.models:
            print(f"⚠️  Model {model_name} not found")
            return
        
        print(f"\n📝 Testing Text Model: {model_name}")
        
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
        
        model = self.models[model_name]
        vectorizer = self.vectorizers.get(model_name)
        
        if vectorizer:
            # Vectorize test messages
            X_test = vectorizer.transform(test_messages)
            predictions = model.predict(X_test)
            probabilities = model.predict_proba(X_test)
            
            for i, message in enumerate(test_messages):
                pred = "POSITIVE" if predictions[i] == 1 else "NEGATIVE"
                # Handle single-class models (only one probability value)
                if probabilities[i].shape[0] == 1:
                    prob = probabilities[i][0]
                else:
                    prob = probabilities[i][1] if predictions[i] == 1 else probabilities[i][0]
                print(f"   '{message[:50]}...' -> {pred} ({prob:.3f})")
        else:
            print("⚠️  Vectorizer not found for text model")
    
    def test_tabular_model(self, model_name):
        """Test tabular model"""
        if model_name not in self.models:
            print(f"⚠️  Model {model_name} not found")
            return
        
        print(f"\n📊 Testing Tabular Model: {model_name}")
        
        model = self.models[model_name]
        scaler = self.scalers.get(model_name)
        
        # Get feature count from model
        if hasattr(model, 'n_features_in_'):
            n_features = model.n_features_in_
        else:
            n_features = 10  # Default fallback
        
        # Create test samples
        test_samples = np.random.rand(5, n_features)
        
        if scaler:
            test_samples = scaler.transform(test_samples)
        
        predictions = model.predict(test_samples)
        probabilities = model.predict_proba(test_samples)
        
        for i in range(len(test_samples)):
            pred = "POSITIVE" if predictions[i] == 1 else "NEGATIVE"
            # Handle single-class models (only one probability value)
            if probabilities[i].shape[0] == 1:
                prob = probabilities[i][0]
            else:
                prob = probabilities[i][1] if predictions[i] == 1 else probabilities[i][0]
            print(f"   Sample {i+1}: {pred} ({prob:.3f})")
    
    def test_specific_models(self):
        """Test specific model types"""
        # Test SMS spam model
        if 'sms_spam' in self.models:
            self.test_text_model('sms_spam')
        
        # Test other text models
        for model_name in self.models:
            if model_name.startswith('text_'):
                self.test_text_model(model_name)
        
        # Test tabular models
        for model_name in self.models:
            if model_name.startswith('tabular_') or model_name.startswith('arff_'):
                self.test_tabular_model(model_name)
    
    def run_comprehensive_tests(self):
        """Run comprehensive tests on all models"""
        print("🚀 Starting Comprehensive Model Tests...")
        
        if not self.load_all_models():
            return
        
        print(f"\n{'='*60}")
        print("🧪 TESTING ALL MODELS")
        print(f"{'='*60}")
        
        # Test each model based on its type
        for model_name in self.models:
            print(f"\n--- Testing {model_name} ---")
            
            if model_name in self.vectorizers:
                # Text model
                self.test_text_model(model_name)
            elif model_name in self.scalers:
                # Tabular model
                self.test_tabular_model(model_name)
            else:
                # Try to determine type from model name
                if 'sms' in model_name.lower() or 'text' in model_name.lower():
                    self.test_text_model(model_name)
                else:
                    self.test_tabular_model(model_name)
        
        print(f"\n{'='*60}")
        print("✅ ALL MODEL TESTS COMPLETED!")
        print(f"{'='*60}")
        
        # Print summary
        print(f"\n📊 Test Summary:")
        print(f"   Total Models: {len(self.models)}")
        print(f"   Text Models: {len(self.vectorizers)}")
        print(f"   Tabular Models: {len(self.scalers)}")
        
        # Show model details
        summary_path = self.models_dir / "comprehensive_model_summary.json"
        if summary_path.exists():
            with open(summary_path, 'r') as f:
                summary = json.load(f)
            
            print(f"\n🎯 Model Details:")
            for model_name, info in summary['models'].items():
                print(f"   {model_name}:")
                print(f"      Type: {info['type']}")
                print(f"      Algorithm: {info['algorithm']}")
                print(f"      Accuracy: {info['accuracy']:.4f}")
                print(f"      Samples: {info['samples']}")

def main():
    """Main function"""
    tester = AllModelTester()
    tester.run_comprehensive_tests()

if __name__ == '__main__':
    main() 