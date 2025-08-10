#!/usr/bin/env python3
"""
Comprehensive ML Model Training from Raw Datasets
Processes all datasets in the datasets/ folder and trains separate models
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import pickle
import json
from datetime import datetime

# Add project path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
import django
django.setup()

from dashboard.models import Alert

class DatasetProcessor:
    def __init__(self):
        self.datasets_dir = Path("datasets")
        self.models_dir = Path("trained_models")
        self.models_dir.mkdir(exist_ok=True)
        
        # Store trained models
        self.models = {}
        self.vectorizers = {}
        self.model_info = {}
        
        print("🔧 Dataset Processor initialized")
    
    def process_sms_spam_dataset(self):
        """Process SMS spam collection dataset"""
        print("📱 Processing SMS Spam Collection dataset...")
        
        sms_file = self.datasets_dir / "SMSSpamCollection"
        if not sms_file.exists():
            print("⚠️  SMS Spam Collection file not found")
            return None
        
        try:
            # Read SMS dataset (tab-separated: label, message)
            data = []
            with open(sms_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Split by tab or first space
                        parts = line.split('\t', 1)
                        if len(parts) == 2:
                            label, message = parts
                        else:
                            # Try splitting by first space
                            parts = line.split(' ', 1)
                            if len(parts) == 2:
                                label, message = parts
                            else:
                                continue
                        
                        # Clean label
                        label = label.lower().strip()
                        if label in ['spam', 'ham']:
                            data.append({
                                'label': 1 if label == 'spam' else 0,
                                'message': message.strip()
                            })
            
            if data:
                df = pd.DataFrame(data)
                print(f"✅ SMS dataset processed: {len(df)} messages")
                print(f"   Spam: {len(df[df['label'] == 1])}")
                print(f"   Ham: {len(df[df['label'] == 0])}")
                return df
            else:
                print("⚠️  No valid data found in SMS dataset")
                return None
                
        except Exception as e:
            print(f"❌ Error processing SMS dataset: {e}")
            return None
    
    def process_phishing_websites_dataset(self):
        """Process phishing websites dataset"""
        print("🌐 Processing Phishing Websites dataset...")
        
        # Try different possible files
        possible_files = [
            "verified_online.csv",
            "Phishing Websites Features.docx",
            "Training Dataset.arff"
        ]
        
        for filename in possible_files:
            file_path = self.datasets_dir / filename
            if file_path.exists():
                print(f"📄 Found dataset file: {filename}")
                
                if filename.endswith('.csv'):
                    return self.process_csv_phishing(file_path)
                elif filename.endswith('.arff'):
                    return self.process_arff_phishing(file_path)
                elif filename.endswith('.docx'):
                    print("⚠️  DOCX files not supported yet - skipping")
                    continue
        
        print("⚠️  No supported phishing dataset files found")
        return None
    
    def process_csv_phishing(self, file_path):
        """Process CSV phishing dataset"""
        try:
            df = pd.read_csv(file_path)
            print(f"✅ CSV dataset loaded: {df.shape}")
            print(f"   Columns: {list(df.columns)}")
            
            # Look for common phishing dataset columns
            label_columns = ['label', 'class', 'target', 'result', 'phishing', 'type']
            feature_columns = []
            
            for col in df.columns:
                if col.lower() in label_columns:
                    label_col = col
                elif col.lower() not in ['url', 'domain', 'id', 'index', 'phish_id']:
                    feature_columns.append(col)
            
            if 'label_col' in locals() and feature_columns:
                print(f"   Label column: {label_col}")
                print(f"   Feature columns: {feature_columns}")
                
                # Convert labels to binary
                df['label'] = df[label_col].astype(str).str.lower()
                df['label'] = (df['label'].isin(['1', 'true', 'phishing', 'malicious', 'bad', '-1'])).astype(int)
                
                # Select features and label
                final_df = df[feature_columns + ['label']].copy()
                
                # Convert all features to numeric, handling string values
                for col in feature_columns:
                    try:
                        final_df[col] = pd.to_numeric(final_df[col], errors='coerce')
                    except:
                        # If conversion fails, try to extract numeric values
                        final_df[col] = final_df[col].astype(str).str.extract('(\d+)').astype(float)
                
                # Fill NaN values with 0
                final_df = final_df.fillna(0)
                
                print(f"✅ Phishing dataset processed: {len(final_df)} samples")
                print(f"   Phishing: {len(final_df[final_df['label'] == 1])}")
                print(f"   Legitimate: {len(final_df[final_df['label'] == 0])}")
                print(f"   Features: {len(feature_columns)}")
                
                return final_df
            else:
                print(f"⚠️  Could not identify label column or features")
                print(f"   Available columns: {list(df.columns)}")
                return None
            
        except Exception as e:
            print(f"❌ Error processing CSV phishing dataset: {e}")
            import traceback
            traceback.print_exc()
        
        return None
    
    def process_arff_phishing(self, file_path):
        """Process ARFF phishing dataset"""
        try:
            # Simple ARFF parser
            data_section = False
            data_lines = []
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.lower().startswith('@data'):
                        data_section = True
                        continue
                    elif line.startswith('@'):
                        continue
                    
                    if data_section and line:
                        data_lines.append(line)
            
            if data_lines:
                # Parse data lines
                parsed_data = []
                for line in data_lines:
                    values = line.split(',')
                    # Assume last column is label
                    features = [float(x) if x.replace('.', '').replace('-', '').isdigit() else 0 
                              for x in values[:-1]]
                    label = 1 if values[-1].lower() in ['1', 'true', 'phishing', 'malicious'] else 0
                    parsed_data.append(features + [label])
                
                # Create DataFrame
                feature_names = [f'feature_{i}' for i in range(len(parsed_data[0]) - 1)]
                df = pd.DataFrame(parsed_data, columns=feature_names + ['label'])
                
                print(f"✅ ARFF dataset processed: {len(df)} samples")
                print(f"   Phishing: {len(df[df['label'] == 1])}")
                print(f"   Legitimate: {len(df[df['label'] == 0])}")
                print(f"   Features: {len(feature_names)}")
                
                return df
                
        except Exception as e:
            print(f"❌ Error processing ARFF dataset: {e}")
        
        return None
    
    def train_text_model(self, df, model_name, text_column='message'):
        """Train model for text-based classification (SMS spam)"""
        print(f"🤖 Training {model_name} model...")
        
        # Prepare data
        X = df[text_column]
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Vectorize text
        vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        X_train_vec = vectorizer.fit_transform(X_train)
        X_test_vec = vectorizer.transform(X_test)
        
        # Train multiple models
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
            'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000),
            'NaiveBayes': MultinomialNB()
        }
        
        best_model = None
        best_score = 0
        best_model_name = None
        
        for name, model in models.items():
            model.fit(X_train_vec, y_train)
            y_pred = model.predict(X_test_vec)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"   {name}: {accuracy:.4f}")
            
            if accuracy > best_score:
                best_score = accuracy
                best_model = model
                best_model_name = name
        
        # Save best model
        model_path = self.models_dir / f"{model_name}_{best_model_name}.pkl"
        vectorizer_path = self.models_dir / f"{model_name}_vectorizer.pkl"
        
        with open(model_path, 'wb') as f:
            pickle.dump(best_model, f)
        
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f)
        
        # Store model info
        self.models[model_name] = best_model
        self.vectorizers[model_name] = vectorizer
        self.model_info[model_name] = {
            'type': 'text',
            'algorithm': best_model_name,
            'accuracy': best_score,
            'features': len(vectorizer.get_feature_names_out()),
            'samples': len(df),
            'trained_at': datetime.now().isoformat()
        }
        
        print(f"✅ {model_name} model saved: {best_score:.4f} accuracy")
        return best_score
    
    def train_tabular_model(self, df, model_name):
        """Train model for tabular data (phishing websites)"""
        print(f"🤖 Training {model_name} model...")
        
        # Prepare data
        feature_columns = [col for col in df.columns if col != 'label']
        X = df[feature_columns]
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train multiple models
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
            'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000)
        }
        
        best_model = None
        best_score = 0
        best_model_name = None
        
        for name, model in models.items():
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"   {name}: {accuracy:.4f}")
            
            if accuracy > best_score:
                best_score = accuracy
                best_model = model
                best_model_name = name
        
        # Save best model
        model_path = self.models_dir / f"{model_name}_{best_model_name}.pkl"
        
        with open(model_path, 'wb') as f:
            pickle.dump(best_model, f)
        
        # Store model info
        self.models[model_name] = best_model
        self.model_info[model_name] = {
            'type': 'tabular',
            'algorithm': best_model_name,
            'accuracy': best_score,
            'features': len(feature_columns),
            'feature_names': feature_columns,
            'samples': len(df),
            'trained_at': datetime.now().isoformat()
        }
        
        print(f"✅ {model_name} model saved: {best_score:.4f} accuracy")
        return best_score
    
    def save_model_summary(self):
        """Save summary of all trained models"""
        summary = {
            'total_models': len(self.model_info),
            'models': self.model_info,
            'trained_at': datetime.now().isoformat()
        }
        
        summary_path = self.models_dir / "model_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"✅ Model summary saved to {summary_path}")
    
    def process_all_datasets(self):
        """Process all datasets and train models"""
        print("🚀 Starting comprehensive dataset processing and model training...")
        
        # Process SMS spam dataset
        sms_df = self.process_sms_spam_dataset()
        if sms_df is not None and len(sms_df) > 100:
            self.train_text_model(sms_df, 'sms_spam')
        
        # Process phishing websites dataset
        phishing_df = self.process_phishing_websites_dataset()
        if phishing_df is not None and len(phishing_df) > 100:
            # Check if we have both classes
            unique_labels = phishing_df['label'].unique()
            if len(unique_labels) >= 2:
                self.train_tabular_model(phishing_df, 'phishing_websites')
            else:
                print(f"⚠️  Phishing dataset has only one class: {unique_labels}")
                print("   Need at least 2 classes (phishing and legitimate) for training")
        elif phishing_df is not None:
            print(f"⚠️  Phishing dataset too small: {len(phishing_df)} samples (need > 100)")
        
        # Save model summary
        if self.model_info:
            self.save_model_summary()
            
            print("\n🎉 Model Training Summary:")
            for model_name, info in self.model_info.items():
                print(f"   {model_name}: {info['algorithm']} - {info['accuracy']:.4f} accuracy")
                print(f"      Samples: {info['samples']}, Features: {info['features']}")
        else:
            print("⚠️  No models were trained - check your datasets")

def main():
    """Main function"""
    processor = DatasetProcessor()
    processor.process_all_datasets()

if __name__ == '__main__':
    main() 