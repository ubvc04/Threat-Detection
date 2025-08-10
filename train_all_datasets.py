#!/usr/bin/env python3
"""
Comprehensive ML Model Training for All Datasets
Processes ALL files in datasets/ folder and trains separate models for each
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
import re
import json
import pickle
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB, GaussianNB
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer

# Add project path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
import django
django.setup()

from dashboard.models import Alert

class ComprehensiveDatasetTrainer:
    def __init__(self):
        self.datasets_dir = Path("datasets")
        self.models_dir = Path("trained_models")
        self.models_dir.mkdir(exist_ok=True)
        
        # Store all trained models
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.label_encoders = {}
        self.model_info = {}
        
        print("🔧 Comprehensive Dataset Trainer initialized")
    
    def scan_datasets_folder(self):
        """Scan datasets folder and identify all files"""
        print("📁 Scanning datasets folder...")
        
        dataset_files = []
        for file_path in self.datasets_dir.glob("*"):
            if file_path.is_file():
                dataset_files.append(file_path)
                print(f"   Found: {file_path.name}")
        
        return dataset_files
    
    def process_sms_spam_dataset(self, file_path):
        """Process SMS spam collection dataset"""
        print(f"📱 Processing SMS dataset: {file_path.name}")
        
        try:
            data = []
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Split by tab or first space
                        parts = line.split('\t', 1)
                        if len(parts) == 2:
                            label, message = parts
                        else:
                            parts = line.split(' ', 1)
                            if len(parts) == 2:
                                label, message = parts
                            else:
                                continue
                        
                        label = label.lower().strip()
                        if label in ['spam', 'ham']:
                            data.append({
                                'label': 1 if label == 'spam' else 0,
                                'message': message.strip()
                            })
            
            if data:
                df = pd.DataFrame(data)
                print(f"✅ SMS dataset: {len(df)} messages")
                print(f"   Spam: {len(df[df['label'] == 1])}, Ham: {len(df[df['label'] == 0])}")
                return df, 'text'
            else:
                print("⚠️  No valid SMS data found")
                return None, None
                
        except Exception as e:
            print(f"❌ Error processing SMS dataset: {e}")
            return None, None
    
    def process_csv_dataset(self, file_path):
        """Process CSV datasets"""
        print(f"📊 Processing CSV dataset: {file_path.name}")
        
        try:
            df = pd.read_csv(file_path)
            print(f"✅ CSV loaded: {df.shape}")
            print(f"   Columns: {list(df.columns)}")
            
            # Analyze the dataset structure
            data_type = self.analyze_csv_structure(df)
            
            if data_type == 'text':
                return self.process_text_csv(df, file_path.name)
            elif data_type == 'tabular':
                return self.process_tabular_csv(df, file_path.name)
            else:
                print(f"⚠️  Unknown CSV structure for {file_path.name}")
                return None, None
                
        except Exception as e:
            print(f"❌ Error processing CSV: {e}")
            return None, None
    
    def analyze_csv_structure(self, df):
        """Analyze CSV structure to determine data type"""
        # Check if it's text-based (has text columns)
        text_columns = []
        numeric_columns = []
        
        for col in df.columns:
            if df[col].dtype == 'object':
                # Check if it's mostly text
                sample_values = df[col].dropna().head(10).astype(str)
                avg_length = sample_values.str.len().mean()
                if avg_length > 20:  # Likely text data
                    text_columns.append(col)
            else:
                numeric_columns.append(col)
        
        if len(text_columns) > 0 and len(text_columns) <= 2:
            return 'text'
        elif len(numeric_columns) > 2:
            return 'tabular'
        else:
            return 'unknown'
    
    def process_text_csv(self, df, filename):
        """Process text-based CSV data"""
        print(f"📝 Processing as text data: {filename}")
        
        # Look for text and label columns
        text_col = None
        label_col = None
        
        for col in df.columns:
            if df[col].dtype == 'object':
                if text_col is None:
                    text_col = col
                elif label_col is None:
                    label_col = col
        
        if text_col and label_col:
            # Create binary labels
            df['label'] = df[label_col].astype(str).str.lower()
            df['label'] = (df['label'].isin(['1', 'true', 'spam', 'phishing', 'malicious', 'bad'])).astype(int)
            
            final_df = df[[text_col, 'label']].copy()
            final_df = final_df.rename(columns={text_col: 'text'})
            final_df = final_df.dropna()
            
            print(f"✅ Text dataset: {len(final_df)} samples")
            print(f"   Positive: {len(final_df[final_df['label'] == 1])}")
            print(f"   Negative: {len(final_df[final_df['label'] == 0])}")
            
            return final_df, 'text'
        
        return None, None
    
    def process_tabular_csv(self, df, filename):
        """Process tabular CSV data"""
        print(f"📊 Processing as tabular data: {filename}")
        
        # Look for label column
        label_columns = ['label', 'class', 'target', 'result', 'phishing', 'type', 'category']
        label_col = None
        
        for col in df.columns:
            if col.lower() in label_columns:
                label_col = col
                break
        
        if label_col:
            # Convert labels to numeric
            df['label'] = df[label_col].astype(str).str.lower()
            df['label'] = (df['label'].isin(['1', 'true', 'spam', 'phishing', 'malicious', 'bad'])).astype(int)
            
            # Select numeric features
            feature_columns = []
            for col in df.columns:
                if col != 'label' and col != label_col:
                    if df[col].dtype in ['int64', 'float64']:
                        feature_columns.append(col)
                    else:
                        # Try to convert to numeric
                        try:
                            df[col] = pd.to_numeric(df[col], errors='coerce')
                            feature_columns.append(col)
                        except:
                            continue
            
            if feature_columns:
                final_df = df[feature_columns + ['label']].copy()
                final_df = final_df.dropna()
                
                print(f"✅ Tabular dataset: {len(final_df)} samples")
                print(f"   Features: {len(feature_columns)}")
                print(f"   Positive: {len(final_df[final_df['label'] == 1])}")
                print(f"   Negative: {len(final_df[final_df['label'] == 0])}")
                
                return final_df, 'tabular'
        
        return None, None
    
    def process_arff_dataset(self, file_path):
        """Process ARFF dataset"""
        print(f"📄 Processing ARFF dataset: {file_path.name}")
        
        try:
            # Simple ARFF parser
            data_section = False
            data_lines = []
            attributes = []
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.lower().startswith('@attribute'):
                        # Parse attribute
                        parts = line.split()
                        if len(parts) >= 3:
                            attr_name = parts[1]
                            attr_type = parts[2].lower()
                            attributes.append((attr_name, attr_type))
                    elif line.lower().startswith('@data'):
                        data_section = True
                        continue
                    elif line.startswith('@'):
                        continue
                    
                    if data_section and line:
                        data_lines.append(line)
            
            if data_lines and attributes:
                # Parse data
                parsed_data = []
                for line in data_lines:
                    values = line.split(',')
                    if len(values) == len(attributes):
                        # Convert values based on attribute types
                        row = []
                        for i, (attr_name, attr_type) in enumerate(attributes):
                            if attr_type in ['numeric', 'real', 'integer']:
                                try:
                                    row.append(float(values[i]))
                                except:
                                    row.append(0.0)
                            else:
                                # Categorical - convert to numeric
                                row.append(hash(values[i]) % 1000)  # Simple hash
                        parsed_data.append(row)
                
                if parsed_data:
                    # Create DataFrame
                    feature_names = [attr[0] for attr in attributes[:-1]]  # Last is label
                    df = pd.DataFrame(parsed_data, columns=feature_names + ['label'])
                    
                    # Convert label to binary
                    df['label'] = (df['label'] > 500).astype(int)  # Simple threshold
                    
                    print(f"✅ ARFF dataset: {len(df)} samples")
                    print(f"   Features: {len(feature_names)}")
                    print(f"   Positive: {len(df[df['label'] == 1])}")
                    print(f"   Negative: {len(df[df['label'] == 0])}")
                    
                    return df, 'tabular'
            
            print("⚠️  Could not parse ARFF file")
            return None, None
            
        except Exception as e:
            print(f"❌ Error processing ARFF: {e}")
            return None, None
    
    def train_text_model(self, df, model_name):
        """Train model for text classification"""
        print(f"🤖 Training text model: {model_name}")
        
        # Prepare data
        X = df['text'] if 'text' in df.columns else df.iloc[:, 0]
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
            'NaiveBayes': MultinomialNB(),
            'SVM': SVC(kernel='linear', random_state=42)
        }
        
        best_model, best_score, best_name = self.train_and_evaluate_models(
            models, X_train_vec, X_test_vec, y_train, y_test
        )
        
        # Save model
        self.save_model(best_model, vectorizer, model_name, best_name, 'text', best_score, len(df))
        
        return best_score
    
    def train_tabular_model(self, df, model_name):
        """Train model for tabular data"""
        print(f"🤖 Training tabular model: {model_name}")
        
        # Prepare data
        feature_columns = [col for col in df.columns if col != 'label']
        X = df[feature_columns]
        y = df['label']
        
        # Handle missing values
        imputer = SimpleImputer(strategy='mean')
        X = pd.DataFrame(imputer.fit_transform(X), columns=feature_columns)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train multiple models
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
            'GradientBoosting': GradientBoostingClassifier(random_state=42),
            'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000),
            'SVM': SVC(kernel='rbf', random_state=42)
        }
        
        best_model, best_score, best_name = self.train_and_evaluate_models(
            models, X_train_scaled, X_test_scaled, y_train, y_test
        )
        
        # Save model
        self.save_model(best_model, scaler, model_name, best_name, 'tabular', best_score, len(df))
        
        return best_score
    
    def train_and_evaluate_models(self, models, X_train, X_test, y_train, y_test):
        """Train and evaluate multiple models"""
        best_model = None
        best_score = 0
        best_name = None
        
        for name, model in models.items():
            try:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                
                print(f"   {name}: {accuracy:.4f}")
                
                if accuracy > best_score:
                    best_score = accuracy
                    best_model = model
                    best_name = name
            except Exception as e:
                print(f"   {name}: Error - {e}")
        
        return best_model, best_score, best_name
    
    def save_model(self, model, preprocessor, model_name, algorithm, data_type, accuracy, samples):
        """Save trained model and metadata"""
        # Save model
        model_path = self.models_dir / f"{model_name}_{algorithm}.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Save preprocessor
        preprocessor_path = self.models_dir / f"{model_name}_preprocessor.pkl"
        with open(preprocessor_path, 'wb') as f:
            pickle.dump(preprocessor, f)
        
        # Store info
        self.models[model_name] = model
        if data_type == 'text':
            self.vectorizers[model_name] = preprocessor
        else:
            self.scalers[model_name] = preprocessor
        
        self.model_info[model_name] = {
            'type': data_type,
            'algorithm': algorithm,
            'accuracy': accuracy,
            'samples': samples,
            'trained_at': datetime.now().isoformat()
        }
        
        print(f"✅ {model_name} model saved: {accuracy:.4f} accuracy")
    
    def save_comprehensive_summary(self):
        """Save comprehensive model summary"""
        summary = {
            'total_models': len(self.model_info),
            'models': self.model_info,
            'trained_at': datetime.now().isoformat(),
            'dataset_files_processed': list(self.datasets_dir.glob("*"))
        }
        
        summary_path = self.models_dir / "comprehensive_model_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        print(f"✅ Comprehensive summary saved to {summary_path}")
    
    def process_all_datasets(self):
        """Process all datasets and train models"""
        print("🚀 Starting comprehensive dataset processing and training...")
        
        # Scan for all dataset files
        dataset_files = self.scan_datasets_folder()
        
        if not dataset_files:
            print("⚠️  No dataset files found in datasets/ folder")
            return
        
        # Process each file
        for file_path in dataset_files:
            print(f"\n{'='*60}")
            print(f"Processing: {file_path.name}")
            print(f"{'='*60}")
            
            try:
                if file_path.name.lower() == 'smsspamcollection':
                    df, data_type = self.process_sms_spam_dataset(file_path)
                    if df is not None:
                        self.train_text_model(df, 'sms_spam')
                
                elif file_path.suffix.lower() == '.csv':
                    df, data_type = self.process_csv_dataset(file_path)
                    if df is not None and data_type:
                        if data_type == 'text':
                            self.train_text_model(df, f"text_{file_path.stem}")
                        elif data_type == 'tabular':
                            self.train_tabular_model(df, f"tabular_{file_path.stem}")
                
                elif file_path.suffix.lower() == '.arff':
                    df, data_type = self.process_arff_dataset(file_path)
                    if df is not None:
                        self.train_tabular_model(df, f"arff_{file_path.stem}")
                
                else:
                    print(f"⚠️  Unsupported file type: {file_path.suffix}")
                    
            except Exception as e:
                print(f"❌ Error processing {file_path.name}: {e}")
                continue
        
        # Save comprehensive summary
        if self.model_info:
            self.save_comprehensive_summary()
            
            print(f"\n{'='*60}")
            print("🎉 COMPREHENSIVE TRAINING SUMMARY")
            print(f"{'='*60}")
            for model_name, info in self.model_info.items():
                print(f"   {model_name}:")
                print(f"      Type: {info['type']}")
                print(f"      Algorithm: {info['algorithm']}")
                print(f"      Accuracy: {info['accuracy']:.4f}")
                print(f"      Samples: {info['samples']}")
                print()
        else:
            print("⚠️  No models were trained successfully")

def main():
    """Main function"""
    trainer = ComprehensiveDatasetTrainer()
    trainer.process_all_datasets()

if __name__ == '__main__':
    main() 