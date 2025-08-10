#!/usr/bin/env python3
"""
AI-Powered Behavioral Anomaly Detection System
Detects unknown malware (zero-day) by modeling baseline system behavior
"""

import os
import sys
import time
import threading
import json
import numpy as np
import pandas as pd
from datetime import datetime
from collections import deque
import pickle
from pathlib import Path

# Add project path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
import django
django.setup()

from dashboard.models import Alert

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    print("⚠️  Scikit-learn not available")
    SKLEARN_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
    TENSORFLOW_AVAILABLE = True
except ImportError:
    print("⚠️  TensorFlow not available")
    TENSORFLOW_AVAILABLE = False

import psutil

class AIBehavioralDetection:
    def __init__(self):
        self.running = False
        self.models_dir = Path("ai_models")
        self.models_dir.mkdir(exist_ok=True)
        
        # Data collection buffers
        self.behavioral_sequences = deque(maxlen=1000)
        
        # AI Models
        self.isolation_forest = None
        self.lstm_model = None
        self.autoencoder = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        
        # Detection settings
        self.anomaly_threshold = 0.8
        self.sequence_length = 50
        self.is_trained = False
        
        print("🧠 AI-Powered Behavioral Anomaly Detection initialized")
    
    def collect_behavioral_data(self):
        """Collect comprehensive behavioral data"""
        try:
            # Process behavior
            processes = psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads'])
            process_data = []
            
            for proc in processes:
                try:
                    info = proc.info
                    process_data.append({
                        'cpu_percent': info['cpu_percent'],
                        'memory_percent': info['memory_percent'],
                        'num_threads': info['num_threads']
                    })
                except:
                    continue
            
            # Network behavior
            connections = psutil.net_connections()
            network_data = {
                'total_connections': len(connections),
                'established': len([c for c in connections if c.status == 'ESTABLISHED']),
                'external_ips': len(set([c.raddr.ip for c in connections if c.raddr]))
            }
            
            # System behavior
            system_data = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            }
            
            # Combine all behavioral data
            behavioral_point = {
                'process_count': len(process_data),
                'avg_cpu': np.mean([p['cpu_percent'] for p in process_data]) if process_data else 0,
                'avg_memory': np.mean([p['memory_percent'] for p in process_data]) if process_data else 0,
                'avg_threads': np.mean([p['num_threads'] for p in process_data]) if process_data else 0,
                'high_cpu_processes': len([p for p in process_data if p['cpu_percent'] > 50]),
                'high_memory_processes': len([p for p in process_data if p['memory_percent'] > 10]),
                'total_connections': network_data['total_connections'],
                'established_connections': network_data['established'],
                'external_ips': network_data['external_ips'],
                'system_cpu': system_data['cpu_percent'],
                'system_memory': system_data['memory_percent'],
                'system_disk': system_data['disk_percent']
            }
            
            self.behavioral_sequences.append(behavioral_point)
            return behavioral_point
            
        except Exception as e:
            print(f"⚠️  Behavioral data collection error: {e}")
            return {}
    
    def train_models(self):
        """Train AI models on collected behavioral data"""
        print("🧠 Training AI models...")
        
        if len(self.behavioral_sequences) < 100:
            print("⚠️  Need at least 100 data points for training")
            return False
        
        # Prepare training data
        data = list(self.behavioral_sequences)
        df = pd.DataFrame(data)
        df = df.fillna(0)
        
        if self.scaler:
            scaled_data = self.scaler.fit_transform(df)
        else:
            scaled_data = df.values
        
        # Train Isolation Forest
        if SKLEARN_AVAILABLE:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            self.isolation_forest.fit(scaled_data)
            print("✅ Isolation Forest trained")
        
        # Train Autoencoder
        if TENSORFLOW_AVAILABLE:
            input_dim = scaled_data.shape[1]
            encoding_dim = max(8, input_dim // 4)
            
            input_layer = Input(shape=(input_dim,))
            encoded = Dense(encoding_dim * 2, activation='relu')(input_layer)
            encoded = Dense(encoding_dim, activation='relu')(encoded)
            decoded = Dense(encoding_dim * 2, activation='relu')(encoded)
            decoded = Dense(input_dim, activation='sigmoid')(decoded)
            
            self.autoencoder = Model(input_layer, decoded)
            self.autoencoder.compile(optimizer='adam', loss='mse')
            self.autoencoder.fit(scaled_data, scaled_data, epochs=10, batch_size=32, verbose=0)
            print("✅ Autoencoder trained")
        
        self.is_trained = True
        self.save_models()
        print(f"✅ AI models trained on {len(data)} data points")
        return True
    
    def detect_anomalies(self, current_data):
        """Detect behavioral anomalies"""
        if not self.is_trained:
            return []
        
        anomalies = []
        
        try:
            # Prepare current data
            if self.scaler:
                scaled_data = self.scaler.transform([current_data])
            else:
                scaled_data = np.array([current_data])
            
            # Isolation Forest detection
            if self.isolation_forest:
                if_prediction = self.isolation_forest.predict(scaled_data)[0]
                if_score = self.isolation_forest.decision_function(scaled_data)[0]
                
                if if_prediction == -1:
                    anomalies.append({
                        'model': 'Isolation Forest',
                        'score': if_score,
                        'severity': 'HIGH' if abs(if_score) > 0.5 else 'MEDIUM'
                    })
            
            # Autoencoder detection
            if self.autoencoder:
                reconstructed = self.autoencoder.predict(scaled_data, verbose=0)
                reconstruction_error = np.mean(np.square(scaled_data - reconstructed))
                
                if reconstruction_error > self.anomaly_threshold:
                    anomalies.append({
                        'model': 'Autoencoder',
                        'score': reconstruction_error,
                        'severity': 'HIGH' if reconstruction_error > 1.0 else 'MEDIUM'
                    })
            
        except Exception as e:
            print(f"⚠️  Anomaly detection error: {e}")
        
        return anomalies
    
    def create_ai_alert(self, anomaly_data):
        """Create alert for AI-detected anomalies"""
        try:
            model_name = anomaly_data['model']
            score = anomaly_data['score']
            severity = anomaly_data['severity']
            
            message = f"AI Behavioral Anomaly: {model_name} detected suspicious behavior (score: {score:.3f})"
            
            Alert.objects.create(
                alert_type='AI_BEHAVIORAL',
                severity=severity,
                message=message,
                source=f'AI {model_name}',
                details={
                    'model': model_name,
                    'anomaly_score': score,
                    'detection_method': 'behavioral_analysis',
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            print(f"🚨 AI Alert: {model_name} - {message}")
            
        except Exception as e:
            print(f"❌ Error creating AI alert: {e}")
    
    def save_models(self):
        """Save trained models"""
        try:
            if self.isolation_forest:
                with open(self.models_dir / 'isolation_forest.pkl', 'wb') as f:
                    pickle.dump(self.isolation_forest, f)
            
            if self.autoencoder:
                self.autoencoder.save(self.models_dir / 'autoencoder.h5')
            
            if self.scaler:
                with open(self.models_dir / 'scaler.pkl', 'wb') as f:
                    pickle.dump(self.scaler, f)
            
            print("✅ AI models saved")
            
        except Exception as e:
            print(f"⚠️  Model saving error: {e}")
    
    def load_models(self):
        """Load trained models"""
        try:
            if (self.models_dir / 'isolation_forest.pkl').exists():
                with open(self.models_dir / 'isolation_forest.pkl', 'rb') as f:
                    self.isolation_forest = pickle.load(f)
            
            if (self.models_dir / 'autoencoder.h5').exists() and TENSORFLOW_AVAILABLE:
                self.autoencoder = tf.keras.models.load_model(self.models_dir / 'autoencoder.h5')
            
            if (self.models_dir / 'scaler.pkl').exists():
                with open(self.models_dir / 'scaler.pkl', 'rb') as f:
                    self.scaler = pickle.load(f)
            
            self.is_trained = any([self.isolation_forest, self.autoencoder])
            
            if self.is_trained:
                print("✅ AI models loaded")
            else:
                print("⚠️  No trained models found")
            
        except Exception as e:
            print(f"⚠️  Model loading error: {e}")
    
    def start_ai_monitoring(self):
        """Start AI behavioral monitoring"""
        if self.running:
            print("⚠️  AI monitoring already running")
            return
        
        print("🧠 Starting AI Behavioral Monitoring...")
        self.running = True
        
        # Load or train models
        self.load_models()
        
        if not self.is_trained:
            print("⚠️  Training AI models...")
            for _ in range(100):
                self.collect_behavioral_data()
                time.sleep(5)
            self.train_models()
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=self.ai_monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        print("✅ AI behavioral monitoring started")
    
    def ai_monitoring_loop(self):
        """Main AI monitoring loop"""
        while self.running:
            try:
                current_data = self.collect_behavioral_data()
                
                if current_data:
                    anomalies = self.detect_anomalies(current_data)
                    
                    for anomaly in anomalies:
                        self.create_ai_alert(anomaly)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"⚠️  AI monitoring error: {e}")
                time.sleep(60)
    
    def stop_ai_monitoring(self):
        """Stop AI monitoring"""
        if not self.running:
            print("⚠️  AI monitoring not running")
            return
        
        print("🛑 Stopping AI Behavioral Monitoring...")
        self.running = False
        print("✅ AI behavioral monitoring stopped")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Behavioral Anomaly Detection')
    parser.add_argument('action', choices=['start', 'stop', 'train', 'demo'], 
                       help='Action to perform')
    
    args = parser.parse_args()
    
    ai_detection = AIBehavioralDetection()
    
    if args.action == 'start':
        ai_detection.start_ai_monitoring()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Received interrupt signal")
            ai_detection.stop_ai_monitoring()
    
    elif args.action == 'stop':
        ai_detection.stop_ai_monitoring()
    
    elif args.action == 'train':
        print("🧠 Training AI models...")
        for _ in range(100):
            ai_detection.collect_behavioral_data()
            time.sleep(5)
        ai_detection.train_models()
    
    elif args.action == 'demo':
        print("🎭 Running AI Behavioral Demo...")
        
        sample_anomalies = [
            {'model': 'Isolation Forest', 'score': -0.85, 'severity': 'HIGH'},
            {'model': 'Autoencoder', 'score': 1.25, 'severity': 'HIGH'},
        ]
        
        for anomaly in sample_anomalies:
            ai_detection.create_ai_alert(anomaly)
            time.sleep(2)
        
        print("✅ AI behavioral demo completed!")

if __name__ == '__main__':
    main() 