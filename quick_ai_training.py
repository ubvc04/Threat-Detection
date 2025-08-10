#!/usr/bin/env python3
"""
Quick AI Behavioral Detection Training
Faster training with real-time progress display
"""

import time
import os
from pathlib import Path
from ai_behavioral_detection import AIBehavioralDetection

def quick_ai_training():
    """Quick AI training with progress display"""
    print("🚀 Quick AI Training Started")
    print("=" * 50)
    
    # Initialize AI system
    ai = AIBehavioralDetection()
    
    print(f"📊 Initial State:")
    print(f"   Models directory: {ai.models_dir.exists()}")
    print(f"   Is trained: {ai.is_trained}")
    print(f"   Sequences: {len(ai.behavioral_sequences)}")
    
    # Collect data with progress
    print("\n📈 Collecting behavioral data...")
    for cycle in range(20):  # 20 cycles = 100 seconds
        ai.collect_behavioral_data()
        time.sleep(5)  # 5 seconds per cycle
        
        print(f"   Cycle {cycle + 1}/20: {len(ai.behavioral_sequences)} sequences collected")
        
        # Show some data samples
        if len(ai.behavioral_sequences) > 0:
            latest = ai.behavioral_sequences[-1]
            print(f"      Latest data: CPU={latest.get('cpu_percent', 0):.1f}%, "
                  f"Memory={latest.get('memory_percent', 0):.1f}%, "
                  f"Processes={len(latest.get('process_data', []))}")
    
    print(f"\n✅ Data collection complete: {len(ai.behavioral_sequences)} sequences")
    
    # Train models
    print("\n🤖 Training AI models...")
    try:
        ai.train_models()
        print("✅ Model training completed!")
    except Exception as e:
        print(f"❌ Training error: {e}")
        return False
    
    # Check results
    print("\n📊 Training Results:")
    print(f"   Is trained: {ai.is_trained}")
    
    # Check saved models
    model_files = list(ai.models_dir.glob("*.pkl"))
    if model_files:
        print(f"   Models saved: {len(model_files)}")
        for file in model_files:
            size = file.stat().st_size / 1024  # KB
            print(f"      - {file.name} ({size:.1f} KB)")
    else:
        print("   ⚠️  No model files found")
    
    # Test the models
    print("\n🧪 Testing trained models...")
    if ai.is_trained and len(ai.behavioral_sequences) > 0:
        test_data = ai.behavioral_sequences[-1]
        anomalies = ai.detect_anomalies(test_data)
        print(f"   Test anomalies detected: {len(anomalies)}")
        for i, anomaly in enumerate(anomalies):
            print(f"      Anomaly {i+1}: {anomaly.get('model', 'Unknown')} "
                  f"(score: {anomaly.get('score', 0):.3f})")
    
    print("\n✅ Quick AI training completed!")
    return True

if __name__ == "__main__":
    quick_ai_training() 