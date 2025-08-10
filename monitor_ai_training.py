#!/usr/bin/env python3
"""
Monitor AI Behavioral Detection Training
Track the training progress and model creation
"""

import time
import os
from pathlib import Path
from ai_behavioral_detection import AIBehavioralDetection

def monitor_ai_training():
    """Monitor AI training process with detailed output"""
    print("🔍 AI Training Monitor Started")
    print("=" * 50)
    
    # Initialize AI system
    ai = AIBehavioralDetection()
    
    # Check initial state
    print(f"📊 Initial State:")
    print(f"   Models directory exists: {ai.models_dir.exists()}")
    print(f"   Is trained: {ai.is_trained}")
    print(f"   Behavioral sequences: {len(ai.behavioral_sequences)}")
    
    # Start monitoring
    print("\n🚀 Starting AI monitoring...")
    ai.start_ai_monitoring()
    
    # Monitor for 3 minutes
    print("\n⏱️  Monitoring training progress...")
    for cycle in range(18):  # 18 * 10 seconds = 3 minutes
        time.sleep(10)
        
        print(f"\n📈 Cycle {cycle + 1}/18:")
        print(f"   Behavioral sequences collected: {len(ai.behavioral_sequences)}")
        
        # Check model status
        if hasattr(ai, 'isolation_forest') and ai.isolation_forest is not None:
            print("   ✅ Isolation Forest: TRAINED")
        else:
            print("   ⏳ Isolation Forest: Training...")
            
        if hasattr(ai, 'autoencoder') and ai.autoencoder is not None:
            print("   ✅ Autoencoder: TRAINED")
        else:
            print("   ⏳ Autoencoder: Training...")
            
        if hasattr(ai, 'lstm_model') and ai.lstm_model is not None:
            print("   ✅ LSTM: TRAINED")
        else:
            print("   ⏳ LSTM: Training...")
        
        # Check if models are saved
        model_files = list(ai.models_dir.glob("*.pkl"))
        if model_files:
            print(f"   💾 Model files saved: {len(model_files)}")
            for file in model_files:
                print(f"      - {file.name}")
        
        # Check if training is complete
        if ai.is_trained:
            print("   🎉 TRAINING COMPLETE!")
            break
    
    # Stop monitoring
    print("\n🛑 Stopping AI monitoring...")
    ai.stop_ai_monitoring()
    
    # Final status
    print("\n📊 Final Status:")
    print(f"   Total sequences collected: {len(ai.behavioral_sequences)}")
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
    
    print("\n✅ Monitoring complete!")

if __name__ == "__main__":
    monitor_ai_training() 