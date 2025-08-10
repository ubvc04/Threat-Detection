#!/usr/bin/env python3
"""
Enhanced AI Behavioral Detection Training
Collects more data and shows detailed progress
"""

import time
import os
from pathlib import Path
from ai_behavioral_detection import AIBehavioralDetection

def enhanced_ai_training():
    """Enhanced AI training with more data collection"""
    print("🚀 Enhanced AI Training Started")
    print("=" * 50)
    
    # Initialize AI system
    ai = AIBehavioralDetection()
    
    print(f"📊 Initial State:")
    print(f"   Models directory: {ai.models_dir.exists()}")
    print(f"   Is trained: {ai.is_trained}")
    print(f"   Sequences: {len(ai.behavioral_sequences)}")
    
    # Collect data with detailed progress
    print("\n📈 Collecting behavioral data (need 100+ points)...")
    target_cycles = 120  # Collect 120 data points
    
    for cycle in range(target_cycles):
        data_point = ai.collect_behavioral_data()
        time.sleep(3)  # 3 seconds per cycle = 6 minutes total
        
        # Show progress every 10 cycles
        if (cycle + 1) % 10 == 0:
            print(f"   Cycle {cycle + 1}/{target_cycles}: {len(ai.behavioral_sequences)} sequences")
            
            # Show detailed data
            if data_point:
                print(f"      System: CPU={data_point.get('system_cpu', 0):.1f}%, "
                      f"Memory={data_point.get('system_memory', 0):.1f}%")
                print(f"      Processes: {data_point.get('process_count', 0)}, "
                      f"Connections: {data_point.get('total_connections', 0)}")
        
        # Early exit if we have enough data
        if len(ai.behavioral_sequences) >= 100:
            print(f"   ✅ Sufficient data collected: {len(ai.behavioral_sequences)} sequences")
            break
    
    print(f"\n✅ Data collection complete: {len(ai.behavioral_sequences)} sequences")
    
    # Show data summary
    if ai.behavioral_sequences:
        latest = ai.behavioral_sequences[-1]
        print(f"\n📊 Latest Data Sample:")
        print(f"   System CPU: {latest.get('system_cpu', 0):.1f}%")
        print(f"   System Memory: {latest.get('system_memory', 0):.1f}%")
        print(f"   Process Count: {latest.get('process_count', 0)}")
        print(f"   Network Connections: {latest.get('total_connections', 0)}")
        print(f"   External IPs: {latest.get('external_ips', 0)}")
    
    # Train models
    print("\n🤖 Training AI models...")
    try:
        success = ai.train_models()
        if success:
            print("✅ Model training completed successfully!")
        else:
            print("❌ Model training failed - insufficient data")
            return False
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
    
    print("\n✅ Enhanced AI training completed!")
    return True

if __name__ == "__main__":
    enhanced_ai_training() 