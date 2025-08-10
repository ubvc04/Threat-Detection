"""
Model Training Script
Trains phishing and spam detection models using user-provided datasets
"""

import os
import sys
import django
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(project_dir))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_site.settings')
django.setup()

from detection_core.phishing_detector import phishing_detector
from detection_core.spam_detector import spam_detector

def check_dataset_format():
    """Check and explain the expected dataset format"""
    print("=" * 60)
    print("DATASET FORMAT REQUIREMENTS")
    print("=" * 60)
    
    print("\n1. PHISHING DATASET (UCI Phishing Website Dataset)")
    print("   Expected file: datasets/phishing_dataset.csv")
    print("   Required columns:")
    print("     - url: The URL to analyze")
    print("     - label: 1 for phishing, 0 for legitimate")
    print("   Example:")
    print("     url,label")
    print("     https://www.google.com,0")
    print("     http://fake-bank-login.com,1")
    
    print("\n2. SPAM DATASET (UCI/Kaggle SMS Spam Dataset)")
    print("   Expected file: datasets/spam_dataset.csv")
    print("   Required columns:")
    print("     - text: The message text")
    print("     - label: 'spam' or 'ham'")
    print("   Example:")
    print("     text,label")
    print("     Hello, how are you?,ham")
    print("     URGENT: You've won $1,000,000!,spam")
    
    print("\n" + "=" * 60)
    print("Please place your datasets in the 'datasets/' folder")
    print("Then run: python train_models.py")
    print("=" * 60)

def check_datasets():
    """Check if datasets exist and are in the correct format"""
    datasets_dir = Path("datasets")
    
    if not datasets_dir.exists():
        print("❌ 'datasets/' directory not found!")
        print("Please create the 'datasets/' directory and place your datasets there.")
        return False
    
    phishing_file = datasets_dir / "phishing_dataset.csv"
    spam_file = datasets_dir / "spam_dataset.csv"
    
    missing_files = []
    
    if not phishing_file.exists():
        missing_files.append("phishing_dataset.csv")
    
    if not spam_file.exists():
        missing_files.append("spam_dataset.csv")
    
    if missing_files:
        print(f"❌ Missing dataset files: {', '.join(missing_files)}")
        print("Please place the required datasets in the 'datasets/' folder.")
        return False
    
    print("✅ All dataset files found!")
    return True

def train_phishing_model():
    """Train the phishing detection model"""
    print("\n" + "=" * 40)
    print("TRAINING PHISHING DETECTION MODEL")
    print("=" * 40)
    
    try:
        dataset_path = "datasets/phishing_dataset.csv"
        
        if not os.path.exists(dataset_path):
            print(f"❌ Dataset not found: {dataset_path}")
            return False
        
        print(f"📁 Using dataset: {dataset_path}")
        print("🔄 Training phishing detection model...")
        
        success = phishing_detector.train_model(dataset_path)
        
        if success:
            print("✅ Phishing detection model trained successfully!")
            return True
        else:
            print("❌ Failed to train phishing detection model")
            return False
            
    except Exception as e:
        print(f"❌ Error training phishing model: {e}")
        return False

def train_spam_model():
    """Train the spam detection model"""
    print("\n" + "=" * 40)
    print("TRAINING SPAM DETECTION MODEL")
    print("=" * 40)
    
    try:
        dataset_path = "datasets/spam_dataset.csv"
        
        if not os.path.exists(dataset_path):
            print(f"❌ Dataset not found: {dataset_path}")
            return False
        
        print(f"📁 Using dataset: {dataset_path}")
        print("🔄 Training spam detection model...")
        
        success = spam_detector.train_model(dataset_path)
        
        if success:
            print("✅ Spam detection model trained successfully!")
            return True
        else:
            print("❌ Failed to train spam detection model")
            return False
            
    except Exception as e:
        print(f"❌ Error training spam model: {e}")
        return False

def test_trained_models():
    """Test the trained models with sample data"""
    print("\n" + "=" * 40)
    print("TESTING TRAINED MODELS")
    print("=" * 40)
    
    # Test phishing detection
    print("\n🔍 Testing Phishing Detection:")
    test_urls = [
        "https://www.google.com",
        "http://login-bank-secure.verify-account.com",
        "https://www.microsoft.com",
        "http://fake-paypal-login.com",
    ]
    
    for url in test_urls:
        try:
            result = phishing_detector.predict(url)
            if result:
                status = "PHISHING" if result['is_phishing'] else "LEGITIMATE"
                confidence = result['confidence']
                print(f"  {url} -> {status} (confidence: {confidence:.2f})")
            else:
                print(f"  {url} -> ERROR (model not loaded)")
        except Exception as e:
            print(f"  {url} -> ERROR: {e}")
    
    # Test spam detection
    print("\n🔍 Testing Spam Detection:")
    test_messages = [
        "Hello, how are you?",
        "URGENT: You've won $1,000,000! Click here now!",
        "Meeting reminder for tomorrow at 2 PM",
        "FREE VIAGRA NOW!!! LIMITED TIME OFFER!!!",
    ]
    
    for message in test_messages:
        try:
            result = spam_detector.predict(message)
            if result:
                status = "SPAM" if result['is_spam'] else "HAM"
                confidence = result['confidence']
                print(f"  '{message[:30]}...' -> {status} (confidence: {confidence:.2f})")
            else:
                print(f"  '{message[:30]}...' -> ERROR (model not loaded)")
        except Exception as e:
            print(f"  '{message[:30]}...' -> ERROR: {e}")

def main():
    """Main training function"""
    print("=" * 60)
    print("THREAT DETECTION SYSTEM - MODEL TRAINING")
    print("=" * 60)
    
    # Check if datasets exist
    if not check_datasets():
        print("\n" + "=" * 60)
        print("SETUP INSTRUCTIONS:")
        print("=" * 60)
        check_dataset_format()
        return
    
    # Train models
    phishing_success = train_phishing_model()
    spam_success = train_spam_model()
    
    # Test models if training was successful
    if phishing_success and spam_success:
        test_trained_models()
        
        print("\n" + "=" * 60)
        print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("✅ Phishing detection model: models/phishing_detector.pkl")
        print("✅ Spam detection model: models/spam_detector.pkl")
        print("\nYou can now run the threat detection system:")
        print("  python threat_detection_system.py start")
        print("  python manage.py runserver")
    else:
        print("\n" + "=" * 60)
        print("❌ TRAINING FAILED")
        print("=" * 60)
        print("Please check your dataset format and try again.")
        print("Run 'python train_models.py' to see format requirements.")

if __name__ == '__main__':
    main() 