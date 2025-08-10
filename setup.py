#!/usr/bin/env python3
"""
Setup script for Threat Detection System
Handles initial setup, dependency installation, and configuration
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header():
    """Print setup header"""
    print("=" * 60)
    print("Threat Detection System - Setup")
    print("=" * 60)

def check_windows():
    """Check if running on Windows"""
    print("Checking operating system...")
    if platform.system() != "Windows":
        print("  ❌ This system is designed for Windows only")
        return False
    print("  ✅ Windows detected")
    return True

def check_python_version():
    """Check Python version compatibility"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 11:
        print(f"  ✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"  ❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.11+")
        return False

def create_directories():
    """Create necessary directories"""
    print("Creating directories...")
    directories = [
        'datasets',
        'models', 
        'logs',
        'static',
        'templates/dashboard'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✅ Created: {directory}")

def install_dependencies():
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    try:
        # Install from requirements.txt with exact versions for Python 3.11
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"  ❌ Error installing dependencies: {result.stderr}")
            print("\nTroubleshooting tips:")
            print("1. Make sure you're using Python 3.11")
            print("2. Try updating pip: python -m pip install --upgrade pip")
            print("3. Try installing with --no-cache-dir: pip install -r requirements.txt --no-cache-dir")
            return False
        else:
            print("  ✅ Dependencies installed successfully")
            return True
            
    except Exception as e:
        print(f"  ❌ Error installing dependencies: {e}")
        return False

def setup_django():
    """Setup Django database and migrations"""
    print("Setting up Django...")
    try:
        # Make migrations
        result = subprocess.run([
            sys.executable, 'manage.py', 'makemigrations'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"  ❌ Error creating migrations: {result.stderr}")
            return False
        
        # Migrate
        result = subprocess.run([
            sys.executable, 'manage.py', 'migrate'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"  ❌ Error running migrations: {result.stderr}")
            return False
        
        print("  ✅ Django setup completed")
        return True
        
    except Exception as e:
        print(f"  ❌ Error setting up Django: {e}")
        return False

def check_datasets():
    """Check if datasets are present"""
    print("Checking datasets...")
    phishing_dataset = Path('datasets/phishing_dataset.csv')
    spam_dataset = Path('datasets/spam_dataset.csv')
    
    if not phishing_dataset.exists():
        print("  ⚠️  Phishing dataset not found")
        print("     Expected: datasets/phishing_dataset.csv")
        print("     Format: url,label (0=legitimate, 1=phishing)")
        print("     Source: UCI Machine Learning Repository")
    
    if not spam_dataset.exists():
        print("  ⚠️  Spam dataset not found")
        print("     Expected: datasets/spam_dataset.csv")
        print("     Format: text,label (ham/spam)")
        print("     Source: SMS Spam Collection Dataset")
    
    if phishing_dataset.exists() and spam_dataset.exists():
        print("  ✅ All datasets found")
        return True
    else:
        print("  ⚠️  Some datasets missing - you'll need to add them before training models")
        return False

def check_sysmon():
    """Check if Sysmon is installed"""
    print("Checking Sysmon installation...")
    try:
        # Check if Sysmon service exists
        result = subprocess.run([
            'sc', 'query', 'SysmonDrv'
        ], capture_output=True, text=True)
        
        if 'RUNNING' in result.stdout or 'STOPPED' in result.stdout:
            print("  ✅ Sysmon service found")
            return True
        else:
            print("  ⚠️  Sysmon not found")
            print("     Download from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon")
            print("     Install with: sysmon.exe -i sysmon_config.xml")
            return False
            
    except Exception:
        print("  ⚠️  Could not check Sysmon status")
        return False

def create_sample_config():
    """Create sample configuration files"""
    print("Creating sample configuration...")
    
    # Create .env file
    env_content = """# Threat Detection System Configuration
DEBUG=True
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=sqlite:///db.sqlite3

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/threat_detection.log

# Detection Settings
SCAN_INTERVAL=30
MAX_FILE_SIZE=100MB
SUSPICIOUS_PORTS=22,23,3389,445
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("  ✅ Created .env file")

def main():
    """Main setup function"""
    print_header()
    
    # Check system requirements
    if not check_windows():
        return False
    
    if not check_python_version():
        return False
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed: Could not install dependencies")
        return False
    
    # Setup Django
    if not setup_django():
        print("\n❌ Setup failed: Could not setup Django")
        return False
    
    # Check additional requirements
    check_datasets()
    check_sysmon()
    
    # Create configuration
    create_sample_config()
    
    print("\n" + "=" * 60)
    print("✅ Setup completed successfully!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Add your datasets to the datasets/ folder")
    print("2. Run: python train_models.py")
    print("3. Start the system: python threat_detection_system.py start")
    print("4. Access dashboard: http://localhost:8000")
    print("\nFor help, see README.md")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 