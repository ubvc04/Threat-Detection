# 🚀 Threat Detection System - Setup Guide (Python 3.11)

## Prerequisites
- **Python 3.11** installed on your system
- **Windows 10/11** operating system
- **Git** (optional, for version control)

## Step-by-Step Setup

### 1. Create Virtual Environment with Python 3.11

```bash
# Navigate to your project directory
cd Threat-Detection

# Create virtual environment with Python 3.11
python3.11 -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

### 2. Verify Python Version

```bash
# Check Python version (should show 3.11.x)
python --version
```

### 3. Update pip

```bash
# Update pip to latest version
python -m pip install --upgrade pip
```

### 4. Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

### 5. Setup Django

```bash
# Create Django migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

### 6. Add Your Datasets

Place your downloaded datasets in the `datasets/` folder:

- **Phishing Dataset**: `datasets/phishing_dataset.csv`
  - Format: `url,label` (0=legitimate, 1=phishing)
  
- **Spam Dataset**: `datasets/spam_dataset.csv`
  - Format: `text,label` (ham/spam)

### 7. Train Machine Learning Models

```bash
# Train phishing and spam detection models
python train_models.py
```

### 8. Start the System

```bash
# Terminal 1: Start Django server
python manage.py runserver

# Terminal 2: Start threat detection system
python threat_detection_system.py start
```

### 9. Access the Dashboard

Open your browser and go to: **http://localhost:8000**

## Alternative: Automated Setup

If you prefer automated setup:

```bash
# Run the setup script (make sure venv is activated)
python setup.py
```

## Troubleshooting

### Common Issues:

1. **Python 3.11 not found**:
   ```bash
   # Check available Python versions
   py -0
   
   # Use specific Python version
   py -3.11 -m venv venv
   ```

2. **Package installation fails**:
   ```bash
   # Try with no cache
   pip install -r requirements.txt --no-cache-dir
   
   # Or install packages individually
   pip install Django==4.2.7
   pip install pandas==2.1.3
   # ... etc
   ```

3. **Permission errors**:
   - Run PowerShell as Administrator
   - Or use: `pip install --user -r requirements.txt`

4. **Virtual environment not activating**:
   ```bash
   # PowerShell execution policy
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## System Commands

```bash
# Check system status
python threat_detection_system.py status

# Stop the system
python threat_detection_system.py stop

# Run demo
python threat_detection_system.py demo

# Test specific detections
python threat_detection_system.py test-phishing <url>
python threat_detection_system.py test-spam <message>
```

## Next Steps

1. **Add your datasets** to the `datasets/` folder
2. **Train the models** with `python train_models.py`
3. **Start monitoring** with the threat detection system
4. **Access the dashboard** at http://localhost:8000

## Support

- Check the `README.md` for detailed documentation
- Review logs in the `logs/` folder
- Ensure all prerequisites are installed (Sysmon, Npcap)

---

**Happy Threat Detection! 🛡️** 