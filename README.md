# 🛡️ Threat Detection System

A comprehensive, real-time Windows-based threat detection system with Django GUI that provides both user-level and kernel-level monitoring capabilities.

## 📋 Overview

This system provides real-time threat detection for Windows systems with the following capabilities:

### ✅ User-Level Detection
- **Phishing Detection**: ML-based URL analysis using UCI Phishing Website Dataset
- **Spam Detection**: ML-based message analysis using SMS Spam Dataset
- **File Scanning**: Heuristic and rule-based malware detection
- **USB Monitoring**: Real-time USB device insertion detection and autorun.inf scanning
- **Network Monitoring**: Packet analysis and suspicious connection detection

### ✅ Kernel/System-Level Monitoring
- **Process Monitoring**: CPU/memory spikes, suspicious process behavior detection
- **Sysmon Integration**: Windows Event Log parsing for deep system monitoring
- **Registry Monitoring**: Suspicious registry key changes detection
- **System Performance**: Real-time system resource monitoring

### 🎯 Key Features
- **Django Web Dashboard**: Modern, responsive GUI for all alerts and monitoring
- **Real-time Alerts**: Live threat detection with severity-based alerting
- **Machine Learning**: Trained models for phishing and spam detection
- **Modular Architecture**: Extensible detection modules
- **Local Operation**: Runs entirely within Python virtual environment
- **No CLI Output**: All information displayed through Django GUI

## 🏗️ Project Structure

```
threat_detection_system/
├── manage.py                          # Django management script
├── requirements.txt                   # Python dependencies
├── threat_detection_system.py         # Main system integration
├── train_models.py                    # ML model training script
├── datasets/                          # User-provided datasets
│   ├── phishing_dataset.csv          # UCI Phishing Website Dataset
│   └── spam_dataset.csv              # SMS Spam Dataset
├── models/                           # Trained ML models (.pkl files)
├── detection_core/                   # Core detection modules
│   ├── phishing_detector.py         # Phishing URL detection
│   ├── spam_detector.py             # Spam message detection
│   ├── file_scanner.py              # Malware file scanning
│   ├── usb_monitor.py               # USB device monitoring
│   ├── network_sniffer.py           # Network traffic analysis
│   ├── process_monitor.py           # Process behavior monitoring
│   └── sysmon_monitor.py            # Sysmon event log parsing
├── dashboard/                        # Django web application
│   ├── models.py                    # Database models
│   ├── views.py                     # Web views and API endpoints
│   ├── urls.py                      # URL routing
│   └── templates/                   # HTML templates
├── threat_site/                     # Django project settings
│   ├── settings.py                  # Django configuration
│   ├── urls.py                      # Main URL routing
│   └── wsgi.py                      # WSGI configuration
└── templates/                       # Base HTML templates
```

## ⚙️ Prerequisites

### System Requirements
- **Windows 10/11** (64-bit)
- **Python 3.11** or higher
- **Administrator privileges** (for network sniffing and Sysmon)
- **Git** (for cloning the repository)

### Required Windows Tools
1. **Sysmon** (System Monitor)
   - Download from Microsoft Sysinternals
   - Install with configuration for event logging

2. **Npcap** (Network packet capture)
   - Required for network sniffing functionality
   - Download from nmap.org

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd threat_detection_system
```

### 2. Create Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Django Database
```bash
python manage.py makemigrations
python manage.py migrate
```

### 5. Prepare Datasets

#### Dataset Format Requirements

**Phishing Dataset** (`datasets/phishing_dataset.csv`):
```csv
url,label
https://www.google.com,0
http://fake-bank-login.com,1
```

**Spam Dataset** (`datasets/spam_dataset.csv`):
```csv
text,label
Hello, how are you?,ham
URGENT: You've won $1,000,000!,spam
```

#### Dataset Sources
- **UCI Phishing Website Dataset**: [Download here](https://archive.ics.uci.edu/ml/datasets/Phishing+Websites)
- **SMS Spam Collection Dataset**: [Download here](https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset)

### 6. Train ML Models
```bash
python train_models.py
```

This will:
- Check for required datasets
- Train phishing detection model
- Train spam detection model
- Save models to `models/` directory

## 🎯 Usage

### Starting the System

1. **Start Django Web Server**:
```bash
python manage.py runserver
```

2. **Start Threat Detection System** (in separate terminal):
```bash
python threat_detection_system.py start
```

3. **Access Web Dashboard**:
   - Open browser: `http://localhost:8000`
   - View real-time alerts and system monitoring

### System Commands

```bash
# Start the threat detection system
python threat_detection_system.py start

# Stop the system
python threat_detection_system.py stop

# Check system status
python threat_detection_system.py status

# Run demonstration
python threat_detection_system.py demo

# Test specific detections
python threat_detection_system.py test-phishing <url>
python threat_detection_system.py test-spam <message>
python threat_detection_system.py test-file <file_path>

# Scan USB drives
python threat_detection_system.py scan-usb
```

## 📊 Dashboard Features

### Main Dashboard
- **Real-time Statistics**: Total alerts, critical alerts, unresolved alerts
- **Alert Distribution**: Charts showing alert types and severities
- **System Information**: CPU, memory, disk usage monitoring
- **Recent Alerts**: Latest threat detections with severity indicators

### Alerts Management
- **Filtering**: By type, severity, status, and search terms
- **Pagination**: Navigate through large numbers of alerts
- **Alert Resolution**: Mark alerts as resolved
- **Detailed View**: View comprehensive alert information

### System Monitor
- **Process Monitoring**: Real-time process analysis
- **Suspicious Process Detection**: Identify potentially malicious processes
- **System Performance**: CPU, memory, and network usage tracking
- **Process Actions**: Kill suspicious processes (with confirmation)

## 🔧 Configuration

### Detection Thresholds
Modify detection sensitivity in respective modules:

- **Process Monitor**: `detection_core/process_monitor.py`
  - `cpu_threshold = 80.0`
  - `memory_threshold = 80.0`
  - `suspicious_score_threshold = 20`

- **Network Sniffer**: `detection_core/network_sniffer.py`
  - Suspicious ports and IPs
  - Packet analysis thresholds

### Alert Severity Levels
- **CRITICAL**: Immediate attention required
- **HIGH**: High-priority threats
- **MEDIUM**: Moderate threats
- **LOW**: Informational alerts

## 🛠️ Development

### Adding New Detection Modules

1. Create new module in `detection_core/`
2. Implement detection logic
3. Add alert logging to Django
4. Register module in `threat_detection_system.py`

### Extending the Dashboard

1. Add new views in `dashboard/views.py`
2. Create templates in `templates/dashboard/`
3. Update URL routing in `dashboard/urls.py`

## 🔒 Security Considerations

### Permissions Required
- **Administrator privileges**: For network sniffing and Sysmon access
- **File system access**: For USB monitoring and file scanning
- **Process monitoring**: For system-wide process analysis

### Data Privacy
- All data processed locally
- No external data transmission
- Alert data stored in local SQLite database

## 🐛 Troubleshooting

### Common Issues

1. **Network Sniffing Not Working**
   - Ensure Npcap is installed
   - Run as Administrator
   - Check firewall settings

2. **Sysmon Events Not Detected**
   - Verify Sysmon is installed and running
   - Check Windows Event Log permissions
   - Ensure Sysmon configuration is correct

3. **ML Models Not Loading**
   - Run `python train_models.py` first
   - Check dataset format
   - Verify models exist in `models/` directory

4. **Django Server Issues**
   - Check virtual environment is activated
   - Verify all dependencies installed
   - Check database migrations

### Logs
- System logs: `logs/threat_detection.log`
- Django logs: Console output
- Windows Event Logs: For Sysmon events

## 📈 Performance

### System Requirements
- **CPU**: 2+ cores recommended
- **Memory**: 4GB+ RAM recommended
- **Storage**: 1GB+ free space
- **Network**: For network monitoring features

### Optimization Tips
- Adjust monitoring intervals in modules
- Limit historical data retention
- Use SSD for better database performance
- Close unnecessary applications during monitoring

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Implement changes
4. Add tests
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **UCI Machine Learning Repository** for phishing dataset
- **Kaggle** for SMS spam dataset
- **Microsoft Sysinternals** for Sysmon
- **Nmap Project** for Npcap

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review system logs
3. Create an issue in the repository

---

**⚠️ Disclaimer**: This system is for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations. 