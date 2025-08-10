# 🪟 Windows Installation Guide for Advanced Threat Detection

## 🔧 **Fixing the pypcap Installation Issue**

The error you encountered is because `pypcap` requires WinPcap/Npcap library. Here's how to fix it:

### **Option 1: Use Windows-Compatible Requirements (Recommended)**

```bash
# Install Windows-compatible requirements
pip install -r requirements_windows.txt
```

### **Option 2: Install WinPcap/Npcap (Advanced Users Only)**

If you specifically need `pypcap` functionality:

1. **Download Npcap**: Visit [https://npcap.com/](https://npcap.com/)
2. **Install Npcap**: Run the installer with default settings
3. **Install pypcap**: `pip install pypcap==1.2.3`

## 🚀 **Step-by-Step Windows Installation**

### **Step 1: Install Python Dependencies**

```bash
# Install Windows-compatible requirements
pip install -r requirements_windows.txt

# Install additional Windows-specific tools
pip install pywin32 WMI
```

### **Step 2: Install YARA (Optional but Recommended)**

```bash
# Install YARA for malware detection
pip install yara-python==4.3.1
```

### **Step 3: Configure VirusTotal (Optional)**

1. Get a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Set environment variable:
```bash
set VIRUSTOTAL_API_KEY=your_api_key_here
```

### **Step 4: Database Migration**

```bash
python manage.py makemigrations dashboard
python manage.py migrate
```

## 🎯 **Running Advanced Features on Windows**

### **Start Windows Advanced Monitoring**

```bash
# Start basic monitoring
python immediate_upgrades_windows.py start

# Start with VirusTotal integration
python immediate_upgrades_windows.py start --vt-api-key YOUR_API_KEY

# Run demo to test features
python immediate_upgrades_windows.py demo
```

### **Start Django Web Interface**

```bash
python manage.py runserver
```

Visit: `http://127.0.0.1:8000/dashboard/`

## 🔍 **Windows-Specific Features**

### **Enhanced Windows Security Monitoring**

The Windows version includes additional features:

- **Windows Defender Status**: Monitors real-time protection
- **Windows Firewall Status**: Checks firewall configuration
- **Registry Monitoring**: Scans for suspicious registry entries
- **Windows Services**: Monitors critical system services
- **Process Analysis**: Enhanced process behavior analysis

### **Windows Registry Scanning**

The system automatically monitors:
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

## 🛠️ **Troubleshooting Windows Issues**

### **Common Windows Installation Issues**

#### **1. Permission Errors**
```bash
# Run PowerShell as Administrator
# Then run your commands
```

#### **2. Python Path Issues**
```bash
# Check Python version
python --version

# Ensure you're using the correct Python
where python
```

#### **3. Missing Visual C++ Redistributable**
Download and install from Microsoft:
- [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)

#### **4. YARA Installation Issues**
```bash
# Alternative YARA installation
pip install yara-python --no-cache-dir
```

### **Windows-Specific Error Solutions**

#### **"Access Denied" Errors**
```bash
# Run as Administrator or adjust permissions
# Check Windows Defender exclusions
```

#### **"Module Not Found" Errors**
```bash
# Reinstall specific packages
pip uninstall package_name
pip install package_name
```

#### **Registry Access Issues**
```bash
# Ensure running with appropriate permissions
# Check Windows security settings
```

## 📊 **Windows Performance Optimization**

### **System Requirements**
- **Minimum**: Windows 10, 4GB RAM, 2 CPU cores
- **Recommended**: Windows 10/11, 8GB RAM, 4 CPU cores
- **Production**: Windows Server, 16GB RAM, 8 CPU cores

### **Performance Tips**
1. **Exclude from Windows Defender**: Add project directory to exclusions
2. **Run as Administrator**: For full system access
3. **Adjust monitoring intervals**: Increase intervals for better performance
4. **Use SSD storage**: For faster file scanning

## 🔐 **Windows Security Best Practices**

### **Running with Elevated Privileges**
```bash
# Run PowerShell as Administrator
# Navigate to project directory
cd C:\Users\baves\Downloads\Threat-Detection
```

### **Windows Defender Configuration**
1. Add project directory to Windows Defender exclusions
2. Configure real-time protection settings
3. Set up custom scan exclusions

### **Firewall Configuration**
```bash
# Allow Python through Windows Firewall
netsh advfirewall firewall add rule name="Python Threat Detection" dir=in action=allow program="C:\Python39\python.exe"
```

## 🎮 **Testing Windows Features**

### **Run Windows Demo**
```bash
python immediate_upgrades_windows.py demo
```

This will create sample alerts for:
- Network anomalies
- Process behavior
- Malware detection
- Windows security issues
- Registry anomalies

### **Check Windows Security Status**
```bash
# Check Windows Defender
powershell "Get-MpComputerStatus"

# Check Windows Firewall
netsh advfirewall show allprofiles
```

## 📈 **Windows Monitoring Dashboard**

### **New Windows-Specific Metrics**
- **Windows Defender Status**: Real-time protection status
- **Firewall Status**: Windows Firewall configuration
- **Registry Alerts**: Suspicious registry entries
- **Windows Services**: Critical service monitoring
- **System Security Score**: Overall Windows security assessment

### **Windows Alert Types**
- **REGISTRY**: Suspicious registry entries
- **WINDOWS_SECURITY**: Windows security issues
- **SYSTEM**: System-level alerts
- **NETWORK**: Network anomalies
- **PROCESS**: Process behavior analysis
- **MALWARE**: Malware detection

## 🚀 **Advanced Windows Features**

### **Windows Event Log Monitoring**
The system can monitor Windows Event Logs for:
- Security events
- System events
- Application events
- PowerShell execution

### **Windows Service Monitoring**
Monitors critical Windows services:
- Windows Defender
- Windows Firewall
- Windows Update
- Security Center

### **Windows Process Analysis**
Enhanced process monitoring for:
- Suspicious command lines
- High resource usage
- Unusual process behavior
- Process injection detection

## 🎉 **Success Indicators**

### **Windows Installation Success**
✅ All packages installed without errors  
✅ Django server starts successfully  
✅ Advanced monitoring runs without issues  
✅ Dashboard displays Windows-specific metrics  
✅ Alerts are generated for Windows events  

### **Performance Indicators**
- **CPU Usage**: <10% during normal operation
- **Memory Usage**: <500MB for monitoring processes
- **Response Time**: <5 seconds for alert generation
- **False Positives**: <5% for Windows events

---

## 🏆 **Congratulations!**

You've successfully installed the Advanced Threat Detection System on Windows! Your system now includes:

✅ **Windows-Specific Security Monitoring**  
✅ **Registry Analysis**  
✅ **Windows Defender Integration**  
✅ **Enhanced Process Monitoring**  
✅ **Windows Firewall Monitoring**  
✅ **Real-time Security Assessment**  

Your Windows threat detection system is now ready for production use! 