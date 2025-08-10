"""
File Scanner Module
Heuristic and rule-based scanning for executable files
"""

import os
import re
import hashlib
import pefile
import struct
from pathlib import Path
import time

class FileScanner:
    def __init__(self):
        self.suspicious_patterns = [
            # Suspicious strings
            r'(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)',
            r'(http|https|ftp)://',
            r'(download|upload|execute|run)',
            r'(registry|regedit)',
            r'(system32|windows)',
            r'(admin|administrator)',
            r'(password|credential)',
            r'(keylog|hook)',
            r'(inject|dll)',
            r'(encrypt|decrypt)',
            r'(backdoor|trojan|virus|malware)',
        ]
        
        self.suspicious_apis = [
            'CreateRemoteThread',
            'WriteProcessMemory',
            'VirtualAllocEx',
            'CreateFileA',
            'RegCreateKey',
            'RegSetValue',
            'URLDownloadToFile',
            'WinExec',
            'ShellExecute',
            'system',
            'CreateProcess',
            'WinHttpOpen',
            'InternetOpen',
            'GetProcAddress',
            'LoadLibrary',
        ]
        
        self.suspicious_sections = [
            '.text',
            '.data',
            '.rdata',
            '.idata',
            '.edata',
            '.pdata',
            '.reloc',
        ]
        
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None
    
    def scan_strings(self, file_path):
        """Extract and analyze strings from file"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract printable strings
            strings = re.findall(b'[A-Za-z0-9./\-_]{4,}', content)
            strings = [s.decode('utf-8', errors='ignore') for s in strings]
            
            suspicious_strings = []
            for pattern in self.suspicious_patterns:
                for string in strings:
                    if re.search(pattern, string, re.IGNORECASE):
                        suspicious_strings.append(string)
            
            return suspicious_strings
            
        except Exception as e:
            print(f"Error scanning strings: {e}")
            return []
    
    def analyze_pe_file(self, file_path):
        """Analyze PE file structure for suspicious characteristics"""
        try:
            pe = pefile.PE(file_path)
            
            analysis = {
                'suspicious_imports': [],
                'suspicious_sections': [],
                'entry_point': None,
                'image_base': None,
                'subsystem': None,
                'machine': None,
                'timestamp': None,
                'characteristics': [],
            }
            
            # Check imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode('utf-8', errors='ignore')
                            if api_name in self.suspicious_apis:
                                analysis['suspicious_imports'].append(api_name)
            
            # Check sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if section_name in self.suspicious_sections:
                    analysis['suspicious_sections'].append(section_name)
            
            # Get basic info
            analysis['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            analysis['image_base'] = pe.OPTIONAL_HEADER.ImageBase
            analysis['subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            analysis['machine'] = pe.FILE_HEADER.Machine
            analysis['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            
            # Check characteristics
            characteristics = pe.FILE_HEADER.Characteristics
            if characteristics & 0x0002:  # IMAGE_FILE_EXECUTABLE_IMAGE
                analysis['characteristics'].append('EXECUTABLE')
            if characteristics & 0x2000:  # IMAGE_FILE_DLL
                analysis['characteristics'].append('DLL')
            if characteristics & 0x0001:  # IMAGE_FILE_RELOCS_STRIPPED
                analysis['characteristics'].append('RELOCS_STRIPPED')
            
            pe.close()
            return analysis
            
        except Exception as e:
            print(f"Error analyzing PE file: {e}")
            return None
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def scan_file(self, file_path):
        """Comprehensive file scan"""
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return None
            
            # Basic file info
            file_size = file_path.stat().st_size
            file_hash = self.calculate_file_hash(file_path)
            
            scan_result = {
                'file_path': str(file_path),
                'file_name': file_path.name,
                'file_size': file_size,
                'file_hash': file_hash,
                'file_extension': file_path.suffix.lower(),
                'is_executable': False,
                'suspicious_score': 0,
                'suspicious_strings': [],
                'pe_analysis': None,
                'entropy': 0,
                'is_suspicious': False,
                'reasons': []
            }
            
            # Check if it's an executable
            executable_extensions = ['.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1']
            if file_path.suffix.lower() in executable_extensions:
                scan_result['is_executable'] = True
                scan_result['suspicious_score'] += 10
                scan_result['reasons'].append('Executable file')
            
            # Scan strings
            suspicious_strings = self.scan_strings(file_path)
            scan_result['suspicious_strings'] = suspicious_strings
            scan_result['suspicious_score'] += len(suspicious_strings) * 5
            if suspicious_strings:
                scan_result['reasons'].append(f'Found {len(suspicious_strings)} suspicious strings')
            
            # Analyze PE file if it's an executable
            if scan_result['is_executable'] and file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
                pe_analysis = self.analyze_pe_file(file_path)
                scan_result['pe_analysis'] = pe_analysis
                
                if pe_analysis:
                    # Check suspicious imports
                    if pe_analysis['suspicious_imports']:
                        scan_result['suspicious_score'] += len(pe_analysis['suspicious_imports']) * 10
                        scan_result['reasons'].append(f'Found {len(pe_analysis["suspicious_imports"])} suspicious APIs')
                    
                    # Check if it's a DLL
                    if 'DLL' in pe_analysis['characteristics']:
                        scan_result['suspicious_score'] += 5
                        scan_result['reasons'].append('DLL file')
                    
                    # Check if relocations are stripped
                    if 'RELOCS_STRIPPED' in pe_analysis['characteristics']:
                        scan_result['suspicious_score'] += 5
                        scan_result['reasons'].append('Relocations stripped')
            
            # Calculate entropy
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(min(file_size, 1024))  # Read first 1KB for entropy calculation
                scan_result['entropy'] = self.calculate_entropy(data)
                
                # High entropy might indicate packed/encrypted content
                if scan_result['entropy'] > 7.5:
                    scan_result['suspicious_score'] += 15
                    scan_result['reasons'].append('High entropy (possibly packed/encrypted)')
            except Exception as e:
                print(f"Error calculating entropy: {e}")
            
            # Determine if suspicious
            scan_result['is_suspicious'] = scan_result['suspicious_score'] >= 20
            
            return scan_result
            
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return None
    
    def scan_directory(self, directory_path, recursive=True):
        """Scan all files in a directory"""
        try:
            directory_path = Path(directory_path)
            if not directory_path.exists():
                return []
            
            scan_results = []
            
            if recursive:
                files = directory_path.rglob('*')
            else:
                files = directory_path.glob('*')
            
            for file_path in files:
                if file_path.is_file():
                    result = self.scan_file(file_path)
                    if result:
                        scan_results.append(result)
            
            return scan_results
            
        except Exception as e:
            print(f"Error scanning directory {directory_path}: {e}")
            return []
    
    def detect_malware(self, file_path, source="file_scanner"):
        """Detect malware and log alert if detected"""
        try:
            scan_result = self.scan_file(file_path)
            if scan_result is None:
                return False
            
            if scan_result['is_suspicious']:
                # Log alert to Django
                from dashboard.models import Alert
                
                severity = 'HIGH' if scan_result['suspicious_score'] > 50 else 'MEDIUM'
                
                Alert.objects.create(
                    alert_type='MALWARE',
                    severity=severity,
                    message=f"Suspicious file detected: {scan_result['file_name']}",
                    source=source,
                    details={
                        'file_path': scan_result['file_path'],
                        'file_hash': scan_result['file_hash'],
                        'suspicious_score': scan_result['suspicious_score'],
                        'reasons': scan_result['reasons'],
                        'entropy': scan_result['entropy'],
                        'suspicious_strings': scan_result['suspicious_strings'][:10]  # Limit to first 10
                    }
                )
                
                return True
            
            return False
            
        except Exception as e:
            print(f"Error in malware detection: {e}")
            return False

# Global instance
file_scanner = FileScanner() 