"""
Network Sniffer Module
Uses Scapy to monitor network traffic and detect suspicious patterns
"""

import os
import time
import threading
import socket
import struct
from scapy.all import *
import psutil
from collections import defaultdict, deque

class NetworkSniffer:
    def __init__(self):
        self.monitoring = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.suspicious_connections = deque(maxlen=1000)
        self.connection_stats = defaultdict(int)
        
        # Suspicious patterns
        self.suspicious_ports = {
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            1433: 'MSSQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
        }
        
        self.suspicious_ips = set()
        self.suspicious_domains = set()
        
        # Load suspicious IPs and domains (can be expanded)
        self.load_suspicious_lists()
    
    def load_suspicious_lists(self):
        """Load lists of suspicious IPs and domains"""
        # This could be loaded from external threat intelligence feeds
        self.suspicious_ips.update([
            '192.168.1.100',  # Example suspicious IP
            '10.0.0.50',      # Example suspicious IP
        ])
        
        self.suspicious_domains.update([
            'malware.example.com',
            'phishing.example.com',
            'botnet.example.com',
        ])
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        for interface in get_if_list():
            try:
                if get_if_addr(interface) != '127.0.0.1':  # Skip loopback
                    interfaces.append(interface)
            except:
                continue
        return interfaces
    
    def analyze_packet(self, packet):
        """Analyze a single packet for suspicious activity"""
        try:
            analysis = {
                'timestamp': time.time(),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'payload_size': 0,
                'suspicious_score': 0,
                'suspicious_reasons': []
            }
            
            # Extract IP layer information
            if IP in packet:
                analysis['src_ip'] = packet[IP].src
                analysis['dst_ip'] = packet[IP].dst
                analysis['payload_size'] = len(packet[IP].payload)
                
                # Check for suspicious IPs
                if analysis['src_ip'] in self.suspicious_ips:
                    analysis['suspicious_score'] += 50
                    analysis['suspicious_reasons'].append(f'Suspicious source IP: {analysis["src_ip"]}')
                
                if analysis['dst_ip'] in self.suspicious_ips:
                    analysis['suspicious_score'] += 50
                    analysis['suspicious_reasons'].append(f'Suspicious destination IP: {analysis["dst_ip"]}')
            
            # Extract TCP layer information
            if TCP in packet:
                analysis['protocol'] = 'TCP'
                analysis['src_port'] = packet[TCP].sport
                analysis['dst_port'] = packet[TCP].dport
                
                # Check for suspicious ports
                if analysis['dst_port'] in self.suspicious_ports:
                    analysis['suspicious_score'] += 10
                    analysis['suspicious_reasons'].append(f'Suspicious destination port: {analysis["dst_port"]} ({self.suspicious_ports[analysis["dst_port"]]})')
                
                # Check for port scanning
                if analysis['src_port'] > 1024 and analysis['dst_port'] < 1024:
                    analysis['suspicious_score'] += 5
                    analysis['suspicious_reasons'].append('Potential port scan (high source port to low destination port)')
            
            # Extract UDP layer information
            elif UDP in packet:
                analysis['protocol'] = 'UDP'
                analysis['src_port'] = packet[UDP].sport
                analysis['dst_port'] = packet[UDP].dport
                
                # Check for suspicious ports
                if analysis['dst_port'] in self.suspicious_ports:
                    analysis['suspicious_score'] += 10
                    analysis['suspicious_reasons'].append(f'Suspicious destination port: {analysis["dst_port"]} ({self.suspicious_ports[analysis["dst_port"]]})')
            
            # Extract DNS layer information
            if DNS in packet:
                analysis['protocol'] = 'DNS'
                
                # Check for DNS queries
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    
                    # Check for suspicious domains
                    for domain in self.suspicious_domains:
                        if domain in qname:
                            analysis['suspicious_score'] += 30
                            analysis['suspicious_reasons'].append(f'Suspicious DNS query: {qname}')
                            break
                    
                    # Check for DNS tunneling attempts
                    if len(qname) > 100:
                        analysis['suspicious_score'] += 20
                        analysis['suspicious_reasons'].append('Potential DNS tunneling (very long query)')
            
            # Check for large payloads (potential data exfiltration)
            if analysis['payload_size'] > 10000:  # 10KB
                analysis['suspicious_score'] += 15
                analysis['suspicious_reasons'].append(f'Large payload: {analysis["payload_size"]} bytes')
            
            # Check for unusual packet patterns
            if analysis['protocol'] == 'TCP' and packet.haslayer(TCP):
                flags = packet[TCP].flags
                
                # SYN scan detection
                if flags == 2:  # SYN flag only
                    analysis['suspicious_score'] += 10
                    analysis['suspicious_reasons'].append('SYN scan detected')
                
                # FIN scan detection
                elif flags == 1:  # FIN flag only
                    analysis['suspicious_score'] += 10
                    analysis['suspicious_reasons'].append('FIN scan detected')
                
                # XMAS scan detection
                elif flags == 41:  # FIN, PSH, URG flags
                    analysis['suspicious_score'] += 15
                    analysis['suspicious_reasons'].append('XMAS scan detected')
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing packet: {e}")
            return None
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        try:
            self.packet_count += 1
            
            # Analyze packet
            analysis = self.analyze_packet(packet)
            if not analysis:
                return
            
            # Store suspicious connections
            if analysis['suspicious_score'] > 0:
                connection_key = f"{analysis['src_ip']}:{analysis['src_port']} -> {analysis['dst_ip']}:{analysis['dst_port']}"
                self.suspicious_connections.append(analysis)
                self.connection_stats[connection_key] += 1
            
            # Log high-severity suspicious activity
            if analysis['suspicious_score'] >= 30:
                self.log_network_alert(analysis)
            
            # Limit processing to avoid overwhelming the system
            if self.packet_count % 1000 == 0:
                print(f"Processed {self.packet_count} packets")
            
        except Exception as e:
            print(f"Error in packet callback: {e}")
    
    def log_network_alert(self, analysis):
        """Log network alert to Django"""
        try:
            from dashboard.models import Alert
            
            # Determine severity
            if analysis['suspicious_score'] >= 50:
                severity = 'HIGH'
            elif analysis['suspicious_score'] >= 30:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Create alert message
            message = f"Suspicious network activity: {analysis['src_ip']}:{analysis['src_port']} -> {analysis['dst_ip']}:{analysis['dst_port']}"
            if analysis['suspicious_reasons']:
                message += f" - {', '.join(analysis['suspicious_reasons'][:3])}"
            
            Alert.objects.create(
                alert_type='NETWORK',
                severity=severity,
                message=message,
                source='network_sniffer',
                details={
                    'protocol': analysis['protocol'],
                    'src_ip': analysis['src_ip'],
                    'dst_ip': analysis['dst_ip'],
                    'src_port': analysis['src_port'],
                    'dst_port': analysis['dst_port'],
                    'payload_size': analysis['payload_size'],
                    'suspicious_score': analysis['suspicious_score'],
                    'suspicious_reasons': analysis['suspicious_reasons']
                }
            )
            
        except Exception as e:
            print(f"Error logging network alert: {e}")
    
    def start_sniffing(self, interface=None, filter_string=""):
        """Start network sniffing"""
        if self.monitoring:
            return
        
        try:
            self.monitoring = True
            
            # Get interface if not specified
            if not interface:
                interfaces = self.get_network_interfaces()
                if interfaces:
                    interface = interfaces[0]
                else:
                    print("No suitable network interface found")
                    return
            
            print(f"Starting network sniffing on interface: {interface}")
            
            # Start sniffing in a separate thread
            self.sniffer_thread = threading.Thread(
                target=self._sniff_packets,
                args=(interface, filter_string),
                daemon=True
            )
            self.sniffer_thread.start()
            
        except Exception as e:
            print(f"Error starting network sniffing: {e}")
            self.monitoring = False
    
    def _sniff_packets(self, interface, filter_string):
        """Internal method to sniff packets"""
        try:
            sniff(
                iface=interface,
                prn=self.packet_callback,
                filter=filter_string,
                store=0,
                stop_filter=lambda x: not self.monitoring
            )
        except Exception as e:
            print(f"Error in packet sniffing: {e}")
        finally:
            self.monitoring = False
    
    def stop_sniffing(self):
        """Stop network sniffing"""
        self.monitoring = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        print("Network sniffing stopped")
    
    def get_connection_stats(self):
        """Get statistics about network connections"""
        return {
            'total_packets': self.packet_count,
            'suspicious_connections': len(self.suspicious_connections),
            'connection_stats': dict(self.connection_stats),
            'recent_suspicious': list(self.suspicious_connections)[-10:] if self.suspicious_connections else []
        }
    
    def add_suspicious_ip(self, ip):
        """Add an IP to the suspicious list"""
        self.suspicious_ips.add(ip)
    
    def add_suspicious_domain(self, domain):
        """Add a domain to the suspicious list"""
        self.suspicious_domains.add(domain)
    
    def get_active_connections(self):
        """Get currently active network connections"""
        try:
            connections = psutil.net_connections()
            active_connections = []
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    active_connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            return active_connections
            
        except Exception as e:
            print(f"Error getting active connections: {e}")
            return []

# Global instance
network_sniffer = NetworkSniffer() 