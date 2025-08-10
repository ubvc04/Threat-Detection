from django.db import models
from django.utils import timezone

def get_current_time():
    """Returns the current time with timezone awareness"""
    return timezone.now()

class Alert(models.Model):
    """Model for storing threat detection alerts"""
    ALERT_TYPES = [
        ('PHISHING', 'Phishing'),
        ('SPAM', 'Spam'),
        ('MALWARE', 'Malware'),
        ('USB', 'USB Activity'),
        ('NETWORK', 'Network'),
        ('PROCESS', 'Process'),
        ('SYSMON', 'Sysmon'),
        ('SYSTEM', 'System'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    timestamp = models.DateTimeField(default=get_current_time)
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='MEDIUM')
    message = models.TextField()
    source = models.CharField(max_length=100)
    details = models.JSONField(default=dict, blank=True)
    resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.alert_type} - {self.message[:50]}"

class SystemInfo(models.Model):
    """Model for storing system information"""
    timestamp = models.DateTimeField(default=get_current_time)
    cpu_percent = models.FloatField()
    memory_percent = models.FloatField()
    disk_usage = models.FloatField()
    network_connections = models.IntegerField()
    active_processes = models.IntegerField()
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"System Info - {self.timestamp}"

class ProcessLog(models.Model):
    """Model for storing process monitoring logs"""
    timestamp = models.DateTimeField(default=get_current_time)
    process_name = models.CharField(max_length=255)
    process_id = models.IntegerField()
    cpu_percent = models.FloatField()
    memory_percent = models.FloatField()
    command_line = models.TextField(blank=True)
    suspicious = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.process_name} (PID: {self.process_id})" 