from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
import json
from datetime import datetime, timedelta
from .models import Alert, SystemInfo, ProcessLog
import psutil
import pickle
import os
from pathlib import Path
import numpy as np
from detection_core.advanced_security_manager import AdvancedSecurityManager
from django.utils import timezone

def dashboard(request):
    """Enhanced dashboard with advanced analytics"""
    # Get current theme
    current_theme = request.session.get('theme', 'light')
    
    # Get recent alerts
    recent_alerts = Alert.objects.order_by('-timestamp')[:10]
    
    # Get system statistics
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get network statistics
        network_stats = psutil.net_io_counters()
        
        # Get process count
        process_count = len(psutil.pids())
        
        # Get alert statistics
        total_alerts = Alert.objects.count()
        critical_alerts = Alert.objects.filter(severity='CRITICAL').count()
        high_alerts = Alert.objects.filter(severity='HIGH').count()
        medium_alerts = Alert.objects.filter(severity='MEDIUM').count()
        low_alerts = Alert.objects.filter(severity='LOW').count()
        
        # Get alerts by type
        alert_types = {}
        for alert in Alert.objects.all():
            alert_type = alert.alert_type
            if alert_type not in alert_types:
                alert_types[alert_type] = 0
            alert_types[alert_type] += 1
        
        # Get recent system info
        recent_system_info = SystemInfo.objects.order_by('-timestamp')[:5]
        
        # Calculate threat score (0-100)
        threat_score = min(100, (critical_alerts * 25 + high_alerts * 15 + medium_alerts * 5 + low_alerts * 1))
        
        context = {
            'current_theme': current_theme,
            'recent_alerts': recent_alerts,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'network_bytes_sent': network_stats.bytes_sent,
            'network_bytes_recv': network_stats.bytes_recv,
            'process_count': process_count,
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'medium_alerts': medium_alerts,
            'low_alerts': low_alerts,
            'alert_types': alert_types,
            'recent_system_info': recent_system_info,
            'threat_score': threat_score,
            'system_status': 'Healthy' if threat_score < 30 else 'Warning' if threat_score < 70 else 'Critical'
        }
        
    except Exception as e:
        context = {
            'current_theme': current_theme,
            'error': str(e),
            'system_status': 'Error'
        }
    
    return render(request, 'dashboard/dashboard.html', context)

def alerts_list(request):
    """Enhanced alerts list with filtering and search"""
    current_theme = request.session.get('theme', 'light')
    
    # Get filter parameters
    severity_filter = request.GET.get('severity', '')
    alert_type_filter = request.GET.get('alert_type', '')
    resolved_filter = request.GET.get('resolved', '')
    search_query = request.GET.get('search', '')
    
    # Build query
    alerts = Alert.objects.all()
    
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    
    if alert_type_filter:
        alerts = alerts.filter(alert_type=alert_type_filter)
    
    if resolved_filter:
        if resolved_filter == 'true':
            alerts = alerts.filter(resolved=True)
        elif resolved_filter == 'false':
            alerts = alerts.filter(resolved=False)
    
    if search_query:
        alerts = alerts.filter(message__icontains=search_query)
    
    # Get unique values for filters
    severities = Alert.objects.values_list('severity', flat=True).distinct()
    alert_types = Alert.objects.values_list('alert_type', flat=True).distinct()
    
    # Create severity levels mapping
    severity_levels = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low')
    ]
    
    # Create alert types mapping
    alert_types_mapping = [
        ('NETWORK', 'Network'),
        ('PROCESS', 'Process'),
        ('MALWARE', 'Malware'),
        ('SYSTEM', 'System'),
        ('REGISTRY', 'Registry'),
        ('FILE', 'File')
    ]
    
    # Pagination
    paginator = Paginator(alerts.order_by('-timestamp'), 50)  # 50 alerts per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'current_theme': current_theme,
        'page_obj': page_obj,
        'severity_levels': severity_levels,
        'alert_types': alert_types_mapping,
        'current_filters': {
            'severity': severity_filter,
            'alert_type': alert_type_filter,
            'resolved': resolved_filter,
            'search': search_query
        },
        'search_query': search_query
    }
    
    return render(request, 'dashboard/alerts_list.html', context)

def system_monitor(request):
    """Enhanced system monitor with real-time data"""
    current_theme = request.session.get('theme', 'light')
    
    try:
        # Get system information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get network information
        network_stats = psutil.net_io_counters()
        network_connections = psutil.net_connections()
        
        # Get process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                proc_info = proc.info
                if proc_info['cpu_percent'] > 0 or proc_info['memory_percent'] > 1:
                    processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort processes by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        top_processes = processes[:10]
        
        # Get recent process logs
        recent_process_logs = ProcessLog.objects.order_by('-timestamp')[:20]
        
        # Get system info history for charts
        system_history = SystemInfo.objects.order_by('-timestamp')[:100]
        
        context = {
            'current_theme': current_theme,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used': memory.used,
            'memory_total': memory.total,
            'disk_percent': disk.percent,
            'disk_used': disk.used,
            'disk_total': disk.total,
            'network_bytes_sent': network_stats.bytes_sent,
            'network_bytes_recv': network_stats.bytes_recv,
            'network_connections_count': len(network_connections),
            'top_processes': top_processes,
            'recent_process_logs': recent_process_logs,
            'system_history': system_history
        }
        
    except Exception as e:
        context = {
            'current_theme': current_theme,
            'error': str(e)
        }
    
    return render(request, 'dashboard/system_monitor.html', context)

@csrf_exempt
def toggle_theme(request):
    """Handle theme toggle via AJAX"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_theme = data.get('theme', 'light')
            request.session['theme'] = new_theme
            return JsonResponse({'status': 'success', 'theme': new_theme})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def api_system_stats(request):
    """API endpoint for real-time system statistics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network_stats = psutil.net_io_counters()
        
        # Get recent alerts count
        recent_alerts = Alert.objects.filter(
            timestamp__gte=datetime.now() - timedelta(hours=1)
        ).count()
        
        # Get threat score
        critical_alerts = Alert.objects.filter(severity='CRITICAL').count()
        high_alerts = Alert.objects.filter(severity='HIGH').count()
        medium_alerts = Alert.objects.filter(severity='MEDIUM').count()
        low_alerts = Alert.objects.filter(severity='LOW').count()
        threat_score = min(100, (critical_alerts * 25 + high_alerts * 15 + medium_alerts * 5 + low_alerts * 1))
        
        return JsonResponse({
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'network_bytes_sent': network_stats.bytes_sent,
            'network_bytes_recv': network_stats.bytes_recv,
            'recent_alerts': recent_alerts,
            'threat_score': threat_score,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def api_alerts_data(request):
    """API endpoint for alerts data (for charts)"""
    try:
        # Get alerts by severity for the last 24 hours
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        alerts_data = {}
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = Alert.objects.filter(
                severity=severity,
                timestamp__range=(start_time, end_time)
            ).count()
            alerts_data[severity] = count
        
        # Get alerts by type
        alert_types_data = {}
        for alert_type in Alert.objects.values_list('alert_type', flat=True).distinct():
            count = Alert.objects.filter(
                alert_type=alert_type,
                timestamp__range=(start_time, end_time)
            ).count()
            alert_types_data[alert_type] = count
        
        return JsonResponse({
            'alerts_by_severity': alerts_data,
            'alerts_by_type': alert_types_data,
            'time_range': '24h'
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def api_process_data(request):
    """API endpoint for process data"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                proc_info = proc.info
                if proc_info['cpu_percent'] > 0 or proc_info['memory_percent'] > 1:
                    processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return JsonResponse({
            'processes': processes[:20],  # Top 20 processes
            'total_processes': len(psutil.pids()),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def threat_analytics(request):
    """Advanced threat analytics page"""
    current_theme = request.session.get('theme', 'light')
    
    try:
        # Get threat statistics
        total_alerts = Alert.objects.count()
        critical_alerts = Alert.objects.filter(severity='CRITICAL').count()
        high_alerts = Alert.objects.filter(severity='HIGH').count()
        medium_alerts = Alert.objects.filter(severity='MEDIUM').count()
        low_alerts = Alert.objects.filter(severity='LOW').count()
        
        # Calculate threat score
        threat_score = min(100, (critical_alerts * 25 + high_alerts * 15 + medium_alerts * 5 + low_alerts * 1))
        
        # Get alerts by type
        alert_types = {}
        for alert in Alert.objects.all():
            alert_type = alert.alert_type
            if alert_type not in alert_types:
                alert_types[alert_type] = 0
            alert_types[alert_type] += 1
        
        # Get recent threats
        recent_threats = Alert.objects.filter(
            severity__in=['CRITICAL', 'HIGH']
        ).order_by('-timestamp')[:10]
        
        # Get threat timeline (last 7 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        threat_timeline = []
        for i in range(7):
            date = start_date + timedelta(days=i)
            count = Alert.objects.filter(
                timestamp__date=date.date()
            ).count()
            threat_timeline.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        context = {
            'current_theme': current_theme,
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'medium_alerts': medium_alerts,
            'low_alerts': low_alerts,
            'threat_score': threat_score,
            'alert_types': alert_types,
            'recent_threats': recent_threats,
            'threat_timeline': threat_timeline,
            'system_status': 'Healthy' if threat_score < 30 else 'Warning' if threat_score < 70 else 'Critical'
        }
        
    except Exception as e:
        context = {
            'current_theme': current_theme,
            'error': str(e)
        }
    
    return render(request, 'dashboard/threat_analytics.html', context)

def kernel_monitoring_dashboard(request):
    """Advanced kernel-level monitoring dashboard"""
    current_theme = request.session.get('theme', 'light')
    
    try:
        # Get kernel-level alerts
        kernel_alerts = Alert.objects.filter(
            source__in=['Packet Analyzer', 'Process Behavior Analyzer', 'Registry Monitor', 
                       'Service Monitor', 'File System Monitor', 'Kernel Event Monitor', 
                       'Memory Analyzer', 'Network Behavior Analyzer']
        ).order_by('-timestamp')[:20]
        
        # Get system statistics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get network statistics
        network_stats = psutil.net_io_counters()
        network_connections = psutil.net_connections()
        
        # Get process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'connections']):
            try:
                proc_info = proc.info
                if proc_info['cpu_percent'] > 0 or proc_info['memory_percent'] > 1:
                    processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort processes by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        top_processes = processes[:10]
        
        # Get recent alerts by type
        recent_network_alerts = Alert.objects.filter(alert_type='NETWORK').order_by('-timestamp')[:5]
        recent_process_alerts = Alert.objects.filter(alert_type='PROCESS').order_by('-timestamp')[:5]
        recent_system_alerts = Alert.objects.filter(alert_type='SYSTEM').order_by('-timestamp')[:5]
        
        # Calculate kernel-level threat score
        kernel_alerts_count = Alert.objects.filter(
            source__in=['Packet Analyzer', 'Process Behavior Analyzer', 'Registry Monitor', 
                       'Service Monitor', 'File System Monitor', 'Kernel Event Monitor', 
                       'Memory Analyzer', 'Network Behavior Analyzer']
        ).count()
        
        kernel_threat_score = min(100, kernel_alerts_count * 5)
        
        context = {
            'current_theme': current_theme,
            'kernel_alerts': kernel_alerts,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'network_bytes_sent': network_stats.bytes_sent,
            'network_bytes_recv': network_stats.bytes_recv,
            'network_connections_count': len(network_connections),
            'top_processes': top_processes,
            'recent_network_alerts': recent_network_alerts,
            'recent_process_alerts': recent_process_alerts,
            'recent_system_alerts': recent_system_alerts,
            'kernel_threat_score': kernel_threat_score,
            'kernel_alerts_count': kernel_alerts_count,
            'system_status': 'Healthy' if kernel_threat_score < 30 else 'Warning' if kernel_threat_score < 70 else 'Critical'
        }
        
    except Exception as e:
        context = {
            'current_theme': current_theme,
            'error': str(e)
        }
    
    return render(request, 'dashboard/kernel_monitoring.html', context)

@csrf_exempt
def resolve_alert(request, alert_id):
    """API endpoint to mark an alert as resolved"""
    if request.method == 'POST':
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.resolved = True
            alert.save()
            return JsonResponse({'success': True, 'message': 'Alert marked as resolved'})
        except Alert.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Alert not found'}, status=404)
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

def ml_model_tester(request):
    """ML Model Testing Interface"""
    current_theme = request.session.get('theme', 'light')
    
    # Load available models
    models_dir = Path("trained_models")
    available_models = []
    
    if models_dir.exists():
        summary_path = models_dir / "comprehensive_model_summary.json"
        if summary_path.exists():
            try:
                with open(summary_path, 'r') as f:
                    summary = json.load(f)
                available_models = list(summary['models'].keys())
            except:
                pass
    
    context = {
        'current_theme': current_theme,
        'available_models': available_models
    }
    
    return render(request, 'dashboard/ml_model_tester.html', context)

@csrf_exempt
def test_ml_model(request):
    """Test ML model via AJAX"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            test_type = data.get('type')  # 'sms' or 'url'
            test_text = data.get('text', '').strip()
            
            if not test_text:
                return JsonResponse({
                    'success': False, 
                    'message': 'Test text cannot be empty'
                })
            
            # Load models
            models_dir = Path("trained_models")
            if not models_dir.exists():
                return JsonResponse({
                    'success': False, 
                    'message': 'No trained models found'
                })
            
            # Load text model for both SMS and URL testing
            model_file = models_dir / "text_spam_dataset_SVM.pkl"
            vectorizer_file = models_dir / "text_spam_dataset_preprocessor.pkl"
            
            if not model_file.exists() or not vectorizer_file.exists():
                return JsonResponse({
                    'success': False, 
                    'message': 'Text model not found'
                })
            
            # Load model and vectorizer
            with open(model_file, 'rb') as f:
                model = pickle.load(f)
            
            with open(vectorizer_file, 'rb') as f:
                vectorizer = pickle.load(f)
            
            # Vectorize and predict
            X_test = vectorizer.transform([test_text])
            prediction = model.predict(X_test)[0]
            probability = model.predict_proba(X_test)[0]
            
            # Format results
            if test_type == 'sms':
                result = {
                    'prediction': 'SPAM' if prediction == 1 else 'HAM',
                    'confidence': float(max(probability)),
                    'spam_probability': float(probability[1] if len(probability) > 1 else probability[0]),
                    'ham_probability': float(probability[0] if len(probability) > 1 else 0)
                }
            else:  # url
                result = {
                    'prediction': 'PHISHING' if prediction == 1 else 'SAFE',
                    'confidence': float(max(probability)),
                    'phishing_probability': float(probability[1] if len(probability) > 1 else probability[0]),
                    'safe_probability': float(probability[0] if len(probability) > 1 else 0)
                }
            
            return JsonResponse({
                'success': True,
                'result': result
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False, 
                'message': f'Error testing model: {str(e)}'
            })
    
    return JsonResponse({
        'success': False, 
        'message': 'Invalid request method'
    })

# Advanced Security Features Views

def advanced_security_dashboard(request):
    """Advanced Security Dashboard"""
    current_theme = request.session.get('theme', 'light')
    
    # Initialize advanced security manager (singleton pattern)
    if not hasattr(advanced_security_dashboard, 'security_manager'):
        advanced_security_dashboard.security_manager = AdvancedSecurityManager(
            alert_callback=create_alert_callback
        )
    
    security_manager = advanced_security_dashboard.security_manager
    
    # Get comprehensive status
    status = security_manager.get_comprehensive_status()
    
    # Get recent advanced security alerts
    recent_advanced_alerts = Alert.objects.filter(
        source__in=['credential_theft_detector', 'brute_force_detector', 
                    'signature_verifier', 'clipboard_monitor', 'insider_threat_detector',
                    'Zero Trust Monitor']
    ).order_by('-timestamp')[:10]
    
    context = {
        'current_theme': current_theme,
        'security_status': status,
        'recent_advanced_alerts': recent_advanced_alerts,
        'modules': [
            {
                'name': 'Credential Theft Detection',
                'description': 'Monitors LSASS access and suspicious credential dumping tools',
                'icon': 'fa-key',
                'status': status['modules'].get('credential_theft', {}).get('monitoring', False)
            },
            {
                'name': 'Brute Force Detection',
                'description': 'Monitors Windows Security Event Logs for failed login attempts',
                'icon': 'fa-shield-alt',
                'status': status['modules'].get('brute_force', {}).get('monitoring', False)
            },
            {
                'name': 'Signature Verification',
                'description': 'Verifies digital signatures and file hashes',
                'icon': 'fa-certificate',
                'status': status['modules'].get('signature_verification', {}).get('monitoring', False)
            },
            {
                'name': 'Clipboard Monitoring',
                'description': 'Detects sensitive information in clipboard',
                'icon': 'fa-clipboard',
                'status': status['modules'].get('clipboard_monitoring', {}).get('monitoring', False)
            },
            {
                'name': 'Insider Threat Detection',
                'description': 'Monitors file transfers and behavioral anomalies',
                'icon': 'fa-user-secret',
                'status': status['modules'].get('insider_threat', {}).get('monitoring', False)
            },
            {
                'name': 'Zero Trust Security',
                'description': 'Continuous identity, device, and resource access verification',
                'icon': 'fa-lock',
                'status': status['modules'].get('zero_trust', {}).get('monitoring', False)
            }
        ]
    }
    
    return render(request, 'dashboard/advanced_security_dashboard.html', context)

@csrf_exempt
def start_advanced_security(request):
    """Start advanced security monitoring"""
    if request.method == 'POST':
        try:
            if not hasattr(advanced_security_dashboard, 'security_manager'):
                advanced_security_dashboard.security_manager = AdvancedSecurityManager(
                    alert_callback=create_alert_callback
                )
            
            security_manager = advanced_security_dashboard.security_manager
            security_manager.start_all_monitoring()
            
            return JsonResponse({
                'success': True,
                'message': 'Advanced security monitoring started successfully'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error starting advanced security: {str(e)}'
            })
    
    return JsonResponse({
        'success': False,
        'message': 'Invalid request method'
    })

@csrf_exempt
def stop_advanced_security(request):
    """Stop advanced security monitoring"""
    if request.method == 'POST':
        try:
            if hasattr(advanced_security_dashboard, 'security_manager'):
                security_manager = advanced_security_dashboard.security_manager
                security_manager.stop_all_monitoring()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Advanced security monitoring stopped successfully'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Advanced security manager not initialized'
                })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error stopping advanced security: {str(e)}'
            })
    
    return JsonResponse({
        'success': False,
        'message': 'Invalid request method'
    })

@csrf_exempt
def get_advanced_security_status(request):
    """Get advanced security status via AJAX"""
    try:
        if hasattr(advanced_security_dashboard, 'security_manager'):
            security_manager = advanced_security_dashboard.security_manager
            status = security_manager.get_comprehensive_status()
            
            return JsonResponse({
                'success': True,
                'status': status
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Advanced security manager not initialized'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error getting status: {str(e)}'
        })

@csrf_exempt
def configure_advanced_security(request):
    """Configure advanced security module settings"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            module_name = data.get('module_name')
            config = data.get('config', {})
            
            if not module_name:
                return JsonResponse({
                    'success': False,
                    'message': 'Module name is required'
                })
            
            if hasattr(advanced_security_dashboard, 'security_manager'):
                security_manager = advanced_security_dashboard.security_manager
                security_manager.configure_module(module_name, config)
                
                return JsonResponse({
                    'success': True,
                    'message': f'Module {module_name} configured successfully'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Advanced security manager not initialized'
                })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error configuring module: {str(e)}'
            })
    
    return JsonResponse({
        'success': False,
        'message': 'Invalid request method'
    })

@csrf_exempt
def test_advanced_security_module(request):
    """Test specific advanced security module"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            module_name = data.get('module_name')
            test_data = data.get('test_data', {})
            
            if not module_name:
                return JsonResponse({
                    'success': False,
                    'message': 'Module name is required'
                })
            
            if hasattr(advanced_security_dashboard, 'security_manager'):
                security_manager = advanced_security_dashboard.security_manager
                result = security_manager.test_module(module_name, test_data)
                
                return JsonResponse({
                    'success': True,
                    'result': result
                })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Advanced security manager not initialized'
                })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error testing module: {str(e)}'
            })
    
    return JsonResponse({
        'success': False,
        'message': 'Invalid request method'
    })

@csrf_exempt
def get_security_report(request):
    """Get comprehensive security report"""
    try:
        if hasattr(advanced_security_dashboard, 'security_manager'):
            security_manager = advanced_security_dashboard.security_manager
            report = security_manager.get_security_report()
            
            return JsonResponse({
                'success': True,
                'report': report
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Advanced security manager not initialized'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error generating report: {str(e)}'
        })

@csrf_exempt
def get_zero_trust_report(request):
    """Get Zero Trust security report"""
    try:
        if hasattr(advanced_security_dashboard, 'security_manager'):
            security_manager = advanced_security_dashboard.security_manager
            zero_trust_report = security_manager.zero_trust_monitor.get_trust_report()
            
            return JsonResponse({
                'success': True,
                'report': zero_trust_report
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Advanced security manager not initialized'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error generating Zero Trust report: {str(e)}'
        })

def create_alert_callback(alert_data):
    """Callback function to create alerts from advanced security modules"""
    try:
        Alert.objects.create(
            severity=alert_data.get('severity', 'MEDIUM'),
            title=alert_data.get('title', 'Advanced Security Alert'),
            description=alert_data.get('description', ''),
            alert_type=alert_data.get('alert_type', 'advanced_security'),
            source=alert_data.get('source', 'advanced_security_manager'),
            timestamp=alert_data.get('timestamp', timezone.now())
        )
    except Exception as e:
        print(f"Error creating alert: {e}") 