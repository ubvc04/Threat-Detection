from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('system-monitor/', views.system_monitor, name='system_monitor'),
    path('threat-analytics/', views.threat_analytics, name='threat_analytics'),
    path('kernel-monitoring/', views.kernel_monitoring_dashboard, name='kernel_monitoring'),
    
    # ML Model Testing
    path('ml-tester/', views.ml_model_tester, name='ml_model_tester'),
    
    # API endpoints
    path('api/toggle-theme/', views.toggle_theme, name='toggle_theme'),
    path('api/system-stats/', views.api_system_stats, name='api_system_stats'),
    path('api/alerts-data/', views.api_alerts_data, name='api_alerts_data'),
    path('api/process-data/', views.api_process_data, name='api_process_data'),
    path('api/alerts/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('api/test-ml-model/', views.test_ml_model, name='test_ml_model'),
    
    # Advanced Security Features
    path('advanced-security/', views.advanced_security_dashboard, name='advanced_security_dashboard'),
    path('api/advanced-security/start/', views.start_advanced_security, name='start_advanced_security'),
    path('api/advanced-security/stop/', views.stop_advanced_security, name='stop_advanced_security'),
    path('api/advanced-security/status/', views.get_advanced_security_status, name='get_advanced_security_status'),
    path('api/advanced-security/configure/', views.configure_advanced_security, name='configure_advanced_security'),
    path('api/advanced-security/test/', views.test_advanced_security_module, name='test_advanced_security_module'),
    path('api/advanced-security/report/', views.get_security_report, name='get_security_report'),
] 