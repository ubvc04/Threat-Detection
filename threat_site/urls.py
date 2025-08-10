"""threat_site URL Configuration"""
from django.contrib import admin
from django.urls import path, include
from dashboard import views

urlpatterns = [
    path('', views.dashboard, name='home'),
    path('admin/', admin.site.urls),
    path('dashboard/', include('dashboard.urls')),
    path('ml-tester/', views.ml_model_tester, name='ml_tester_root'),
] 