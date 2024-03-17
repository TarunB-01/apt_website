from django.contrib import admin
from django.urls import path,include
from pen_test_app import views

urlpatterns = [
    path('',views.home,name='home'),
    path('signup/',views.registerView,name='reg-form'),
    path('signin/',views.loginView,name='login'),
    path('dashboard/',views.dashboard,name='dashboard'),
    path('scan_with_nmap_and_zap/', views.scan_with_nmap_and_zap_view, name='scan_with_nmap_and_zap'),
    path('scan_form/',views.submit_url_view,name='scan_form'),
    path('fetch-scan-status/', views.fetch_scan_status, name='fetch_scan_status'),
    path('reports/<int:report_id>/download/', views.download_report, name='download_report')

]
    
