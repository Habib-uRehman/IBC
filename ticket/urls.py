from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # User Management
    path('user/register/', views.register_user, name='register_user'),
    path('users/', views.users_list, name='users_list'),
    path('user/<uuid:user_id>/', views.user_detail, name='user_detail'),
    path('user/<uuid:user_id>/edit/', views.edit_user, name='edit_user'),
    path('user/<uuid:user_id>/delete/', views.delete_user, name='delete_user'),
    
    # Ticket Management
    path('ticket/generate/<uuid:user_id>/', views.generate_ticket, name='generate_ticket'),
    path('ticket/<uuid:ticket_id>/', views.ticket_detail, name='ticket_detail'),
    path('ticket/print/<uuid:ticket_id>/', views.print_ticket, name='print_ticket'),
    path('tickets/', views.ticket_list, name='ticket_list'),
    path('search/', views.ticket_search, name='ticket_search'),
    path('ticket/<uuid:ticket_id>/delete/', views.delete_ticket, name='delete_ticket'),
    
    # Scanning
    path('scan/', views.scan_monitor, name='scan_monitor'),
    path('scan/process/', views.process_scan, name='process_scan'),
    
    # Reports and Statistics
    path('stats/', views.ticket_stats, name='ticket_stats'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    
    # Settings
    path('settings/', views.settings_view, name='settings'),
    
    # Public Verification (for QR codes)
    path('verify/<uuid:ticket_id>/', views.verify_ticket, name='verify_ticket'),

    # Operator URLs
    path('operator/dashboard/', views.operator_dashboard, name='operator_dashboard'),
    path('operator/users/', views.operator_users, name='operator_users'),
    
    # Admin URLs
    path('manager/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('manager/quotas/', views.quota_management, name='quota_management'),
    
    # Financial Reports
    path('reports/financial/', views.financial_reports, name='financial_reports'),
    path('reports/financial/export/', views.export_financial_report, name='export_financial_report'),
    
    path('debug/operators/', views.debug_ticket_operators, name='debug_operators'),
    path('fix-operators/', views.fix_operator_relationships, name='fix_operators'),
    # Root URL
    path('', views.dashboard, name='index'),
]