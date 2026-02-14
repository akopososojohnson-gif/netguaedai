from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('connections/', views.connections_view, name='connections'),
    path('threats/', views.threats_view, name='threats'),
    path('alerts/', views.alerts_view, name='alerts'),
    
    # API endpoints
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/connections/', views.api_connections, name='api_connections'),
    path('api/threats/', views.api_threats, name='api_threats'),
    path('api/alerts/recent/', views.api_alerts_recent, name='api_alerts_recent'),
    path('api/alerts/<int:alert_id>/acknowledge/', views.api_alerts_acknowledge, name='api_alerts_acknowledge'),
    path('api/search/', views.api_search, name='api_search'),
]
