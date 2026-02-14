from django.db import models
from django.contrib.auth.models import User


class AlertRule(models.Model):
    """User-configurable alert rules"""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    
    # Rule conditions
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    threat_type = models.CharField(max_length=50, blank=True)
    min_threat_score = models.FloatField(default=0.5)
    
    # Actions
    email_alert = models.BooleanField(default=False)
    webhook_url = models.URLField(blank=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name


class UserProfile(models.Model):
    """Extended user profile"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    timezone = models.CharField(max_length=50, default='UTC')
    items_per_page = models.IntegerField(default=50)
    email_alerts = models.BooleanField(default=True)
    
    def __str__(self):
        return self.user.username
