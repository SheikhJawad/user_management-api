from django.db import models
from django.contrib.auth.models import User
from django_prometheus.models import ExportModelOperationsMixin
from django.conf import settings
from django.utils import timezone

class UserToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='token')
    access_token = models.TextField()
    refresh_token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_logged_in = models.BooleanField(default=True)
    
    def logout(self):
        self.is_logged_in = False
        self.access_token = ''
        self.save()

    def __str__(self):
        return f'Tokens for {self.user.username}'


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    password_reset_token = models.CharField(max_length=255, blank=True, null=True)
    password_change_count = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.user.username
    
class LoginAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_locked_out = models.BooleanField(default=False)

    def __str__(self):
        return f'Login attempt by {self.user} on {self.timestamp}'

    class Meta:
        ordering = ['-timestamp']

    @classmethod
    def get_recent_attempts(cls, user, minutes=30):
        cutoff_time = timezone.now() - timezone.timedelta(minutes=minutes)
        return cls.objects.filter(user=user, timestamp__gt=cutoff_time, successful=False)

class LoginSettings(models.Model):
    max_attempts = models.PositiveIntegerField(default=5)
    lockout_duration = models.PositiveIntegerField(default=30)  # in minutes
    def __str__(self):
        return f'Login settings: max attempts: {self.max_attempts}, lockout duration: {self.lockout_duration} minutes'


    @classmethod
    def get_settings(cls):
        return cls.objects.first() or cls.objects.create()
    
    
# class UserProfile(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     password_reset_token = models.CharField(max_length=255, blank=True, null=True)
#     password_change_count = models.PositiveIntegerField(default=0)
#     failed_attempts = models.IntegerField(default=0)
#     lockout_until = models.DateTimeField(null=True, blank=True)

#     def reset_failed_attempts(self):
#         self.failed_attempts = 0
#         self.lockout_until = None
#         self.save()

#     def __str__(self):
#         return self.user.username