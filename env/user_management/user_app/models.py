from django.db import models
from django.contrib.auth.models import User
from django_prometheus.models import ExportModelOperationsMixin


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

