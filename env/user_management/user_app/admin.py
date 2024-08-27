from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff')
admin.site .register(UserToken)
admin.site .register(UserProfile)
admin.site.register(LoginSettings)
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

class LoginSettingsAdmin(admin.ModelAdmin):
    list_display = ('max_attempts', 'lockout_duration')
    
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'timestamp', 'successful', 'ip_address', 'is_locked_out')
    list_filter = ('successful', 'is_locked_out', 'timestamp')
    search_fields = ('user__username', 'ip_address')

admin.site.register(LoginAttempt, LoginAttemptAdmin)

