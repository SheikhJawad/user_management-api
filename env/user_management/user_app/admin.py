# from django.contrib import admin
# from .models import *
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# class UserAdmin(BaseUserAdmin):
#     list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff')
# admin.site .register(UserToken)
# admin.site .register(UserProfile)
# admin.site.register(LoginSettings)
# admin.site.unregister(User)
# admin.site.register(User, UserAdmin)

# class LoginSettingsAdmin(admin.ModelAdmin):
#     list_display = ('max_attempts', 'lockout_duration')
    
# class LoginAttemptAdmin(admin.ModelAdmin):
#     list_display = ('user', 'timestamp', 'successful', 'ip_address', 'is_locked_out')
#     list_filter = ('successful', 'is_locked_out', 'timestamp')
#     search_fields = ('user__username', 'ip_address')

# admin.site.register(LoginAttempt, LoginAttemptAdmin)

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserToken, UserProfile, LoginSettings, LoginAttempt

class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('username', 'email') 
    list_filter = ('is_active', 'is_staff', 'date_joined')
    ordering = ('-date_joined',)

admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'access_token', 'is_logged_in')
    list_filter = ('is_logged_in',)
    search_fields = ('user__username', 'user__email')  

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'successful', 'ip_address', 'timestamp')
    list_filter = ('successful', 'timestamp')
    search_fields = ('user__username', 'ip_address')  
    ordering = ('-timestamp',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'password_change_count', 'password_reset_token')
    search_fields = ('user__username', 'user__email')  
    list_filter = ('password_change_count',)

@admin.register(LoginSettings)
class LoginSettingsAdmin(admin.ModelAdmin):
    list_display = ('max_attempts', 'lockout_duration')
    search_fields = ('max_attempts',) 
    list_filter = ('lockout_duration',)
