from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff')
admin.site .register(UserToken)
admin.site .register(UserProfile)
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

