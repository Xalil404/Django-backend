# core/admin.py
# Make sure to add Core to installed apps in settings
from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

# Customizing UserAdmin to display the 'id' column
class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active')

# Unregister the default User admin and register your custom one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
