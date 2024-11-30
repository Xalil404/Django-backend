from django.contrib import admin
from .models import Profile

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'bio', 'profile_picture')
    search_fields = ('user__username', 'bio')
    list_filter = ('user',)
