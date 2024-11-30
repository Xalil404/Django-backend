# tasks/admin.py
from django.contrib import admin
from .models import Task

# Register the Task model with the admin site
@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ['id', 'title', 'description', 'created_at', 'user']
    search_fields = ['title', 'description', 'user__username']
    list_filter = ['created_at', 'user']
