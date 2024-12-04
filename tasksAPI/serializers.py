# tasks/serializers.py
from rest_framework import serializers
from .models import Task

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'created_at', 'user']

    def update(self, instance, validated_data):
        # Prevent the user from being overwritten during update
        validated_data.pop('user', None)
        return super().update(instance, validated_data)
