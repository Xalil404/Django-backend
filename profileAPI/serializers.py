from rest_framework import serializers
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    # Optional: Include username or other user-specific details
    username = serializers.CharField(source='user.username', read_only=True)  # If you want to include username

    class Meta:
        model = Profile
        fields = ['id', 'bio', 'profile_picture', 'username']  # Add more fields if needed
