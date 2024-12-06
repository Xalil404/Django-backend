from rest_framework import serializers

class AppleAuthSerializer(serializers.Serializer):
    apple_token = serializers.CharField(required=True)
