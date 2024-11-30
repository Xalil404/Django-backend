from rest_framework import serializers
from .models import ContactMessage

class ContactMessageSerializer(serializers.ModelSerializer):
    # Inquiry type field with choices for the selector (you can use the model choices directly)
    inquiry_type = serializers.ChoiceField(
        choices=ContactMessage.INQUIRY_CHOICES
    )

    # Email field
    email = serializers.EmailField()

    # Username field
    username = serializers.CharField(max_length=100)

    # Message field - use TextField for large text inputs (message)
    message = serializers.CharField(style={'base_template': 'textarea.html'})

    class Meta:
        model = ContactMessage
        fields = ['inquiry_type', 'email', 'username', 'message', 'created_at']
