# models.py in your Django app
from django.db import models

class ContactMessage(models.Model):
    INQUIRY_CHOICES = [
        ('account_closure', 'Account closure & deletion'),
        ('general_inquiry', 'General inquiry'),
        ('feature_request', 'Feature request'),
    ]
    
    inquiry_type = models.CharField(
        max_length=20,
        choices=INQUIRY_CHOICES,
        default='general_inquiry',
    )
    email = models.EmailField()
    username = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.username} ({self.inquiry_type})"
