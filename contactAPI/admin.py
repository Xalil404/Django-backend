from django.contrib import admin
from .models import ContactMessage

class ContactMessageAdmin(admin.ModelAdmin):
    # Specify the fields to display in the list view
    list_display = ('inquiry_type', 'email', 'username', 'message', 'created_at')

# Register the model with the custom admin
admin.site.register(ContactMessage, ContactMessageAdmin)

