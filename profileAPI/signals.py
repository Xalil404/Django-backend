from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        # If the user is newly created, create a corresponding profile
        Profile.objects.create(user=instance)
    else:
        if hasattr(instance, 'profile'):
            # If the user already has a profile, save the profile
            instance.profile.save()

