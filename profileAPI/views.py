from django.shortcuts import render

# Create your views here.
from rest_framework import generics
from .models import Profile
from .serializers import ProfileSerializer
from rest_framework.permissions import IsAuthenticated

# Retrieve or update the logged-in user's profile
class ProfileDetailUpdateView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # This ensures the profile returned is the one related to the logged-in user
        return self.request.user.profile
