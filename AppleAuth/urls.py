# urls.py
from django.urls import path
from .views import apple_auth_web

urlpatterns = [
    path('api/auth/apple/web/', apple_auth_web, name='apple-auth-web'),
]
