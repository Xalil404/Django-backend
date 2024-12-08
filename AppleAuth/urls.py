# urls.py
from django.urls import path
from .views import apple_auth_web, apple_auth_web_redirect

urlpatterns = [
    path('api/auth/apple/web/', apple_auth_web, name='apple-auth-web'),
    path('api/auth/apple/web-redirect/', apple_auth_web_redirect, name='apple-auth-web-redirect'),
]
