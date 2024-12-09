# urls.py
from django.urls import path
from .views import apple_auth_web, apple_auth_web_redirect, apple_auth_web_callback

urlpatterns = [
    path('api/auth/apple/web/', apple_auth_web, name='apple-auth-web'),
    path("api/auth/apple/redirect", apple_auth_web_redirect, name="apple-auth-redirect"),
    path("api/auth/apple/callback", apple_auth_web_callback, name="apple-auth-callback"),
]
