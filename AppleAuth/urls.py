# urls.py
from django.urls import path
from .views import apple_auth_web, apple_auth_redirect, apple_auth_mobile

urlpatterns = [
    path('api/auth/apple/web/', apple_auth_web, name='apple-auth-web'),
    path('api/auth/apple/web/redirect/', apple_auth_redirect, name='apple_auth_redirect'),
    path('api/auth/apple/mobile/', apple_auth_mobile, name='apple-auth-mobile'),
]
