"""
URL configuration for Core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from .views import handler404
from django.contrib import admin
from django.urls import path, include
# For swagger & Redoc
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
#For Google authentication
from GoogleAuth.views import google_auth, google_auth_redirect, google_auth_mobile
#For Apple authentication
from AppleAuth.views import apple_auth_web, apple_auth_redirect, apple_auth_mobile

# REST API Documentation
schema_view = get_schema_view(
    openapi.Info(
        title="Template Project API",
        default_version='v1',
        description="API endpoints for managing template project",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="support@yourapi.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('admin/', admin.site.urls),
    path("accounts/", include("allauth.urls")),
    path('auth/', include('dj_rest_auth.urls')),  # Login/logout/password reset
    path('auth/registration/', include('dj_rest_auth.registration.urls')),  # Registration
    path('', include('home.urls')),
    path('api/', include('contactAPI.urls')),
    path('api/', include('profileAPI.urls')),
    path('api/', include('tasksAPI.urls')),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('api/auth/google/', google_auth, name='google-auth'),
    path('api/auth/google-redirect/', google_auth_redirect, name='google-auth-redirect'),
    path('api/auth/google/mobile/', google_auth_mobile, name='google-auth-mobile'),
    path('api/auth/apple/web/', apple_auth_web, name='apple-auth-web'),
    path('api/auth/apple/web/redirect/', apple_auth_redirect, name='apple_auth_redirect'),
    path('api/auth/apple/mobile/', apple_auth_mobile, name='apple-auth-mobile'),
]
handler404 = 'Core.views.handler404'
