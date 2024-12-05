from django.urls import path
from .views import google_auth, google_auth_redirect

urlpatterns = [
    path('api/auth/google/', google_auth, name='google-auth'), # Popup flow
    path('api/auth/google-redirect/', google_auth_redirect, name='google-auth-redirect'),  # Redirect flow
]
