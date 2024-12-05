from django.urls import path
from .views import google_auth


urlpatterns = [
    path('api/auth/google/', google_auth, name='google-auth'), # Web Popup flow
]
