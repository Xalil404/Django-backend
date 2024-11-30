from django.urls import path
from .views import ProfileDetailUpdateView

urlpatterns = [
    path('profile/', ProfileDetailUpdateView.as_view(), name='profile_detail'),
]
