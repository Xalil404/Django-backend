from django.shortcuts import render

# Create your views here.
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import ContactMessage
from .serializers import ContactMessageSerializer

from rest_framework.permissions import AllowAny

class ContactMessageView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Log the incoming request data for debugging
        print(request.data)  # This will print the incoming JSON data to the console for debugging purposes
        
        serializer = ContactMessageSerializer(data=request.data)
        
        if serializer.is_valid():
            # Save the message to the database
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        # Return any validation errors as response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
