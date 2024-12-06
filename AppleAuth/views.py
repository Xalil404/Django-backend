from django.shortcuts import render
'''
# views.py
import jwt
import requests
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from .serializers import AppleAuthSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def apple_auth_web(request):
    serializer = AppleAuthSerializer(data=request.data)
    if serializer.is_valid():
        apple_token = serializer.validated_data['apple_token']

        if '.' not in apple_token:
            return JsonResponse({'error': 'Invalid token format'}, status=400)

        try:
            # Fetch Apple's public keys to verify the token
            apple_public_keys_url = "https://appleid.apple.com/auth/keys"
            apple_public_keys = requests.get(apple_public_keys_url).json()

            # Decode and verify the Apple token
            decoded_token = decode_apple_token(apple_token, apple_public_keys)

            email = decoded_token.get('email')
            user_id = decoded_token.get('sub')

            # Create or update the user
            user, created = create_or_update_user(email, user_id, decoded_token)

            # Generate a token for the user
            token, _ = Token.objects.get_or_create(user=user)

            return JsonResponse({
                'message': 'Sign-in successful',
                'email': email,
                'user_id': user_id,
                'token': token.key
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid data'}, status=400)

def decode_apple_token(token, apple_public_keys):
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header['kid']
    key = next((key for key in apple_public_keys['keys'] if key['kid'] == kid), None)
    if key is None:
        raise ValueError("Public key not found")
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
    decoded_token = jwt.decode(token, public_key, algorithms=['RS256'], audience=settings.APPLE_CLIENT_ID, options={"verify_exp": True})

    if decoded_token.get('iss') != 'https://appleid.apple.com':
        raise ValueError("Invalid issuer")

    return decoded_token

def create_or_update_user(email, user_id, decoded_token):
    user = User.objects.filter(email=email).first()

    if not user:
        user = User.objects.create_user(
            username=email,
            email=email,
            password=None  # Apple does not send a password
        )

    user.first_name = decoded_token.get('given_name', '')
    user.last_name = decoded_token.get('family_name', '')
    user.save()

    return user, False  # Return user and False if the user is not newly created
'''

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import jwt
import requests
from django.conf import settings
from .models import User
from .serializers import AppleAuthSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def apple_auth_web(request):
    serializer = AppleAuthSerializer(data=request.data)
    if serializer.is_valid():
        apple_token = serializer.validated_data['apple_token']

        if '.' not in apple_token:
            return Response({'error': 'Invalid token format'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch Apple's public keys to verify the token
            apple_public_keys_url = "https://appleid.apple.com/auth/keys"
            apple_public_keys = requests.get(apple_public_keys_url).json()

            # Decode and verify the Apple token
            decoded_token = decode_apple_token(apple_token, apple_public_keys)

            email = decoded_token.get('email')
            user_id = decoded_token.get('sub')

            # Create or update the user
            user, created = create_or_update_user(email, user_id, decoded_token)

            # Generate a token for the user
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                'message': 'Sign-in successful',
                'email': email,
                'user_id': user_id,
                'token': token.key
            })

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

def decode_apple_token(token, apple_public_keys):
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header['kid']
    key = next((key for key in apple_public_keys['keys'] if key['kid'] == kid), None)
    if key is None:
        raise ValueError("Public key not found")
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
    decoded_token = jwt.decode(token, public_key, algorithms=['RS256'], audience=settings.APPLE_CLIENT_ID, options={"verify_exp": True})

    if decoded_token.get('iss') != 'https://appleid.apple.com':
        raise ValueError("Invalid issuer")

    return decoded_token

def create_or_update_user(email, user_id, decoded_token):
    # Check if the user already exists using either the email or user_id (sub)
    user = User.objects.filter(email=email).first()

    if not user:
        # Create a new user if not found
        user = User.objects.create_user(
            username=email,  # You can use the email or generate a unique username
            email=email,
            password=None  # Apple does not send a password
        )
    
    # Update the user with information from the decoded token
    user.first_name = decoded_token.get('given_name', '')
    user.last_name = decoded_token.get('family_name', '')
    
    # Optionally, store the Apple user ID (sub) in the user model for future reference
    user.profile.apple_user_id = user_id  # Assuming you have a custom user profile model
    user.save()

    return user, False  # Returning user and False to indicate we didn't create the user again
