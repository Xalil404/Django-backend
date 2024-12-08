import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from jose import jwt
from django.conf import settings
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

import requests
from django.core.cache import cache

logger = logging.getLogger(__name__)


APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys"

def fetch_apple_public_key():
    """
    Fetch and cache Apple's public key for verifying JWT tokens.
    """
    cached_key = cache.get("apple_public_key")
    if cached_key:
        return cached_key

    response = requests.get(APPLE_KEYS_URL)
    if response.status_code == 200:
        keys = response.json().get("keys")
        # Cache the public key for 24 hours (86400 seconds)
        cache.set("apple_public_key", keys, timeout=86400)
        return keys
    return None


@csrf_exempt
def apple_auth_web(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))
        token = body.get('token')

        if not token:
            logger.error("Token is missing from the request body.")
            return JsonResponse({'error': 'Token is missing'}, status=400)

        # Decode and validate the token
        decoded_token = jwt.decode(
            token,
            settings.APPLE_PUBLIC_KEY,  # Replace with the public key for Apple Sign-In
            algorithms=['RS256'],
            audience=settings.APPLE_CLIENT_ID
        )
        logger.info(f"Decoded token: {decoded_token}")

        # Use `sub` (unique user identifier) as the username
        apple_user_id = decoded_token['sub']
        email = decoded_token.get('email', '')

        # Get or create the user
        user, created = User.objects.get_or_create(username=apple_user_id, defaults={'email': email})
        if created:
            logger.info(f"Created new user: {user.username}")

        # Generate an auth token for the user
        token, _ = Token.objects.get_or_create(user=user)

        logger.info(f"Authentication successful for user: {user.username}")
        return JsonResponse({'token': token.key, 'redirect': '/dashboard/'})  # Redirect to the appropriate page

    except jwt.ExpiredSignatureError:
        logger.error("The token has expired.")
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except jwt.JWTError as e:
        logger.error(f"Token validation error: {str(e)}")
        return JsonResponse({'error': 'Invalid token'}, status=400)
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)



'''
from django.shortcuts import render

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
'''