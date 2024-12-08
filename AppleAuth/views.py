import json
import requests
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from jose import jwt  # PyJWT or python-jose can be used to decode and verify JWT
from django.conf import settings
from rest_framework.authtoken.models import Token
import logging


logger = logging.getLogger(__name__)
logger.info(f"Received body: {request.body.decode('utf-8')}")


# Apple's public keys URL
APPLE_PUBLIC_KEYS_URL = "https://appleid.apple.com/auth/keys"


# Function to fetch Apple's public keys
def get_apple_public_keys():
    try:
        response = requests.get(APPLE_PUBLIC_KEYS_URL)
        response.raise_for_status()
        return response.json()['keys']
    except requests.RequestException as e:
        logger.error(f"Error fetching Apple's public keys: {e}")
        return None


# Function to decode and verify the Apple token
def verify_apple_token(id_token):
    # Fetch Apple's public keys to verify the signature
    public_keys = get_apple_public_keys()

    if public_keys is None:
        return None, 'Failed to fetch Apple public keys.'

    for key in public_keys:
        try:
            # Decode and verify the token using Apple's public key
            decoded_token = jwt.decode(
                id_token,
                key,
                algorithms=['RS256'],
                audience=settings.APPLE_CLIENT_ID,
                issuer='https://appleid.apple.com'
            )
            return decoded_token, None  # Token is valid, return decoded token

        except jwt.ExpiredSignatureError:
            return None, 'Token is expired.'
        except jwt.JWTClaimsError:
            return None, 'Invalid claims in the token.'
        except Exception as e:
            logger.error(f"Error verifying Apple token: {e}")
            return None, str(e)


@csrf_exempt
def apple_auth_web(request):
    if request.method == 'POST':
        try:
            logger.info("Received Apple Redirect request")

            # Parse the request body
            body = json.loads(request.body)
            id_token = body.get('token')

            if not id_token:
                logger.error("Token not provided in request")
                return JsonResponse({'error': 'Token not provided'}, status=400)

            # Verify the Apple ID token
            decoded_token, error = verify_apple_token(id_token)
            if decoded_token is None:
                logger.error(f"Token verification failed: {error}")
                return JsonResponse({'error': 'Invalid token', 'details': error}, status=400)

            logger.info(f"Token verified successfully: {decoded_token}")

            # Extract user information from the token
            email = decoded_token.get('email')
            first_name = decoded_token.get('given_name', '')
            last_name = decoded_token.get('family_name', '')

            if not email:
                logger.error("Email not available in token")
                return JsonResponse({'error': 'Email not available in token'}, status=400)

            # Check if the user exists, or create a new one
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],
                    'first_name': first_name,
                    'last_name': last_name,
                }
            )
            logger.info(f"User {'created' if created else 'retrieved'}: {user}")

            # Generate or retrieve the user's token
            user_token, _ = Token.objects.get_or_create(user=user)
            logger.info(f"Token for user: {user_token.key}")

            # Return the token and redirect URL
            return JsonResponse({'token': user_token.key, 'redirect': '/dashboard'}, status=200)

        except Exception as e:
            logger.exception("An unexpected error occurred")
            return JsonResponse({'error': 'Something went wrong', 'details': str(e)}, status=500)

    # Handle non-POST requests
    logger.warning("Non-POST method used for Apple Redirect")
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)


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