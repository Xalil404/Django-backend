import json
import logging
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from jose import jwt, jwk
from django.conf import settings
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
import requests
from django.core.cache import cache

# For redirect authentication
from django.shortcuts import redirect
import jwt
import datetime
from django.core.cache import cache



logger = logging.getLogger(__name__)
# for pop up method
APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys"
# for redirect method
APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"

# Apple Web Pop-up authentication
def fetch_apple_public_key():
    cached_keys = cache.get("apple_public_key")
    if cached_keys:
        return cached_keys

    response = requests.get(APPLE_KEYS_URL)
    if response.status_code == 200:
        keys = response.json().get("keys")
        cache.set("apple_public_key", keys, timeout=86400)
        return keys
    return None

def get_key_for_kid(kid, keys):
    for key in keys:
        if key["kid"] == kid:
            return key
    return None

@csrf_exempt
def apple_auth_web(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        body = json.loads(request.body.decode('utf-8'))
        token = body.get('token')

        if not token:
            return JsonResponse({'error': 'Token is missing'}, status=400)

        # Fetch Apple's public key
        public_keys = fetch_apple_public_key()
        if not public_keys:
            return JsonResponse({'error': 'Could not fetch Apple public key'}, status=500)

        # Decode and validate the token
        header = jwt.get_unverified_header(token)
        key = get_key_for_kid(header['kid'], public_keys)

        if not key:
            logger.error("No matching key found for the token.")
            return JsonResponse({'error': 'Invalid token'}, status=400)

        public_key = jwk.construct(key)
        decoded_token = jwt.decode(
            token,
            public_key.to_pem(),
            algorithms=['RS256'],
            audience=settings.APPLE_CLIENT_ID
        )

        # Extract user info
        apple_user_id = decoded_token['sub']
        email = decoded_token.get('email', '')

        # Get or create the user
        user, created = User.objects.get_or_create(username=apple_user_id, defaults={'email': email})
        if created:
            logger.info(f"Created new user: {user.username}")

        # Generate an auth token for the user
        token, _ = Token.objects.get_or_create(user=user)

        return JsonResponse({'token': token.key, 'redirect': '/dashboard/'})

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except jwt.JWTError as e:
        logger.error(f"Token validation error: {str(e)}")
        return JsonResponse({'error': 'Invalid token'}, status=400)
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)









# Web redirect view
def generate_client_secret():
    apple_settings = settings.SOCIALACCOUNT_PROVIDERS.get('apple', {})
    team_id = apple_settings.get('TEAM_ID')
    client_id = apple_settings.get('CLIENT_ID')
    key_id = apple_settings.get('KEY_ID')
    secret_key_path = apple_settings.get('SECRET_KEY')

    with open(secret_key_path, 'r') as key_file:
        secret_key = key_file.read()

    headers = {
        'kid': key_id,
        'alg': 'ES256'
    }

    claims = {
        'iss': team_id,
        'iat': int(time.time()),
        'exp': int(time.time()) + 86400 * 180,  # 6 months
        'aud': 'https://appleid.apple.com',
        'sub': client_id
    }

    client_secret = jwt.encode(claims, secret_key, algorithm='ES256', headers=headers)
    return client_secret

@csrf_exempt
def apple_auth_redirect(request):
    if request.method == 'POST':
        try:
            # Handle the POST request from Apple
            body = json.loads(request.body.decode('utf-8'))
            code = body.get('code')

            if not code:
                return JsonResponse({'error': 'Authorization code is missing'}, status=400)

            # Exchange the authorization code for an access token
            client_id = settings.SOCIALACCOUNT_PROVIDERS['apple']['CLIENT_ID']
            client_secret = generate_client_secret()
            redirect_uri = settings.APPLE_REDIRECT_URI  # Ensure this is defined in your settings

            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
            }

            response = requests.post(APPLE_TOKEN_URL, data=data)
            if response.status_code != 200:
                return JsonResponse({'error': 'Failed to fetch token from Apple'}, status=500)

            token_response = response.json()
            id_token = token_response.get('id_token')

            if not id_token:
                return JsonResponse({'error': 'ID token is missing'}, status=400)

            # Decode and validate the token
            decoded_token = jwt.decode(
                id_token,
                algorithms=['RS256'],
                audience=client_id
            )

            # Extract user info
            apple_user_id = decoded_token['sub']
            email = decoded_token.get('email', '')

            # Get or create the user
            user, created = User.objects.get_or_create(username=apple_user_id, defaults={'email': email})
            if created:
                logger.info(f"Created new user: {user.username}")

            # Generate an auth token for the user
            token, _ = Token.objects.get_or_create(user=user)

            return JsonResponse({'token': token.key, 'redirect': '/dashboard/'})

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.JWTError as e:
            logger.error(f"Token validation error: {str(e)}")
            return JsonResponse({'error': 'Invalid token'}, status=400)
        except Exception as e:
            logger.error(f"Unhandled error: {str(e)}")
            return JsonResponse({'error': 'Internal server error'}, status=500)

    elif request.method == 'GET':
        # Handle GET requests for debugging purposes
        return JsonResponse({'error': 'GET method not supported for authentication'}, status=405)

    return JsonResponse({'error': 'Method not allowed'}, status=405)