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
import requests
import datetime

logger = logging.getLogger(__name__)

APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys"

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
@csrf_exempt
def apple_auth_web_redirect(request):
    """
    Initiates Apple Sign-In (Step 1).
    """
    client_id = "com.template.applicationwebproject"
    redirect_uri = "https://backend-django-9c363a145383.herokuapp.com/api/auth/apple/callback"
    state = "state"  # Optionally use a dynamic state for CSRF protection

    apple_auth_url = (
        f"https://appleid.apple.com/auth/authorize"
        f"?response_type=code&response_mode=form_post"
        f"&client_id={client_id}&redirect_uri={redirect_uri}&scope=name%20email&state={state}"
    )
    return redirect(apple_auth_url)


@csrf_exempt
def apple_auth_web_callback(request):
    """
    Handles the Apple callback (Step 2).
    """
    if request.method != "POST":
        return JsonResponse({"error": "Get Method Not Allowed"}, status=405)

    # Get the code from the callback
    code = request.POST.get("code")
    if not code:
        return JsonResponse({"error": "Authorization code missing"}, status=400)

    # Exchange code for tokens
    token_url = "https://appleid.apple.com/auth/token"
    client_id = "com.template.applicationwebproject"
    client_secret = settings.apple['SECRET_KEY']
    redirect_uri = "https://backend-django-9c363a145383.herokuapp.com/api/auth/apple/callback"

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(token_url, data=data, headers=headers)

    if response.status_code != 200:
        return JsonResponse({"error": "Failed to retrieve token from Apple"}, status=500)

    response_data = response.json()
    id_token = response_data.get("id_token")
    if not id_token:
        return JsonResponse({"error": "ID token missing"}, status=400)

    # Decode the ID token (no signature verification for now)
    decoded_id_token = jwt.decode(id_token, options={"verify_signature": False})
    user_id = decoded_id_token.get("sub")  # Unique user ID from Apple

    # Generate your own JWT for user authentication
    def generate_jwt(user_id):
        payload = {
            "user_id": user_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
        }
        secret_key = settings.JWT_SECRET_KEY
        return jwt.encode(payload, secret_key, algorithm="HS256")

    user_token = generate_jwt(user_id)

    # Redirect to the React app with the authentication completed
    frontend_dashboard_url = f"https://web-frontend-dun.vercel.app/dashboard"
    return redirect(f"{frontend_dashboard_url}?token={user_token}")



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