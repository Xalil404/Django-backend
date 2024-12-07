# views.py (for Web Pop-up Flow)
import json
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from rest_framework.authtoken.models import Token


# (for Web Redirect Flow)
import requests
import logging
from google.auth.transport.requests import Request



# views.py (for Web Pop-up Flow)
@csrf_exempt
def google_auth(request):
    if request.method == 'POST':
        body = json.loads(request.body)
        token = body.get('token')

        try:
            # Verify the token with Google
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), "26271032790-djnijd5ookmvg0d58pneg2l8l6bdgvbn.apps.googleusercontent.com")
            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            # Check if user exists; if not, create a new one
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],
                    'first_name': first_name,
                    'last_name': last_name,
                }
            )

            # Create or get a token for the user
            from rest_framework.authtoken.models import Token
            token, _ = Token.objects.get_or_create(user=user)

            return JsonResponse({'token': token.key}, status=200)

        except ValueError:
            return JsonResponse({'error': 'Invalid token'}, status=400)

    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)



# (for Web Redirect Flow)
# Set up logging
logger = logging.getLogger(__name__)
'''
@csrf_exempt
def google_auth_redirect(request):
    if request.method == 'POST':
        try:
            logger.info("Received Google Redirect request")
            
            # Parse the request body
            body = json.loads(request.body)
            token = body.get('token')
            logger.info(f"Token received: {token}")

            if not token:
                logger.error("Token not provided in request")
                return JsonResponse({'error': 'Token not provided'}, status=400)

            # Verify the Google ID token
            google_request = Request()  # Instantiate the Request object
            CLIENT_ID = "26271032790-djnijd5ookmvg0d58pneg2l8l6bdgvbn.apps.googleusercontent.com"  # Replace with your actual Google Client ID
            idinfo = id_token.verify_oauth2_token(token, google_request, CLIENT_ID)
            logger.info(f"ID Token verified successfully: {idinfo}")

            # Extract user information from the token
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

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

            # Return the token to the frontend (debugging line)
            return JsonResponse({'token': user_token.key}, status=200)

        except ValueError as e:
            # Handle invalid token errors
            logger.error(f"Invalid token: {e}")
            return JsonResponse({'error': 'Invalid token', 'details': str(e)}, status=400)

        except Exception as e:
            # Handle unexpected exceptions
            logger.exception("An unexpected error occurred")
            return JsonResponse({'error': 'Something went wrong', 'details': str(e)}, status=500)

    # Handle non-POST requests
    logger.warning("Non-POST method used for Google Redirect")
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
'''

@csrf_exempt
def google_auth_redirect(request):
    if request.method == 'POST':
        try:
            logger.info("Received Google Redirect request")
            
            # Parse the request body
            body = json.loads(request.body)
            token = body.get('token')
            logger.info(f"Token received: {token}")

            if not token:
                logger.error("Token not provided in request")
                return JsonResponse({'error': 'Token not provided'}, status=400)

            # Verify the Google ID token
            google_request = Request()  # Instantiate the Request object
            CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID"
            idinfo = id_token.verify_oauth2_token(token, google_request, CLIENT_ID)
            logger.info(f"ID Token verified successfully: {idinfo}")

            # Extract user information from the token
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

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

            # Return the token to the frontend (for frontend handling)
            return JsonResponse({'redirect': '/dashboard'}, status=200)

        except ValueError as e:
            logger.error(f"Invalid token: {e}")
            return JsonResponse({'error': 'Invalid token', 'details': str(e)}, status=400)

        except Exception as e:
            logger.exception("An unexpected error occurred")
            return JsonResponse({'error': 'Something went wrong', 'details': str(e)}, status=500)

    # Handle non-POST requests
    logger.warning("Non-POST method used for Google Redirect")
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
