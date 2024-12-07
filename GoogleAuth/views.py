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
@csrf_exempt
def google_auth_redirect(request):
    if request.method == 'POST':
        try:
            # Parse the request body
            body = json.loads(request.body)
            token = body.get('token')

            if not token:
                return JsonResponse({'error': 'Token not provided'}, status=400)

            # Verify the Google ID token
            google_request = requests.Request()
            CLIENT_ID = "26271032790-djnijd5ookmvg0d58pneg2l8l6bdgvbn.apps.googleusercontent.com"  # Replace with your actual Google Client ID
            idinfo = id_token.verify_oauth2_token(token, google_request, CLIENT_ID)

            # Extract user information from the token
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            if not email:
                return JsonResponse({'error': 'Email not available in token'}, status=400)

            # Check if the user exists, create one if not
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],
                    'first_name': first_name,
                    'last_name': last_name,
                }
            )

            # Generate or retrieve the user's token
            user_token, _ = Token.objects.get_or_create(user=user)

            # Return the token to the frontend
            return JsonResponse({'token': user_token.key}, status=200)

        except ValueError as e:
            # Handle invalid token errors
            return JsonResponse({'error': 'Invalid token', 'details': str(e)}, status=400)

        except Exception as e:
            # Handle any other exceptions
            return JsonResponse({'error': 'Something went wrong', 'details': str(e)}, status=500)

    # Handle non-POST requests
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)