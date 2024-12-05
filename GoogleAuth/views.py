import json
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from rest_framework.authtoken.models import Token

from google.auth.transport import requests as google_requests


# views.py (for Pop-up Flow)
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



# views.py (for Redirect Flow)
@csrf_exempt
def google_auth_redirect(request):
    if request.method == 'GET':
        # The code that Google sends as a query parameter after redirection
        code = request.GET.get('code')
        if not code:
            return JsonResponse({'error': 'Authorization code is missing'}, status=400)

        # Exchange the code for an access token and ID token
        try:
            # Google token endpoint for exchanging the code for tokens
            token_url = "https://oauth2.googleapis.com/token"
            client_id = "26271032790-djnijd5ookmvg0d58pneg2l8l6bdgvbn.apps.googleusercontent.com"
            client_secret = "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"
            redirect_uri = "https://backend-django-9c363a145383.herokuapp.com/api/auth/google-redirect/"

            # Prepare the data for token exchange
            data = {
                'code': code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code',
            }

            # Make the POST request to exchange the code for a token
            response = requests.post(token_url, data=data)
            response_data = response.json()

            if 'id_token' not in response_data:
                return JsonResponse({'error': 'Failed to obtain ID token'}, status=400)

            id_token_str = response_data['id_token']

            # Verify the ID token
            idinfo = id_token.verify_oauth2_token(id_token_str, google_requests.Request(), client_id)

            # Get user information from the ID token
            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            # Check if the user exists; if not, create a new one
            user, created = User.objects.get_or_create(
                email=email,
                defaults={'username': email.split('@')[0], 'first_name': first_name, 'last_name': last_name}
            )

            # Create or get a token for the user
            token, _ = Token.objects.get_or_create(user=user)

            return JsonResponse({'token': token.key}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Only GET method is allowed'}, status=405)
