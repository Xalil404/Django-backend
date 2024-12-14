"""
Django settings for Core project.

Generated by 'django-admin startproject' using Django 4.2.16.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os
import dj_database_url
if os.path.isfile('env.py'):
    import env

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
#DEBUG = True
DEBUG = False

ALLOWED_HOSTS = [
    'backend-django-9c363a145383.herokuapp.com',
    '127.0.0.1', 
    'localhost'
]


# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'cloudinary_storage',
    'django.contrib.staticfiles',
    'cloudinary',
    'crispy_forms',
    'crispy_bootstrap4',
    'Core', # To customize admin panel & show user ID
    'home',
    'contactAPI',
    'profileAPI',
    'tasksAPI',
    'GoogleAuth',
    'AppleAuth',
    'drf_yasg', # To generate swagger & redo docs
    'rest_framework',  # For Django REST Framework API URLs
    'corsheaders', # To allow React app to communicate with Django backend
    'dj_rest_auth', # Authentication for react app
    'rest_framework.authtoken', # Authentication for react app
]

SITE_ID = 1

CRISPY_TEMPLATE_PACK = 'bootstrap4'

ACCOUNT_AUTHENTICATION_METHOD = 'username_email'
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATED_LOGIN_REDIRECTS = True
ACCOUNT_LOGOUT_ON_GET = True
ACCOUNT_EMAIL_VERIFICATION = 'none' # Options: "mandatory", "optional", or "none"
#ACCOUNT_SIGNUP_EMAIL_ENTER_TWICE = True
ACCOUNT_USERNAME_MIN_LENGTH = 4
LOGIN_URL = '/accounts/login/'
# Redirect after login/logout (customize as needed)
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

SOCIALACCOUNT_LOGIN_ON_GET = True

# Tokens are stored in the database and can be accessed again later for API calls or 
# refreshes without needing to authenticate the user again
SOCIALACCOUNT_STORE_TOKENS = True

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    },
    'apple': {
        'CLIENT_ID': os.environ.get('APPLE_CLIENT_ID', 'com.template.applicationwebproject'),  # Default to your client ID
        'SECRET_KEY': os.environ.get('APPLE_AUTH_KEY_PATH', str(BASE_DIR / 'private_keys' / 'AuthKey_866S5JW2TH.p8')),  # Make sure the path is correct
        'TEAM_ID': os.environ.get('APPLE_TEAM_ID', 'TGGQFAW4Y5'),  # Default to your Team ID
        'KEY_ID': os.environ.get('APPLE_KEY_ID', '866S5JW2TH'),  # Default to your Key ID
    }
}


APPLE_CLIENT_ID = 'com.template.applicationwebproject'
APPLE_REDIRECT_URI = os.environ.get('APPLE_REDIRECT_URI', 'https://web-frontend-dun.vercel.app/auth/callback')  # Replace with your actual redirect URI

# Mobile App Apple Authentication Credentials
APPLE_MOBILE_CLIENT_ID = os.environ.get('APPLE_MOBILE_CLIENT_ID', 'com.ios.template.Template-iOS')  # Your mobile app's CLIENT_ID
APPLE_MOBILE_SECRET_KEY = os.environ.get('APPLE_MOBILE_SECRET_KEY_PATH', str(BASE_DIR / 'private_keys' / 'AuthKey_R8MP33FL68.p8'))  # Mobile app secret key file
APPLE_MOBILE_TEAM_ID = os.environ.get('APPLE_MOBILE_TEAM_ID', 'TGGQFAW4Y5')  # Team ID for the mobile app (same as web app if it's the same team)
APPLE_MOBILE_KEY_ID = os.environ.get('APPLE_MOBILE_KEY_ID', 'R8MP33FL68')  # Key ID for the mobile app


# Top one is for web & second one is for mobile
GOOGLE_CLIENT_IDS = [
    '26271032790-djnijd5ookmvg0d58pneg2l8l6bdgvbn.apps.googleusercontent.com'
    '1010986907178-s8ckurj79jcu41a56fdk1ng7bnah1bgm.apps.googleusercontent.com'
] 

# GOOGLE_CLIENT_ID = "26271032790-djnijd5ookmvg0d58pneg2l8l6bdgvbn.apps.googleusercontent.com"

#EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'


if 'DEVELOPMENT' in os.environ:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'boutiqueado@example.com'
else:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_USE_TLS = True
    EMAIL_PORT = 587
    EMAIL_HOST = 'smtp.gmail.com'
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASS')
    DEFAULT_FROM_EMAIL = os.environ.get('EMAIL_HOST_USER')


AUTHENTICATION_BACKENDS = (
    # Needed to login by username in Django admin, regardless of `allauth`
    'django.contrib.auth.backends.ModelBackend',

    # `allauth` specific authentication methods, such as login by e-mail
    'allauth.account.auth_backends.AuthenticationBackend',
)


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',  # Token Authentication
        'rest_framework.authentication.SessionAuthentication',  # Use session authentication for testing Profile API url
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',  # Permissions for authenticated users
    ],
}


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware', # to serve css of admin panel in production
    'allauth.account.middleware.AccountMiddleware', 
]


# These settings are related to Cross-Origin Resource Sharing (CORS) and 
# secure cookie handling, and they play a crucial role when your frontend 
# and backend are hosted on different domains (which is the case for your setup)

# This setting allows the browser to send cookies and credentials (like authentication tokens)
CORS_ALLOW_CREDENTIALS = True
# This setting ensures that session cookies are only sent over HTTPS connections
SESSION_COOKIE_SECURE = True
# This setting ensures that the CSRF cookie is only sent over HTTPS connections, similar to SESSION_COOKIE_SECURE
CSRF_COOKIE_SECURE = True


# CORS configuration
CORS_ALLOW_ALL_ORIGINS = True  # True For development

# CSRF trusted origins
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "https://web-frontend-dun.vercel.app",
    "https://appleid.apple.com",
]

# For production, restrict this to specific domains
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React local development server
    'https://web-frontend-dun.vercel.app',  # Your deployed React app
    "https://appleid.apple.com",
]

# When your frontend and backend are hosted on different domains (e.g., 
# frontend on Vercel and backend on Heroku or localhost), browsers enforce 
# the Same-Origin Policy. This policy restricts how scripts from one origin 
# can interact with resources on another origin. For security, Django includes 
# CSRF protection by default, which checks whether the request comes from a trusted domain
CSRF_TRUSTED_ORIGINS = [
    "https://web-frontend-dun.vercel.app",  # Replace with your frontend's actual domain
    "https://backend-django-9c363a145383.herokuapp.com/",  # Replace with your backend's actual domain (if necessary)
]


ROOT_URLCONF = 'Core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
            os.path.join(BASE_DIR, 'templates', 'allauth'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'Core.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': BASE_DIR / 'db.sqlite3',
#    }
#}

DATABASES = {
    'default': dj_database_url.parse(os.environ.get("DATABASE_URL"))
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = '/static/'

STATICFILES_STORAGE = 'cloudinary_storage.storage.StaticHashedCloudinaryStorage'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static'), ]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

MEDIA_URL = '/media/'
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
