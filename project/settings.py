"""
Django settings for project project.

Generated by 'django-admin startproject' using Django 5.0.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
from datetime import timedelta, datetime

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# # Secrets Setting
import os, json
from django.core.exceptions import ImproperlyConfigured

secret_file = os.path.join(BASE_DIR, 'secrets.json')

with open(secret_file) as f:
    secrets = json.loads(f.read())

def get_secret(setting, secrets=secrets):
    try:
        return secrets[setting]
    except KeyError:
        error_msg = "Set the {} environment variable".format(setting)
        raise ImproperlyConfigured(error_msg)

# Secrets Setting with dotenv
# def os.getenv(setting, secrets=secrets):
#     try:
#         return secrets[setting]
#     except KeyError:
#         error_msg = "Set the {} environment variable".format(setting)
#         raise ImproperlyConfigured(error_msg)

# import os
# from dotenv import load_dotenv

# load_dotenv(
#     dotenv_path="local.env",
#     verbose=True
# )

# SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")
SECRET_KEY = get_secret("DJANGO_SECRET_KEY")

# Secrets Setting End

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# CORS
CORS_EXPOSE_HEADERS = ['Content-Disposition']
CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_ALLOW_ALL = True


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # pip
    'rest_framework',
    'rest_framework_simplejwt.token_blacklist',
    'drf_yasg',
    'storages',
    'corsheaders',
    # app
    'app',
    'question',
    'oauth',
    'users',
    'ddd',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'project.wsgi.application'

# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': os.getenv('POSTGRES_NAME'),
#         'USER': os.getenv('POSTGRES_USER'),
#         'PASSWORD': os.getenv('POSTGRES_PASSWORD'),
#         'HOST': os.getenv('POSTGRES_HOST'),
#         'PORT': os.getenv('POSTGRES_PORT'),
#     }
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'ko-kr'

TIME_ZONE = 'Asia/Seoul'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

# STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# AWS Setting
# AWS_REGION = os.getenv("AWS_REGION")
# AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
# AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
# AWS_STORAGE_BUCKET_NAME = os.getenv("AWS_STORAGE_BUCKET_NAME")

# DEFAULT_FILE_STORAGE = 'project.storages.MediaStorage'
# STATICFILES_STORAGE = 'project.storages.StaticStorage'

# MEDIAFILES_LOCATION = 'media'
# STATICFILES_LOCATION = 'static'

# AWS_S3_CUSTOM_DOMAIN = '%s.s3.%s.amazonaws.com' % (
#     AWS_STORAGE_BUCKET_NAME, AWS_REGION)
# AWS_DEFAULT_ACL = 'public-read'
# AWS_LOCATION = 'static'

# STATIC_URL = 'https://%s/%s/' % (AWS_S3_CUSTOM_DOMAIN, AWS_LOCATION)

# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, 'static')
# ]
# AWS Setting End

# Static File Settings Start
STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]
# Static File Settings End

# Loggin Setting Start
if not os.path.exists(os.path.join(BASE_DIR, 'logs')):
    os.makedirs(os.path.join(BASE_DIR, 'logs'))

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {'format': '%(asctime)s %(levelname)s: %(message)s'},
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', f'logs-{datetime.now().strftime("%Y-%m-%d")}.log'),
            'formatter': 'simple',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',  # 모든 로그 모니터링
            'propagate': False,
        },
    },
}
# Loggin Setting End

# OAuth Setting Start
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [  # 기본 Permission 설정
        # 'rest_framework.permissions.AllowAny',  # 모든 계정 액세스 허용
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': (  # Authenticationt 설정
        # 'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        # 'rest_framework.authentication.TokenAuthentication',
        # 'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_RENDERER_CLASSES': [  # api 결과 전달 방식
        'rest_framework.renderers.JSONRenderer',  # json 방식
    ],
    'DEFAULT_PARSER_CLASSES': [  # 요청 받을 때 body 형태
        'rest_framework.parsers.JSONParser',
        # 'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DATETIME_FORMAT': '%Y-%m-%d %H:%M:%S',  # serializer datetime format
}

ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_PASSWORD_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_EMAIL_VERIFICATION = 'none'

REST_USE_JWT = False
ACCOUNT_LOGOUT_ON_GET = False
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=3),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=14),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,

    'ALGORITHM': 'HS512',
    'SIGNING_KEY': get_secret("DJANGO_SECRET_KEY"),

    'AUTH_HEADER_TYPES': ('Bearer',),  # 인증 헤더 유형
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',  # 인증 헤더 명칭
    'USER_ID_FIELD': 'social_id',  # 사용자 식별을 위한 토큰에 포함할 사용자 모델의 DB 필드명
    'USER_ID_CLAIM': 'social_id',  # 사용자 식별을 저장하는 데 사용할 생성된 토큰의 클레임

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),  # 토큰 유형 지정 클래스
    'TOKEN_TYPE_CLAIM': 'token_type',  # 토큰 유형 저장 클레임 명칭

    'JTI_CLAIM': 'jti',
}

AUTH_USER_MODEL = 'users.UserModel'
AUTHENTICATION_BACKENDS = (
    'users.backends.SettingsBackend',
    'django.contrib.auth.backends.ModelBackend',
)
# OAuth Setting End

# SWAGGER Setting Start
SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization'
        },
        'CSRF Token': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'X-CSRFToken',  # CSRF 토큰을 헤더에 포함
        }
    },
    'LOGIN_URL': 'users:login',
    'LOGOUT_URL': 'users:logout',
    'USE_SESSION_AUTH': True,  # 세션 인증을 사용하여 CSRF 보호에 대응
}
# SWAGGER Setting End


#
# OAuth Secrets
#

# KAKAO
KAKAO_CLIENT_ID = get_secret('KAKAO_CLIENT_ID')
KAKAO_CLIENT_SECRET = get_secret('KAKAO_CLIENT_SECRET')
KAKAO_REDIRECT_URI = get_secret('KAKAO_REDIRECT_URI')

# GOOGLE
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_SECRET = os.getenv('GOOGLE_SECRET')
GOOGLE_REDIRECT_URI =os.getenv('GOOGLE_REDIRECT_URI')

# APPLE
APPLE_CLIENT_ID = get_secret('APPLE_CLIENT_ID')
APPLE_KEY_ID = get_secret('APPLE_KEY_ID')
APPLE_TEAM_ID = get_secret('APPLE_TEAM_ID')
APPLE_PRIVATE_KEY = get_secret('APPLE_PRIVATE_KEY')
APPLE_REDIRECT_URI = get_secret('APPLE_REDIRECT_URI')
