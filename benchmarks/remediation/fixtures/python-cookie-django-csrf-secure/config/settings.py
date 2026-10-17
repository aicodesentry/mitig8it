import os

DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ROOT_URLCONF = "config.urls"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

CSRF_COOKIE_SECURE = False  # flipped for the local docker setup
CSRF_TRUSTED_ORIGINS = ["https://portal.example.com"]
