"""Django settings for the shop project."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
DEBUG = False
ALLOWED_HOSTS = ["shop.example.com"]

INSTALLED_APPS = [
    "django.contrib.sessions",
    "shop",
]

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_AGE = 1209600
