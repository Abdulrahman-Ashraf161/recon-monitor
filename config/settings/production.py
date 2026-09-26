import os

from django.core.exceptions import ImproperlyConfigured

from .base import *

DEBUG = False

# Task 16: ephemeral SECRET_KEY fallback is development-only. Production must
# provide a stable secret (sessions/CSRF/signed URLs break across restarts and
# across daphne/worker/beat processes otherwise).
if SECRET_KEY_WAS_GENERATED or SECRET_KEY == "change-me-in-production-use-50-random-chars":
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY must be set to a stable random value in production "
        "(generate with: python -c \"import secrets; print(secrets.token_urlsafe(50))\")")
# Task 15: never run production with a wildcard/empty ALLOWED_HOSTS (Host
# header / cache-poisoning risk). Set ALLOWED_HOSTS=app.example.com.
if not ALLOWED_HOSTS or ALLOWED_HOSTS == ["*"]:
    raise ImproperlyConfigured(
        "ALLOWED_HOSTS must be set to your public hostname(s) in production "
        "(e.g. ALLOWED_HOSTS=app.example.com). Refusing to boot with '*'.")

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "False").lower() == "true"
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
