"""Base Django settings for recon-monitor."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except ImportError:
    pass


def env(name, default=""):
    return os.environ.get(name, default)


def env_bool(name, default=False):
    val = os.environ.get(name, "")
    if val == "":
        return default
    return val.lower() in ("1", "true", "yes", "on")


SECRET_KEY = env("DJANGO_SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY == "change-me-in-production-use-50-random-chars":
    import logging as _logging

    from django.core.management.utils import get_random_secret_key

    SECRET_KEY = get_random_secret_key()
    _logging.getLogger(__name__).warning(
        "DJANGO_SECRET_KEY not set — using an ephemeral key. Sessions will reset on restart. "
        "Set DJANGO_SECRET_KEY in .env for production.")
DEBUG = env_bool("DJANGO_DEBUG", True)
ALLOWED_HOSTS = [h.strip() for h in env("ALLOWED_HOSTS", "*" if DEBUG else "localhost,127.0.0.1").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = [h.strip() for h in env("CSRF_TRUSTED_ORIGINS", "").split(",") if h.strip()]

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_filters",
    "channels",
    "apps.core",
    "apps.accounts",
    "apps.dashboard",
    "apps.targets",
    "apps.scope",
    "apps.assets",
    "apps.events",
    "apps.jobs",
    "apps.monitoring",
    "apps.alerts",
    "apps.audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.audit.middleware.AuditMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context_processors.target_context",
            ],
        },
    },
]

DATABASE_URL = env("DATABASE_URL", "sqlite:///db.sqlite3")
if DATABASE_URL.startswith("postgres"):
    # postgres://user:pass@host:port/dbname
    from urllib.parse import urlparse

    u = urlparse(DATABASE_URL)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": u.path.lstrip("/"),
            "USER": u.username,
            "PASSWORD": u.password,
            "HOST": u.hostname or "localhost",
            "PORT": u.port or 5432,
        }
    }
else:
    path = DATABASE_URL.replace("sqlite:///", "")
    if not os.path.isabs(path):
        path = str(BASE_DIR / path)
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": path}}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/dashboard/"

# --- Channels / Redis ---
REDIS_URL = env("REDIS_URL", "redis://localhost:6379/0")
if env_bool("USE_REDIS_CHANNELS", False):
    CHANNEL_LAYERS = {
        "default": {"BACKEND": "channels_redis.core.RedisChannelLayer", "CONFIG": {"hosts": [REDIS_URL]}}
    }
else:
    CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "recon-monitor",
    }
}

# --- Celery ---
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = "cache+memory://"
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", True)
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_TIMEZONE = "UTC"
CELERY_TASK_DEFAULT_QUEUE = "recon"
CELERY_TASK_ROUTES = {
    "apps.jobs.tasks.queue_js_analysis": {"queue": "js_analysis"},
    "apps.jobs.tasks.analyze_js_task": {"queue": "js_analysis"},
    "apps.jobs.tasks.nuclei_for_url": {"queue": "cve"},
    "apps.monitoring.tasks.sync_cve_database": {"queue": "cve"},
    "apps.alerts.tasks.*": {"queue": "notifications"},
}
CELERY_BEAT_SCHEDULE = {
    "reconcile-every-30m": {"task": "apps.monitoring.tasks.reconcile_all", "schedule": 1800.0},
    "cve-sync-every-6h": {"task": "apps.monitoring.tasks.sync_cve_database", "schedule": 21600.0},
    "check-auth-expiry-every-15m": {"task": "apps.monitoring.tasks.check_authorization_expiry", "schedule": 900.0},
    "flush-discord-batches-every-60s": {"task": "apps.alerts.tasks.flush_discord_batches", "schedule": 60.0},
    "detect-stalled-jobs-every-10m": {"task": "apps.monitoring.tasks.detect_stalled_jobs", "schedule": 600.0},
}

# --- DRF ---
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
}

# --- Recon monitor ---
DISCORD_ENABLED = env_bool("DISCORD_ENABLED", False)
DISCORD_WEBHOOK_URL = env("DISCORD_WEBHOOK_URL", "")
DISCORD_MIN_SEVERITY = env("DISCORD_MIN_SEVERITY", "LOW")
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
ARTIFACTS_DIR = DATA_DIR / "artifacts"

SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False


# --- Structured logging (TASK-071): never log secrets ---
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"context_defaults": {"()": "django.utils.log.CallbackFilter", "callback": lambda r: (all(hasattr(r, k) for k in ("target_id", "scan_run_id", "task_id", "operation", "status")) or [setattr(r, k, "-") for k in ("target_id", "scan_run_id", "task_id", "operation", "status") if not hasattr(r, k)], True)[-1]}},
    "formatters": {
        "structured": {
            "format": "%(asctime)s %(levelname)s %(name)s target=%(target_id)s scan=%(scan_run_id)s task=%(task_id)s op=%(operation)s status=%(status)s %(message)s",
        },
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "structured", "filters": ["context_defaults"]}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
