from pathlib import Path
import environ

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
    CORS_ALLOWED_ORIGINS=(list, []),
    CELERY_BROKER_URL=(str, "redis://redis:6379/0"),
)
environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="unsafe-dev-secret")
DEBUG = env("DJANGO_DEBUG")
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt",
    "core",
    "accounts",
    "assets",
    "scans",
    "code_security",
    "network_security",
    "reports",
    "incidents",
    "activity_log",
    "service_requests",
    "cloud_security",
    "marketing",
    "internal",
    "triage",
]

CLOUD_CREDENTIALS_KEY = env("CLOUD_CREDENTIALS_KEY", default="")

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "aegis_backend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

WSGI_APPLICATION = "aegis_backend.wsgi.application"

DATABASES = {"default": env.db("DATABASE_URL", default="postgres://postgres:postgres@db:5432/aegis")}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.ScopedRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "user": "120/minute",
        "anon": "30/minute",
        "login": "10/minute",
        "contact": "20/hour",
    },
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "EXCEPTION_HANDLER": "core.exception_handler.custom_exception_handler",
}


EMAIL_BACKEND = env("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = env("EMAIL_HOST", default="")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="security@aegis.local")
CONTACT_INBOX_EMAIL = env("CONTACT_INBOX_EMAIL", default="")
CONTACT_WEBHOOK_URL = env("CONTACT_WEBHOOK_URL", default="")
CONTACT_CONFIRMATION_SUBJECT = env(
    "CONTACT_CONFIRMATION_SUBJECT",
    default="We received your security request",
)
CONTACT_CONFIRMATION_BODY = env(
    "CONTACT_CONFIRMATION_BODY",
    default=(
        "Hi {name},\n\n"
        "Thanks for reaching out to the Aegis security team. "
        "We have received your request and will respond within 1 business day.\n\n"
        "Summary:\n"
        "- Organization: {company}\n"
        "- Message: {message}\n\n"
        "Regards,\n"
        "Aegis Security Team"
    ),
)

CORS_ALLOWED_ORIGINS = env("CORS_ALLOWED_ORIGINS", default=["http://localhost:5173"])
CORS_ALLOW_CREDENTIALS = True
if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True

CELERY_BROKER_URL = env("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = env("CELERY_BROKER_URL")
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

CELERY_TASK_ROUTES = {
    "service_requests.tasks.execute_service_request_job": {"queue": "scanner"},
}

CELERY_BEAT_SCHEDULE = {
    "run_scan_schedules": {
        "task": "scans.tasks.run_scan_schedules",
        "schedule": 300.0,
    },
}

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
