import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aegis_backend.settings")

app = Celery("aegis_backend")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
