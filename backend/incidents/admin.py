from django.contrib import admin
from .models import Incident


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("severity", "status", "organization", "detected_at", "resolved_at")
    list_filter = ("severity", "status")
