from django.contrib import admin
from .models import Scan, ScanJob


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("scan_type", "asset", "organization", "status", "started_at", "completed_at")
    list_filter = ("scan_type", "status")


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("scan_type", "organization", "status", "started_at", "completed_at")
    list_filter = ("scan_type", "status")
