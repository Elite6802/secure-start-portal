from django.contrib import admin
from .models import Asset


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "asset_type", "organization", "risk_level", "last_scanned_at")
    list_filter = ("asset_type", "risk_level")
    search_fields = ("name", "identifier")
