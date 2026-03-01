from django.contrib import admin
from .models import NetworkAsset, NetworkFinding


@admin.register(NetworkAsset)
class NetworkAssetAdmin(admin.ModelAdmin):
    list_display = ("asset", "organization", "network_type")
    list_filter = ("network_type",)


@admin.register(NetworkFinding)
class NetworkFindingAdmin(admin.ModelAdmin):
    list_display = ("summary", "network_asset", "finding_type", "severity", "created_at")
    list_filter = ("finding_type", "severity")
