from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("scope", "organization", "generated_at")
    list_filter = ("scope",)
