from django.contrib import admin
from .models import CodeRepository, CodeFinding


@admin.register(CodeRepository)
class CodeRepositoryAdmin(admin.ModelAdmin):
    list_display = ("repo_url", "organization", "language")
    search_fields = ("repo_url",)


@admin.register(CodeFinding)
class CodeFindingAdmin(admin.ModelAdmin):
    list_display = ("title", "repository", "category", "severity", "created_at")
    list_filter = ("category", "severity")
