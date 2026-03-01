from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import User, Organization, UserOrganization


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "email", "is_staff", "is_active")
    search_fields = ("username", "email")


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "industry", "domain", "created_at")
    search_fields = ("name", "domain")


@admin.register(UserOrganization)
class UserOrganizationAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "is_primary", "created_at")
    list_filter = ("role", "is_primary")
