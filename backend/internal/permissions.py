from rest_framework import permissions
from accounts.models import UserOrganization


class IsInternalAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or user.is_superuser:
            return True
        return UserOrganization.objects.filter(user=user, role=UserOrganization.ROLE_SOC_ADMIN).exists()
