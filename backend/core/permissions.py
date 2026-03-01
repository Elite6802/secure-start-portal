from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied
from functools import wraps
from accounts.models import UserOrganization


def get_user_role(user):
    if not user or not user.is_authenticated:
        return None
    membership = user.memberships.filter(is_primary=True).first() or user.memberships.first()
    return membership.role if membership else None


class OrganizationAccessPermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser or user.is_staff:
            return True
        role = get_user_role(user)
        if not role:
            return False
        required_roles = getattr(view, "required_roles", None)
        if not required_roles:
            return True
        return role in required_roles


class RolePermissionMixin:
    required_roles = None
    role_action_map = None

    def enforce_role(self, request, roles):
        user = request.user
        if user.is_superuser or user.is_staff:
            return
        role = get_user_role(user)
        if not role or role not in roles:
            raise PermissionDenied("Your role does not allow this action.")

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        roles = None
        if isinstance(getattr(self, "role_action_map", None), dict):
            roles = self.role_action_map.get(getattr(self, "action", None))
        if roles is None:
            roles = getattr(self, "required_roles", None)
        if roles:
            self.enforce_role(request, roles)


def requires_role(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(self, request, *args, **kwargs):
            user = request.user
            if user.is_superuser or user.is_staff:
                return func(self, request, *args, **kwargs)
            role = get_user_role(user)
            if not role or role not in roles:
                raise PermissionDenied("Your role does not allow this action.")
            return func(self, request, *args, **kwargs)
        return wrapper
    return decorator
