from rest_framework.views import exception_handler
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, PermissionDenied, ValidationError


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return response

    if isinstance(exc, NotAuthenticated):
        response.data = {"detail": "Authentication required.", "code": "auth_required"}
    elif isinstance(exc, AuthenticationFailed):
        # Preserve explicit auth failure details for login flows.
        pass
    elif isinstance(exc, PermissionDenied):
        response.data = {"detail": "Permission denied.", "code": "permission_denied"}
    elif isinstance(exc, ValidationError):
        response.data = {"detail": "Validation error.", "errors": response.data}

    return response
