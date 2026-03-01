from django.conf import settings
from django.core.checks import Warning, register


@register()
def security_settings_check(app_configs, **kwargs):
    warnings = []
    if settings.DEBUG:
        warnings.append(
            Warning(
                "DEBUG is enabled. Disable DEBUG in production.",
                id="aegis.W001",
            )
        )
    if settings.SECRET_KEY.startswith("unsafe-dev"):
        warnings.append(
            Warning(
                "Using an unsafe default SECRET_KEY. Set DJANGO_SECRET_KEY.",
                id="aegis.W002",
            )
        )
    return warnings
