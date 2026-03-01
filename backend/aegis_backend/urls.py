from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from accounts.views import MeView, EmailOrUsernameTokenObtainPairView
from scans.views import SecurityStatusView

urlpatterns = [
    path("auth/login/", EmailOrUsernameTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/me/", MeView.as_view(), name="auth_me"),
    path("security-status/", SecurityStatusView.as_view(), name="security_status"),
    path("", include("accounts.urls")),
    path("", include("assets.urls")),
    path("", include("scans.urls")),
    path("", include("code_security.urls")),
    path("", include("network_security.urls")),
    path("", include("reports.urls")),
    path("", include("incidents.urls")),
    path("", include("activity_log.urls")),
    path("", include("service_requests.urls")),
    path("", include("cloud_security.urls")),
    path("", include("marketing.urls")),
    path("", include("internal.urls")),
]
