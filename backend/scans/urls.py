from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import ScanViewSet, ScanJobViewSet, ScanRequestViewSet, ScanAlertViewSet, AnalystMetricsView

router = DefaultRouter()
router.register(r"scans", ScanViewSet, basename="scans")
router.register(r"scan-jobs", ScanJobViewSet, basename="scan-jobs")
router.register(r"scan-requests", ScanRequestViewSet, basename="scan-requests")
router.register(r"scan-alerts", ScanAlertViewSet, basename="scan-alerts")

urlpatterns = [
    path("scan-metrics/", AnalystMetricsView.as_view(), name="scan-metrics"),
    *router.urls,
]
