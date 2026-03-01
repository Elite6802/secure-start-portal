from rest_framework.routers import DefaultRouter
from .views import (
    OrganizationInternalViewSet,
    UserInternalViewSet,
    AssetInternalViewSet,
    ScanJobInternalViewSet,
    ScanScheduleInternalViewSet,
    ScanAlertInternalViewSet,
    ScanRequestInternalViewSet,
    IncidentInternalViewSet,
    ActivityLogInternalViewSet,
    ReportInternalViewSet,
    HygieneInternalViewSet,
    OpsInternalViewSet,
    GovernanceInternalViewSet,
)
from triage.views_internal import TriageInternalViewSet
from service_requests.views import ServiceRequestInternalViewSet

router = DefaultRouter()
router.register(r"internal/organizations", OrganizationInternalViewSet, basename="internal-organizations")
router.register(r"internal/users", UserInternalViewSet, basename="internal-users")
router.register(r"internal/assets", AssetInternalViewSet, basename="internal-assets")
router.register(r"internal/scan-jobs", ScanJobInternalViewSet, basename="internal-scan-jobs")
router.register(r"internal/scan-schedules", ScanScheduleInternalViewSet, basename="internal-scan-schedules")
router.register(r"internal/scan-alerts", ScanAlertInternalViewSet, basename="internal-scan-alerts")
router.register(r"internal/scan-requests", ScanRequestInternalViewSet, basename="internal-scan-requests")
router.register(r"internal/service-requests", ServiceRequestInternalViewSet, basename="internal-service-requests")
router.register(r"internal/incidents", IncidentInternalViewSet, basename="internal-incidents")
router.register(r"internal/activity-log", ActivityLogInternalViewSet, basename="internal-activity-log")
router.register(r"internal/reports", ReportInternalViewSet, basename="internal-reports")
router.register(r"internal/hygiene", HygieneInternalViewSet, basename="internal-hygiene")
router.register(r"internal/ops", OpsInternalViewSet, basename="internal-ops")
router.register(r"internal/governance", GovernanceInternalViewSet, basename="internal-governance")
router.register(r"internal/triage", TriageInternalViewSet, basename="internal-triage")

urlpatterns = router.urls
