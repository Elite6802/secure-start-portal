from rest_framework.routers import DefaultRouter
from .views import CloudAccountViewSet, CloudFindingViewSet

router = DefaultRouter()
router.register(r"cloud-accounts", CloudAccountViewSet, basename="cloud-accounts")
router.register(r"cloud-findings", CloudFindingViewSet, basename="cloud-findings")

urlpatterns = router.urls
