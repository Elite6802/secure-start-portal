from rest_framework.routers import DefaultRouter
from .views import NetworkAssetViewSet, NetworkFindingViewSet

router = DefaultRouter()
router.register(r"network-assets", NetworkAssetViewSet, basename="network-assets")
router.register(r"network-findings", NetworkFindingViewSet, basename="network-findings")

urlpatterns = router.urls
