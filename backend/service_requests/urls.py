from rest_framework.routers import DefaultRouter
from .views import ServiceRequestViewSet

router = DefaultRouter()
router.register(r"service-requests", ServiceRequestViewSet, basename="service-requests")

urlpatterns = router.urls
